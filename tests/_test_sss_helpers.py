"""SSS (Simple Shared Secret) keytab + credential minting, in pure Python.

Why this exists: every SSS test in the tree so far drives the protocol through
``client/bin/xrdsssadmin-brix`` and ``client/bin/xrdfs``, so it skips wherever
the native client has not been built.  The credential is a small, fully
specified byte layout, and ``cryptography`` (a declared requirement) carries
Blowfish, so a socket-level test can mint one without a compiler.

The layout is the module's own, read off the single source of truth rather
than reconstructed from the spec:

  src/protocols/root/protocol/sss.h   the wire constants
  src/core/compat/sss_bf.c            brix_sss_build_credential(), the shared
                                      minting kernel the server's proxy path
                                      and the native client both call
  src/auth/sss/sss_keytab_kernel.c    the keytab line grammar and the
                                      permission check

  outer (16 bytes)  "sss\\0" | version=1 | spare | kn_size=0 | enc='0'
                    | key-id (8-byte big-endian)
  body              BF32(cleartext + CRC32-IEEE(cleartext), big-endian CRC)
  cleartext         32-byte nonce | gen_time (4B BE, epoch BRIX_SSS_BASE_TIME)
                    | 3 reserved | option byte | identity TLVs
  identity TLV      type | len (2 bytes, big-endian) | value
  packed string     NUL-terminated, the NUL counted in the length — NAME,
                    VORG, ROLE, GRPS and ENDO all use this form; CRED is
                    raw bytes and LGID (server → client) is packed

BF32 is Blowfish-CFB64 with an all-zero IV and no padding — a stream mode, so
the ciphertext is the same length as the plaintext.
"""

import os
import struct
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    # Blowfish and CFB move to `decrepit` in cryptography 49; requirements.txt
    # pins <49, so both spellings are live inside the supported range and only
    # the new one is warning-free where it exists.
    from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:                                     # cryptography < 43
    Blowfish, CFB = algorithms.Blowfish, modes.CFB

# src/protocols/root/protocol/sss.h — single source of truth for these.
SSS_HDR_LEN = 16
SSS_DATA_HDR_LEN = 40
SSS_BASE_TIME = 1222183880
SSS_ENC_BF32 = ord("0")
SSS_OPT_USEDATA = 0x00
SSS_OPT_SNDLID = 0x01

# The identity tags.  NAME/GRPS/HOST are the 1.x set; VORG, ROLE, ENDO and
# CRED are what F9 taught the parser, and LGID is the one the server sends
# back inside a kXR_authmore challenge.
SSS_TYPE_NAME = 0x01
SSS_TYPE_VORG = 0x02
SSS_TYPE_ROLE = 0x03
SSS_TYPE_GRPS = 0x04
SSS_TYPE_ENDO = 0x05
SSS_TYPE_CRED = 0x06
SSS_TYPE_RAND = 0x07
SSS_TYPE_LGID = 0x10
SSS_TYPE_HOST = 0x20

KXR_AUTH = 3000
KXR_AUTHMORE = 4002


def sss_write_keytab(path, key, key_id=1, user="anybody", group="anygroup",
                     name="brixtest"):
    """Write a one-entry keytab and lock it down to 0600.

    ``u:anybody g:anygroup`` sets BRIX_SSS_OPT_ANYUSR|ANYGRP (src/auth/sss/
    config.c:63-72), so the name inside the credential is accepted as given
    instead of having to match a local account.  The mode matters: the loader
    refuses a keytab with any group or other permission bit
    (sss_keytab_mode_ok), which is also what makes a permissions negative test
    possible without touching the key material.
    """
    line = (f"0 u:{user} g:{group} n:{name} N:{key_id} k:{key.hex()}\n")
    with open(path, "w") as f:
        f.write(line)
    os.chmod(path, 0o600)
    return path


def sss_tlv(tag, value):
    """One identity TLV: 1-byte tag, 2-byte big-endian length, value."""
    return struct.pack(">BH", tag, len(value)) + value


def sss_packed(text):
    """A packed string field: NUL-terminated, the NUL counted in the length."""
    return text.encode() + b"\x00"


def _sss_clear(nonce, gen_time, opt, username, tlvs, trailer):
    """The pre-encryption cleartext: the 40-byte data header, then the TLVs.

    Split out of sss_credential so the minter stays one decision per
    keyword: this is where the wire SHAPE lives, that is where the
    defaults and the tamper switch live.
    """
    clear = bytearray(SSS_DATA_HDR_LEN)
    clear[0:32] = nonce
    clear[32:36] = struct.pack(">I", gen_time & 0xFFFFFFFF)
    clear[39] = opt

    if username is not None:
        clear += sss_tlv(SSS_TYPE_NAME, sss_packed(username))
    for tag, value in tlvs:
        clear += sss_tlv(tag, value)
    return bytes(clear) + trailer


def sss_credential(key, key_id=1, username="xrd", gen_time=None, nonce=None,
                   opt=SSS_OPT_USEDATA, corrupt_crc=False, tlvs=(),
                   trailer=b""):
    """Mint one SSS credential.

    ``gen_time`` is seconds since BRIX_SSS_BASE_TIME; pass an explicit value to
    drive the freshness check.  ``corrupt_crc`` flips a bit of the integrity
    trailer *before* encryption, which is how a tamper negative is expressed
    without also breaking the framing the server checks first.

    ``tlvs`` is [(tag, value)] appended after NAME, which is how a v2 entity
    is put on the wire; ``username=None`` omits NAME entirely.  ``trailer``
    is appended raw, inside the CRC and the cipher, so a malformed-TLV
    negative can hand the parser a shape sss_tlv() cannot express.
    """
    if gen_time is None:
        import time
        gen_time = int(time.time()) - SSS_BASE_TIME
    if nonce is None:
        nonce = os.urandom(32)

    clear = _sss_clear(nonce, gen_time, opt, username, tlvs, trailer)

    crc = zlib.crc32(bytes(clear)) & 0xFFFFFFFF
    if corrupt_crc:
        crc ^= 0x00000001
    plain = bytes(clear) + struct.pack(">I", crc)

    enc = Cipher(Blowfish(key), CFB(b"\x00" * 8)).encryptor()
    body = enc.update(plain) + enc.finalize()

    header = (b"sss\x00" + bytes([1, 0, 0, SSS_ENC_BF32])
              + struct.pack(">q", key_id))
    return header + body


def sss_auth_frame(cred):
    """The kXR_auth request carrying an SSS credential (credtype "sss\\0")."""
    return (struct.pack(">BBH", 0, 1, KXR_AUTH) + b"\x00" * 12 + b"sss\x00"
            + struct.pack(">I", len(cred)) + cred)


def sss_decrypt(key, blob):
    """The cleartext inside an SSS blob: header stripped, CRC32 verified.

    The mirror of the minter, and the only way to read what the SERVER put
    on the wire — the kXR_authmore challenge is a full SSS blob under the
    same key.  The framing checks are brix_sss_challenge_lgid()'s
    (src/core/compat/sss_entity.c), so a test fails here for exactly the
    reasons the native client would refuse the same bytes.
    """
    assert blob[:4] == b"sss\x00" and blob[7] == SSS_ENC_BF32, blob[:8].hex()
    dec = Cipher(Blowfish(key), CFB(b"\x00" * 8)).decryptor()
    body = blob[SSS_HDR_LEN + blob[6]:]
    plain = dec.update(body) + dec.finalize()
    clear = plain[:-4]
    assert struct.unpack(">I", plain[-4:])[0] == zlib.crc32(clear) & 0xFFFFFFFF
    return clear


def sss_identity_tlvs(clear):
    """[(tag, value)] parsed out of a decrypted credential, in wire order."""
    out = []
    pos = SSS_DATA_HDR_LEN
    while pos + 3 <= len(clear):
        tag, length = struct.unpack(">BH", clear[pos:pos + 3])
        pos += 3
        out.append((tag, clear[pos:pos + length]))
        pos += length
    return out
