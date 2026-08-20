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
  NAME TLV          type=0x01 | 0x00 | len | value NUL-terminated (len counts
                    the NUL)

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
SSS_TYPE_NAME = 0x01

KXR_AUTH = 3000


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


def sss_credential(key, key_id=1, username="xrd", gen_time=None, nonce=None,
                   opt=SSS_OPT_USEDATA, corrupt_crc=False):
    """Mint one SSS credential.

    ``gen_time`` is seconds since BRIX_SSS_BASE_TIME; pass an explicit value to
    drive the freshness check.  ``corrupt_crc`` flips a bit of the integrity
    trailer *before* encryption, which is how a tamper negative is expressed
    without also breaking the framing the server checks first.
    """
    if gen_time is None:
        import time
        gen_time = int(time.time()) - SSS_BASE_TIME
    if nonce is None:
        nonce = os.urandom(32)

    clear = bytearray(SSS_DATA_HDR_LEN)
    clear[0:32] = nonce
    clear[32:36] = struct.pack(">I", gen_time & 0xFFFFFFFF)
    clear[39] = opt

    value = username.encode() + b"\x00"
    clear += bytes([SSS_TYPE_NAME, 0, len(value)]) + value

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
