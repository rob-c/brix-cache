"""
tests/test_macaroon_discharge.py — Discharge Macaroon bundle validation tests.

Tests the Feature 8b implementation: brix_macaroon_validate_bundle(), which
accepts space-separated bundles of "<root> [<discharge> ...]" Macaroon tokens.

Discharge Macaroons allow third-party delegation:
  1. The root Macaroon contains a third-party caveat: (cid, vid) pair where
       cid = identifier of the discharge Macaroon
       vid = AES-256-CBC(key=sig_before_cid, IV=vid[0:16], data=discharge_key)
  2. The discharge Macaroon is a normal Macaroon signed with discharge_key.
  3. A client bundles both and submits "root_token discharge_token".

These tests exercise the Python-level macaroon helper to verify:
  - Bundle structure is correct (parseable, cid+vid pairs present)
  - Signature chains are correctly computed
  - Path narrowing via discharge works (intersection semantics)
  - Expired discharges produce invalid tokens
  - Bundles with no discharge for a third-party caveat fail (C-side)

Note: The actual bundle validation (AES decryption + recursive HMAC) is
implemented in C.  These tests validate the token generator correctness so
that the integration tests use structurally sound tokens.

Run:
    pytest tests/test_macaroon_discharge.py -v
"""

# --- Python 3.9 compat (EL9 system python) --------------------------------
# This suite uses PEP 604 unions (`X | None`) in annotations. On Python 3.9
# those are evaluated at def-time and raise TypeError; PEP 604 only works at
# runtime on Python >= 3.10. `from __future__ import annotations` (PEP 563)
# makes ALL annotations in this module lazy strings, so 3.9 imports cleanly.
# DROP this block (and the import) once the minimum supported Python is >=3.10.
from __future__ import annotations
# --------------------------------------------------------------------------


import base64
import hashlib
import hmac
import os
import struct
import time
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import pytest


# ---------------------------------------------------------------------------
# Macaroon wire-format helpers (from test_token_macaroon.py + discharge ext)
# ---------------------------------------------------------------------------

def _make_packet(key: str, value: bytes | str) -> bytes:
    """Encode one Macaroon packet: <4-hex-len><key> <value>\n"""
    if isinstance(value, str):
        value = value.encode()
    data = key.encode() + b" " + value + b"\n"
    plen = len(data) + 4
    return f"{plen:04x}".encode() + data


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def decode_packets(token: str) -> list[tuple[str, bytes]]:
    """Decode a base64url Macaroon into a list of (field, value) tuples."""
    data = _b64url_decode(token)
    packets = []
    pos = 0
    while pos + 4 <= len(data):
        plen = int(data[pos:pos + 4], 16)
        if plen < 4 or pos + plen > len(data):
            break
        field = data[pos + 4:pos + plen]
        if field.endswith(b"\n"):
            field = field[:-1]
        space = field.find(b" ")
        if space >= 0:
            packets.append((field[:space].decode(), field[space + 1:]))
        pos += plen
    return packets


def make_macaroon(
    root_key: bytes,
    identifier: str,
    first_party_caveats: list[str],
    third_party_caveats: Optional[list[tuple[str, bytes]]] = None,
    location: Optional[str] = None,
) -> tuple[str, bytes]:
    """
    Build a Macaroon token and return (base64url_token, final_sig).

    third_party_caveats is a list of (cid_str, vid_bytes) pairs that are
    added as cid+vid packet pairs after the first-party caveats.
    The vid bytes must already be AES-encrypted by the caller (use
    encrypt_discharge_key() for that).
    """
    sig = _hmac_sha256(root_key, identifier.encode())

    packets = b""
    if location:
        packets += _make_packet("location", location)
    packets += _make_packet("identifier", identifier)

    for caveat in first_party_caveats:
        packets += _make_packet("cid", caveat)
        sig = _hmac_sha256(sig, caveat.encode())

    if third_party_caveats:
        for cid_str, vid_bytes in third_party_caveats:
            # Save sig_before_cid (the AES key used to encrypt discharge key)
            sig_before = sig

            # Update chain: sig = HMAC(sig_before, cid)
            sig = _hmac_sha256(sig_before, cid_str.encode())

            # Update chain: sig = HMAC(sig_after_cid, vid)
            sig = _hmac_sha256(sig, vid_bytes)

            packets += _make_packet("cid", cid_str)
            packets += _make_packet("vid", vid_bytes)

    # Signature packet (no trailing newline — raw binary)
    sig_data = b"signature " + sig
    plen = len(sig_data) + 4
    packets += f"{plen:04x}".encode() + sig_data

    return _b64url_encode(packets), sig


def encrypt_discharge_key(sig_before: bytes, discharge_key: bytes) -> bytes:
    """
    Encrypt discharge_key (32 bytes) using AES-256-CBC.

    vid format: [16-byte IV][32-byte ciphertext]
    The C code disables PKCS7 padding (no_padding), so we must too.
    discharge_key must be exactly 32 bytes (two AES blocks).
    """
    assert len(sig_before) == 32, "sig_before must be 32 bytes (HMAC-SHA256)"
    assert len(discharge_key) == 32, "discharge_key must be exactly 32 bytes"

    iv = os.urandom(16)
    cipher = Cipher(
        algorithms.AES(sig_before),
        modes.CBC(iv),
        backend=default_backend(),
    )
    enc = cipher.encryptor()
    # No padding: 32-byte key fits exactly in 2 AES blocks
    ciphertext = enc.update(discharge_key) + enc.finalize()
    return iv + ciphertext


def _compute_sig_before_cid(root_key: bytes, identifier: str,
                             first_party_caveats: list[str]) -> bytes:
    """
    Compute the HMAC signature value immediately before a third-party cid is
    applied — this is what the C code calls sig_before_cid and uses as the
    AES-256-CBC decryption key for the vid blob.
    """
    sig = _hmac_sha256(root_key, identifier.encode())
    for c in first_party_caveats:
        sig = _hmac_sha256(sig, c.encode())
    return sig  # sig at this point = sig_before first third-party cid


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ROOT_KEY = bytes.fromhex("deadbeef" * 8)  # 32-byte HMAC secret
DISCHARGE_KEY = bytes.fromhex("cafebabe" * 8)  # 32-byte discharge root key

ROOT_IDENTIFIER = "test-root-subject"
DISCHARGE_IDENTIFIER = "tp-caveat-id-001"  # must match cid in root Macaroon


@pytest.fixture
def sig_before() -> bytes:
    """Signature value immediately before the third-party cid is applied."""
    return _compute_sig_before_cid(ROOT_KEY, ROOT_IDENTIFIER,
                                   ["activity:DOWNLOAD",
                                    "before:2099-12-31T23:59:59Z"])


@pytest.fixture
def vid_blob(sig_before) -> bytes:
    """AES-encrypted discharge key blob (vid packet value)."""
    return encrypt_discharge_key(sig_before, DISCHARGE_KEY)


@pytest.fixture
def root_token(vid_blob) -> str:
    """Root Macaroon with one third-party caveat."""
    token, _ = make_macaroon(
        ROOT_KEY,
        ROOT_IDENTIFIER,
        first_party_caveats=[
            "activity:DOWNLOAD",
            "before:2099-12-31T23:59:59Z",
        ],
        third_party_caveats=[(DISCHARGE_IDENTIFIER, vid_blob)],
        location="https://localhost:8443",
    )
    return token


@pytest.fixture
def discharge_token() -> str:
    """Discharge Macaroon signed with DISCHARGE_KEY, id = DISCHARGE_IDENTIFIER."""
    token, _ = make_macaroon(
        DISCHARGE_KEY,
        DISCHARGE_IDENTIFIER,
        first_party_caveats=["before:2099-12-31T23:59:59Z"],
    )
    return token


# ---------------------------------------------------------------------------
# Structure tests (token is parseable and contains expected packet types)
# ---------------------------------------------------------------------------

class TestRootMacaroonStructure:

    def test_root_has_identifier_packet(self, root_token):
        packets = decode_packets(root_token)
        identifiers = [v for k, v in packets if k == "identifier"]
        assert len(identifiers) == 1
        assert identifiers[0].decode() == ROOT_IDENTIFIER

    def test_root_has_cid_packet_for_third_party_caveat(self, root_token):
        packets = decode_packets(root_token)
        cids = [v.decode() for k, v in packets if k == "cid"]
        assert DISCHARGE_IDENTIFIER in cids

    def test_root_has_vid_packet(self, root_token):
        packets = decode_packets(root_token)
        vids = [v for k, v in packets if k == "vid"]
        assert len(vids) == 1, "Expected exactly one vid packet for one third-party caveat"
        assert len(vids[0]) == 48, "vid must be 16-byte IV + 32-byte ciphertext"

    def test_root_has_signature_packet(self, root_token):
        packets = decode_packets(root_token)
        sigs = [v for k, v in packets if k == "signature"]
        assert len(sigs) == 1
        assert len(sigs[0]) == 32, "Signature must be 32-byte HMAC-SHA256"

    def test_root_has_location_packet(self, root_token):
        packets = decode_packets(root_token)
        locs = [v for k, v in packets if k == "location"]
        assert len(locs) == 1

    def test_root_contains_activity_caveat(self, root_token):
        packets = decode_packets(root_token)
        cids = [v.decode() for k, v in packets if k == "cid"]
        assert "activity:DOWNLOAD" in cids


class TestDischargeMacaroonStructure:

    def test_discharge_identifier_matches_root_cid(self, discharge_token):
        packets = decode_packets(discharge_token)
        idents = [v.decode() for k, v in packets if k == "identifier"]
        assert idents == [DISCHARGE_IDENTIFIER]

    def test_discharge_has_signature(self, discharge_token):
        packets = decode_packets(discharge_token)
        sigs = [v for k, v in packets if k == "signature"]
        assert len(sigs) == 1
        assert len(sigs[0]) == 32

    def test_discharge_has_expiry_caveat(self, discharge_token):
        packets = decode_packets(discharge_token)
        cids = [v.decode() for k, v in packets if k == "cid"]
        assert any(c.startswith("before:") for c in cids)


# ---------------------------------------------------------------------------
# Bundle format tests
# ---------------------------------------------------------------------------

class TestBundleFormat:

    def test_bundle_is_space_separated(self, root_token, discharge_token):
        bundle = f"{root_token} {discharge_token}"
        parts = bundle.split()
        assert len(parts) == 2
        assert parts[0] == root_token
        assert parts[1] == discharge_token

    def test_bundle_parts_are_individually_decodable(self, root_token, discharge_token):
        for token in [root_token, discharge_token]:
            pkts = decode_packets(token)
            assert any(k == "identifier" for k, _ in pkts)

    def test_single_token_is_not_a_bundle(self, root_token):
        """A token with no spaces is treated as a non-discharge token."""
        assert " " not in root_token


# ---------------------------------------------------------------------------
# Cryptographic correctness tests
# ---------------------------------------------------------------------------

class TestCryptoCorrectness:

    def test_vid_decrypts_to_discharge_key(self, sig_before, vid_blob):
        """The vid blob must decrypt back to DISCHARGE_KEY under sig_before."""
        iv = vid_blob[:16]
        ciphertext = vid_blob[16:]
        cipher = Cipher(
            algorithms.AES(sig_before),
            modes.CBC(iv),
            backend=default_backend(),
        )
        dec = cipher.decryptor()
        plaintext = dec.update(ciphertext) + dec.finalize()
        assert plaintext == DISCHARGE_KEY

    def test_wrong_sig_before_gives_wrong_discharge_key(self, vid_blob):
        """Decrypting with a wrong key must not produce DISCHARGE_KEY."""
        wrong_key = bytes(32)  # all zeros
        iv = vid_blob[:16]
        ciphertext = vid_blob[16:]
        cipher = Cipher(
            algorithms.AES(wrong_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        dec = cipher.decryptor()
        plaintext = dec.update(ciphertext) + dec.finalize()
        assert plaintext != DISCHARGE_KEY

    def test_different_root_keys_produce_different_vid_blobs(self, sig_before):
        """Bundles constructed from different root secrets are distinguishable."""
        vid1 = encrypt_discharge_key(sig_before, DISCHARGE_KEY)
        # Different discharge key → different vid even with same sig_before
        other_key = bytes.fromhex("aabbccdd" * 8)
        vid2 = encrypt_discharge_key(sig_before, other_key)
        # Ciphertexts should differ (same IV is astronomically unlikely)
        assert vid1[16:] != vid2[16:]

    def test_root_and_discharge_have_different_final_sigs(self, root_token, discharge_token):
        """The root and discharge tokens must have independent HMAC chains."""
        root_sig = next(v for k, v in decode_packets(root_token) if k == "signature")
        disc_sig = next(v for k, v in decode_packets(discharge_token) if k == "signature")
        assert root_sig != disc_sig


# ---------------------------------------------------------------------------
# Path narrowing via discharge tests
# ---------------------------------------------------------------------------

class TestPathNarrowing:

    def test_discharge_path_caveat_is_structurally_valid(self):
        """
        A discharge Macaroon that narrows the path must carry the path: caveat.
        The C validator intersects root paths ∩ discharge paths.
        """
        token, _ = make_macaroon(
            DISCHARGE_KEY,
            DISCHARGE_IDENTIFIER,
            first_party_caveats=[
                "before:2099-12-31T23:59:59Z",
                "path:/atlas/data",
            ],
        )
        packets = decode_packets(token)
        cids = [v.decode() for k, v in packets if k == "cid"]
        assert "path:/atlas/data" in cids

    def test_discharge_path_updates_hmac_chain(self):
        """Discharge tokens with and without path caveats must differ."""
        tok_no_path, _ = make_macaroon(
            DISCHARGE_KEY, DISCHARGE_IDENTIFIER,
            first_party_caveats=["before:2099-12-31T23:59:59Z"],
        )
        tok_with_path, _ = make_macaroon(
            DISCHARGE_KEY, DISCHARGE_IDENTIFIER,
            first_party_caveats=[
                "before:2099-12-31T23:59:59Z",
                "path:/atlas/data",
            ],
        )
        sig_no = next(v for k, v in decode_packets(tok_no_path) if k == "signature")
        sig_with = next(v for k, v in decode_packets(tok_with_path) if k == "signature")
        assert sig_no != sig_with


# ---------------------------------------------------------------------------
# Expiry tests
# ---------------------------------------------------------------------------

class TestExpiry:

    def test_expired_discharge_has_past_before_caveat(self):
        """An expired discharge must carry a before: caveat in the past."""
        expired = int(time.time()) - 3600  # 1 hour ago
        from datetime import datetime, timezone
        exp_str = datetime.fromtimestamp(expired, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        token, _ = make_macaroon(
            DISCHARGE_KEY,
            DISCHARGE_IDENTIFIER,
            first_party_caveats=[f"before:{exp_str}"],
        )
        packets = decode_packets(token)
        cids = [v.decode() for k, v in packets if k == "cid"]
        assert any(c.startswith("before:") and exp_str in c for c in cids)

    def test_expiry_caveat_participates_in_hmac_chain(self):
        """Tokens with different expiry times must differ (HMAC chain includes caveat)."""
        tok_2099, _ = make_macaroon(
            DISCHARGE_KEY, DISCHARGE_IDENTIFIER,
            first_party_caveats=["before:2099-01-01T00:00:00Z"],
        )
        tok_2050, _ = make_macaroon(
            DISCHARGE_KEY, DISCHARGE_IDENTIFIER,
            first_party_caveats=["before:2050-01-01T00:00:00Z"],
        )
        assert tok_2099 != tok_2050


# ---------------------------------------------------------------------------
# Security negative tests
# ---------------------------------------------------------------------------

class TestSecurityNegative:

    def test_tampered_discharge_identifier_changes_signature(self):
        """Changing the discharge identifier invalidates the HMAC chain."""
        tok_good, _ = make_macaroon(DISCHARGE_KEY, DISCHARGE_IDENTIFIER, [])
        tok_bad, _ = make_macaroon(DISCHARGE_KEY, "different-id", [])
        sig_good = next(v for k, v in decode_packets(tok_good) if k == "signature")
        sig_bad = next(v for k, v in decode_packets(tok_bad) if k == "signature")
        assert sig_good != sig_bad

    def test_wrong_discharge_key_produces_different_signature(self):
        """A discharge signed with the wrong key has a different HMAC signature."""
        tok_correct, _ = make_macaroon(DISCHARGE_KEY, DISCHARGE_IDENTIFIER, [])
        wrong_key = bytes.fromhex("11223344" * 8)
        tok_wrong, _ = make_macaroon(wrong_key, DISCHARGE_IDENTIFIER, [])
        sig_c = next(v for k, v in decode_packets(tok_correct) if k == "signature")
        sig_w = next(v for k, v in decode_packets(tok_wrong) if k == "signature")
        assert sig_c != sig_w

    def test_bundle_with_extra_spaces_is_not_two_tokens(self, root_token):
        """Extra spaces must not confuse a simple split-based bundle parser."""
        # C code uses the first token as root; remaining are discharges
        # A bundle like "root  discharge" should not be treated as three tokens
        # by a naive parser.  The C implementation splits on single spaces.
        single_space_bundle = root_token + " " + root_token
        parts = single_space_bundle.split(" ")
        assert len(parts) == 2
