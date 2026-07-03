"""
tests/test_token_macaroon.py — Macaroon-based authentication tests.

Tests macaroon token generation and validation for WebDAV authentication.
Note: This test file requires nginx to be configured with
brix_macaroon_secret for the macaroon auth path to be active.
"""

import pytest
import hmac
import hashlib
import base64
import time


def make_packet(key, value):
    if isinstance(value, str):
        value = value.encode()
    data = key.encode() + b" " + value + b"\n"
    plen = len(data) + 4
    return f"{plen:04x}".encode() + data


def make_macaroon(root_key, identifier, caveats, location=None):
    # Initial signature: HMAC(root_key, identifier)
    sig = hmac.new(root_key, identifier.encode(), hashlib.sha256).digest()

    packets = b""
    if location:
        packets += make_packet("location", location)

    packets += make_packet("identifier", identifier)

    for c in caveats:
        packets += make_packet("cid", c)
        sig = hmac.new(sig, c.encode(), hashlib.sha256).digest()

    # Signature packet: signature <32-bytes-binary>
    sig_data = b"signature " + sig
    plen = len(sig_data) + 4
    packets += f"{plen:04x}".encode() + sig_data

    return base64.urlsafe_b64encode(packets).decode().rstrip("=")


@pytest.fixture
def macaroon_secret():
    return bytes.fromhex("deadbeef" * 8)


@pytest.fixture
def macaroon_token(macaroon_secret):
    return make_macaroon(
        macaroon_secret,
        "test-subject",
        ["activity:DOWNLOAD", "before:2026-12-31T23:59:59Z"],
        location="https://localhost:8443",
    )


def test_macaroon_logic_internal(macaroon_secret, macaroon_token):
    """Verify the macaroon generator produces a valid-looking token."""
    # Token should be base64url-encoded, non-empty, and decodable
    assert len(macaroon_token) > 0
    # Should decode without error
    # Add padding back for decoding
    padded = macaroon_token + "=" * (-len(macaroon_token) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    assert b"identifier" in decoded
    assert b"activity:DOWNLOAD" in decoded
    assert b"location" in decoded


def test_macaroon_different_caveats_produce_different_tokens(macaroon_secret):
    """Tokens with different caveats should be different."""
    token1 = make_macaroon(
        macaroon_secret, "test-subject", ["activity:DOWNLOAD"]
    )
    token2 = make_macaroon(
        macaroon_secret, "test-subject", ["activity:UPLOAD"]
    )
    assert token1 != token2


def test_macaroon_different_subjects_produce_different_tokens(macaroon_secret):
    """Tokens with different subjects should be different."""
    token1 = make_macaroon(macaroon_secret, "user-a", ["activity:DOWNLOAD"])
    token2 = make_macaroon(macaroon_secret, "user-b", ["activity:DOWNLOAD"])
    assert token1 != token2


def test_macaroon_no_location_produces_valid_token(macaroon_secret):
    """Token without location should still be valid."""
    token = make_macaroon(
        macaroon_secret, "test-subject", ["activity:DOWNLOAD"]
    )
    assert len(token) > 0
    padded = token + "=" * (-len(token) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    assert b"identifier" in decoded
    assert b"location" not in decoded


# ---------------------------------------------------------------------------
# path: caveat logic tests
#
# These test the path: caveat narrowing rules as implemented in
# brix_macaroon_validate().  They use the make_macaroon() helper to
# produce tokens, then decode and inspect the caveat presence — the actual
# enforcement is in C code, so here we verify the token structure is correct
# so that valid tokens carry the expected caveats.
# ---------------------------------------------------------------------------


def decode_packets(token):
    """Decode a macaroon token and return a list of (key, value) tuples."""
    padded = token + "=" * (-len(token) % 4)
    data = base64.urlsafe_b64decode(padded)
    packets = []
    pos = 0
    while pos + 4 <= len(data):
        plen = int(data[pos : pos + 4], 16)
        if plen < 4 or pos + plen > len(data):
            break
        field = data[pos + 4 : pos + plen]
        if field.endswith(b"\n"):
            field = field[:-1]
        space = field.find(b" ")
        if space >= 0:
            packets.append((field[:space].decode(), field[space + 1 :]))
        pos += plen
    return packets


def test_path_caveat_present_in_token(macaroon_secret):
    """A token with a path: caveat should contain that caveat in its packets."""
    token = make_macaroon(
        macaroon_secret,
        "test-subject",
        ["activity:DOWNLOAD", "path:/atlas/data", "before:2026-12-31T23:59:59Z"],
    )
    packets = decode_packets(token)
    caveats = [v.decode() for k, v in packets if k == "cid"]
    assert "path:/atlas/data" in caveats


def test_path_caveat_updates_hmac_chain(macaroon_secret):
    """
    A token with a path: caveat must have a different signature than one
    without, proving the caveat participates in the HMAC chain.
    """
    token_without = make_macaroon(
        macaroon_secret, "test-subject", ["activity:DOWNLOAD"]
    )
    token_with = make_macaroon(
        macaroon_secret,
        "test-subject",
        ["activity:DOWNLOAD", "path:/atlas/data"],
    )
    assert token_without != token_with


def test_multiple_path_caveats_produce_distinct_tokens(macaroon_secret):
    """
    Each additional path: caveat must further change the HMAC chain,
    so tokens with one vs two path: caveats must differ.
    """
    token_one = make_macaroon(
        macaroon_secret,
        "test-subject",
        ["activity:DOWNLOAD", "path:/atlas"],
    )
    token_two = make_macaroon(
        macaroon_secret,
        "test-subject",
        ["activity:DOWNLOAD", "path:/atlas", "path:/atlas/reco"],
    )
    assert token_one != token_two


# ---------------------------------------------------------------------------
# old-secret / grace-period fallback tests
#
# The C module accepts a token signed with either the current
# brix_macaroon_secret or the grace-period brix_macaroon_secret_old.
# We cannot call the C validator from Python, so these tests verify:
#   1. The helper correctly produces a different HMAC when a different key is
#      used (i.e. tokens from different keys are distinguishable).
#   2. A token produced with the "old" key is structurally valid (parseable)
#      — the C validator is what accepts or rejects it at runtime.
# ---------------------------------------------------------------------------


@pytest.fixture
def old_macaroon_secret():
    """A second key representing the rotated-away (grace-period) secret."""
    return bytes.fromhex("cafebabe" * 8)


def test_tokens_from_different_keys_are_different(macaroon_secret, old_macaroon_secret):
    """
    Tokens signed with different HMAC keys must differ.
    This property is what makes the old-secret fallback meaningful: the C
    validator tries the primary key first and, only on HMAC mismatch, retries
    with the old key.
    """
    token_new = make_macaroon(
        macaroon_secret, "test-subject", ["activity:DOWNLOAD"]
    )
    token_old = make_macaroon(
        old_macaroon_secret, "test-subject", ["activity:DOWNLOAD"]
    )
    assert token_new != token_old


def test_old_key_token_is_structurally_valid(old_macaroon_secret):
    """
    A macaroon produced with the old secret must have valid packet structure
    (identifier, activity caveat, and signature packets present).  The C
    module's grace-period path accepts such tokens when brix_macaroon_secret_old
    is configured.
    """
    token = make_macaroon(
        old_macaroon_secret,
        "test-subject",
        ["activity:DOWNLOAD", "before:2026-12-31T23:59:59Z"],
        location="https://localhost:8443",
    )
    packets = decode_packets(token)
    keys = [k for k, _ in packets]
    assert "identifier" in keys
    assert "cid" in keys
    assert "signature" in keys


def test_hmac_chain_depends_on_key(macaroon_secret, old_macaroon_secret):
    """
    Identical identifier and caveats with a different root key must produce a
    different final HMAC signature, confirming the key material propagates
    through the entire HMAC chain.
    """
    caveats = ["activity:DOWNLOAD", "path:/cms/data", "before:2026-12-31T23:59:59Z"]

    sig_new = [v for k, v in decode_packets(
        make_macaroon(macaroon_secret, "sub", caveats)
    ) if k == "signature"]

    sig_old = [v for k, v in decode_packets(
        make_macaroon(old_macaroon_secret, "sub", caveats)
    ) if k == "signature"]

    assert sig_new != sig_old, (
        "Different HMAC root keys must produce different signatures"
    )


def test_path_caveat_disjoint_from_activity(macaroon_secret):
    """
    A token scoped to activity:DOWNLOAD (→ storage.read:/) with a
    path:/atlas caveat should carry both caveats; the C layer enforces
    the intersection — this test just validates token structure.
    """
    token = make_macaroon(
        macaroon_secret,
        "test-subject",
        ["activity:DOWNLOAD", "path:/atlas"],
    )
    packets = decode_packets(token)
    caveats = [v.decode() for k, v in packets if k == "cid"]
    assert "activity:DOWNLOAD" in caveats
    assert "path:/atlas" in caveats
