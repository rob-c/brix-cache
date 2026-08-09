"""Macaroons over root:// — the stream-plane twin of the WebDAV battery.

`brix_macaroon_secret` is registered on the stream server too
(src/protocols/root/stream/directives_auth.h), and `brix_auth token` routes a
dot-free bearer to the macaroon validator (src/auth/gsi/token.c
tokenauth_validate).  Every existing macaroon test drives that validator over
HTTP, so the whole cell "macaroon × root://" was empty
(docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md §7 P1-5) —
including the grace-period old-secret retry, which had no live coverage on any
plane.

Coverage (success · error · security-negative):
  success       a macaroon signed with the configured secret authenticates over
                the kXR `ztn` credential and the session then reads bytes;
                a macaroon signed with the *previous* secret is accepted while
                `brix_macaroon_secret_old` is configured (key rotation)
  error         a token that is not a macaroon at all is refused rather than
                crashing or half-authenticating the session
  security-neg  wrong signing secret, one flipped signature byte, an expired
                `before:` caveat, a `path:` caveat that does not cover the file,
                an `activity:` set that conveys no read scope, a macaroon minted
                for another service (location ≠ `brix_token_issuer`), and a token
                signed with a secret that is neither the current nor the old one
                (proving rotation widens the key set by exactly one).

Every case re-runs the full handshake on a fresh socket: the validator caches
verified claims (L1), so reusing a session would let an earlier success mask a
later rejection.
"""

import os
import struct
import sys

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN, TOKENS_DIR
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer                       # noqa: E402

from test_pgwrite_cse import (
    _handshake_login,
    _read_response,
    kXR_ok,
    kXR_error,
)
from test_token_macaroon import make_macaroon

pytestmark = [pytest.mark.serial, pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-macaroon-root")]

kXR_auth, kXR_open, kXR_read = 3000, 3010, 3013
kXR_open_read = 0x0010
kXR_NotAuthorized = 3010          # errno EPERM -> kXR (error_mapping.c)

SECRET_HEX = "deadbeef" * 8
OLD_SECRET_HEX = "0badc0de" * 8
OTHER_SECRET_HEX = "cafebabe" * 8
SECRET = bytes.fromhex(SECRET_HEX)
OLD_SECRET = bytes.fromhex(OLD_SECRET_HEX)
OTHER_SECRET = bytes.fromhex(OTHER_SECRET_HEX)

SEED = b"macaroon root-plane payload\n"
FILE = b"/m.txt"

FUTURE = "2099-12-31T23:59:59Z"
PAST = "2000-01-01T00:00:00Z"

# The macaroon location packet is checked against brix_token_issuer, which the
# template takes from the same TokenIssuer the JWT leg uses.
LOCATION = TokenIssuer.DEFAULT_ISSUER


def _caveats(before=FUTURE, path="/", activity="DOWNLOAD"):
    return [f"activity:{activity}", f"path:{path}", f"before:{before}"]


def _mac(secret, location=LOCATION, **caveats):
    """A macaroon for this server's identity, signed with `secret`.

    `location` defaults to the configured brix_token_issuer: the stream plane
    checks a macaroon's location packet against that issuer
    (src/auth/token/validate.c "issuer/location mismatch"), so a macaroon minted
    for a different service is refused here even with the right root key.
    """
    return make_macaroon(secret, "root-subject", _caveats(**caveats),
                         location=location)


# --------------------------------------------------------------------------- #
# Wire helpers
# --------------------------------------------------------------------------- #

def _auth_ztn(sock, token):
    """Send kXR_auth with credtype `ztn`; return (status, errcode).

    The credential blob repeats the protocol tag ("ztn\\0") ahead of the bearer,
    exactly as the XRootD client frames it.
    """
    cred = b"ztn\x00" + (token.encode() if isinstance(token, str) else token)
    sock.sendall(struct.pack("!2sH12s4sI", b"\x00\x03", kXR_auth,
                             b"\x00" * 12, b"ztn\x00", len(cred)) + cred)
    status, body = _read_response(sock)
    errcode = (struct.unpack("!I", body[:4])[0]
               if (status == kXR_error and len(body) >= 4) else None)
    return status, errcode


def _open_read(sock, path=FILE):
    sock.sendall(struct.pack("!2sHHH2s6s4sI", b"\x00\x04", kXR_open,
                             0, kXR_open_read, b"\x00\x00", b"\x00" * 6,
                             b"\x00" * 4, len(path)) + path)
    return _read_response(sock)


def _read(sock, fhandle, length):
    sock.sendall(struct.pack("!2sH4sqiI", b"\x00\x05", kXR_read,
                             fhandle, 0, length, 0))
    return _read_response(sock)


def _authenticate(endpoint, token):
    """Full handshake + kXR_auth on a fresh socket; caller closes."""
    sock = _handshake_login(host=HOST, port=endpoint.port)
    status, errcode = _auth_ztn(sock, token)
    return sock, status, errcode


def _assert_refused(endpoint, token, why):
    sock, status, errcode = _authenticate(endpoint, token)
    try:
        assert status == kXR_error and errcode == kXR_NotAuthorized, \
            f"{why}: expected NotAuthorized, got st={status} err={errcode}"
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def harness():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    h = LifecycleHarness()
    try:
        yield h
    finally:
        h.close()


@pytest.fixture(scope="module")
def issuer():
    # Only needed to satisfy the stream plane's JWKS precondition (see the
    # template comment); the JWT leg below also uses it to prove the two token
    # families coexist on one server.
    ti = TokenIssuer(TOKENS_DIR)
    if not os.path.exists(ti.key_path):
        ti.init_keys()
    if not os.path.exists(ti.jwks_path):
        ti.init_keys()
    return ti


def _start(lifecycle, issuer, name, secret_hex, old_secret_hex):
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_root_macaroon.conf",
        protocol="root",
        host=BIND_HOST,
        template_values={"BIND_HOST": BIND_HOST,
                         "SECRET_HEX": secret_hex,
                         "SECRET_OLD_HEX": old_secret_hex,
                         "JWKS": issuer.jwks_path,
                         "ISSUER": issuer.issuer,
                         "AUDIENCE": issuer.audience},
        reason="macaroon auth over the root:// stream plane"))
    with open(f"{endpoint.data_root}/m.txt", "wb") as fh:
        fh.write(SEED)
    return endpoint


@pytest.fixture(scope="module")
def mac_srv(harness, issuer):
    # Old secret == current secret: rotation is a no-op here, so this instance
    # answers only for the primary key and the negatives cannot be rescued by
    # the grace-period retry.
    return _start(harness, issuer, "lc-macaroon-root", SECRET_HEX, SECRET_HEX)


@pytest.fixture(scope="module")
def rotate_srv(harness, issuer):
    return _start(harness, issuer, "lc-macaroon-root-rotate",
                  SECRET_HEX, OLD_SECRET_HEX)


# --------------------------------------------------------------------------- #
# success
# --------------------------------------------------------------------------- #

def test_valid_macaroon_authenticates(mac_srv):
    # Control for the whole module: right secret, DOWNLOAD on /, future expiry.
    sock, status, errcode = _authenticate(mac_srv, _mac(SECRET))
    try:
        assert status == kXR_ok, \
            f"a valid macaroon must authenticate over root://, st={status} err={errcode}"
    finally:
        sock.close()


def test_authenticated_macaroon_session_reads(mac_srv):
    # Auth that does not unlock the session would be a false positive: prove the
    # DOWNLOAD activity really conveys storage.read by moving bytes.
    sock, status, _ = _authenticate(mac_srv, _mac(SECRET))
    try:
        assert status == kXR_ok
        status, body = _open_read(sock)
        assert status == kXR_ok, f"open after macaroon auth failed: {status}"
        status, data = _read(sock, body[:4], len(SEED))
        assert status == kXR_ok and data == SEED, (status, data)
    finally:
        sock.close()


def test_old_secret_accepted_during_rotation(rotate_srv):
    # brix_macaroon_secret_old exists so in-flight tokens survive a reload that
    # swaps the root key; this is the only live exercise of that retry.
    sock, status, errcode = _authenticate(rotate_srv, _mac(OLD_SECRET))
    try:
        assert status == kXR_ok, \
            f"a macaroon signed with the previous secret must be accepted while " \
            f"brix_macaroon_secret_old is set, st={status} err={errcode}"
    finally:
        sock.close()


def test_current_secret_still_accepted_during_rotation(rotate_srv):
    # ...and the rotation must not cost the current key its validity.
    sock, status, errcode = _authenticate(rotate_srv, _mac(SECRET))
    try:
        assert status == kXR_ok, \
            f"the current secret must keep working during rotation, " \
            f"st={status} err={errcode}"
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# error
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("token, why", [
    ("garbagemacaroonwithoutanydots", "unparseable bearer with no dots"),
    ("", "empty bearer"),
    ("a" * 4096, "over-long bearer"),
])
def test_unparseable_bearer_refused(mac_srv, token, why):
    # A dot-free bearer is classified as a macaroon, so these all land in the
    # macaroon frame parser: it must fail closed rather than authenticate.
    _assert_refused(mac_srv, token, why)


# --------------------------------------------------------------------------- #
# security-negative
# --------------------------------------------------------------------------- #

def test_forged_macaroon_refused(mac_srv):
    # Same caveats, wrong signing secret: the HMAC chain must be what decides.
    _assert_refused(mac_srv, _mac(OTHER_SECRET),
                    "macaroon signed with the wrong secret")


def test_flipped_signature_byte_refused(mac_srv):
    # Right secret, right structure, one flipped signature byte. This is the
    # case the constant-time compare in src/auth/token/macaroon.c guards: a
    # byte-wise memcmp would be a signature-forgery oracle.
    import base64
    tok = _mac(SECRET)
    raw = bytearray(base64.urlsafe_b64decode(tok + "=" * (-len(tok) % 4)))
    raw[-1] ^= 0x01
    forged = base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")
    _assert_refused(mac_srv, forged, "macaroon with one flipped signature byte")


def test_expired_macaroon_refused(mac_srv):
    _assert_refused(mac_srv, _mac(SECRET, before=PAST),
                    "macaroon whose before: caveat is in the past")


def test_path_caveat_outside_target_refused(mac_srv):
    # The path: caveat intersects the granted scope down to /elsewhere, which
    # does not cover /m.txt — so either the handshake or the open must refuse.
    # Asserting on the pair keeps the test honest about where the cut lands
    # while still failing if the file becomes readable.
    sock, status, _ = _authenticate(mac_srv, _mac(SECRET, path="/elsewhere"))
    try:
        if status == kXR_ok:
            status, body = _open_read(sock)
            errcode = (struct.unpack("!I", body[:4])[0]
                       if len(body) >= 4 else None)
            assert status == kXR_error, \
                "a path:/elsewhere macaroon must not open /m.txt"
            assert errcode == kXR_NotAuthorized, f"unexpected errcode {errcode}"
    finally:
        sock.close()


def test_activity_without_read_scope_refused(mac_srv):
    # UPLOAD maps to storage.modify, never to storage.read: a write-only
    # macaroon must not become a download token.
    sock, status, _ = _authenticate(mac_srv, _mac(SECRET, activity="UPLOAD"))
    try:
        if status == kXR_ok:
            status, body = _open_read(sock)
            errcode = (struct.unpack("!I", body[:4])[0]
                       if len(body) >= 4 else None)
            assert status == kXR_error, \
                "an activity:UPLOAD macaroon must not open a file for read"
            assert errcode == kXR_NotAuthorized, f"unexpected errcode {errcode}"
    finally:
        sock.close()


def test_third_secret_refused_during_rotation(rotate_srv):
    # Rotation widens the accepted key set by exactly one: current + old, not
    # "any secret". Without this, the grace-period retry could hide a validator
    # that stopped checking the signature at all.
    _assert_refused(rotate_srv, _mac(OTHER_SECRET),
                    "macaroon signed with neither the current nor the old secret")


@pytest.mark.parametrize("location, why", [
    ("https://someone-else.example.com", "another service's location"),
    (None, "no location packet at all"),
])
def test_location_mismatch_refused(mac_srv, location, why):
    # A macaroon is a bearer token for ONE service; the location packet is what
    # ties it to this one. Accepting a foreign location would let a macaroon
    # minted by any peer that happens to share the root key be replayed here.
    _assert_refused(mac_srv, _mac(SECRET, location=location),
                    f"macaroon carrying {why}")


def test_jwt_and_macaroon_coexist(mac_srv, issuer):
    # The stream plane forces a JWKS trio alongside the macaroon secret, so both
    # token families are live on the same server: neither may shadow the other,
    # and a JWT must still be routed to the JWT validator rather than to the
    # (dot-free) macaroon parser.
    sock, status, errcode = _authenticate(
        mac_srv, issuer.generate(scope="storage.read:/"))
    try:
        assert status == kXR_ok, \
            f"a JWT must still authenticate on a macaroon-enabled server, " \
            f"st={status} err={errcode}"
    finally:
        sock.close()


def test_operations_before_auth_refused(mac_srv):
    # Login alone must not unlock the session on a token-auth server.
    sock = _handshake_login(host=HOST, port=mac_srv.port)
    try:
        status, body = _open_read(sock)
        errcode = struct.unpack("!I", body[:4])[0] if len(body) >= 4 else None
        assert status == kXR_error and errcode == kXR_NotAuthorized, \
            f"open before kXR_auth must be refused, got st={status}"
    finally:
        sock.close()
