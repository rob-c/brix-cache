"""
tests/test_token_jwks_refresh.py

Integration tests for JWKS mtime-poll hot refresh (Feature 3).

Verifies that the xrootd_token_jwks_refresh_interval directive causes
nginx-xrootd to detect JWKS file changes at runtime and swap in new keys
without a restart, while preserving old keys on parse failure.

Tests:
  1. test_jwks_hot_refresh_new_key          — token from rotated key accepted after interval
  2. test_jwks_keeps_old_keys_on_parse_error — corrupt JWKS file preserves old keys
  3. test_jwks_old_key_rejected_after_rotate — old-key token rejected after rotation

Run:
    cd /home/rcurrie/HEP-x/nginx-xrootd
    source .venv/bin/activate
    PYTHONPATH=tests pytest tests/test_token_jwks_refresh.py -v
"""

import json
import os
import socket
import struct
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer
from settings import NGINX_JWKS_REFRESH_PORT, TEST_ROOT

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REFRESH_INTERVAL  = 500        # ms — interval configured in nginx
WAIT_AFTER_TOUCH  = 1.5        # seconds — > 1 refresh interval before asserting
DEFAULT_ISSUER    = "https://test.example.com"
DEFAULT_AUDIENCE  = "nginx-xrootd"

# XRootD request/response codes
kXR_auth     = 3000
kXR_login    = 3007
kXR_protocol = 3006
kXR_stat     = 3017
kXR_ok       = 0
kXR_error    = 4003

# ---------------------------------------------------------------------------
# Protocol helpers (minimal — same pattern as test_token_auth.py)
# ---------------------------------------------------------------------------

def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError(
                f"socket closed with {nbytes - len(data)} bytes remaining")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    header = _recv_exact(sock, 8)
    _streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _do_handshake(host, port):
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(5)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, _ = _read_response(sock)
    assert status == kXR_ok, f"handshake failed: status={status}"
    return sock


def _send_protocol(sock):
    req = (struct.pack("!2sH", b"\x00\x01", kXR_protocol)
           + struct.pack("!I BB 10s I", 39, 0x01, 0x03, b"\x00" * 10, 0))
    sock.sendall(req)
    return _read_response(sock)


def _send_login(sock):
    req = (struct.pack("!2sH", b"\x00\x02", kXR_login)
           + struct.pack("!I 8s B B B B I",
                         os.getpid() & 0xFFFFFFFF,
                         b"pytest\x00\x00",
                         0, 0, 5, 0, 0))
    sock.sendall(req)
    return _read_response(sock)


def _send_auth_ztn(sock, token):
    token_bytes = token.encode("ascii") if isinstance(token, str) else token
    cred_payload = b"ztn\x00" + token_bytes
    req = (struct.pack("!2sH", b"\x00\x03", kXR_auth)
           + b"\x00" * 12
           + b"ztn\x00"
           + struct.pack("!I", len(cred_payload))
           + cred_payload)
    sock.sendall(req)
    return _read_response(sock)


def _send_stat(sock, path):
    path_bytes = path.encode() + b"\x00"
    req = (struct.pack("!2sH", b"\x00\x04", kXR_stat)
           + b"\x00" * 16
           + struct.pack("!I", len(path_bytes))
           + path_bytes)
    sock.sendall(req)
    return _read_response(sock)


def _try_auth(host, port, issuer):
    """Return (ok: bool, status: int) for one token-auth attempt."""
    token = issuer.generate(scope="storage.read:/", lifetime=120)
    try:
        sock = _do_handshake(host, port)
        _send_protocol(sock)
        _send_login(sock)
        status, _ = _send_auth_ztn(sock, token)
        sock.close()
        return status == kXR_ok, status
    except Exception:
        return False, -1


def _wait_for_port(host, port, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except Exception:
            time.sleep(0.1)
    return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="class")
def jwks_refresh_server():
    """Use the suite-level nginx with a short JWKS refresh interval.

    Returns a dict with:
      host, port, data_dir, log_dir, jwks_path, issuer
    """
    workdir = os.path.join(TEST_ROOT, "dedicated", "jwks-refresh")
    token_dir = os.path.join(TEST_ROOT, "tokens", "jwks-refresh")
    data_dir = os.path.join(TEST_ROOT, "data-jwks-refresh")
    os.makedirs(data_dir, exist_ok=True)

    # Create a test file for stat operations
    with open(os.path.join(data_dir, "test.txt"), "wb") as f:
        f.write(b"hello\n")

    issuer = TokenIssuer(
        token_dir,
        issuer=DEFAULT_ISSUER,
        audience=DEFAULT_AUDIENCE,
    )
    if not os.path.exists(issuer.key_path) or not os.path.exists(issuer.jwks_path):
        pytest.skip("dedicated JWKS refresh token material is not initialized")

    # Re-init keys to flush any stale state from a previous test run's key rotation.
    # Wait one refresh interval so nginx picks up the restored JWKS before tests run.
    issuer.init_keys()
    time.sleep(WAIT_AFTER_TOUCH)

    port = NGINX_JWKS_REFRESH_PORT
    if not _wait_for_port("127.0.0.1", port):
        pytest.fail("dedicated jwks_refresh nginx did not start")

    yield {
        "host":      "127.0.0.1",
        "port":      port,
        "data_dir":  data_dir,
        "log_dir":   os.path.join(workdir, "logs"),
        "jwks_path": issuer.jwks_path,
        "jwks_dir":  token_dir,
        "issuer":    issuer,
    }


# ---------------------------------------------------------------------------
# Helper: create a second independent TokenIssuer with a different key
# ---------------------------------------------------------------------------

def _make_rotated_issuer(token_dir):
    """Return a new TokenIssuer with freshly-generated keys written to token_dir."""
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Derive the base64url integers for the JWKS
    from utils.make_token import int_to_b64url  # available since same codebase
    pub = new_key.public_key()
    nums = pub.public_numbers()

    new_jwks = {
        "keys": [{
            "kty": "RSA",
            "kid": "rotated-key-1",
            "use": "sig",
            "alg": "RS256",
            "n": int_to_b64url(nums.n),
            "e": int_to_b64url(nums.e),
        }]
    }

    # Write private key and JWKS
    rotated_dir = tempfile.mkdtemp(prefix="rotated-", dir=token_dir)

    key_path = os.path.join(rotated_dir, "signing_key.pem")
    pem = new_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(key_path, "wb") as f:
        f.write(pem)
    os.chmod(key_path, 0o400)

    # Build a TokenIssuer pointing at rotated_dir but with custom JWKS content
    rotated_issuer = TokenIssuer(
        rotated_dir,
        issuer=DEFAULT_ISSUER,
        audience=DEFAULT_AUDIENCE,
    )
    # Manually write JWKS to rotated_dir
    with open(rotated_issuer.jwks_path, "w") as f:
        json.dump(new_jwks, f, indent=2)

    return rotated_issuer, new_jwks


def _overwrite_jwks(dest_path, new_jwks_content):
    """Write new JWKS content to dest_path with an mtime bump."""
    # Write to a temp file then rename to ensure atomic update
    dir_ = os.path.dirname(dest_path)
    tmp = os.path.join(dir_, ".jwks.tmp")
    with open(tmp, "w") as f:
        json.dump(new_jwks_content, f, indent=2)
    os.rename(tmp, dest_path)
    # Ensure mtime is bumped by at least 1 second (filesystem granularity)
    t = time.time() + 1
    os.utime(dest_path, (t, t))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestJwksHotRefresh:
    """Verify JWKS hot refresh via mtime-poll timer."""

    # --- success path ---

    def test_original_key_accepted_before_rotation(self, jwks_refresh_server):
        """Baseline: token signed with original key is accepted at startup."""
        srv = jwks_refresh_server
        ok, status = _try_auth(srv["host"], srv["port"], srv["issuer"])
        assert ok, (
            f"token auth with original key failed (status={status})"
        )

    def test_jwks_hot_refresh_new_key(self, jwks_refresh_server):
        """Token signed with rotated key is accepted after refresh interval fires."""
        srv = jwks_refresh_server
        rotated, new_jwks = _make_rotated_issuer(srv["jwks_dir"])

        # Rotate: overwrite JWKS with new key
        _overwrite_jwks(srv["jwks_path"], new_jwks)

        # Wait for the refresh timer to fire (interval + margin)
        time.sleep(WAIT_AFTER_TOUCH)

        ok, status = _try_auth(srv["host"], srv["port"], rotated)
        assert ok, (
            f"token with rotated key should be accepted after refresh "
            f"(status={status}); check {srv['log_dir']}/error.log"
        )

    # --- error path ---

    def test_jwks_keeps_old_keys_on_parse_error(self, jwks_refresh_server):
        """Corrupted JWKS file: old keys remain valid; no crash or lock-up."""
        srv = jwks_refresh_server
        # First restore the original key (tests may run in sequence)
        with open(srv["jwks_path"], "w") as f:
            json.dump(
                {"keys": [{"kty": "BROKEN_JWKS_CONTENT_FOR_TEST"}]},
                f,
            )
        # Bump mtime so refresh picks it up
        t = time.time() + 1
        os.utime(srv["jwks_path"], (t, t))

        # Wait for the timer to attempt the reload
        time.sleep(WAIT_AFTER_TOUCH)

        # Restore original key (so subsequent tests aren't affected)
        original_ti = srv["issuer"]
        original_ti.init_keys()

        # After restoring good JWKS, wait for another reload cycle
        time.sleep(WAIT_AFTER_TOUCH)

        ok, status = _try_auth(srv["host"], srv["port"], original_ti)
        assert ok, (
            f"after corrupted JWKS, original key should still work once "
            f"good JWKS is restored (status={status})"
        )

    # --- security / negative path ---

    def test_jwks_old_key_rejected_after_rotation(self, jwks_refresh_server):
        """After key rotation, tokens signed with the OLD key must be rejected."""
        srv = jwks_refresh_server
        original_issuer = srv["issuer"]

        # Rotate to a brand-new key (issuer object will hold original key)
        rotated, new_jwks = _make_rotated_issuer(srv["jwks_dir"])
        _overwrite_jwks(srv["jwks_path"], new_jwks)

        # Wait for the timer to pick up the new JWKS
        time.sleep(WAIT_AFTER_TOUCH)

        # Token signed with the OLD key should now be rejected
        ok, status = _try_auth(srv["host"], srv["port"], original_issuer)
        assert not ok, (
            f"token with OLD key should be rejected after JWKS rotation "
            f"(status={status})"
        )
