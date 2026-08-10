"""brix_ztn_maxsz — the ztn ``-maxsz`` analog (parity audit §5.9).

An unauthenticated peer must not get to choose how much validation CPU a
single kXR_auth burns: the new knob refuses a bearer credential longer than
the configured cap BEFORE any parse/JWKS/crypto work. Default 0 = no extra
cap (current behaviour) — the knob is an operator opt-in, matching the audit
row's "stricter default" posture note for ztn.

The probes send junk (never-valid) tokens and distinguish WHERE the refusal
happened by the kXR_error text: the size gate says "bearer token too large",
the validation stage says something else.

Coverage (the change-class trio):
  * success (gate fires)   — cap 1k: a 2 KiB junk token is refused with
                             "too large".
  * error   (gate scoped)  — cap 1k: a SMALL junk token still reaches
                             validation (refused, but NOT "too large").
  * security-neg (default) — no directive: the same 2 KiB junk token is NOT
                             size-refused (uncapped default preserves current
                             behaviour; refusal comes from validation).

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_ztn_maxsz.py -v
"""

import json
import os
import socket
import struct

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    _HAVE_CRYPTO = True
except Exception:                                # pragma: no cover
    _HAVE_CRYPTO = False

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-ztn-maxsz")]

kXR_auth, kXR_login, kXR_protocol = 3000, 3007, 3006
kXR_ok, kXR_error = 0, 4003


def _b64u(b):
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


@pytest.fixture()
def srv(lifecycle, tmp_path, request):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    if not _HAVE_CRYPTO:
        pytest.skip("cryptography required for the JWKS fixture")
    data = tmp_path / "data"
    data.mkdir()

    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    jwks = {"keys": [{"kty": "EC", "crv": "P-256", "kid": "maxsz-key",
                      "use": "sig", "alg": "ES256",
                      "x": _b64u(nums.x.to_bytes(32, "big")),
                      "y": _b64u(nums.y.to_bytes(32, "big"))}]}
    jwks_path = tmp_path / "jwks.json"
    jwks_path.write_text(json.dumps(jwks))

    maxsz_line = getattr(request, "param", "brix_ztn_maxsz 1k;")
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-ztn-maxsz",
        template="nginx_lc_ztn_maxsz.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "JWKS_FILE": str(jwks_path),
                         "MAXSZ_LINE": maxsz_line},
        reason="brix_ztn_maxsz size-gate postures"))
    return ep.port


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _resp(sock):
    hdr = _recv_exact(sock, 8)
    assert hdr is not None, "connection closed mid-response"
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    return status, (_recv_exact(sock, dlen) or b"") if dlen else b""


def _auth_error_text(port, token_bytes):
    """handshake + login + one ztn kXR_auth with `token_bytes`; returns the
    kXR_error body text (the auth must NEVER succeed — tokens are junk)."""
    sock = socket.create_connection((HOST, port), timeout=10)
    try:
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        assert _recv_exact(sock, 16) is not None
        sock.sendall(b"\x00\x01" + struct.pack(">H", kXR_protocol)
                     + b"\x00" * 16 + struct.pack(">I", 0))
        status, _ = _resp(sock)
        assert status == kXR_ok
        sock.sendall(struct.pack(">2sHI8sBBBBI", b"\x00\x01", kXR_login,
                                 os.getpid() & 0x7FFFFFFF,
                                 b"ztn\x00\x00\x00\x00\x00", 0, 0, 0, 0, 0))
        status, _ = _resp(sock)
        assert status == kXR_ok, "login refused before auth"

        payload = b"ztn\x00" + token_bytes
        sock.sendall(b"\x00\x02" + struct.pack(">H", kXR_auth)
                     + b"\x00" * 12 + b"ztn\x00"
                     + struct.pack(">I", len(payload)) + payload)
        status, body = _resp(sock)
        assert status == kXR_error, \
            f"junk ztn credential was not refused: status={status}"
        return body[4:].decode("utf-8", "replace").lower()
    finally:
        sock.close()


def test_oversize_token_refused_by_size_gate(srv):
    """(success) cap 1k: a 2 KiB junk token is refused with 'too large'."""
    text = _auth_error_text(srv, b"J" * 2048)
    assert "too large" in text, f"size gate did not fire: {text!r}"


def test_small_token_reaches_validation(srv):
    """(error-path scoping) cap 1k: a small junk token passes the size gate
    and is refused by VALIDATION instead — the cap must not over-trigger."""
    text = _auth_error_text(srv, b"J" * 64)
    assert "too large" not in text, f"size gate over-triggered: {text!r}"


@pytest.mark.parametrize("srv", [""], indirect=True)
def test_default_is_uncapped(srv):
    """(security-neg for compatibility) no directive: the 2 KiB junk token is
    NOT size-refused — the default posture is byte-identical to before the
    knob existed (refusal comes from validation)."""
    text = _auth_error_text(srv, b"J" * 2048)
    assert "too large" not in text, \
        f"default posture grew a size cap: {text!r}"
