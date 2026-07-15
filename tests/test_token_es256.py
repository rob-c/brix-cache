"""
tests/test_token_es256.py

Coverage gap #9 (test-coverage-gap-audit): ES256 / EC P-256 POSITIVE JWT verify.

Before this, only the FORGED ES256 case (test_token_security::test_alg_es256_rejected)
existed — make_token.py emits RSA JWKS only, so brix_token_verify_es256() and
brix_token_ec_pubkey_from_xy() (the P1363 r||s → DER conversion + the EC
pubkey-from-(x,y) build) had NEVER executed with a genuine ES256 signature.  A
byte-order / ownership / length bug in that conversion would either silently
accept an invalid signature or false-deny every legitimate EC token.

These tests stand up a self-contained WebDAV token-auth server whose JWKS holds
a real EC P-256 public key, then:
  * a correctly ES256-signed token authenticates (200)   — the dark path
  * a token with one signature byte flipped is rejected (403)
  * a token whose signature is the DER form (len != 64) is rejected (403)
"""

import base64
import json
import os
import socket
import subprocess
import time

import pytest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    _HAVE_REQUESTS = True
except Exception:                                # pragma: no cover
    _HAVE_REQUESTS = False

from settings import NGINX_BIN, free_port, HOST, BIND_HOST
from config_templates import render_config

PORT = int(os.environ.get("TEST_ES256_PORT") or free_port())
KID = "ec-key-1"
ISSUER = "https://test.example.com"
AUDIENCE = "nginx-xrootd"


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def es256_server(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")

    d = tmp_path_factory.mktemp("es256")
    (d / "logs").mkdir()
    (d / "t").mkdir()
    (d / "cadir").mkdir()
    data = d / "data"
    data.mkdir()
    (data / "test.txt").write_text("hello-es256\n")

    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    jwks = {"keys": [{
        "kty": "EC", "crv": "P-256", "kid": KID, "use": "sig", "alg": "ES256",
        "x": _b64u(nums.x.to_bytes(32, "big")),
        "y": _b64u(nums.y.to_bytes(32, "big")),
    }]}
    jwks_path = d / "jwks.json"
    jwks_path.write_text(json.dumps(jwks))

    conf = render_config("nginx_webdav_token_aud.conf",
                         BASE_DIR=d,
                         BIND_HOST=BIND_HOST,
                         PORT=PORT,
                         DATA_DIR=data,
                         JWKS_PATH=jwks_path,
                         ISSUER=ISSUER,
                         AUDIENCE=AUDIENCE)
    cp = d / "nginx.conf"
    cp.write_text(conf)
    proc = subprocess.Popen([NGINX_BIN, "-p", str(d), "-c", str(cp)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not _wait_port(PORT):
        err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
        proc.terminate()
        pytest.skip(f"es256 webdav server did not start: {err}")
    yield key
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _signing_input(extra_payload=None):
    now = int(time.time())
    header = {"alg": "ES256", "typ": "JWT", "kid": KID}
    payload = {"iss": ISSUER, "sub": "ec-user", "aud": AUDIENCE,
               "exp": now + 3600, "iat": now, "nbf": now,
               "scope": "storage.read:/", "wlcg.ver": "1.0"}
    if extra_payload:
        payload.update(extra_payload)
    return (_b64u(json.dumps(header, separators=(",", ":")).encode())
            + "." + _b64u(json.dumps(payload, separators=(",", ":")).encode()))


def _es256_token(key, raw_sig_override=None):
    si = _signing_input()
    der = key.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")     # JWT P1363 form
    sig = raw_sig_override if raw_sig_override is not None else raw
    return si + "." + _b64u(sig), der


def _get(token):
    r = requests.get(f"http://{HOST}:{PORT}/test.txt",
                     headers={"Authorization": f"Bearer {token}"}, timeout=10)
    return r.status_code


def test_valid_es256_authenticates(es256_server):
    token, _der = _es256_token(es256_server)
    assert _get(token) in (200, 206), \
        "a correctly ES256-signed token must authenticate (verify_es256 path)"


def test_bad_es256_signature_rejected(es256_server):
    token, _der = _es256_token(es256_server)
    si, sig_b64 = token.rsplit(".", 1)
    raw = bytearray(base64.urlsafe_b64decode(sig_b64 + "=="))
    raw[0] ^= 0xFF                                          # corrupt r
    bad = si + "." + _b64u(bytes(raw))
    assert _get(bad) == 403, "a corrupted ES256 signature must be rejected"


def test_der_form_signature_rejected(es256_server):
    # The DER ASN.1 form (len != 64) must be rejected — the verifier requires
    # raw P1363 r||s and explicitly checks sig_len == 64.
    token, der = _es256_token(es256_server, raw_sig_override=b"")
    si = token.rsplit(".", 1)[0]
    bad = si + "." + _b64u(der)
    assert _get(bad) == 403, "DER-encoded (non-64-byte) ES256 sig must be rejected"
