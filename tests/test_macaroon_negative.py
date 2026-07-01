"""
tests/test_macaroon_negative.py

Coverage gap #6 (test-coverage-gap-audit): server-side macaroon REJECTION.

The macaroon tests (test_token_macaroon / test_macaroon_discharge) validate only
the Python helper's structure — they never send a macaroon to the running
server.  The C validator's negative branches in src/token/macaroon.c
(HMAC-chain signature mismatch, before:-in-the-past expiry, malformed token)
had no end-to-end coverage.  A regression there (e.g. signature not actually
checked, or expiry compared the wrong way) is a direct auth bypass.

These drive the validator over HTTP against a macaroon-secret WebDAV server:
  * forged macaroon (signed with the WRONG secret)   → rejected (not 2xx)
  * expired macaroon (right secret, before: in past)  → rejected (not 2xx)
  * malformed / garbage bearer                        → rejected (not 2xx)
  * (control) macaroon signed with the RIGHT secret + read scope → authenticates
"""

import os
import socket
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))
from test_token_macaroon import make_macaroon       # noqa: E402

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:                                    # pragma: no cover
    _HAVE_REQUESTS = False

from settings import NGINX_BIN, free_port, HOST, BIND_HOST   # noqa: E402

PORT = int(os.environ.get("TEST_MACAROON_PORT") or free_port())
SECRET_HEX = "deadbeef" * 8
SECRET = bytes.fromhex(SECRET_HEX)
WRONG_SECRET = bytes.fromhex("cafebabe" * 8)
LOCATION = f"http://{HOST}:{PORT}"


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
def mac_server(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")

    d = tmp_path_factory.mktemp("mac")
    (d / "logs").mkdir()
    (d / "t").mkdir()
    (d / "cadir").mkdir()
    data = d / "data"
    data.mkdir()
    (data / "test.txt").write_text("hello-macaroon\n")

    conf = f"""
error_log {d}/logs/error.log info;
pid {d}/logs/nginx.pid;
events {{ worker_connections 64; }}
http {{
    client_body_temp_path {d}/t; proxy_temp_path {d}/t; fastcgi_temp_path {d}/t;
    uwsgi_temp_path {d}/t; scgi_temp_path {d}/t; access_log off;
    server {{
        listen {BIND_HOST}:{PORT};
        location / {{
            xrootd_webdav on;
            xrootd_webdav_storage_backend posix:{data};
            xrootd_webdav_auth required;
            xrootd_webdav_cadir {d}/cadir;
            xrootd_webdav_allow_write on;
            xrootd_webdav_macaroon_secret {SECRET_HEX};
        }}
    }}
}}
daemon off;
master_process off;
"""
    cp = d / "nginx.conf"
    cp.write_text(conf)
    proc = subprocess.Popen([NGINX_BIN, "-p", str(d), "-c", str(cp)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not _wait_port(PORT):
        err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
        proc.terminate()
        pytest.skip(f"macaroon webdav server did not start: {err}")
    yield
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _caveats(before="2099-12-31T23:59:59Z"):
    return ["activity:DOWNLOAD", "path:/", f"before:{before}"]


def _get(token):
    return requests.get(f"http://{HOST}:{PORT}/test.txt",
                        headers={"Authorization": f"Bearer {token}"}, timeout=10)


def test_valid_macaroon_authenticates(mac_server):
    # Control: a macaroon signed with the right secret, read scope, future
    # expiry must authenticate — otherwise the negative tests prove nothing.
    tok = make_macaroon(SECRET, "test-subject", _caveats(), location=LOCATION)
    assert _get(tok).status_code in (200, 206), \
        "a valid macaroon (right secret, DOWNLOAD on /, future expiry) must authenticate"


def test_forged_macaroon_rejected(mac_server):
    # Same caveats, WRONG signing secret → HMAC chain mismatch → must reject.
    tok = make_macaroon(WRONG_SECRET, "test-subject", _caveats(), location=LOCATION)
    assert _get(tok).status_code not in (200, 206), \
        "a macaroon signed with the wrong secret must NOT authenticate (HMAC bypass)"


def test_flipped_signature_byte_rejected(mac_server):
    # Correct structure + right secret, but ONE byte of the 32-byte HMAC
    # signature flipped → must be rejected. This is the exact case the
    # constant-time CRYPTO_memcmp in src/token/macaroon.c guards: a
    # timing-variable memcmp would be a byte-by-byte signature-forgery oracle.
    import base64
    tok = make_macaroon(SECRET, "test-subject", _caveats(), location=LOCATION)
    padded = tok + "=" * (-len(tok) % 4)
    raw = bytearray(base64.urlsafe_b64decode(padded))
    raw[-1] ^= 0x01                      # flip the last signature byte
    forged = base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")
    assert _get(forged).status_code not in (200, 206), \
        "a macaroon with a single flipped signature byte must NOT authenticate"


def test_expired_macaroon_rejected(mac_server):
    tok = make_macaroon(SECRET, "test-subject",
                        _caveats(before="2000-01-01T00:00:00Z"), location=LOCATION)
    assert _get(tok).status_code not in (200, 206), \
        "an expired macaroon (before: in the past) must NOT authenticate"


def test_garbage_macaroon_rejected(mac_server):
    # No dots → classified as a macaroon → must fail to parse → reject.
    assert _get("garbagemacaroonwithoutanydots").status_code not in (200, 206), \
        "a malformed macaroon must be rejected"
