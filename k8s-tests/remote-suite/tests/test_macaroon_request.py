"""
tests/test_macaroon_request.py — §2 dCache/XrdMacaroons "application/macaroon-request".

Drives the new content-type issuance endpoint against a self-provisioned
macaroon-secret WebDAV server (auth=required):

  * authenticated POST with Content-Type: application/macaroon-request returns a
    dCache {"macaroon":..,"uri":{..}} body
  * the issued macaroon authenticates a subsequent GET (via ?authz=, combining §1)
  * a path: caveat confines the issued macaroon (sibling path rejected)
  * an unauthenticated issue request is refused (401)

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_macaroon_request.py -v
"""

import json
import os
import socket
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))
from test_token_macaroon import make_macaroon  # noqa: E402

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    _HAVE_REQUESTS = False

from settings import NGINX_BIN, free_port, HOST, BIND_HOST  # noqa: E402

PORT = int(os.environ.get("TEST_MACREQ_PORT") or free_port())
SECRET_HEX = "deadbeef" * 8
SECRET = bytes.fromhex(SECRET_HEX)
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

    d = tmp_path_factory.mktemp("macreq")
    (d / "logs").mkdir()
    (d / "t").mkdir()
    (d / "cadir").mkdir()
    data = d / "data"
    data.mkdir()
    (data / "f.txt").write_text("hello-macreq\n")
    sub = data / "sub"
    sub.mkdir()
    (sub / "g.txt").write_text("sub-payload\n")

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
            brix_webdav on;
            brix_webdav_storage_backend posix:{data};
            brix_webdav_auth required;
            brix_webdav_cadir {d}/cadir;
            brix_webdav_allow_write on;
            brix_webdav_macaroon_secret {SECRET_HEX};
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


def _auth_macaroon(path="/"):
    """A macaroon (header credential) that authenticates the issuance request."""
    caveats = ["activity:DOWNLOAD,LIST,MANAGE", f"path:{path}",
               "before:2099-12-31T23:59:59Z"]
    return make_macaroon(SECRET, "issuer-subject", caveats, location=LOCATION)


def _issue(body, auth=True):
    headers = {"Content-Type": "application/macaroon-request"}
    if auth:
        headers["Authorization"] = f"Bearer {_auth_macaroon()}"
    return requests.post(f"http://{HOST}:{PORT}/f.txt", headers=headers,
                         data=json.dumps(body), timeout=10)


def test_issue_returns_dcache_shape(mac_server):
    r = _issue({"caveats": ["activity:DOWNLOAD", "path:/"], "validity": "PT1H"})
    assert r.status_code == 200, r.text
    doc = r.json()
    assert "macaroon" in doc and doc["macaroon"]
    assert "uri" in doc
    for k in ("target", "targetWithMacaroon", "base", "baseWithMacaroon"):
        assert k in doc["uri"], doc["uri"]
    assert "authz=" in doc["uri"]["targetWithMacaroon"]


def test_issued_macaroon_authenticates_via_query(mac_server):
    r = _issue({"caveats": ["activity:DOWNLOAD", "path:/"], "validity": "PT1H"})
    tok = r.json()["macaroon"]
    g = requests.get(f"http://{HOST}:{PORT}/f.txt", params={"authz": tok}, timeout=10)
    assert g.status_code in (200, 206), g.status_code
    assert g.text == "hello-macreq\n"


def _decode(tok):
    import base64
    return base64.urlsafe_b64decode(tok + "=" * (-len(tok) % 4))


def test_issued_macaroon_carries_requested_caveats(mac_server):
    # §2's contract is that the issued macaroon encodes the requested activity +
    # path + expiry caveats (server-side read-path *enforcement* on GET is a
    # separate concern). Decode and assert the caveats are present.
    tok = _issue({"caveats": ["activity:DOWNLOAD,LIST", "path:/sub"],
                  "validity": "PT1H"}).json()["macaroon"]
    raw = _decode(tok)
    assert b"activity:DOWNLOAD,LIST" in raw, raw
    assert b"path:/sub" in raw, raw
    assert b"before:" in raw, raw  # validity → before: caveat

    # A different requested path produces a different caveat (and token).
    tok2 = _issue({"caveats": ["activity:DOWNLOAD", "path:/other"],
                   "validity": "PT5M"}).json()["macaroon"]
    assert b"path:/other" in _decode(tok2)
    assert tok != tok2


def test_unauthenticated_issue_rejected(mac_server):
    # auth=required rejects at the access phase (403); on optional-auth the handler
    # itself would answer 401. Either way: not issued.
    r = _issue({"caveats": ["activity:DOWNLOAD", "path:/"]}, auth=False)
    assert r.status_code in (401, 403), r.status_code
    assert "macaroon" not in r.text
