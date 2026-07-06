"""
tests/test_dig.py — §3 XrdDig remote diagnostics (security-first).

Self-provisions a WebDAV server with a dig export + a principal→export allow-file
(JWT auth via a test JWKS) and asserts the security envelope BEFORE any convenience:

  * authorized principal reads a whitelisted file              -> 200 + content
  * authenticated-but-unlisted principal                       -> 403
  * anonymous (no credential)                                  -> 403  (fail-closed)
  * symlink escape out of the export (RESOLVE_BENEATH/NOFOLLOW)-> 403
  * unknown export name                                        -> 404
  * write method on a dig path                                 -> 405  (read-only)
  * dig disabled                                               -> 404  (falls through)

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_dig.py -v
"""

import os
import socket
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    _HAVE_REQUESTS = False

from utils.make_token import TokenIssuer  # noqa: E402
from settings import NGINX_BIN, free_port, HOST, BIND_HOST, TOKENS_DIR  # noqa: E402


def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _issuer():
    iss = TokenIssuer(TOKENS_DIR)
    if not os.path.exists(iss.key_path):
        iss.init_keys()
    if not os.path.exists(iss.jwks_path):
        iss.init_keys()
    return iss


def _start(tmp_path_factory, dig_on):
    iss = _issuer()
    d = tmp_path_factory.mktemp("dig")
    (d / "logs").mkdir()
    (d / "t").mkdir()
    (d / "data").mkdir()
    (d / "cadir").mkdir()
    # The dig export tree + a secret OUTSIDE it + a symlink escaping the export.
    exp = d / "export"
    exp.mkdir()
    (exp / "server.cfg").write_text("DIG-CONFIG-CONTENT\n")
    (d / "outside.txt").write_text("OUTSIDE-SECRET\n")
    try:
        os.symlink(str(d / "outside.txt"), str(exp / "escape"))
    except OSError:
        pass
    allow = d / "dig.allow"
    allow.write_text("# principal export\ndiguser conf\n")

    port = free_port()
    dig = (f"brix_webdav_dig on;\n"
           f"            brix_webdav_dig_export conf {exp};\n"
           f"            brix_webdav_dig_auth {allow};") if dig_on else ""
    conf = f"""
error_log {d}/logs/error.log info;
pid {d}/logs/nginx.pid;
events {{ worker_connections 64; }}
http {{
    client_body_temp_path {d}/t; proxy_temp_path {d}/t; fastcgi_temp_path {d}/t;
    uwsgi_temp_path {d}/t; scgi_temp_path {d}/t; access_log off;
    server {{
        listen {BIND_HOST}:{port};
        location / {{
            brix_webdav on;
            brix_storage_backend posix:{d}/data;
            brix_webdav_auth optional;
            brix_webdav_cadir {d}/cadir;
            brix_allow_write on;
            brix_webdav_token_jwks {iss.jwks_path};
            brix_webdav_token_issuer {iss.issuer};
            brix_webdav_token_audience {iss.audience};
            {dig}
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
    if not _wait_port(port):
        err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
        proc.terminate()
        pytest.skip(f"dig server did not start: {err}")
    return proc, port, iss


@pytest.fixture(scope="module")
def dig_server(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")
    proc, port, iss = _start(tmp_path_factory, dig_on=True)
    yield port, iss
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="module")
def dig_off_server(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")
    proc, port, iss = _start(tmp_path_factory, dig_on=False)
    yield port, iss
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _get(port, path, sub=None, iss=None):
    h = {}
    if sub is not None:
        h["Authorization"] = f"Bearer {iss.generate(sub=sub, scope='storage.read:/')}"
    return requests.get(f"http://{HOST}:{port}{path}", headers=h, timeout=10)


def test_authorized_principal_reads(dig_server):
    port, iss = dig_server
    r = _get(port, "/.well-known/dig/conf/server.cfg", sub="diguser", iss=iss)
    assert r.status_code == 200, r.status_code
    assert r.text == "DIG-CONFIG-CONTENT\n"


def test_unlisted_principal_forbidden(dig_server):
    port, iss = dig_server
    r = _get(port, "/.well-known/dig/conf/server.cfg", sub="otheruser", iss=iss)
    assert r.status_code == 403, r.status_code


def test_anonymous_forbidden(dig_server):
    port, iss = dig_server
    r = _get(port, "/.well-known/dig/conf/server.cfg")
    assert r.status_code == 403, r.status_code


def test_symlink_escape_blocked(dig_server):
    port, iss = dig_server
    # 'escape' is a symlink to a file OUTSIDE the export; RESOLVE_BENEATH/NOFOLLOW
    # must refuse it even for an authorized principal.
    r = _get(port, "/.well-known/dig/conf/escape", sub="diguser", iss=iss)
    assert r.status_code in (403, 404), r.status_code
    assert "OUTSIDE-SECRET" not in r.text


def test_unknown_export_not_found(dig_server):
    port, iss = dig_server
    r = _get(port, "/.well-known/dig/nope/server.cfg", sub="diguser", iss=iss)
    assert r.status_code == 404, r.status_code


def test_write_method_rejected(dig_server):
    port, iss = dig_server
    tok = iss.generate(sub="diguser", scope="storage.read:/ storage.write:/")
    r = requests.put(f"http://{HOST}:{port}/.well-known/dig/conf/server.cfg",
                     data=b"x", headers={"Authorization": f"Bearer {tok}"},
                     timeout=10)
    assert r.status_code == 405, r.status_code


def test_dig_disabled_falls_through(dig_off_server):
    port, iss = dig_off_server
    r = _get(port, "/.well-known/dig/conf/server.cfg", sub="diguser", iss=iss)
    # dig off → not handled as dig; normal WebDAV has no such file → 404
    assert r.status_code == 404, r.status_code
