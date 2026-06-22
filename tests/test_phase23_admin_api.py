"""
Phase 23 — dynamic upstreams: REST admin write API + dynamic WebDAV proxy pool.

Coverage:
  1. Source-marker checks: the admin API module, the SHM proxy pool, registry
     helpers, directives, and build registration are wired.
  2. Config validation: the admin directives + xrootd_webdav_proxy_dynamic
     parse, and the admin API is disabled (403) unless explicitly configured.
  3. Functional admin auth: bearer-secret gate — missing/wrong token → 403,
     correct token → 200; the admin API is read from a file, never nginx.conf.
  4. Functional cluster registry: register (good + invalid-host reject).
  5. Functional dynamic proxy pool: add → list → live proxy GET → drain →
     remove, exercising the SHM pool end-to-end through the admin API.
"""

import json
import os
import socket
import subprocess
import threading
import time
import http.server
from pathlib import Path

import pytest

from settings import NGINX_BIN, free_port, HOST, BIND_HOST, url_host

ROOT = Path(__file__).resolve().parents[1]
SECRET = "phase23-admin-secret-token-value"

# Distinct free OS ports for the config-validation listens (each test binds its
# own one-server nginx -t check, so no cross-references between them).
_P_PARSE = int(os.environ.get("TEST_PHASE23_PARSE_PORT") or free_port())
_P_DYNAMIC = int(os.environ.get("TEST_PHASE23_DYNAMIC_PORT") or free_port())
_P_BADSECRET = int(os.environ.get("TEST_PHASE23_BADSECRET_PORT") or free_port())


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _read(rel):
    p = ROOT / rel
    assert p.exists(), f"missing {rel}"
    return p.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# 1. Source-marker checks                                                      #
# --------------------------------------------------------------------------- #

def test_admin_module_present():
    assert (ROOT / "src/dashboard/api_admin.c").exists()
    assert (ROOT / "src/dashboard/api_admin.h").exists()
    cfg = _read("config")
    assert "src/dashboard/api_admin.c" in cfg


def test_proxy_pool_module_present():
    assert (ROOT / "src/webdav/proxy_pool.c").exists()
    assert (ROOT / "src/webdav/proxy_pool.h").exists()
    cfg = _read("config")
    assert "src/webdav/proxy_pool.c" in cfg
    # The pool header is a build dependency for both webdav and dashboard.
    assert cfg.count("src/webdav/proxy_pool.h") >= 2


def test_admin_auth_and_validation_present():
    c = _read("src/dashboard/api_admin.c")
    # Constant-time secret compare, whitelist validation (reject not sanitise),
    # audit logging, and the disabled-by-default gate.
    assert "CRYPTO_memcmp" in c
    assert "admin_validate_hostname" in c
    assert "admin_validate_url" in c
    assert "admin_audit" in c
    assert "XROOTD_ADMIN_AUTH_DENIED" in c


def test_registry_undrain_helper_present():
    assert "xrootd_srv_undrain" in _read("src/manager/registry.c")
    assert "xrootd_srv_undrain" in _read("src/manager/registry.h")


def test_proxy_pool_api_present():
    p = _read("src/webdav/proxy_pool.c")
    for fn in ("xrootd_proxy_pool_configure", "xrootd_proxy_pool_add",
               "xrootd_proxy_pool_select", "xrootd_proxy_pool_drain",
               "xrootd_proxy_pool_remove", "xrootd_proxy_pool_snapshot",
               "xrootd_proxy_pool_dec_in_flight"):
        assert fn in p, fn
    # proxy.c branches on the dynamic pool; finalize releases in_flight.
    assert "xrootd_proxy_pool_select" in _read("src/webdav/proxy.c")
    assert "xrootd_proxy_pool_dec_in_flight" in _read("src/webdav/proxy_response.c")


def test_directives_registered():
    d = _read("src/dashboard/module.c")
    for name in ("xrootd_admin_allow", "xrootd_admin_secret",
                 "xrootd_admin_require_both"):
        assert name in d, name
    assert "xrootd_webdav_proxy_dynamic" in _read("src/webdav/module.c")


# --------------------------------------------------------------------------- #
# 2. Config validation                                                         #
# --------------------------------------------------------------------------- #

HEADER = (
    "error_log {logs}/error.log info;\n"
    "pid       {logs}/nginx.pid;\n"
    "events {{ worker_connections 64; }}\n"
)


def _http_block(body, tmp_path):
    return HEADER.format(logs=tmp_path / "logs") + f"""
    http {{
        client_body_temp_path {tmp_path}/t; proxy_temp_path {tmp_path}/t;
        fastcgi_temp_path {tmp_path}/t; uwsgi_temp_path {tmp_path}/t;
        scgi_temp_path {tmp_path}/t; access_log off;
        {body}
    }}
    """


def _nginx_check(conf_text, tmp_path):
    (tmp_path / "logs").mkdir(exist_ok=True)
    (tmp_path / "t").mkdir(exist_ok=True)
    conf = tmp_path / "nginx.conf"
    conf.write_text(conf_text)
    proc = subprocess.run(
        [NGINX_BIN, "-t", "-p", str(tmp_path), "-c", str(conf)],
        capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


def test_admin_directives_parse(tmp_path):
    secret = tmp_path / "admin.secret"
    secret.write_text(SECRET + "\n")
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{_P_PARSE};
            location /xrootd/ {{
                xrootd_dashboard on;
                xrootd_dashboard_password "pw";
                xrootd_admin_allow 127.0.0.1/32 10.0.0.0/8;
                xrootd_admin_secret {secret};
                xrootd_admin_require_both on;
            }}
        }}
    """, tmp_path)
    rc, out = _nginx_check(conf, tmp_path)
    assert rc == 0, out


def test_proxy_dynamic_directive_parses(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{_P_DYNAMIC};
            location / {{
                xrootd_webdav on;
                xrootd_webdav_root {data};
                xrootd_webdav_auth none;
                xrootd_webdav_proxy on;
                xrootd_webdav_proxy_dynamic on;
                xrootd_webdav_proxy_auth anonymous;
            }}
        }}
    """, tmp_path)
    rc, out = _nginx_check(conf, tmp_path)
    assert rc == 0, out


def test_bad_admin_secret_path_rejected(tmp_path):
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{_P_BADSECRET};
            location /xrootd/ {{
                xrootd_dashboard on;
                xrootd_dashboard_password "pw";
                xrootd_admin_secret {tmp_path}/does-not-exist.secret;
            }}
        }}
    """, tmp_path)
    rc, out = _nginx_check(conf, tmp_path)
    assert rc != 0
    assert "xrootd_admin_secret" in out


# --------------------------------------------------------------------------- #
# Functional helpers                                                           #
# --------------------------------------------------------------------------- #

class _Origin(http.server.BaseHTTPRequestHandler):
    tag = b"ORIGIN-OK"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.tag)))
        self.end_headers()
        self.wfile.write(self.tag)

    def log_message(self, *a):
        pass


def _start_origin(port):
    srv = http.server.HTTPServer((BIND_HOST, port), _Origin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _curl(*args, timeout=10):
    rc = subprocess.run(["curl", "-s", "-w", "\n%{http_code}", *args],
                        capture_output=True, text=True, timeout=timeout)
    if rc.returncode != 0:
        return None, rc.stderr
    body, _, status = rc.stdout.rpartition("\n")
    return int(status), body


def _admin(method, url, token=None, data=None):
    args = ["-X", method]
    if token is not None:
        args += ["-H", f"Authorization: Bearer {token}"]
    if data is not None:
        args += ["-H", "Content-Type: application/json", "--data", data]
    args.append(url)
    return _curl(*args)


@pytest.fixture
def admin_server(tmp_path):
    """A self-contained nginx with the dashboard admin API (bearer-secret only,
    so authorization depends purely on the token) and a dynamic WebDAV proxy
    pool, plus one live origin backend."""
    port = int(os.environ.get("TEST_PHASE23_PORT") or free_port())
    be_port = int(os.environ.get("TEST_PHASE23_BE_PORT") or free_port())
    secret = tmp_path / "admin.secret"
    secret.write_text(SECRET + "\n")
    data = tmp_path / "data"
    data.mkdir()
    (data / "x.txt").write_text("proxied\n")

    origin = _start_origin(be_port)
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{port};
            location /dav/ {{
                xrootd_webdav on;
                xrootd_webdav_root {data};
                xrootd_webdav_auth none;
                xrootd_webdav_proxy on;
                xrootd_webdav_proxy_dynamic on;
                xrootd_webdav_proxy_auth anonymous;
            }}
            location /xrootd/ {{
                xrootd_dashboard on;
                xrootd_dashboard_password "pw";
                xrootd_admin_secret {secret};
            }}
        }}
    """, tmp_path)
    conf_path = tmp_path / "nginx.conf"
    (tmp_path / "logs").mkdir(exist_ok=True)
    (tmp_path / "t").mkdir(exist_ok=True)
    conf_path.write_text(conf + "daemon off;\nmaster_process off;\n")
    proc = subprocess.Popen([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf_path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if not _wait_port(port):
            err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            proc.terminate()
            pytest.skip(f"admin server did not start: {err}")
        yield port, be_port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        origin.shutdown()


def _base(port):
    return f"http://{url_host(HOST)}:{port}/xrootd/api/v1/admin"


# --------------------------------------------------------------------------- #
# 3. Functional admin auth (security-negative + positive)                      #
# --------------------------------------------------------------------------- #

def test_admin_requires_token(admin_server):
    port, _ = admin_server
    body = json.dumps({"host": "ds1.example.org", "port": 1094, "paths": "/store"})
    status, _ = _admin("POST", f"{_base(port)}/cluster/servers", data=body)
    assert status == 403, "no Authorization header must be rejected"


def test_admin_wrong_token_rejected(admin_server):
    port, _ = admin_server
    body = json.dumps({"host": "ds1.example.org", "port": 1094, "paths": "/store"})
    status, _ = _admin("POST", f"{_base(port)}/cluster/servers",
                       token="not-the-secret", data=body)
    assert status == 403


# --------------------------------------------------------------------------- #
# 4. Functional cluster registry                                               #
# --------------------------------------------------------------------------- #

def test_cluster_register_and_invalid_host(admin_server):
    port, _ = admin_server
    good = json.dumps({"host": "ds1.example.org", "port": 1094,
                       "paths": "/store", "free_mb": 1000, "util_pct": 12})
    status, body = _admin("POST", f"{_base(port)}/cluster/servers",
                          token=SECRET, data=good)
    assert status == 200, body
    assert json.loads(body)["result"] == "registered"

    # Whitelist rejects an injection-y hostname (reject, never sanitise).
    bad = json.dumps({"host": "ds1;rm -rf/", "port": 1094, "paths": "/store"})
    status, body = _admin("POST", f"{_base(port)}/cluster/servers",
                          token=SECRET, data=bad)
    assert status == 400, body
    assert json.loads(body)["error"] == "invalid_field"


# --------------------------------------------------------------------------- #
# 5. Functional dynamic proxy pool (add → list → proxy → drain → remove)       #
# --------------------------------------------------------------------------- #

def test_proxy_pool_lifecycle(admin_server):
    port, be_port = admin_server
    backends = f"{_base(port)}/proxy/backends"

    # Add the live origin to the pool.
    status, body = _admin("POST", backends, token=SECRET,
                          data=json.dumps({"url": f"http://{url_host(HOST)}:{be_port}",
                                           "weight": 1}))
    assert status == 201, body
    bid = json.loads(body)["id"]
    assert bid >= 1

    # It shows up active in the listing.
    status, body = _admin("GET", backends, token=SECRET)
    assert status == 200, body
    rows = json.loads(body)["backends"]
    assert any(b["id"] == bid and b["state"] == "active" for b in rows), rows

    # A request to the proxy location is served by the pooled origin.
    status, text = _curl(f"http://{url_host(HOST)}:{port}/dav/x.txt")
    assert status == 200, text
    assert "ORIGIN-OK" in text, text

    # Drain it — no new selects, state flips to draining.
    status, _ = _admin("POST", f"{backends}/{bid}/drain", token=SECRET)
    assert status == 200
    status, body = _admin("GET", backends, token=SECRET)
    assert any(b["id"] == bid and b["state"] == "draining"
               for b in json.loads(body)["backends"])

    # Remove it — the pool is empty again.
    status, _ = _admin("DELETE", f"{backends}/{bid}", token=SECRET)
    assert status == 200
    status, body = _admin("GET", backends, token=SECRET)
    assert all(b["id"] != bid for b in json.loads(body)["backends"])


def test_proxy_invalid_url_rejected(admin_server):
    port, _ = admin_server
    status, body = _admin("POST", f"{_base(port)}/proxy/backends", token=SECRET,
                          data=json.dumps({"url": "ftp://127.0.0.1:21/x"}))
    assert status == 400, body
    assert json.loads(body)["error"] == "invalid_field"
