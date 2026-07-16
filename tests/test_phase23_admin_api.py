"""
Phase 23 — dynamic upstreams: REST admin write API + dynamic WebDAV proxy pool.

Coverage:
  1. Source-marker checks: the admin API module, the SHM proxy pool, registry
     helpers, directives, and build registration are wired.
  2. Config validation: the admin directives parse; a missing secret file is
     rejected (both via registry templates).
  3. Functional admin auth: bearer-secret gate — missing/wrong token → 403,
     correct token → 200; the admin API is read from a file, never nginx.conf.
  4. Functional cluster registry: register (good + invalid-host reject).
  5. Dynamic proxy pool lifecycle — retired with brix_webdav_proxy_dynamic
     (skip stub kept to document the legacy-proxy cleanup).

Registry-backed: every nginx here is a throwaway instance provisioned through
the `lifecycle` harness; curl runs through the harness command runner.
"""

import json
import os
import threading
import http.server
from pathlib import Path

import pytest

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, free_ports, HOST, BIND_HOST, url_host

pytestmark = pytest.mark.uses_lifecycle_harness

ROOT = Path(__file__).resolve().parents[1]
SECRET = "phase23-admin-secret-token-value"


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
    assert (ROOT / "src/observability/dashboard/api_admin.c").exists()
    assert (ROOT / "src/observability/dashboard/api_admin.h").exists()
    cfg = _read("config")
    assert "src/observability/dashboard/api_admin.c" in cfg


def test_proxy_pool_module_present():
    assert (ROOT / "src/protocols/webdav/proxy_pool.c").exists()
    assert (ROOT / "src/protocols/webdav/proxy_pool.h").exists()
    cfg = _read("config")
    assert "src/protocols/webdav/proxy_pool.c" in cfg
    # The pool header is a build dependency for both webdav and dashboard.
    assert cfg.count("src/protocols/webdav/proxy_pool.h") >= 2


def test_admin_auth_and_validation_present():
    c = _read("src/observability/dashboard/api_admin.c")
    # Constant-time secret compare, whitelist validation (reject not sanitise),
    # audit logging, and the disabled-by-default gate.
    assert "CRYPTO_memcmp" in c
    assert "admin_validate_hostname" in c
    assert "admin_validate_url" in c
    assert "admin_audit" in c
    assert "BRIX_ADMIN_AUTH_DENIED" in c


def test_registry_undrain_helper_present():
    assert "brix_srv_undrain" in _read("src/net/manager/registry_select.c")  # split out
    assert "brix_srv_undrain" in _read("src/net/manager/registry.h")


def test_proxy_pool_api_present():
    p = _read("src/protocols/webdav/proxy_pool.c")
    for fn in ("brix_proxy_pool_configure", "brix_proxy_pool_add",
               "brix_proxy_pool_select", "brix_proxy_pool_drain",
               "brix_proxy_pool_remove", "brix_proxy_pool_snapshot",
               "brix_proxy_pool_dec_in_flight"):
        assert fn in p, fn
    # proxy.c branches on the dynamic pool; finalize releases in_flight.
    assert "brix_proxy_pool_select" in _read("src/protocols/webdav/proxy.c")
    assert "brix_proxy_pool_dec_in_flight" in _read("src/protocols/webdav/proxy_response.c")


def test_directives_registered():
    d = _read("src/observability/dashboard/module.c")
    for name in ("brix_admin_allow", "brix_admin_secret",
                 "brix_admin_require_both"):
        assert name in d, name
    # NOTE: the WebDAV reverse-proxy directives (brix_webdav_proxy /
    # _dynamic) were retired in the legacy-proxy cleanup; only
    # brix_webdav_proxy_certs (GSI client auth) survives.


# --------------------------------------------------------------------------- #
# 2. Config validation                                                         #
# --------------------------------------------------------------------------- #

def test_admin_directives_parse(lifecycle, tmp_path):
    secret = tmp_path / "admin.secret"
    secret.write_text(SECRET + "\n")
    lifecycle.register(NginxInstanceSpec(
        name="lc-admin-parse",
        template="nginx_admin_parse.conf",
        template_values={"BIND_HOST": BIND_HOST, "SECRET_FILE": str(secret)},
        reason="admin directive parse coverage",
    ))
    lifecycle.reconfigure("lc-admin-parse")
    lifecycle.nginx_test("lc-admin-parse")  # raises on parse failure


@pytest.mark.skip(reason="WebDAV reverse-proxy directives (brix_webdav_proxy/"
                  "_dynamic) retired in the legacy-proxy cleanup; only "
                  "brix_webdav_proxy_certs survives")
def test_proxy_dynamic_directive_parses():
    pass


def test_bad_admin_secret_path_rejected(lifecycle, tmp_path):
    # expect_config_failure renders from template_values only, so all
    # placeholders (including the launcher-provided ones) are passed here.
    (port,) = free_ports(1)
    result = lifecycle.expect_config_failure(NginxInstanceSpec(
        name="lc-admin-badsecret",
        template="nginx_admin_badsecret.conf",
        template_values={
            "BIND_HOST": BIND_HOST,
            "PORT": port,
            "LOG_DIR": str(tmp_path),
            "TMP_DIR": str(tmp_path),
            "SECRET_FILE": str(tmp_path / "does-not-exist.secret"),
        },
        reason="missing admin secret file must be rejected at parse time",
    ))
    out = (result.stdout or "") + (result.stderr or "")
    assert result.returncode != 0
    assert "brix_admin_secret" in out


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


class _AdminServer:
    """Handle for the admin-API instance: ports + curl through the harness."""

    def __init__(self, harness, port, be_port):
        self.harness = harness
        self.port = port
        self.be_port = be_port

    @property
    def base(self):
        return f"http://{url_host(HOST)}:{self.port}/brix/api/v1/admin"

    def curl(self, *args, timeout=10):
        rc = self.harness.run_cmd(
            ["curl", "-s", "-w", "\n%{http_code}", *args], timeout=timeout)
        if rc.returncode != 0:
            return None, rc.stderr
        body, _, status = rc.stdout.rpartition("\n")
        return int(status), body

    def admin(self, method, url, token=None, data=None):
        args = ["-X", method]
        if token is not None:
            args += ["-H", f"Authorization: Bearer {token}"]
        if data is not None:
            args += ["-H", "Content-Type: application/json", "--data", data]
        args.append(url)
        return self.curl(*args)


@pytest.fixture
def admin_server(lifecycle, tmp_path):
    """A self-contained nginx with the dashboard admin API (bearer-secret only,
    so authorization depends purely on the token), plus one live origin
    backend for URL-validation coverage."""
    secret = tmp_path / "admin.secret"
    secret.write_text(SECRET + "\n")
    data = tmp_path / "data"
    data.mkdir()
    (data / "x.txt").write_text("proxied\n")

    origin = http.server.HTTPServer((BIND_HOST, 0), _Origin)
    be_port = origin.server_address[1]
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    try:
        endpoint = lifecycle.start(NginxInstanceSpec(
            name="lc-admin-api",
            template="nginx_admin_api.conf",
            protocol="http",
            data_root=str(data),
            template_values={"BIND_HOST": BIND_HOST,
                             "SECRET_FILE": str(secret)},
            reason="dashboard admin API functional coverage",
        ))
        yield _AdminServer(lifecycle, endpoint.port, be_port)
    finally:
        origin.shutdown()


# --------------------------------------------------------------------------- #
# 3. Functional admin auth (security-negative + positive)                      #
# --------------------------------------------------------------------------- #

def test_admin_requires_token(admin_server):
    body = json.dumps({"host": "ds1.example.org", "port": 1094, "paths": "/store"})
    status, _ = admin_server.admin(
        "POST", f"{admin_server.base}/cluster/servers", data=body)
    assert status == 403, "no Authorization header must be rejected"


def test_admin_wrong_token_rejected(admin_server):
    body = json.dumps({"host": "ds1.example.org", "port": 1094, "paths": "/store"})
    status, _ = admin_server.admin(
        "POST", f"{admin_server.base}/cluster/servers",
        token="not-the-secret", data=body)
    assert status == 403


# --------------------------------------------------------------------------- #
# 4. Functional cluster registry                                               #
# --------------------------------------------------------------------------- #

def test_cluster_register_and_invalid_host(admin_server):
    good = json.dumps({"host": "ds1.example.org", "port": 1094,
                       "paths": "/store", "free_mb": 1000, "util_pct": 12})
    status, body = admin_server.admin(
        "POST", f"{admin_server.base}/cluster/servers", token=SECRET, data=good)
    assert status == 200, body
    assert json.loads(body)["result"] == "registered"

    # Whitelist rejects an injection-y hostname (reject, never sanitise).
    bad = json.dumps({"host": "ds1;rm -rf/", "port": 1094, "paths": "/store"})
    status, body = admin_server.admin(
        "POST", f"{admin_server.base}/cluster/servers", token=SECRET, data=bad)
    assert status == 400, body
    assert json.loads(body)["error"] == "invalid_field"


# --------------------------------------------------------------------------- #
# 5. Functional dynamic proxy pool (add → list → proxy → drain → remove)       #
# --------------------------------------------------------------------------- #

@pytest.mark.skip(reason="admin proxy-pool backs the dynamic WebDAV proxy, whose "
                  "enabler (brix_webdav_proxy_dynamic) was retired in the "
                  "legacy-proxy cleanup — the pool SHM zone is never created")
def test_proxy_pool_lifecycle():
    pass


def test_proxy_invalid_url_rejected(admin_server):
    status, body = admin_server.admin(
        "POST", f"{admin_server.base}/proxy/backends", token=SECRET,
        data=json.dumps({"url": "ftp://127.0.0.1:21/x"}))
    assert status == 400, body
    assert json.loads(body)["error"] == "invalid_field"
