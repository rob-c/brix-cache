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
from pathlib import Path

import pytest

from config_parse import nginx_t
from server_registry import NginxInstanceSpec
from settings import (NGINX_BIN, HOST, BIND_HOST, url_host,
                      STATIC_ORIGIN_PORT)
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT
from settings import HOST

# The static-origin backend is a shared fixed-port fleet mock, declared below.
# Bucket-2: the two admin instances (lc-admin-parse, lc-admin-api) take fixed
# exclusive-band ports; xdist_group serialises the file so they never have two
# concurrent drivers.
pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.registry_server("static-origin"),
    pytest.mark.xdist_group("lc-admin"),
]

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
    assert "brix_srv_undrain" in _read("src/net/manager/registry_select_blacklist.c")  # split out
    assert "brix_srv_undrain" in _read("src/net/manager/registry.h")


def test_proxy_pool_api_present():
    p = _read("src/protocols/webdav/proxy_pool.c")
    for fn in ("brix_proxy_pool_configure", "brix_proxy_pool_add",
               "brix_proxy_pool_select", "brix_proxy_pool_drain",
               "brix_proxy_pool_remove", "brix_proxy_pool_snapshot",
               "brix_proxy_pool_dec_in_flight"):
        assert fn in p, fn
    # The reverse-proxy transport (proxy.c/proxy_response.c) was deleted in the
    # A-2 surface retirement; the pool survives behind the REST admin API.
    admin = _read("src/observability/dashboard/api_admin_proxy.c")
    for fn in ("brix_proxy_pool_add", "brix_proxy_pool_remove",
               "brix_proxy_pool_drain", "brix_proxy_pool_undrain",
               "brix_proxy_pool_snapshot"):
        assert fn in admin, fn


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


def test_bad_admin_secret_path_rejected(tmp_path):
    # Pure config-parse property: render + `nginx -t`, no server ever boots.
    result = nginx_t(
        "nginx_admin_badsecret.conf",
        tmp_path,
        BIND_HOST=BIND_HOST,
        PORT=PARSE_PLACEHOLDER_PORT,
        LOG_DIR=str(tmp_path),
        TMP_DIR=str(tmp_path),
        SECRET_FILE=str(tmp_path / "does-not-exist.secret"),
    )
    out = (result.stdout or "") + (result.stderr or "")
    assert result.returncode != 0
    assert "brix_admin_secret" in out


# --------------------------------------------------------------------------- #
# Functional helpers                                                           #
# --------------------------------------------------------------------------- #

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

    # The URL-validation backend is the shared fixed-port static-origin mock
    # (declared via registry_server above); nothing here to start or stop.
    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-admin-api",
        template="nginx_admin_api.conf",
        protocol="http",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST,
                         "SECRET_FILE": str(secret)},
        reason="dashboard admin API functional coverage",
    ))
    yield _AdminServer(lifecycle, endpoint.port, STATIC_ORIGIN_PORT)


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


# --------------------------------------------------------------------------- #
# 5b. Admin proxy REST — validation / auth / routing / degraded surface        #
#                                                                              #
# The pool SHM zone is never created in the current tree (enabler retired), so #
# every mutating path lands in the degraded branch. These assert the surface   #
# reachable over HTTP today: URL/JSON validation, auth, method routing, and the#
# degraded 404s (proxy_pool_disabled / not_found).                             #
# --------------------------------------------------------------------------- #

def _backends(admin_server):
    return f"{admin_server.base}/proxy/backends"


def test_proxy_list_empty(admin_server):
    status, body = admin_server.admin("GET", _backends(admin_server), token=SECRET)
    assert status == 200, body
    assert json.loads(body)["backends"] == []


def test_proxy_add_valid_url_pool_disabled(admin_server):
    data = json.dumps({"url": f"http://{HOST}:8080", "weight": 100})
    status, body = admin_server.admin(
        "POST", _backends(admin_server), token=SECRET, data=data)
    assert status == 404, body
    assert json.loads(body)["error"] == "proxy_pool_disabled"


def test_proxy_add_missing_url(admin_server):
    status, body = admin_server.admin(
        "POST", _backends(admin_server), token=SECRET, data=json.dumps({"weight": 5}))
    assert status == 400, body
    assert json.loads(body)["error"] == "missing_field"


def test_proxy_get_unknown_id(admin_server):
    status, body = admin_server.admin(
        "GET", f"{_backends(admin_server)}/7", token=SECRET)
    assert status == 404, body
    assert json.loads(body)["error"] == "not_found"


def test_proxy_drain_unknown_id(admin_server):
    status, body = admin_server.admin(
        "POST", f"{_backends(admin_server)}/7/drain", token=SECRET)
    assert status == 404, body
    assert json.loads(body)["error"] == "not_found"


def test_proxy_delete_unknown_id(admin_server):
    status, body = admin_server.admin(
        "DELETE", f"{_backends(admin_server)}/7", token=SECRET)
    assert status == 404, body
    assert json.loads(body)["error"] == "not_found"


def test_proxy_drain_via_get_405(admin_server):
    status, body = admin_server.admin(
        "GET", f"{_backends(admin_server)}/7/drain", token=SECRET)
    assert status == 405, body
    assert json.loads(body)["error"] == "method_not_allowed"


def test_proxy_non_numeric_id_bad_uri(admin_server):
    status, body = admin_server.admin(
        "GET", f"{_backends(admin_server)}/abc", token=SECRET)
    assert status == 400, body
    assert json.loads(body)["error"] == "bad_uri"


def test_proxy_collection_wrong_method_405(admin_server):
    status, body = admin_server.admin("PUT", _backends(admin_server), token=SECRET)
    assert status == 405, body
    assert json.loads(body)["error"] == "method_not_allowed"


def test_proxy_list_no_token_forbidden(admin_server):
    status, _ = admin_server.admin("GET", _backends(admin_server))
    assert status == 403


def test_proxy_add_empty_body(admin_server):
    status, body = admin_server.admin("POST", _backends(admin_server), token=SECRET)
    assert status == 400, body
    assert json.loads(body)["error"] == "empty_body"


def test_proxy_add_non_object_json(admin_server):
    status, body = admin_server.admin(
        "POST", _backends(admin_server), token=SECRET, data="[]")
    assert status == 400, body
    assert json.loads(body)["error"] == "invalid_json"


def test_proxy_add_body_too_large(admin_server):
    big = json.dumps({"url": "http://h/", "pad": "x" * 70000})
    status, body = admin_server.admin(
        "POST", _backends(admin_server), token=SECRET, data=big)
    assert status == 413, body
    assert json.loads(body)["error"] == "body_too_large"


def test_proxy_invalid_url_rejected(admin_server):
    status, body = admin_server.admin(
        "POST", f"{admin_server.base}/proxy/backends", token=SECRET,
        data=json.dumps({"url": f"ftp://{HOST}:21/x"}))
    assert status == 400, body
    assert json.loads(body)["error"] == "invalid_field"
