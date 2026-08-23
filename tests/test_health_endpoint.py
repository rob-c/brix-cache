"""
test_health_endpoint.py — phase-47 W2: the /healthz liveness/readiness probe.

The metrics server block carries `brix_health on;` at `location = /healthz`
(see tests/configs/nginx_shared.conf). These tests assert the contract an LB or
Kubernetes probe relies on:

  * GET  /healthz          -> 200 application/json, {"status":"ok",...}   (liveness)
                              with a per-request "time"/"time_epoch" pair that
                              proves the answer is freshly built (not cached)
  * GET  /healthz?verbose  -> 200 + a "checks" object (readiness signals), an
                              "endpoints" array (every bound listen socket:
                              addr/port/layer/open, root:// rows joined with
                              auth + connection counters) and an "exports"
                              array (path + backend per registered export)
  * HEAD /healthz          -> 200, no body
  * POST /healthz          -> 405 (read-only, method-gated like /metrics)

Three cases per the project norm: success, the verbose variant, and the
security/negatives (rejected method; no secrets in the endpoint map).
"""

import json
import pathlib
import re
import time

import requests

# The version /healthz reports is BRIX_SERVER_VERSION (src/core/ident.h) — read
# it from the source of truth so a release bump cannot silently stale this test.
def _expression_1(endpoints, test_env):
    return (
        [e for e in endpoints if e["port"] == test_env["metrics_port"]]
    )

def _expression_2(endpoints, test_env):
    return (
        [e for e in endpoints if e["port"] == test_env["anon_port"]]
    )


def _check_test_healthz_verbose_endpoint_map_1(endpoints):
    assert isinstance(endpoints, list) and endpoints

def _check_test_healthz_verbose_endpoint_map_2(metrics_rows):
    assert metrics_rows and all(
        e["layer"] == "http" and e["open"] for e in metrics_rows
    )

def _check_test_healthz_verbose_endpoint_map_3(anon_rows):
    assert anon_rows, "anon stream listener missing from endpoint map"

def _check_test_healthz_verbose_endpoint_map_4(anon):
    assert isinstance(anon["connections_total"], int)

def _check_test_healthz_verbose_endpoint_map_5(exports):
    assert isinstance(exports, list)


_IDENT_H = pathlib.Path(__file__).parent.parent / "src" / "core" / "ident.h"
_VERSION_MATCH = re.search(
    r'#define BRIX_SERVER_VERSION_BARE\s+"([^"]+)"', _IDENT_H.read_text()
)
assert _VERSION_MATCH is not None, "BRIX_SERVER_VERSION_BARE not found in src/core/ident.h"
_SERVER_VERSION = "v" + _VERSION_MATCH.group(1)


def _health_url(test_env):
    # Derive the health URL from the metrics URL (same server block / port).
    return test_env["metrics_url"].rsplit("/", 1)[0] + "/healthz"


def test_healthz_liveness_ok(test_env):
    url = _health_url(test_env)
    r = requests.get(url, timeout=5)
    assert r.status_code == 200
    assert r.headers["Content-Type"] == "application/json"
    body = json.loads(r.text)
    assert body["status"] == "ok"
    assert body["service"] == "BriX-Cache"
    assert body["version"] == _SERVER_VERSION


def test_healthz_verbose_readiness(test_env):
    url = _health_url(test_env)
    r = requests.get(url, params={"verbose": ""}, timeout=5)
    assert r.status_code == 200
    body = json.loads(r.text)
    assert body["status"] == "ok"
    checks = body["checks"]
    # A live shared instance with a stream block must have the metrics SHM mapped.
    assert checks["metrics_shm"] == "mapped"
    assert isinstance(checks["worker_pid"], int) and checks["worker_pid"] > 0
    assert checks["nginx_version"]


def test_healthz_head_no_body(test_env):
    url = _health_url(test_env)
    r = requests.head(url, timeout=5)
    assert r.status_code == 200
    assert r.headers["Content-Type"] == "application/json"
    assert r.content == b""


def test_healthz_rejects_post(test_env):
    url = _health_url(test_env)
    r = requests.post(url, data=b"x", timeout=5)
    assert r.status_code == 405


_ISO8601_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def test_healthz_reports_fresh_timestamp(test_env):
    # SUCCESS: the default (probe) document carries a per-request timestamp —
    # the "service has not locked up" signal — but stays minimal: the heavier
    # endpoint/export map is verbose-only.
    url = _health_url(test_env)
    body = json.loads(requests.get(url, timeout=5).text)
    assert _ISO8601_RE.match(body["time"]), body["time"]
    assert isinstance(body["time_epoch"], int)
    # Wide tolerance: the WSL2 host clock can step; a day still catches a
    # frozen/garbage timestamp without flaking on clock drift.
    assert abs(body["time_epoch"] - int(time.time())) < 86400
    assert "endpoints" not in body
    assert "exports" not in body


def test_healthz_verbose_endpoint_map(test_env):
    # SUCCESS (verbose): every bound listen socket is reported with its plane
    # and open state; root:// listeners carry their SHM identity + counters;
    # exports list the namespace surface.
    url = _health_url(test_env)
    body = json.loads(requests.get(url, params={"verbose": ""}, timeout=5).text)

    endpoints = body["endpoints"]
    _check_test_healthz_verbose_endpoint_map_1(endpoints)
    for row in endpoints:
        def _assert_test_healthz_verbose_endpoint_map_3():
            assert row["layer"] in ("http", "stream", "other")
            assert isinstance(row["port"], int)

        _assert_test_healthz_verbose_endpoint_map_3()
        def _assert_test_healthz_verbose_endpoint_map_4():
            assert isinstance(row["open"], bool)
            assert row["addr"]

        _assert_test_healthz_verbose_endpoint_map_4()

    # The metrics/health port itself must be an open http listener.
    metrics_rows = _expression_1(endpoints, test_env)
    _check_test_healthz_verbose_endpoint_map_2(metrics_rows)

    # The anon root:// port (first stream server block => always owns an SHM
    # slot) must be a stream listener joined with auth + counters.
    anon_rows = _expression_2(endpoints, test_env)
    _check_test_healthz_verbose_endpoint_map_3(anon_rows)
    anon = anon_rows[0]
    def _assert_test_healthz_verbose_endpoint_map_1():
        assert anon["layer"] == "stream" and anon["open"]
        assert anon["proto"] == "root"

    _assert_test_healthz_verbose_endpoint_map_1()
    def _assert_test_healthz_verbose_endpoint_map_2():
        assert anon["auth"] == "anon"
        assert isinstance(anon["connections_active"], int)

    _assert_test_healthz_verbose_endpoint_map_2()
    _check_test_healthz_verbose_endpoint_map_4(anon)

    exports = body["exports"]
    _check_test_healthz_verbose_endpoint_map_5(exports)
    for row in exports:
        def _assert_test_healthz_verbose_endpoint_map_5():
            assert row["path"].startswith("/")
            assert row["backend"]

        _assert_test_healthz_verbose_endpoint_map_5()


def test_healthz_verbose_leaks_no_secrets(test_env):
    # SECURITY-NEGATIVE: the endpoint/export map is identity only — no
    # credential material may ride along on an unauthenticated probe endpoint.
    url = _health_url(test_env)
    text = requests.get(url, params={"verbose": ""}, timeout=5).text
    lowered = text.lower()
    for needle in ("private key", "secret", "keytab", "password", "bearer "):
        assert needle not in lowered, f"credential material {needle!r} in /healthz"
