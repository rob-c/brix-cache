"""
test_health_endpoint.py — phase-47 W2: the /healthz liveness/readiness probe.

The metrics server block carries `brix_health on;` at `location = /healthz`
(see tests/configs/nginx_shared.conf). These tests assert the contract an LB or
Kubernetes probe relies on:

  * GET  /healthz          -> 200 application/json, {"status":"ok",...}   (liveness)
  * GET  /healthz?verbose  -> 200 + a "checks" object (readiness signals)
  * HEAD /healthz          -> 200, no body
  * POST /healthz          -> 405 (read-only, method-gated like /metrics)

Three cases per the project norm: success, the verbose variant, and the
security/negative (rejected method).
"""

import json
import pathlib
import re

import requests

# The version /healthz reports is BRIX_SERVER_VERSION (src/core/ident.h) — read
# it from the source of truth so a release bump cannot silently stale this test.
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
