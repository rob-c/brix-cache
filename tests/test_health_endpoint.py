"""
test_health_endpoint.py — phase-47 W2: the /healthz liveness/readiness probe.

The metrics server block carries `xrootd_health on;` at `location = /healthz`
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

import requests


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
    assert body["service"] == "GNUBall"
    assert body["version"] == "v1.0.5"


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
