"""
Phase 20 — shared-memory KV store, caches, and rate limiting.

Three layers of coverage:

  1. Source-marker checks — the new infrastructure and its integration points
     stay wired (cheap, no server needed).
  2. Config validation — the new directives parse, and bad input is rejected
     with a clear error (driven through `nginx -t`).
  3. Functional — a dedicated nginx instance proves the IP rate limiter sheds
     traffic with 429 and that the KV Prometheus counters are exported.
"""

import itertools
import os
import socket
import time
from pathlib import Path

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import (
    SHARED_PARSE_PLACEHOLDER_PORT,
    lifecycle_ports_for,
)
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-phase20")]

ROOT = Path(__file__).resolve().parents[1]

_SEQ = itertools.count()


# --------------------------------------------------------------------------- #
# 1. Source-marker checks                                                      #
# --------------------------------------------------------------------------- #

def _read(relpath):
    path = ROOT / relpath
    assert path.exists(), f"missing expected file: {relpath}"
    return path.read_text(encoding="utf-8")


def test_phase20_foundation_files_exist():
    for relpath in (
        "src/core/shm/kv.h",
        "src/core/shm/kv.c",
        "src/auth/token/token_cache.c",
        "src/auth/authz/auth_cache.c",
        "src/core/shm/rate_limit.c",
    ):
        assert (ROOT / relpath).exists(), f"missing {relpath}"


def test_phase20_kv_store_is_wired_into_consumers():
    # Token cache short-circuits signature verification in both protocols.
    for relpath in ("src/auth/gsi/token.c", "src/protocols/webdav/auth_token.c"):
        text = _read(relpath)
        assert "brix_token_cache_lookup(" in text, relpath
        assert "brix_token_cache_store(" in text, relpath

    # Auth-result cache lives in the stream auth gate.
    auth_gate = _read("src/auth/authz/auth_gate.c")
    assert "auth_cache.kv" in auth_gate
    assert "brix_kv_get(" in auth_gate

    # Rate limiting hooks both protocols.
    assert "brix_rate_limit_check(" in _read("src/auth/gsi/auth.c")
    assert "brix_rate_limit_check(" in _read("src/protocols/webdav/access.c")

    # Prometheus export iterates the zone registry.
    assert "brix_kv_metrics_emit(" in _read("src/observability/metrics/handler.c")


def test_phase20_session_registry_is_runtime_sized():
    reg = _read("src/protocols/root/session/registry.c")
    assert "tbl->capacity" in reg, "session scans must use runtime capacity"
    assert "brix_session_registry_nslots" in reg


# --------------------------------------------------------------------------- #
# config helpers                                                               #
# --------------------------------------------------------------------------- #

@pytest.fixture()
def kv_check(tmp_path):
    """Config-parse check: render the committed stream template with the given
    top-level zone lines and per-server directives, run nginx -t, and return
    (rc, combined stdout+stderr) — the emerg messages ride stderr.  Parse-only
    (config_parse.nginx_t): no registry spec, no bound listener — the {PORT}
    placeholder is the non-binding shared parse placeholder."""

    def run(stream_zones, server_body):
        root = tmp_path / f"kv{next(_SEQ)}"
        data = root / "data"
        logs = root / "logs"
        data.mkdir(parents=True)
        logs.mkdir(parents=True)
        r = nginx_t("nginx_phase20_kv_stream.conf", root,
                    PORT=SHARED_PARSE_PLACEHOLDER_PORT,
                    DATA_ROOT=str(data), LOG_DIR=str(logs),
                    STREAM_ZONES=stream_zones, SERVER_BODY=server_body)
        return r.returncode, (r.stdout or "") + (r.stderr or "")

    return run


# --------------------------------------------------------------------------- #
# 2. Config validation                                                         #
# --------------------------------------------------------------------------- #

def test_kv_directives_parse(kv_check):
    rc, out = kv_check(
        """
        brix_kv_zone tkn 16m key=32  val=5120;
        brix_kv_zone ac   4m key=32  val=8;
        brix_kv_zone rl   2m key=256 val=16;
""",
        """
            brix_session_slots 4096;
            brix_token_cache zone=tkn;
            brix_auth_cache  zone=ac ttl=15;
            brix_rate_limit  zone=rl rate=200r/s burst=500 key=dn;
""")
    assert rc == 0, out


def test_token_cache_rejects_undersized_zone(kv_check):
    # val too small for brix_token_claims_t -> must be rejected.
    rc, out = kv_check(
        "        brix_kv_zone tkn 1m key=32 val=16;\n",
        "            brix_token_cache zone=tkn;\n")
    assert rc != 0
    assert "too small" in out


def test_unknown_zone_is_rejected(kv_check):
    rc, out = kv_check(
        "",
        "            brix_auth_cache zone=does_not_exist;\n")
    assert rc != 0
    assert "unknown zone" in out


def test_rate_limit_requires_rate_and_burst(kv_check):
    rc, out = kv_check(
        "        brix_kv_zone rl 2m key=256 val=16;\n",
        "            brix_rate_limit zone=rl;\n")
    assert rc != 0
    assert "rate_limit" in out


# --------------------------------------------------------------------------- #
# 3. Functional: HTTP IP rate limit + KV Prometheus metrics                    #
# --------------------------------------------------------------------------- #

# WEBDAV_PORT (primary) + METRICS_PORT (embedded listen) are owned by the
# lifecycle ledger (fleet_lifecycle_ports.lc-phase20-ratelimit); the live
# rate_limited_server fixture binds those exact ports, so the module globals the
# test bodies dial must come from the same ledger entry.
_P20_PORT, _P20_EXTRA = lifecycle_ports_for("lc-phase20-ratelimit")
WEBDAV_PORT = _P20_PORT
METRICS_PORT = _P20_EXTRA["METRICS_PORT"]


def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture
def rate_limited_server():
    harness = LifecycleHarness()
    try:
        harness.start(NginxInstanceSpec(
            name="lc-phase20-ratelimit",
            template="nginx_phase20_kv_http.conf",
            protocol="http", readiness="tcp"))
        assert _wait_port(METRICS_PORT), "metrics listener did not come up"
        yield
    finally:
        harness.close()


def _http_get(port, path, host=HOST):
    with socket.create_connection((host, port), timeout=3) as s:
        s.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            .encode()
        )
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    status_line = data.split(b"\r\n", 1)[0].decode(errors="replace")
    # "HTTP/1.1 429 Too Many Requests"
    return int(status_line.split()[1])


def test_ip_rate_limit_sheds_with_429(rate_limited_server):
    # burst=2 -> first two admitted, the rest rejected with 429 (one client IP).
    statuses = [_http_get(WEBDAV_PORT, "/nonexistent") for _ in range(6)]
    assert 429 in statuses, f"expected a 429, got {statuses}"
    # The earliest requests must have been admitted (not rate-limited).
    assert statuses[0] != 429, f"first request should be admitted: {statuses}"
    # Admitted requests reach the handler (404 for the missing file).
    assert any(s != 429 for s in statuses), statuses


def test_kv_metrics_exported(rate_limited_server):
    # Drive some traffic so the rate-limit zone has activity, then scrape.
    for _ in range(3):
        _http_get(WEBDAV_PORT, "/nonexistent")
    body_status = _http_get_body(METRICS_PORT, "/metrics")
    body = body_status[1]
    assert body_status[0] == 200, body[:200]
    assert "brix_kv_hits_total" in body
    assert "brix_kv_capacity" in body
    assert 'zone="h_rl"' in body


def _http_get_body(port, path, host=HOST):
    with socket.create_connection((host, port), timeout=3) as s:
        s.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            .encode()
        )
        data = b""
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    status = int(head.split(b"\r\n", 1)[0].split()[1])
    return status, body.decode(errors="replace")
