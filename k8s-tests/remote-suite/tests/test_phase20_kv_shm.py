# brix-remote-ok
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

import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

from settings import NGINX_BIN, free_port, free_ports, HOST, BIND_HOST

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = "/tmp/xrd-test/data"


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

def _nginx_check(conf_text, tmp_path):
    """Run `nginx -t` against conf_text; return (rc, combined output)."""
    prefix = tmp_path
    (prefix / "logs").mkdir(exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(conf_text)
    proc = subprocess.run(
        [NGINX_BIN, "-t", "-p", str(prefix), "-c", str(conf)],
        capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


HEADER = (
    "error_log {logs}/error.log info;\n"
    "pid {logs}/nginx.pid;\n"
    "events {{ worker_connections 64; }}\n"
)


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


# --------------------------------------------------------------------------- #
# 2. Config validation                                                         #
# --------------------------------------------------------------------------- #

def test_kv_directives_parse(tmp_path):
    conf = HEADER.format(logs=tmp_path / "logs") + f"""
    stream {{
        brix_kv_zone tkn 16m key=32  val=5120;
        brix_kv_zone ac   4m key=32  val=8;
        brix_kv_zone rl   2m key=256 val=16;
        server {{
            listen {BIND_HOST}:{free_port()};
            xrootd on;
            brix_storage_backend posix:{DATA_DIR};
            brix_auth none;
            brix_session_slots 4096;
            brix_token_cache zone=tkn;
            brix_auth_cache  zone=ac ttl=15;
            brix_rate_limit  zone=rl rate=200r/s burst=500 key=dn;
        }}
    }}
    """
    rc, out = _nginx_check(conf, tmp_path)
    assert rc == 0, out


def test_token_cache_rejects_undersized_zone(tmp_path):
    # val too small for brix_token_claims_t -> must be rejected.
    conf = HEADER.format(logs=tmp_path / "logs") + f"""
    stream {{
        brix_kv_zone tkn 1m key=32 val=16;
        server {{
            listen {BIND_HOST}:{free_port()};
            xrootd on;
            brix_storage_backend posix:{DATA_DIR};
            brix_auth none;
            brix_token_cache zone=tkn;
        }}
    }}
    """
    rc, out = _nginx_check(conf, tmp_path)
    assert rc != 0
    assert "too small" in out


def test_unknown_zone_is_rejected(tmp_path):
    conf = HEADER.format(logs=tmp_path / "logs") + f"""
    stream {{
        server {{
            listen {BIND_HOST}:{free_port()};
            xrootd on;
            brix_storage_backend posix:{DATA_DIR};
            brix_auth none;
            brix_auth_cache zone=does_not_exist;
        }}
    }}
    """
    rc, out = _nginx_check(conf, tmp_path)
    assert rc != 0
    assert "unknown zone" in out


def test_rate_limit_requires_rate_and_burst(tmp_path):
    conf = HEADER.format(logs=tmp_path / "logs") + f"""
    stream {{
        brix_kv_zone rl 2m key=256 val=16;
        server {{
            listen {BIND_HOST}:{free_port()};
            xrootd on;
            brix_storage_backend posix:{DATA_DIR};
            brix_auth none;
            brix_rate_limit zone=rl;
        }}
    }}
    """
    rc, out = _nginx_check(conf, tmp_path)
    assert rc != 0
    assert "rate_limit" in out


# --------------------------------------------------------------------------- #
# 3. Functional: HTTP IP rate limit + KV Prometheus metrics                    #
# --------------------------------------------------------------------------- #

_WEBDAV_PORT_ENV = os.environ.get("TEST_PHASE20_WEBDAV_PORT")
_METRICS_PORT_ENV = os.environ.get("TEST_PHASE20_METRICS_PORT")
if _WEBDAV_PORT_ENV is None and _METRICS_PORT_ENV is None:
    WEBDAV_PORT, METRICS_PORT = free_ports(2)
else:
    WEBDAV_PORT = int(_WEBDAV_PORT_ENV) if _WEBDAV_PORT_ENV else free_port()
    METRICS_PORT = int(_METRICS_PORT_ENV) if _METRICS_PORT_ENV else free_port()


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
def rate_limited_server(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    (tmp_path / "tmp").mkdir(exist_ok=True)
    conf = HEADER.format(logs=logs) + f"""
    http {{
        client_body_temp_path {tmp_path}/tmp;
        proxy_temp_path        {tmp_path}/tmp;
        fastcgi_temp_path      {tmp_path}/tmp;
        uwsgi_temp_path        {tmp_path}/tmp;
        scgi_temp_path         {tmp_path}/tmp;
        access_log off;

        brix_kv_zone h_rl 2m key=256 val=16;

        server {{
            listen {BIND_HOST}:{WEBDAV_PORT};
            location / {{
                brix_webdav      on;
                brix_webdav_storage_backend posix:{DATA_DIR};
                brix_webdav_auth none;
                brix_rate_limit  zone=h_rl rate=1r/s burst=2 key=ip;
            }}
        }}
        server {{
            listen {BIND_HOST}:{METRICS_PORT};
            location /metrics {{ brix_metrics on; }}
        }}
    }}
    """
    conf_path = tmp_path / "nginx.conf"
    conf_path.write_text(conf + "daemon off;\nmaster_process off;\n")
    proc = subprocess.Popen(
        [NGINX_BIN, "-p", str(tmp_path), "-c", str(conf_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        if not _wait_port(WEBDAV_PORT) or not _wait_port(METRICS_PORT):
            out = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            proc.terminate()
            pytest.skip(f"rate-limit test server did not start: {out}")
        yield
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


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
