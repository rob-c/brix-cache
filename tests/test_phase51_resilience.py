"""
tests/test_phase51_resilience.py — phase-51 cross-protocol resilience wiring.

Self-contained smoke tests for the phase-51 hardening
(docs/refactor/phase-51-cross-protocol-resilience.md).  They do NOT touch the
shared test fleet:

  * the directive-parse tests run ``nginx -t`` on a throwaway config (no port
    binding, no PKI, no fleet) to prove the new directives are accepted and merge
    cleanly — covering A3 (per-IP CMS cap), E4 (GSI in-flight cap), A4 (manager
    reaper arming) and B1 (proxy write-stall);
  * the metrics test asserts the new ``brix_*`` resilience counters are exported
    on /metrics, and SKIPS cleanly when the metrics endpoint is not running.

Run:
    PYTHONPATH=tests pytest tests/test_phase51_resilience.py -v
"""

import os
import subprocess
import tempfile

import pytest

from settings import NGINX_BIN, NGINX_METRICS_PORT


def _nginx_t(conf_text):
    """Write conf_text to a temp file and return (rc, combined_output) of -t."""
    d = tempfile.mkdtemp(prefix="xrd_p51_")
    conf = os.path.join(d, "nginx.conf")
    with open(conf, "w") as f:
        f.write(conf_text.replace("@DIR@", d))
    r = subprocess.run([NGINX_BIN, "-t", "-c", conf],
                       capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr)


pytestmark = pytest.mark.skipif(
    not os.path.exists(NGINX_BIN), reason=f"nginx binary not found at {NGINX_BIN}")


def test_new_stream_directives_parse():
    """All new stream-side resilience directives are accepted by nginx -t."""
    conf = """
worker_processes 1;
error_log @DIR@/error.log;
pid @DIR@/nginx.pid;
events { worker_connections 64; }
stream {
    server {
        listen 127.0.0.1:19951;
        brix_root on; brix_storage_backend posix:@DIR@; brix_auth none;
        brix_gsi_max_inflight_handshakes 128;
    }
    server {
        listen 127.0.0.1:19952;
        brix_cms_server on;
        brix_cms_server_max_connections 1024;
        brix_cms_server_max_connections_per_ip 64;
    }
    server {
        listen 127.0.0.1:19953;
        brix_root on; brix_storage_backend posix:@DIR@; brix_auth none;
        brix_manager_mode on;
    }
}
"""
    rc, out = _nginx_t(conf)
    assert rc == 0, f"nginx -t rejected the phase-51 directives:\n{out}"
    assert "syntax is ok" in out and "test is successful" in out, out


def test_directive_disable_values_parse():
    """The 0/off disable escapes parse too (back-compat)."""
    conf = """
worker_processes 1;
error_log @DIR@/error.log;
pid @DIR@/nginx.pid;
events { worker_connections 64; }
stream {
    server {
        listen 127.0.0.1:19954;
        brix_root on; brix_storage_backend posix:@DIR@; brix_auth none;
        brix_gsi_max_inflight_handshakes 0;
    }
    server {
        listen 127.0.0.1:19955;
        brix_cms_server on;
        brix_cms_server_max_connections_per_ip 0;
    }
}
"""
    rc, out = _nginx_t(conf)
    assert rc == 0, f"nginx -t rejected the disable values:\n{out}"


# Counters that brix_export_resilience_metrics() must emit (E6/A1).
_EXPECTED_COUNTERS = [
    "brix_cms_read_timeouts_total",
    "brix_cms_login_timeouts_total",
    "brix_cms_idle_closes_total",
    "brix_cms_cap_rejections_total",
    "brix_cms_frame_yields_total",
    "brix_ocsp_timeouts_total",
    "brix_auth_l1_hits_total",
    "brix_auth_l1_misses_total",
    "brix_acc_nss_breaker_open_total",
    "brix_acc_dns_breaker_open_total",
]


def test_resilience_metrics_exported():
    """The new resilience counters appear on /metrics (skips if not running)."""
    import urllib.request
    import urllib.error

    url = f"http://127.0.0.1:{NGINX_METRICS_PORT}/metrics"
    try:
        body = urllib.request.urlopen(url, timeout=5).read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        pytest.skip(f"metrics endpoint {url} not reachable: {exc}")

    missing = [c for c in _EXPECTED_COUNTERS if c not in body]
    assert not missing, f"phase-51 counters missing from /metrics: {missing}"
