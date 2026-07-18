"""
tests/test_ssi_metrics.py — Phase-6 SSI metrics.

A self-contained nginx (stream SSI listener + http /metrics) verifies the SSI
counters increment and carry only low-cardinality labels (port/auth — never a
path, reqId, or username).

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_ssi_metrics.py -v
"""
import os
import re
import urllib.request

import pytest

from settings import NGINX_BIN, BIND_HOST, free_port
from server_registry import NginxInstanceSpec
from test_ssi_wire import _handshake_login, _open_ssi, _write_request, _query_wait

pytestmark = pytest.mark.uses_lifecycle_harness


@pytest.fixture()
def ssi_metrics_server(lifecycle):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip("nginx binary not found")
    mport = free_port()
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-ssi-metrics",
        template="nginx_lc_ssi_metrics.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST},
        extra_ports={"METRICS_PORT": mport},
        reason="SSI stream listener + http /metrics scrape target"))
    return ep.port, ep.extra_ports["METRICS_PORT"]


def _scrape(mport):
    with urllib.request.urlopen(f"http://127.0.0.1:{mport}/metrics", timeout=5) as r:
        return r.read().decode()


def _counter(text, name):
    total = 0
    for m in re.finditer(rf"^{re.escape(name)}\{{([^}}]*)\}}\s+(\d+)", text, re.M):
        total += int(m.group(2))
    return total


def _label_keys(text, name):
    keys = set()
    for m in re.finditer(rf"^{re.escape(name)}\{{([^}}]*)\}}", text, re.M):
        for pair in m.group(1).split(","):
            if "=" in pair:
                keys.add(pair.split("=")[0])
    return keys


class TestSsiMetrics:
    def test_requests_counter_increments(self, ssi_metrics_server):
        sport, mport = ssi_metrics_server
        before = _counter(_scrape(mport), "brix_ssi_requests_total")
        # three echo round-trips → three dispatched requests
        for i in range(3):
            sock = _handshake_login(BIND_HOST, sport)
            fh = _open_ssi(sock, "echo")
            _write_request(sock, fh, i + 1, b"hi")
            _query_wait(sock, fh, i + 1)
            sock.close()
        after = _counter(_scrape(mport), "brix_ssi_requests_total")
        assert after - before >= 3, f"requests {before}->{after}"

    def test_labels_are_low_cardinality(self, ssi_metrics_server):
        _, mport = ssi_metrics_server
        text = _scrape(mport)
        # the SSI counters must carry ONLY port/auth labels — no path/reqid/user.
        for name in ("brix_ssi_requests_total", "brix_ssi_errors_total",
                     "brix_ssi_alerts_pushed_total"):
            keys = _label_keys(text, name)
            assert keys <= {"port", "auth"}, f"{name} has labels {keys}"

    def test_metric_families_present(self, ssi_metrics_server):
        _, mport = ssi_metrics_server
        text = _scrape(mport)
        for name in ("brix_ssi_requests_total", "brix_ssi_errors_total",
                     "brix_ssi_alerts_pushed_total",
                     "brix_ssi_attn_push_failures_total"):
            assert f"# TYPE {name} counter" in text, f"missing {name}"
