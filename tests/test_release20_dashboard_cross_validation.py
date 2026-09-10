"""2.0 readiness F13 — the dashboard snapshot and ``/metrics`` agree.

Both read the same shared-memory slots, so after traffic quiesces the
snapshot's ``totals`` must equal the metrics sums exactly (success); a second
transfer moves both by the same amount, so the snapshot is real-time rather
than a cached view (realtime); and the snapshot is unreachable without the
login cookie while ``/metrics`` on the same server never needs one (security
negative — the boundary between the two surfaces is the cookie, not the port).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from _test_release20_metrics_helpers import scrape, total, value, wait_for, wait_port
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-r20-dash")]

PASSWORD = "r20-xval-secret"
BLOB = 512 * 1024


@pytest.fixture
def dash(lifecycle, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "blob.bin").write_bytes(os.urandom(BLOB))
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-r20-dash-xval", template="nginx_lc_r20_dash_xval.conf",
        protocol="http", data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST, "PASSWORD": PASSWORD},
        reason="2.0 readiness F13: dashboard + metrics over one stream export"))
    if not (wait_port(ep.port) and wait_port(ep.extra_ports["STREAM_PORT"])):
        pytest.skip("dashboard instance did not become ready")
    return ep


def _curl(*args):
    r = subprocess.run(["curl", "-s", *args], capture_output=True, timeout=15)
    assert r.returncode == 0, r.stderr.decode()
    return r.stdout


def _cookie(ep):
    out = _curl("-i", "-X", "POST", "--data", f"password={PASSWORD}",
                f"http://{HOST}:{ep.port}/brix/login").decode("latin1")
    m = re.search(r"(?im)^Set-Cookie:\s*(xrd_dashboard=[^;]+)", out)
    assert m, out
    return m.group(1)


def _snapshot(ep, cookie):
    out = _curl("-w", "\n%{http_code}", "-H", f"Cookie: {cookie}",
                f"http://{HOST}:{ep.port}/brix/api/v1/snapshot")
    body, status = out.rsplit(b"\n", 1)
    return int(status), (json.loads(body) if status == b"200" else None)


def _transfer(ep, tmp_path, tag):
    out = tmp_path / f"{tag}.bin"
    r = subprocess.run(["xrdcp", "-f", f"root://{HOST}:{ep.extra_ports['STREAM_PORT']}//blob.bin", str(out)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert out.stat().st_size == BLOB


def _quiesced(ep):
    body = scrape(ep.port)
    return body if total(body, "brix_connections_active") == 0.0 else None


def _metric_totals(body):
    return {
        "connections_total": total(body, "brix_connections_total"),
        "connections_active": total(body, "brix_connections_active"),
        "bytes_tx_total": total(body, "brix_bytes_tx_ipv4_total") + total(body, "brix_bytes_tx_ipv6_total"),
        "bytes_rx_total": total(body, "brix_bytes_rx_ipv4_total") + total(body, "brix_bytes_rx_ipv6_total"),
    }


def test_snapshot_totals_equal_the_metrics_sums(dash, tmp_path):
    _transfer(dash, tmp_path, "a")
    _transfer(dash, tmp_path, "b")
    body = wait_for(lambda: _quiesced(dash), 10)
    assert body is not None
    status, snap = _snapshot(dash, _cookie(dash))
    assert status == 200
    want = _metric_totals(body)
    assert want["connections_total"] >= 2
    assert want["bytes_tx_total"] >= 2 * BLOB
    for key, expected in want.items():
        assert snap["totals"][key] == expected, (key, snap["totals"][key], expected)


def test_snapshot_is_realtime_not_cached(dash, tmp_path):
    cookie = _cookie(dash)
    _transfer(dash, tmp_path, "a")
    assert wait_for(lambda: _quiesced(dash), 10) is not None
    _, first = _snapshot(dash, cookie)
    _transfer(dash, tmp_path, "b")
    body = wait_for(lambda: _quiesced(dash), 10)
    _, second = _snapshot(dash, cookie)
    assert second["totals"]["bytes_tx_total"] - first["totals"]["bytes_tx_total"] >= BLOB
    assert second["totals"]["connections_total"] == first["totals"]["connections_total"] + 1
    assert second["totals"]["bytes_tx_total"] == _metric_totals(body)["bytes_tx_total"]
    assert second["server_ms"] >= first["server_ms"]


def test_snapshot_needs_the_cookie_and_metrics_never_does(dash):
    status, snap = _snapshot(dash, "xrd_dashboard=not-a-session")
    assert status in (401, 403) and snap is None
    out = _curl("-w", "\n%{http_code}", f"http://{HOST}:{dash.port}/brix/api/v1/snapshot")
    assert out.rsplit(b"\n", 1)[1] in (b"401", b"403")
    assert value(scrape(dash.port), "brix_connections_total", port=str(dash.extra_ports["STREAM_PORT"])) is not None
