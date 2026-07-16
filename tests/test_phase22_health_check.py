"""
Phase 22 — active stream health checks.

Coverage:
  1. Source-marker checks: the probe state machine, registry helpers, timer,
     directives, and metrics are wired.
  2. Config validation: the 6 directives parse; the feature is off by default.
  3. Functional: a manager nginx with health checks enabled probes a live
     registered data server and records passing probes in the cluster metrics.

Registry-backed: every nginx here is a throwaway instance provisioned through
the `lifecycle` harness (templates nginx_hc_parse.conf / nginx_hc_toggle.conf /
nginx_hc_cluster.conf) — no direct NGINX_BIN subprocess management.
"""

import os
import socket
import time
from pathlib import Path

import pytest

import settings
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST

pytestmark = pytest.mark.uses_lifecycle_harness

ROOT = Path(__file__).resolve().parents[1]


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

def test_health_check_module_present():
    assert (ROOT / "src/net/manager/health_check.c").exists()
    assert (ROOT / "src/net/manager/health_check.h").exists()
    cfg = _read("config")
    assert "src/net/manager/health_check.c" in cfg


def test_registry_helpers_present():
    reg = _read("src/net/manager/registry_health.c")   # split out of registry.c
    for fn in ("brix_srv_hc_claim", "brix_srv_hc_pass", "brix_srv_hc_fail"):
        assert fn in reg, fn
    # Entry struct carries the new HC fields.
    h = _read("src/net/manager/registry.h")
    assert "hc_in_progress" in h and "hc_fail_count" in h


def test_probe_state_machine_and_timer_present():
    hc = _read("src/net/manager/health_check.c")
    # Reuses the proven bootstrap wire builder; sends a ping; bounded by timeout.
    assert "brix_upstream_build_bootstrap" in hc
    assert "kXR_ping" in hc
    assert "brix_hc_timer_handler" in hc
    assert "brix_srv_hc_claim" in hc
    # Manager start hooked into init_process.  phase-79 split: the per-server
    # init half of process.c moved into process_server_init.c.
    assert "brix_hc_manager_start" in _read("src/core/config/process_server_init.c")


def test_metrics_present():
    assert "hc_pass_total" in _read("src/observability/metrics/metrics.h")
    assert "brix_cluster_hc_pass_total" in _read("src/observability/metrics/cluster.c")


# --------------------------------------------------------------------------- #
# 2. Config validation                                                         #
# --------------------------------------------------------------------------- #

def test_all_directives_parse(lifecycle):
    lifecycle.register(NginxInstanceSpec(
        name="lc-hc-parse",
        template="nginx_hc_parse.conf",
        template_values={"BIND_HOST": BIND_HOST, "HC_TYPE": "stat"},
        reason="health-check directive parse coverage",
    ))
    lifecycle.reconfigure("lc-hc-parse")
    lifecycle.nginx_test("lc-hc-parse")  # raises on parse failure


def test_bad_type_rejected(lifecycle, tmp_path):
    # expect_config_failure renders from template_values only, so all
    # placeholders (including the launcher-provided ones) are passed here.
    (port,) = settings.free_ports(1)
    result = lifecycle.expect_config_failure(NginxInstanceSpec(
        name="lc-hc-badtype",
        template="nginx_hc_parse.conf",
        template_values={
            "BIND_HOST": BIND_HOST,
            "HC_TYPE": "bogus",
            "PORT": port,
            "DATA_ROOT": str(tmp_path / "data"),
            "LOG_DIR": str(tmp_path),
        },
        reason="health-check bad-type rejection coverage",
    ))
    out = (result.stdout or "") + (result.stderr or "")
    assert result.returncode != 0
    assert "brix_health_check_type" in out or "invalid" in out.lower()


def _toggle_instance(lifecycle, name, hc_knobs):
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_hc_toggle.conf",
        template_values={"BIND_HOST": BIND_HOST, "HC_KNOBS": hc_knobs},
        reason="health-check manager init_process wiring coverage",
    ))
    return os.path.join(endpoint.prefix, "logs", "error.log")


def test_disabled_by_default_no_timer_log(lifecycle):
    # Without `brix_health_check on`, no health-check manager is started, so
    # the "health check manager started" notice must not appear.
    elog = _toggle_instance(lifecycle, "lc-hc-off", "")
    time.sleep(1.0)  # a moment for any (absent) timer to log
    log = Path(elog).read_text(errors="replace")
    assert "health check manager started" not in log, log


def test_enabled_starts_manager(lifecycle):
    # With health checks enabled the per-worker manager timer is started and
    # logs a startup notice — proving the init_process wiring fires.
    elog = _toggle_instance(
        lifecycle, "lc-hc-on",
        "        brix_health_check on;\n"
        "        brix_health_check_interval 5s;\n",
    )
    deadline = time.time() + 8
    while time.time() < deadline:
        log = Path(elog).read_text(errors="replace")
        if "health check manager started" in log:
            return
        time.sleep(0.2)
    assert "health check manager started" in log, log


# --------------------------------------------------------------------------- #
# 3. Functional: manager health-probes a live registered data server          #
# --------------------------------------------------------------------------- #

def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _metrics(port):
    with socket.create_connection((HOST, port), timeout=3) as s:
        s.sendall(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            c = s.recv(8192)
            if not c:
                break
            data += c
    return data.decode(errors="replace")


def _counter(body, name):
    for line in body.splitlines():
        if line.startswith(name + " "):
            try:
                return int(float(line.split()[1]))
            except (ValueError, IndexError):
                return 0
    return 0


@pytest.fixture
def hc_cluster(lifecycle, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "f.txt").write_text("x\n")
    cms_port, ds_port, metrics_port = settings.free_ports(3)
    lifecycle.start(NginxInstanceSpec(
        name="lc-hc-cluster",
        template="nginx_hc_cluster.conf",
        data_root=str(data),
        extra_ports={"CMS_PORT": cms_port, "DS_PORT": ds_port,
                     "METRICS_PORT": metrics_port},
        template_values={"BIND_HOST": BIND_HOST, "HOST": HOST},
        reason="manager + CMS + data server health-probe cluster",
    ))
    if not (_wait_port(ds_port) and _wait_port(metrics_port)):
        pytest.skip("hc cluster did not become fully ready")
    yield metrics_port


def test_probe_passes_live_server(hc_cluster):
    # The data server registers (cms_interval 2s); the manager then probes it
    # (hc_interval 2s after a 2s settle).  Within ~15s a passing probe must be
    # recorded in the cluster health-check metrics.
    metrics_port = hc_cluster
    deadline = time.time() + 18
    passed = 0
    while time.time() < deadline:
        body = _metrics(metrics_port)
        passed = _counter(body, "brix_cluster_hc_pass_total")
        if passed >= 1:
            break
        time.sleep(0.5)
    assert passed >= 1, f"no passing health-check probe recorded (got {passed})"
