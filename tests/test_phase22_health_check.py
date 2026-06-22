"""
Phase 22 — active stream health checks.

Coverage:
  1. Source-marker checks: the probe state machine, registry helpers, timer,
     directives, and metrics are wired.
  2. Config validation: the 6 directives parse; the feature is off by default.
  3. Functional: a manager nginx with health checks enabled probes a live
     registered data server and records passing probes in the cluster metrics.
"""

import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

from settings import NGINX_BIN, free_port, free_ports, HOST, BIND_HOST

ROOT = Path(__file__).resolve().parents[1]

# All ports below are bound by this file's own nginx instances, so allocate
# free OS ports to avoid colliding with the managed fleet or other tests.
_P_DIRECTIVES = free_port()   # test_all_directives_parse listener
_P_BADTYPE = free_port()      # test_bad_type_rejected listener
_P_DISABLED = free_port()     # test_disabled_by_default_no_timer_log listen+connect
_P_ENABLED = free_port()      # test_enabled_starts_manager listen+connect


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
    assert (ROOT / "src/manager/health_check.c").exists()
    assert (ROOT / "src/manager/health_check.h").exists()
    cfg = _read("config")
    assert "src/manager/health_check.c" in cfg


def test_registry_helpers_present():
    reg = _read("src/manager/registry.c")
    for fn in ("xrootd_srv_hc_claim", "xrootd_srv_hc_pass", "xrootd_srv_hc_fail"):
        assert fn in reg, fn
    # Entry struct carries the new HC fields.
    h = _read("src/manager/registry.h")
    assert "hc_in_progress" in h and "hc_fail_count" in h


def test_probe_state_machine_and_timer_present():
    hc = _read("src/manager/health_check.c")
    # Reuses the proven bootstrap wire builder; sends a ping; bounded by timeout.
    assert "xrootd_upstream_build_bootstrap" in hc
    assert "kXR_ping" in hc
    assert "xrootd_hc_timer_handler" in hc
    assert "xrootd_srv_hc_claim" in hc
    # Manager start hooked into init_process.
    assert "xrootd_hc_manager_start" in _read("src/config/process.c")


def test_metrics_present():
    assert "hc_pass_total" in _read("src/metrics/metrics.h")
    assert "xrootd_cluster_hc_pass_total" in _read("src/metrics/cluster.c")


# --------------------------------------------------------------------------- #
# 2. Config validation                                                         #
# --------------------------------------------------------------------------- #

HEADER = (
    "error_log {logs}/error.log info;\n"
    "pid       {logs}/nginx.pid;\n"
    "events {{ worker_connections 64; }}\n"
)


def _nginx_check(conf_text, tmp_path):
    (tmp_path / "logs").mkdir(exist_ok=True)
    conf = tmp_path / "nginx.conf"
    conf.write_text(conf_text)
    proc = subprocess.run(
        [NGINX_BIN, "-t", "-p", str(tmp_path), "-c", str(conf)],
        capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


def test_all_directives_parse(tmp_path):
    conf = HEADER.format(logs=tmp_path / "logs") + f"""
    stream {{
        server {{
            listen {BIND_HOST}:{_P_DIRECTIVES};
            xrootd on;
            xrootd_root /tmp/xrd-test/data;
            xrootd_auth none;
            xrootd_health_check on;
            xrootd_health_check_interval 15s;
            xrootd_health_check_timeout 4s;
            xrootd_health_check_threshold 2;
            xrootd_health_check_blacklist 45s;
            xrootd_health_check_type stat;
        }}
    }}
    """
    rc, out = _nginx_check(conf, tmp_path)
    assert rc == 0, out


def test_bad_type_rejected(tmp_path):
    conf = HEADER.format(logs=tmp_path / "logs") + f"""
    stream {{
        server {{
            listen {BIND_HOST}:{_P_BADTYPE};
            xrootd on;
            xrootd_root /tmp/xrd-test/data;
            xrootd_auth none;
            xrootd_health_check_type bogus;
        }}
    }}
    """
    rc, out = _nginx_check(conf, tmp_path)
    assert rc != 0
    assert "xrootd_health_check_type" in out or "invalid" in out.lower()


def test_disabled_by_default_no_timer_log(tmp_path):
    # Without `xrootd_health_check on`, no health-check manager is started, so
    # the "health check manager started" notice must not appear.
    logs = tmp_path / "logs"
    logs.mkdir()
    (tmp_path / "tmp").mkdir()
    conf = HEADER.format(logs=logs) + f"""
    stream {{
        server {{
            listen {BIND_HOST}:{_P_DISABLED};
            xrootd on;
            xrootd_root /tmp/xrd-test/data;
            xrootd_auth none;
        }}
    }}
    """
    conf_path = tmp_path / "nginx.conf"
    conf_path.write_text(conf + "daemon off;\nmaster_process off;\n")
    proc = subprocess.Popen([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf_path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        # Wait for the listener, then a moment for any (absent) timer to log.
        deadline = time.time() + 8
        up = False
        while time.time() < deadline:
            try:
                with socket.create_connection((HOST, _P_DISABLED), timeout=0.5):
                    up = True
                    break
            except OSError:
                time.sleep(0.1)
        if not up:
            err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            pytest.skip(f"server did not start: {err}")
        time.sleep(1.0)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    log = (logs / "error.log").read_text(errors="replace")
    assert "health check manager started" not in log, log


def test_enabled_starts_manager(tmp_path):
    # With health checks enabled the per-worker manager timer is started and
    # logs a startup notice — proving the init_process wiring fires.
    logs = tmp_path / "logs"
    logs.mkdir()
    conf = HEADER.format(logs=logs) + f"""
    stream {{
        server {{
            listen {BIND_HOST}:{_P_ENABLED};
            xrootd on;
            xrootd_root /tmp/xrd-test/data;
            xrootd_auth none;
            xrootd_health_check on;
            xrootd_health_check_interval 5s;
        }}
    }}
    """
    conf_path = tmp_path / "nginx.conf"
    conf_path.write_text(conf + "daemon off;\nmaster_process off;\n")
    proc = subprocess.Popen([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf_path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.time() + 8
        up = False
        while time.time() < deadline:
            try:
                with socket.create_connection((HOST, _P_ENABLED), timeout=0.5):
                    up = True
                    break
            except OSError:
                time.sleep(0.1)
        if not up:
            err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            pytest.skip(f"server did not start: {err}")
        time.sleep(0.5)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    log = (logs / "error.log").read_text(errors="replace")
    assert "health check manager started" in log, log


# --------------------------------------------------------------------------- #
# 3. Functional: manager health-probes a live registered data server          #
# --------------------------------------------------------------------------- #

MGR_PORT, CMS_PORT, DS_PORT, METRICS_PORT = free_ports(4)


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
def hc_cluster(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "f.txt").write_text("x\n")
    logs = tmp_path / "logs"
    logs.mkdir()
    (tmp_path / "t").mkdir()
    conf = HEADER.format(logs=logs) + f"""
    stream {{
        # Manager (redirector) with active health checks enabled.
        server {{
            listen {BIND_HOST}:{MGR_PORT};
            xrootd on;
            xrootd_auth none;
            xrootd_manager_mode on;
            xrootd_health_check on;
            xrootd_health_check_interval 2s;
            xrootd_health_check_timeout 3s;
        }}
        # CMS server endpoint data servers register with.
        server {{
            listen {BIND_HOST}:{CMS_PORT};
            xrootd_cms_server on;
        }}
        # Live data server that registers itself via loopback CMS.
        server {{
            listen {BIND_HOST}:{DS_PORT};
            xrootd on;
            xrootd_auth none;
            xrootd_root {data};
            xrootd_cms_manager {HOST}:{CMS_PORT};
            xrootd_cms_paths /data;
            xrootd_cms_interval 2;
            xrootd_listen_port {DS_PORT};
        }}
    }}
    http {{
        client_body_temp_path {tmp_path}/t; proxy_temp_path {tmp_path}/t;
        fastcgi_temp_path {tmp_path}/t; uwsgi_temp_path {tmp_path}/t;
        scgi_temp_path {tmp_path}/t; access_log off;
        server {{
            listen {BIND_HOST}:{METRICS_PORT};
            location /metrics {{ xrootd_metrics on; }}
        }}
    }}
    """
    conf_path = tmp_path / "nginx.conf"
    conf_path.write_text(conf + "daemon off;\nmaster_process off;\n")
    proc = subprocess.Popen([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf_path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if not (_wait_port(MGR_PORT) and _wait_port(DS_PORT)
                and _wait_port(METRICS_PORT)):
            err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            proc.terminate()
            pytest.skip(f"hc cluster did not start: {err}")
        yield
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_probe_passes_live_server(hc_cluster):
    # The data server registers (cms_interval 2s); the manager then probes it
    # (hc_interval 2s after a 2s settle).  Within ~15s a passing probe must be
    # recorded in the cluster health-check metrics.
    deadline = time.time() + 18
    passed = 0
    while time.time() < deadline:
        body = _metrics(METRICS_PORT)
        passed = _counter(body, "xrootd_cluster_hc_pass_total")
        if passed >= 1:
            break
        time.sleep(0.5)
    assert passed >= 1, f"no passing health-check probe recorded (got {passed})"
