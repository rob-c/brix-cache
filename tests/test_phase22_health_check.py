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

from config_parse import nginx_t
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT

# Bucket-2 lifecycle subjects: all health-check instances here take fixed
# exclusive-band ports from the ledger (fleet_lifecycle_ports) and the whole
# module serialises under one xdist_group so those ports never have two
# concurrent drivers.  The two parse tests boot nothing (standalone `nginx_t`).
pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-hc")]

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
    # Accept-case parse: register + `nginx -t` (never starts).  Uses the harness
    # so the prefix (logs/ + export dir) exists for brix_export's accessibility
    # check; the fixed port comes from the ledger ("lc-hc-parse").
    lifecycle.register(NginxInstanceSpec(
        name="lc-hc-parse",
        template="nginx_hc_parse.conf",
        template_values={"BIND_HOST": BIND_HOST, "HC_TYPE": "stat"},
        reason="health-check directive parse coverage",
    ))
    lifecycle.reconfigure("lc-hc-parse")
    lifecycle.nginx_test("lc-hc-parse")  # raises on parse failure


def test_bad_type_rejected(tmp_path):
    # Pure config-parse property: render + `nginx -t`, no server ever boots.
    result = nginx_t(
        "nginx_hc_parse.conf",
        tmp_path,
        BIND_HOST=BIND_HOST,
        HC_TYPE="bogus",
        PORT=PARSE_PLACEHOLDER_PORT,
        DATA_ROOT=str(tmp_path / "data"),
        LOG_DIR=str(tmp_path),
    )
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
    # cms/ds/metrics secondary listens come from the fixed ledger by name.
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-hc-cluster",
        template="nginx_hc_cluster.conf",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST, "HOST": HOST},
        reason="manager + CMS + data server health-probe cluster",
    ))
    ds_port = ep.extra_ports["DS_PORT"]
    metrics_port = ep.extra_ports["METRICS_PORT"]
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


# --------------------------------------------------------------------------- #
# 4. Step F: TLS-upgraded deep probes against a kXR_gotoTLS data server       #
# --------------------------------------------------------------------------- #

import shutil
import subprocess


def _make_pki(base):
    """One CA + a host cert signed by it + a second UNRELATED CA (for the
    verification-failure leg).  Returns a dict of paths."""
    import socket as _socket
    fqdn = _socket.getfqdn()
    ca, certs, srv, evil = (base / d for d in ("ca", "certs", "srv", "evil"))
    for d in (ca, certs, srv, evil):
        d.mkdir(parents=True, exist_ok=True)

    def osl(*a):
        r = subprocess.run(["openssl", *a], capture_output=True, text=True,
                           timeout=60)
        assert r.returncode == 0, f"openssl {a}: {r.stderr}"
        return r.stdout

    osl("req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
        "-subj", "/O=HcTlsTest/CN=HcTlsTest CA",
        "-keyout", str(ca / "ca.key"), "-out", str(ca / "ca.pem"))
    chash = osl("x509", "-in", str(ca / "ca.pem"), "-noout", "-hash").strip()
    shutil.copy(ca / "ca.pem", certs / f"{chash}.0")

    csr = base / "host.csr"
    osl("req", "-nodes", "-newkey", "rsa:2048",
        "-subj", f"/O=HcTlsTest/CN={fqdn}",
        "-keyout", str(srv / "hostkey.pem"), "-out", str(csr))
    osl("x509", "-req", "-in", str(csr), "-CA", str(ca / "ca.pem"),
        "-CAkey", str(ca / "ca.key"), "-CAcreateserial", "-days", "1",
        "-out", str(srv / "hostcert.pem"))

    # A CA that did NOT sign the host cert — trusting it must fail the probe.
    osl("req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
        "-subj", "/O=HcTlsTest/CN=Unrelated CA",
        "-keyout", str(evil / "ca.key"), "-out", str(evil / "ca.pem"))

    return {"ca_pem": str(ca / "ca.pem"), "ca_dir": str(certs),
            "cert": str(srv / "hostcert.pem"), "key": str(srv / "hostkey.pem"),
            "evil_ca_pem": str(evil / "ca.pem"), "fqdn": fqdn}


def _tls_cluster(lifecycle, tmp_path, name, mgr_tls_knobs, pki):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (data / "f.txt").write_text("x\n")
    # cms/ds/metrics secondary listens come from the fixed ledger by name.
    ep = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_hc_tls_cluster.conf",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST, "HOST": HOST,
                         "MGR_TLS_KNOBS": mgr_tls_knobs,
                         "CERT_FILE": pki["cert"], "KEY_FILE": pki["key"],
                         "CA_DIR": pki["ca_dir"]},
        reason="Step F TLS deep-probe cluster (gotoTLS data server)",
    ))
    ds_port = ep.extra_ports["DS_PORT"]
    metrics_port = ep.extra_ports["METRICS_PORT"]
    if not (_wait_port(ds_port) and _wait_port(metrics_port)):
        pytest.skip("hc TLS cluster did not become fully ready")
    return metrics_port


def _await_counter(metrics_port, name, timeout=20):
    deadline = time.time() + timeout
    val = 0
    while time.time() < deadline:
        val = _counter(_metrics(metrics_port), name)
        if val >= 1:
            break
        time.sleep(0.5)
    return val


@pytest.fixture(scope="module")
def hc_pki(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("openssl not installed")
    return _make_pki(tmp_path_factory.mktemp("hcpki"))


def test_tls_deep_probe_passes(lifecycle, tmp_path, hc_pki):
    """Success: manager trusts the DS's CA -> the probe upgrades on
    kXR_gotoTLS, re-logins over TLS, and the full-depth ping PASSES."""
    knobs = ("        brix_upstream_tls on;\n"
             f"        brix_upstream_tls_ca {hc_pki['ca_pem']};\n"
             f"        brix_upstream_tls_name {hc_pki['fqdn']};\n")
    mp = _tls_cluster(lifecycle, tmp_path, "lc-hc-tls-deep", knobs, hc_pki)
    passed = _await_counter(mp, "brix_cluster_hc_pass_total")
    assert passed >= 1, "TLS-upgraded deep probe never passed"
    failed = _counter(_metrics(mp), "brix_cluster_hc_fail_total")
    assert failed == 0, f"deep probe recorded failures: {failed}"


def test_tls_untrusted_ca_probe_fails(lifecycle, tmp_path, hc_pki):
    """Security-negative: the manager trusts a CA that did NOT sign the DS
    cert -> the TLS handshake/verify fails and the probe records a FAILURE
    (never a shallow pass — a TLS-demanding server we can't verify is down)."""
    knobs = ("        brix_upstream_tls on;\n"
             f"        brix_upstream_tls_ca {hc_pki['evil_ca_pem']};\n"
             f"        brix_upstream_tls_name {hc_pki['fqdn']};\n")
    mp = _tls_cluster(lifecycle, tmp_path, "lc-hc-tls-badca", knobs, hc_pki)
    failed = _await_counter(mp, "brix_cluster_hc_fail_total")
    assert failed >= 1, "untrusted-CA probe never recorded a failure"
    passed = _counter(_metrics(mp), "brix_cluster_hc_pass_total")
    assert passed == 0, f"untrusted-CA probe must not pass (got {passed})"


def test_tls_no_upstream_ctx_shallow_alive(lifecycle, tmp_path, hc_pki):
    """Compat: without brix_upstream_tls the pre-Step-F behavior is kept —
    a gotoTLS answer at the protocol stage counts as alive (shallow pass),
    so fleets without outbound-TLS config see no behavior change."""
    mp = _tls_cluster(lifecycle, tmp_path, "lc-hc-tls-shallow", "", hc_pki)
    passed = _await_counter(mp, "brix_cluster_hc_pass_total")
    assert passed >= 1, "shallow gotoTLS-alive fallback regressed"
    failed = _counter(_metrics(mp), "brix_cluster_hc_fail_total")
    assert failed == 0, f"shallow fallback recorded failures: {failed}"

