"""
xrddiag tpc-egress — TPC egress (SSRF-control) self-test.

`xrddiag tpc-egress <your-gateway-url> --tpc-target host[:port]` points at your
OWN root:// gateway and asks it to originate a third-party-copy *pull* from the
named source. In the TPC-pull model the destination (your gateway) is the party
that dials the source host, so this is exactly the SSRF surface an attacker
abuses. The self-test reports whether the gateway REFUSES to originate (the safe
outcome a source-egress guard produces) or PERMITS it — and when permitted,
distinguishes conn-refused (source port closed) from filtered/timeout.

Coverage here proves the tool reads a live gateway's egress decision correctly:
  * a default-policy gateway REFUSES a loopback source (the built-in
    allow_local=off address-range gate fires) → verdict REFUSED (policy), exit 0;
  * an allow_local=on gateway PERMITS the pull; a closed loopback port yields
    conn-refused → egress_permitted, exit 3;
  * the report is PII-free and the JSON form is well shaped.

The refusal path here is driven by the pre-existing address-range SSRF gate; the
phase-93 host-allowlist guard (brix_tpc_source_guard) produces the same verdict
and is covered in test_tpc_source_egress_guard.py.

Self-hosted via the lifecycle harness (TPC needs thread_pool + allow_write), so
it never depends on the shared fleet. Runs serial.

Run:
    PYTHONPATH=tests pytest tests/test_xrddiag_tpc_egress.py -v -p no:xdist
"""

import json
import os
import shutil
import socket
import subprocess

import pytest

from server_registry import NginxInstanceSpec
from settings import HOST

def _guard_doctor_1():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")

def _guard_doctor_2(proc):
    if proc.returncode != 0 or not os.path.exists(XRDDIAG):
        pytest.skip(f"xrddiag build failed:\n{proc.stdout}\n{proc.stderr}")

def _guard_doctor_3():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")


pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-tpcegress")]

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDDIAG = os.path.join(CLIENT_DIR, "bin", "xrddiag")

_CLEAN_ENV = {k: v for k, v in os.environ.items()}
for _k in ("X509_USER_PROXY", "X509_CERT_DIR", "BEARER_TOKEN", "BEARER_TOKEN_FILE"):
    _CLEAN_ENV.pop(_k, None)


def _closed_loopback_port():
    """A loopback port with nothing listening: bind, read the number, close."""
    from ephemeral_port import free_port
    return free_port(HOST)


@pytest.fixture(scope="module")
def doctor():
    _guard_doctor_1()
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrddiag"],
                          capture_output=True, text=True, timeout=180)
    _guard_doctor_2(proc)
    _guard_doctor_3()
    return XRDDIAG


def _gateway(lifecycle, tmp_path_factory, name, allow_local):
    data = tmp_path_factory.mktemp(name) / "data"
    data.mkdir()
    (data / "seed.bin").write_bytes(b"x" * 4096)
    line = "brix_tpc_allow_local on;" if allow_local else ""
    ep = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_xrddiag_tpc_egress.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"TPC_ALLOW_LOCAL": line},
        reason="TPC-capable gateway for the tpc-egress SSRF-control self-test.",
    ))
    return ep.port


@pytest.fixture
def gw_default(lifecycle, doctor, tmp_path_factory):
    """Default SSRF policy: allow_local=off → a loopback source is prohibited."""
    return _gateway(lifecycle, tmp_path_factory, "lc-tpceg-default", False)


@pytest.fixture
def gw_allow_local(lifecycle, doctor, tmp_path_factory):
    """allow_local=on → the gateway will originate a pull to a loopback source."""
    return _gateway(lifecycle, tmp_path_factory, "lc-tpceg-local", True)


def _run(*args, timeout=60):
    return subprocess.run([XRDDIAG, "tpc-egress", *args], capture_output=True,
                          text=True, env=_CLEAN_ENV, timeout=timeout)


# --------------------------------------------------------------------------
# (security-positive) a guarded gateway REFUSES egress to a loopback source
# --------------------------------------------------------------------------

def test_egress_refused_by_policy(gw_default):
    port = gw_default
    target = f"{HOST}:{_closed_loopback_port()}"
    p = _run(f"root://{HOST}:{port}//probe.tmp", "--tpc-target", target,
             "--probe-timeout", "3000")
    assert p.returncode == 0, f"expected exit 0 (refused):\n{p.stdout}\n{p.stderr}"
    assert "[GREEN]" in p.stdout, p.stdout
    assert "REFUSED (policy)" in p.stdout, p.stdout


def test_egress_refused_json(gw_default):
    port = gw_default
    target = f"{HOST}:{_closed_loopback_port()}"
    p = _run(f"root://{HOST}:{port}//probe.tmp", "--tpc-target", target,
             "--json", "--probe-timeout", "3000")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    doc = json.loads(p.stdout)["tpc_egress"]
    assert doc["egress_permitted"] is False, doc
    assert "REFUSED" in doc["verdict"], doc
    for k in ("verdict", "egress_permitted", "gateway", "target", "detail",
              "arm_kxr", "trig_kxr", "arm_ms", "trig_ms"):
        assert k in doc, doc


# --------------------------------------------------------------------------
# (success) an unguarded gateway PERMITS egress; a closed port → conn-refused
# --------------------------------------------------------------------------

def test_egress_permitted_conn_refused(gw_allow_local):
    port = gw_allow_local
    target = f"{HOST}:{_closed_loopback_port()}"
    p = _run(f"root://{HOST}:{port}//probe.tmp", "--tpc-target", target,
             "--probe-timeout", "4000")
    assert p.returncode == 3, f"expected exit 3 (permitted):\n{p.stdout}\n{p.stderr}"
    assert "[RED]" in p.stdout, p.stdout
    assert "PERMITTED" in p.stdout, p.stdout
    # a closed loopback port answers with a reset, not a timeout
    assert "conn-refused" in p.stdout.lower() or "refused" in p.stdout.lower(), p.stdout
    assert "RISK" in p.stdout, p.stdout


def test_egress_permitted_json_shape(gw_allow_local):
    port = gw_allow_local
    target = f"{HOST}:{_closed_loopback_port()}"
    p = _run(f"root://{HOST}:{port}//probe.tmp", "--tpc-target", target,
             "--json", "--probe-timeout", "4000")
    assert p.returncode == 3, f"{p.stdout}\n{p.stderr}"
    doc = json.loads(p.stdout)["tpc_egress"]
    assert doc["egress_permitted"] is True, doc
    assert doc["arm_ms"] >= 0 and doc["trig_ms"] >= 0, doc


# --------------------------------------------------------------------------
# (error / usage / PII)
# --------------------------------------------------------------------------

def test_missing_target_is_usage_error(gw_default):
    port = gw_default
    p = _run(f"root://{HOST}:{port}//probe.tmp")
    assert p.returncode == 50, p.stdout + p.stderr
    assert "usage:" in p.stderr, p.stderr


def test_report_pii_free(gw_allow_local):
    """The report must carry no path body, token, or secret — only the verdict,
    the operator-named target, kXR codes and milliseconds."""
    port = gw_allow_local
    target = f"{HOST}:{_closed_loopback_port()}"
    p = _run(f"root://{HOST}:{port}//probe.tmp", "--tpc-target", target,
             "--json", "--probe-timeout", "4000")
    blob = p.stdout
    for leak in ("/tmp/", "BEARER", "PRIVATE", "subject=", "seed.bin",
                 ".brix-egress-selftest"):
        assert leak not in blob, f"PII/secret leaked: {leak} in {blob}"
