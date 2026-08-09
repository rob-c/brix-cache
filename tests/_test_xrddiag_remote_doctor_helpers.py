"""
xrddiag remote-doctor (phase-37 §15.8): network transfer-problem diagnostician.

`xrddiag remote-doctor <url> [url2 ...]` interrogates one endpoint — or every hop
of a transfer path (client→redirector→data-server, or a TPC src+dst pair) — and
root-causes why a transfer is slow or failing. For each endpoint it gathers the
connect-phase breakdown, kernel TCP facts (family / RTT / retransmits), TLS+auth
posture, a live throughput probe, the holder/replica view, and server-reported
load (/metrics), then runs a cross-endpoint diff engine (TLS-downgrade,
auth-fallback, cwnd-limited, retrans-surge, v4/v6-asymmetry, …) and emits a
green/yellow/red report. `--json` emits a machine-readable form.

Pure composition of the public libbrix API — no new wire, no libcurl, no OpenSSL.
PII-free by construction: families / microseconds / counts / hex caps only — never
a resolved IP, a path, or a credential.

Self-contained: each test self-hosts its own anon nginx on a free loopback port
(the shared fleet churns up/down under concurrent work), so it never depends on a
running fleet. Runs serial.

Run:
    PYTHONPATH=tests pytest tests/test_xrddiag_remote_doctor.py -v -p no:xdist
"""

import json
import os
import re
import shutil
import socket
import subprocess
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import HOST, BIND_HOST6, HOST6, url_host
from fleet_lifecycle_ports import lifecycle_ports_for

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-rdoctor")]

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDDIAG = os.path.join(CLIENT_DIR, "bin", "xrddiag")

# Clean env: no X509 / no token so anon stays anon and no credential is in scope.
_CLEAN_ENV = {k: v for k, v in os.environ.items()}
for _k in ("X509_USER_PROXY", "X509_CERT_DIR", "BEARER_TOKEN", "BEARER_TOKEN_FILE"):
    _CLEAN_ENV.pop(_k, None)


def _port_up(host, port, family=socket.AF_INET):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((host, port))
        return True
    except OSError:
        return False


def _have_ipv6_loopback():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind((BIND_HOST6, 0))
        s.close()
        return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def doctor():
    """Build xrddiag once; skip cleanly without a compiler / nginx."""
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrddiag"],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(XRDDIAG):
        pytest.skip(f"xrddiag build failed:\n{proc.stdout}\n{proc.stderr}")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    return XRDDIAG


@pytest.fixture
def anon(lifecycle, doctor, tmp_path_factory):
    """A single anon server bound on v4 (and v6 ::1 when available, on the same
    port) so the v4/v6-asymmetry detector can be exercised."""
    data = tmp_path_factory.mktemp("rdoctor") / "data"
    data.mkdir()
    (data / "big.bin").write_bytes(os.urandom(4 * 1024 * 1024))
    (data / "small.txt").write_bytes(b"hello\n")
    # Fix the port up front (from the lifecycle ledger — the same fixed number
    # LifecycleHarness.register will assign) so the ::1 listen shares it with the
    # v4 listen instead of a divergent dynamic port.
    port, _ = lifecycle_ports_for("lc-rdoctor-anon")
    v6 = _have_ipv6_loopback()
    v6_listen = f"listen [{BIND_HOST6}]:{port};" if v6 else ""
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-rdoctor-anon",
        template="nginx_xrddiag_remote_doctor_anon.conf",
        port=port,
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"V6_LISTEN": v6_listen},
        reason="Anon root:// on v4 (+::1 same port) for the remote-doctor battery.",  # net-literal-allow: IPv6 loopback spec reason text
    ))
    yield {"port": ep.port, "v6": v6}


def _run(*args, timeout=60):
    return subprocess.run([XRDDIAG, *args], capture_output=True, text=True,
                          env=_CLEAN_ENV, timeout=timeout)


# --------------------------------------------------------------------------
# (1) success — single anon endpoint → green, populated facts, exit 0
# --------------------------------------------------------------------------

def _start_stream(lifecycle, name, data, writable):
    """Start an anon stream server; writable adds allow_write. Returns endpoint."""
    return lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_xrddiag_remote_doctor_stream.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"ALLOW_WRITE_LINE":
                         "brix_allow_write on;" if writable else ""},
        reason="Anon root:// export for active remote-doctor diagnosis probes.",
    ))


@pytest.fixture
def rw_server(lifecycle, doctor, tmp_path_factory):
    """A writable (allow_write on) anon export — the write probe must go green."""
    data = tmp_path_factory.mktemp("rdoctor_rw") / "data"
    data.mkdir()
    (data / "f.bin").write_bytes(os.urandom(256 * 1024))
    ep = _start_stream(lifecycle, "lc-rdoctor-rw", data, writable=True)
    yield {"port": ep.port, "data": data}


@pytest.fixture
def empty_server(lifecycle, doctor, tmp_path_factory):
    """A readable but empty export root — the namespace probe must warn."""
    data = tmp_path_factory.mktemp("rdoctor_empty") / "data"
    data.mkdir()
    ep = _start_stream(lifecycle, "lc-rdoctor-empty", data, writable=False)
    yield {"port": ep.port}


def _diagnosis(blob):
    """Pull the diagnosis array out of a --json run as {probe: verdict}."""
    doc = json.loads(blob)["remote_doctor"]
    return {d["probe"]: d for d in doc["endpoints"][0]["diagnosis"]}



def _authsuite_diag(blob):
    doc = json.loads(blob)["remote_doctor"]
    return {d["probe"]: d for d in doc["endpoints"][0]["diagnosis"]}


@pytest.fixture
def sss_server(lifecycle, doctor, tmp_path_factory):
    """An auth-REQUIRED (SSS) server — used to prove anonymous access is denied."""
    if subprocess.run(["make", "-C", CLIENT_DIR, "xrdsssadmin-brix"],
                      capture_output=True).returncode != 0 or not os.path.exists(_SSSADMIN):
        pytest.skip("xrdsssadmin build failed")
    root = tmp_path_factory.mktemp("rd_sss")
    data = root / "data"
    data.mkdir()
    (data / "probe.txt").write_bytes(b"hi\n")
    kt = str(root / "srv.keytab")
    r = subprocess.run([_SSSADMIN, "-k", kt, "add", "--id", "1", "--user",
                        "anybody", "--group", "anygroup", "--name", "testhost"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"xrdsssadmin add failed: {r.stdout}{r.stderr}")
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-rdoctor-sss",
        template="nginx_xrddiag_remote_doctor_sss.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"KEYTAB": kt},
        reason="SSS-required root:// for the anon-access-denied auth-suite probe.",
    ))
    yield {"port": ep.port, "keytab": kt}


@pytest.fixture(scope="module")
def token_issuer():
    try:
        import sys
        sys.path.insert(0, REPO)
        from utils.make_token import TokenIssuer
    except Exception as exc:                       # noqa: BLE001
        pytest.skip(f"make_token unavailable: {exc}")
    import tempfile
    tdir = tempfile.mkdtemp(prefix="rd_tok_")
    ti = TokenIssuer(tdir)
    ti.init_keys()
    return ti


@pytest.fixture
def token_server(lifecycle, doctor, token_issuer, tmp_path_factory):
    """A bearer-token server (RSA JWKS) — used for forged/expired/scope probes."""
    data = tmp_path_factory.mktemp("rd_tok") / "data"
    data.mkdir()
    (data / "probe.txt").write_bytes(b"hi\n")
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-rdoctor-token",
        template="nginx_xrddiag_remote_doctor_token.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"JWKS_PATH": token_issuer.jwks_path,
                         "ISSUER": token_issuer.issuer,
                         "AUDIENCE": token_issuer.audience},
        reason="Bearer-token root:// (RSA JWKS) for the auth-suite forged/expired/scope probes.",
    ))
    yield {"port": ep.port, "issuer": token_issuer}
