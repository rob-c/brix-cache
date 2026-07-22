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

def test_single_endpoint_green(anon):
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    out = p.stdout
    assert "[GREEN]" in out, out
    # populated facts: connect phases, family, TCP_INFO, throughput, holders
    assert "connect: tcp" in out and "login+auth" in out, out
    assert "IPv4" in out or "IPv6" in out, out
    assert "rtt=" in out, out
    assert "MB/s" in out, out
    assert "holders=" in out, out
    assert "worst=GREEN" in out, out


def test_single_endpoint_json(anon):
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    doc = json.loads(p.stdout)["remote_doctor"]
    assert "endpoints" in doc and "cross_endpoint_analysis" in doc, p.stdout
    ep = doc["endpoints"][0]
    assert ep["status"] == "GREEN" and ep["connected"] is True, ep
    f = ep["facts"]
    for k in ("family", "tcp_ms", "tls_ms", "auth_ms", "rtt_us", "mbps", "holders"):
        assert k in f, f
    assert f["holders"] >= 1, f


# --------------------------------------------------------------------------
# (2) multi-endpoint — both hops present + cross-endpoint analysis;
#     a contrived v4-vs-v6 pair fires the asymmetry detector
# --------------------------------------------------------------------------

def test_multi_endpoint_path(anon):
    port = anon["port"]
    p = _run("remote-doctor",
             f"root://{HOST}:{port}//big.bin",
             f"root://{HOST}:{port}//small.txt",
             "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    doc = json.loads(p.stdout)["remote_doctor"]
    assert len(doc["endpoints"]) == 2, doc
    assert doc["cross_endpoint_analysis"]["hops"] == 1, doc
    # a tiny second file must NOT false-positive the cwnd/low-throughput detector
    assert all(e["status"] in ("GREEN", "YELLOW") for e in doc["endpoints"]), doc


def test_v4_v6_asymmetry_detector(anon):
    if not anon["v6"]:
        pytest.skip("no IPv6 loopback on this host")
    port = anon["port"]
    if not _port_up(HOST6, port, family=socket.AF_INET6):
        pytest.skip("server not reachable over ::1")  # net-literal-allow: IPv6 loopback reachability skip message
    p = _run("remote-doctor",
             f"root://{HOST}:{port}//big.bin",
             f"root://{url_host(HOST6)}:{port}//big.bin",
             "--metrics-port", "0", "--probe-timeout", "8000")
    # both hops connect; the family differs → the asymmetry detector must fire
    assert "address-family asymmetry" in p.stdout, p.stdout


# --------------------------------------------------------------------------
# (3) adversarial / error — reachable + unreachable → dead hop red, no hang
# --------------------------------------------------------------------------

def test_dead_hop_red_no_hang(anon):
    port = anon["port"]
    started = time.monotonic()
    p = _run("remote-doctor",
             f"root://{HOST}:{port}//big.bin",
             f"root://{HOST}:1",            # nothing listens on port 1
             "--metrics-port", "0", "--probe-timeout", "2000", timeout=30)
    elapsed = time.monotonic() - started
    assert p.returncode != 0, f"expected nonzero on a dead hop:\n{p.stdout}"
    assert "[RED]" in p.stdout, p.stdout
    assert "connect failed" in p.stdout, p.stdout
    # bounded: the per-endpoint timeout means it can never hang the suite
    assert elapsed < 25, f"remote-doctor took too long ({elapsed:.1f}s) — not bounded"


def test_unparseable_url_clean(anon):
    p = _run("remote-doctor", "::::not-a-url::::",
             "--metrics-port", "0", "--probe-timeout", "2000")
    assert p.returncode != 0, p.stdout
    assert "[RED]" in p.stdout or "unparseable" in (p.stdout + p.stderr), \
        f"{p.stdout}\n{p.stderr}"


# --------------------------------------------------------------------------
# security-neg / PII — facts/JSON leak no path, token, or cert subject
# --------------------------------------------------------------------------

def test_remote_doctor_pii_free(anon):
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode == 0, p.stderr
    blob = p.stdout
    # the probed file path must never appear; nor any credential material.
    for leak in ("big.bin", "BEARER", "x509", "/etc/", "PRIVATE", "subject="):
        assert leak not in blob, f"PII/secret leaked: {leak} in {blob}"
    # facts carry only families / counts / hex caps (no dotted-quad beyond the
    # host the user supplied, which is the endpoint identity, not a resolved IP).
    doc = json.loads(blob)["remote_doctor"]
    f = doc["endpoints"][0]["facts"]
    assert f["family"] in ("IPv4", "IPv6", "none"), f
    assert isinstance(f["caps"], str) and f["caps"].startswith("0x"), f


# ==========================================================================
# active diagnosis — exercise subsystems, classify symptom → root cause
# ==========================================================================

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


def test_diagnosis_present_readonly_default(anon):
    """Read-only probes always run (no --allow-write): auth/namespace/read/
    checksum/locate present and green on a healthy server; no write probe."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    dx = _diagnosis(p.stdout)
    for probe in ("auth", "namespace", "read", "locate"):
        assert probe in dx and dx[probe]["verdict"] == "ok", dx
    # no mutation probe unless --allow-write
    assert "write" not in dx, dx


def test_diagnosis_write_path_healthy(rw_server):
    """On a writable export, --allow-write runs the write probe and it verifies."""
    port = rw_server["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//f.bin",
             "--allow-write", "--i-am-authorized", "--json", "--metrics-port", "0",
             "--probe-timeout", "8000")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    dx = _diagnosis(p.stdout)
    assert dx.get("write", {}).get("verdict") == "ok", dx
    # write probe must clean up after itself — no test artifact left behind
    leftovers = [n for n in os.listdir(rw_server["data"]) if "xrddiag" in n]
    assert leftovers == [], f"write probe left artifacts: {leftovers}"


def test_diagnosis_readonly_export_classified(anon):
    """The headline case: a read-only export's write probe pins the root cause to
    'read-only' with a remediation, escalates to RED, and exits nonzero."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--allow-write", "--i-am-authorized", "--metrics-port", "0",
             "--probe-timeout", "8000")
    assert p.returncode != 0, p.stdout
    assert "[RED]" in p.stdout, p.stdout
    assert "FAIL" in p.stdout and "write" in p.stdout, p.stdout
    assert "read-only" in p.stdout.lower(), p.stdout
    assert "allow_write" in p.stdout, "remediation missing: " + p.stdout


def test_diagnosis_empty_export_warns(empty_server):
    """An empty export root is a real misconfiguration the namespace probe flags."""
    port = empty_server["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}",
             "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    # exits 0 (warn, not fail) but the namespace finding must warn 'empty'
    dx = _diagnosis(p.stdout)
    assert dx.get("namespace", {}).get("verdict") == "warn", dx
    assert "empty" in dx["namespace"]["cause"].lower(), dx["namespace"]


def test_diagnosis_dead_hop_classifies_reachability(anon):
    """An unreachable hop yields a reachability finding with a concrete cause."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             f"root://{HOST}:1", "--json", "--metrics-port", "0",
             "--probe-timeout", "2000")
    assert p.returncode != 0, p.stdout
    doc = json.loads(p.stdout)["remote_doctor"]
    dead = doc["endpoints"][1]
    assert dead["status"] == "RED", dead
    rch = [d for d in dead["diagnosis"] if d["probe"] == "reachability"]
    assert rch and rch[0]["verdict"] == "fail" and rch[0]["remedy"], dead


def test_diagnosis_pii_free(anon):
    """The diagnosis cause/remedy strings must carry no path, token, or secret."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--allow-write", "--i-am-authorized", "--json", "--metrics-port", "0",
             "--probe-timeout", "8000")
    doc = json.loads(p.stdout)["remote_doctor"]
    for d in doc["endpoints"][0]["diagnosis"]:
        joined = d["cause"] + " " + d["remedy"]
        for leak in ("big.bin", "/tmp/", "BEARER", "PRIVATE", "xrddiag-dx",
                     "subject="):
            assert leak not in joined, f"PII/secret in diagnosis: {leak} in {d}"


# ==========================================================================
# auth/permissions suite (--auth-suite) — differential authorization testing
# ==========================================================================
#
# The headline: catch a server build whose authentication/authorization is broken
# (accepts credentials it must reject, or grants access it must deny). Each probe
# asserts a CORRECT server's behavior; on a broken server the verdict flips to FAIL.
# Self-hosting: SSS server (xrdsssadmin keytab) for the anon-enforcement case; a
# token server (utils.make_token RSA issuer + JWKS) for the forged/expired/scope cases.

_SSSADMIN = os.path.join(CLIENT_DIR, "bin", "xrdsssadmin-brix")


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


def test_authsuite_off_by_default(anon):
    """No authz-* findings unless --auth-suite is passed."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    dx = _authsuite_diag(p.stdout)
    assert not any(k.startswith("authz") for k in dx), dx


def test_authsuite_anon_by_design(anon):
    """An anon export reports 'anonymous by design', not a bypass."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//big.bin",
             "--auth-suite", "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    dx = _authsuite_diag(p.stdout)
    assert dx["authz-anon"]["verdict"] == "ok", dx
    assert "design" in dx["authz-anon"]["cause"].lower(), dx


def test_authsuite_anon_bypass_denied(sss_server):
    """Headline: on an auth-required (SSS) server the suite confirms anonymous
    access is DENIED — even though the client holds no credential. A served op
    here would be the auth-bypass FAIL."""
    port = sss_server["port"]
    env = {k: v for k, v in _CLEAN_ENV.items()}
    env.pop("XrdSecSSSKT", None)
    p = subprocess.run([XRDDIAG, "remote-doctor", f"root://{HOST}:{port}//probe.txt",
                        "--auth-suite", "--json", "--metrics-port", "0",
                        "--probe-timeout", "8000"],
                       capture_output=True, text=True, env=env, timeout=60)
    dx = _authsuite_diag(p.stdout)
    assert dx["authz-anon"]["verdict"] == "ok", dx
    assert "denied" in dx["authz-anon"]["cause"].lower(), dx


def test_authsuite_forged_token_rejected(token_server):
    """Headline: a garbage-signature token and an alg:none token MUST be rejected.
    Acceptance would be the broken-signature-verification FAIL."""
    port = token_server["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.txt",
             "--auth-suite", "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    dx = _authsuite_diag(p.stdout)
    assert dx["authz-forgesig"]["verdict"] == "ok", dx
    assert dx["authz-algnone"]["verdict"] == "ok", dx
    assert "rejected" in dx["authz-forgesig"]["cause"].lower(), dx


def test_authsuite_expired_token_rejected(token_server):
    """An expired bearer token in the environment must be rejected by the server."""
    issuer = token_server["issuer"]
    port = token_server["port"]
    env = {k: v for k, v in _CLEAN_ENV.items()}
    env["BEARER_TOKEN"] = issuer.generate_expired()
    p = subprocess.run([XRDDIAG, "remote-doctor", f"root://{HOST}:{port}//probe.txt",
                        "--auth-suite", "--json", "--metrics-port", "0",
                        "--probe-timeout", "8000"],
                       capture_output=True, text=True, env=env, timeout=60)
    dx = _authsuite_diag(p.stdout)
    assert dx["authz-expired"]["verdict"] == "ok", dx
    assert "expired" in dx["authz-expired"]["cause"].lower(), dx


def test_authsuite_scope_enforced(token_server):
    """A read-only token must be DENIED a write (scope enforcement). A successful
    write would be the privilege-escalation FAIL."""
    issuer = token_server["issuer"]
    port = token_server["port"]
    env = {k: v for k, v in _CLEAN_ENV.items()}
    env["BEARER_TOKEN"] = issuer.generate(scope="storage.read:/")
    p = subprocess.run([XRDDIAG, "remote-doctor", f"root://{HOST}:{port}//probe.txt",
                        "--auth-suite", "--allow-write", "--i-am-authorized", "--json",
                        "--metrics-port", "0", "--probe-timeout", "8000"],
                       capture_output=True, text=True, env=env, timeout=60)
    dx = _authsuite_diag(p.stdout)
    assert dx["authz-scope"]["verdict"] == "ok", dx
    assert "denied" in dx["authz-scope"]["cause"].lower(), dx


def test_authsuite_pii_free(token_server):
    """The auth-suite must never echo a token, scope, issuer, or path."""
    issuer = token_server["issuer"]
    port = token_server["port"]
    env = {k: v for k, v in _CLEAN_ENV.items()}
    env["BEARER_TOKEN"] = issuer.generate(scope="storage.read:/")
    p = subprocess.run([XRDDIAG, "remote-doctor", f"root://{HOST}:{port}//probe.txt",
                        "--auth-suite", "--json", "--metrics-port", "0",
                        "--probe-timeout", "8000"],
                       capture_output=True, text=True, env=env, timeout=60)
    doc = json.loads(p.stdout)["remote_doctor"]
    for d in doc["endpoints"][0]["diagnosis"]:
        joined = d["cause"] + " " + d["remedy"]
        for leak in ("eyJ", "storage.read", "test.example.com", "probe.txt",
                     "BEARER", "xrddiag-az"):
            assert leak not in joined, f"auth-suite leak: {leak} in {d}"
