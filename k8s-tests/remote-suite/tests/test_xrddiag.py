# brix-remote-skip
"""
xrddiag (phase-37 §15.3–15.7): the consolidated deployment-diagnostic CLI.

`xrddiag` is a single clean-room (libXrdCl-free) binary that exercises the same
libbrix paths a real client uses and reports pass/fail + numbers:

    check    — protocol-correctness probes (auth-as-advertised, no-TLS-downgrade,
               path-confinement, dirlist dstat==stat, checksum-works, pgread CRC)
    bench    — timed download, single-stream vs --streams N (MB/s)
    topology — brix_locate + redirect-loop convergence (nonexistent → NotFound)
    status   — pull /metrics over the built-in HTTP/1.0 GET and summarise it
    compare  — root-vs-reference: stat size, dirlist set, md5

Run (serial, against a manually-started fleet):
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
    pytest tests/test_xrddiag.py -v -p no:xdist
"""

import os
import socket
import shutil
import subprocess
import time

import pytest

from settings import (
    BIND_HOST,
    CLUSTER_REDIR_PORT,
    DATA_ROOT,
    HOST,
    NGINX_ANON_PORT,
    NGINX_METRICS_PORT,
    REF_BRIX_PORT,
    SERVER_HOST,
    url_host,
)

pytestmark = pytest.mark.timeout(120)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE_XRDDIAG = os.path.join(REPO, "client", "bin", "xrddiag")
ANON_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"

# A clean env: no X509 so anon stays anon.
_CLEAN_ENV = {k: v for k, v in os.environ.items()}
_CLEAN_ENV.pop("X509_USER_PROXY", None)
_CLEAN_ENV.pop("X509_CERT_DIR", None)


@pytest.fixture(scope="module")
def xrddiag():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")
    proc = subprocess.run(["make", "-C", os.path.join(REPO, "client"), "xrddiag"],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(NATIVE_XRDDIAG):
        pytest.skip(f"xrddiag build failed:\n{proc.stdout}\n{proc.stderr}")
    # Every subcommand needs the anon server; skip cleanly when the fleet is down
    # (e.g. between harness restarts) rather than hard-failing.
    if not _port_up(SERVER_HOST, NGINX_ANON_PORT):
        pytest.skip("anon server not running (start the test fleet)")
    return NATIVE_XRDDIAG


def _run(*args, timeout=40):
    return subprocess.run([NATIVE_XRDDIAG, *args], capture_output=True, text=True,
                          env=_CLEAN_ENV, timeout=timeout)


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


# --------------------------------------------------------------------------
# check
# --------------------------------------------------------------------------

def test_check_all_green(xrddiag):
    p = _run("check", ANON_URL)
    assert p.returncode == 0, f"check failed:\n{p.stdout}\n{p.stderr}"
    out = p.stdout
    # Every probe present and passing against a healthy server.
    assert "[PASS] auth-as-advertised" in out, out
    assert "[PASS] path-confinement" in out, out      # the security-negative probe
    assert "[PASS] dirlist" in out, out
    assert "[PASS] checksum-works" in out, out
    assert "[PASS] pgread-integrity" in out, out
    assert "Result: 0 failure(s)" in out, out


def test_check_security_negative_escape_refused(xrddiag):
    """The path-confinement probe must report the escape was REFUSED — never
    served. This is the security-negative case for the whole tool."""
    p = _run("check", ANON_URL)
    assert "[PASS] path-confinement" in p.stdout, p.stdout
    assert "escape refused" in p.stdout, p.stdout
    assert "ESCAPE SERVED" not in p.stdout, "path confinement broken!"


# --------------------------------------------------------------------------
# bench
# --------------------------------------------------------------------------

def test_bench_reports_rate(xrddiag):
    p = _run("bench", ANON_URL)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "single-stream" in p.stdout, p.stdout
    assert "MB/s" in p.stdout, p.stdout


def test_bench_streams_variant(xrddiag):
    p = _run("bench", ANON_URL, "-S", "4")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "single-stream" in p.stdout, p.stdout
    assert "multi-stream" in p.stdout and "4 streams" in p.stdout, p.stdout


# --------------------------------------------------------------------------
# topology
# --------------------------------------------------------------------------

def test_topology_cluster_redirector(xrddiag):
    if not _port_up(SERVER_HOST, CLUSTER_REDIR_PORT):
        pytest.skip("cluster redirector not running")
    url = f"root://{SERVER_HOST}:{CLUSTER_REDIR_PORT}"
    p = _run("topology", url)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "[PASS] locate" in p.stdout, p.stdout
    # nonexistent path must converge to NotFound, not exhaust the redirect budget
    assert "[PASS] redirect-convergence" in p.stdout, p.stdout
    assert "NotFound" in p.stdout, p.stdout


# --------------------------------------------------------------------------
# status (built-in HTTP/1.0 GET of /metrics)
# --------------------------------------------------------------------------

def test_status_pulls_metrics(xrddiag):
    if not _port_up(SERVER_HOST, NGINX_METRICS_PORT):
        pytest.skip("metrics endpoint not running")
    p = _run("status", ANON_URL, "--metrics-port", str(NGINX_METRICS_PORT))
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "HTTP 200" in p.stdout, p.stdout
    assert "metric series total" in p.stdout, p.stdout
    assert "brix_" in p.stdout, p.stdout


def test_status_bad_port_fails(xrddiag):
    # A port nothing listens on → clean non-zero, not a hang/crash.
    p = _run("status", ANON_URL, "--metrics-port", "1", timeout=20)
    assert p.returncode != 0, p.stdout


# --------------------------------------------------------------------------
# compare (root vs reference xrootd)
# --------------------------------------------------------------------------

@pytest.fixture()
def two_files():
    """Write two files (same + different content) into the shared data root that
    both nginx-anon and the reference xrootd serve. Yields (name_a, name_b)."""
    tag = f"{os.getpid()}_{int(time.time() * 1000)}"
    name_a = f"_xrddiag_a_{tag}.bin"
    name_b = f"_xrddiag_b_{tag}.bin"
    payload = os.urandom(65536)
    with open(os.path.join(DATA_ROOT, name_a), "wb") as fh:
        fh.write(payload)
    with open(os.path.join(DATA_ROOT, name_b), "wb") as fh:
        fh.write(os.urandom(65536))   # different bytes
    yield name_a, name_b
    for n in (name_a, name_b):
        try:
            os.unlink(os.path.join(DATA_ROOT, n))
        except OSError:
            pass


def test_compare_identical_matches(xrddiag, two_files):
    if not _port_up(HOST, REF_BRIX_PORT):
        pytest.skip("reference xrootd not running")
    name_a, _ = two_files
    a = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//{name_a}"
    b = f"root://{url_host(HOST)}:{REF_BRIX_PORT}//{name_a}"
    p = _run("compare", a, "--vs-reference", b)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "[PASS] size" in p.stdout, p.stdout
    assert "[PASS] md5" in p.stdout, p.stdout
    assert "Result: 0 difference(s)" in p.stdout, p.stdout


def test_compare_different_fails(xrddiag, two_files):
    """Two different files must be reported as a difference (non-zero exit)."""
    name_a, name_b = two_files
    a = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//{name_a}"
    b = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//{name_b}"
    p = _run("compare", a, "--vs-reference", b)
    assert p.returncode != 0, f"expected a difference:\n{p.stdout}"
    assert "[FAIL] md5" in p.stdout, p.stdout


# --------------------------------------------------------------------------
# diagnostics passthrough (wire-trace/timing land on stderr, not stdout)
# --------------------------------------------------------------------------

def test_diag_flags_stderr_only(xrddiag):
    p = _run("check", "--timing", ANON_URL)
    assert p.returncode == 0, p.stderr
    # the timing summary is stderr-only; the probe report stays clean on stdout
    assert "per-opcode RTT" in p.stderr, p.stderr
    assert "per-opcode RTT" not in p.stdout, "timing leaked onto stdout"


# --------------------------------------------------------------------------
# WS-F: bench networking diagnostics (§15.3) — self-contained anon server
# --------------------------------------------------------------------------

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")


@pytest.fixture(scope="module")
def netdiag_server(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    if not os.path.exists(NATIVE_XRDDIAG):
        proc = subprocess.run(["make", "-C", os.path.join(REPO, "client"), "xrddiag"],
                              capture_output=True, text=True, timeout=180)
        if proc.returncode != 0 or not os.path.exists(NATIVE_XRDDIAG):
            pytest.skip("xrddiag build failed")
    root = tmp_path_factory.mktemp("netdiag")
    data = root / "data"
    data.mkdir()
    (data / "big.bin").write_bytes(os.urandom(1024 * 1024))
    port = _free_port_local()
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 256; }}
stream {{
    server {{
        listen {BIND_HOST}:{port};
        xrootd on;
        brix_storage_backend posix:{data};
        brix_auth none;
    }}
}}
""")
    t = subprocess.run([NGINX_BIN, "-t", "-c", str(conf)], capture_output=True, text=True)
    if t.returncode != 0:
        pytest.skip("nginx -t failed:\n" + t.stderr)
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    for _ in range(50):
        if _port_up(HOST, port):
            break
        time.sleep(0.1)
    yield port
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True)
    time.sleep(0.3)


def _free_port_local():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_bench_netdiag_block(netdiag_server):
    port = netdiag_server
    p = subprocess.run([NATIVE_XRDDIAG, "bench", f"root://{url_host(HOST)}:{port}//big.bin"],
                       capture_output=True, text=True, timeout=40)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    out = p.stdout
    # phase breakdown present + a total line; family; TCP_INFO with an rtt
    assert "Connect phases" in out, out
    assert "total" in out, out
    assert "Connected via IPv4" in out or "Connected via IPv6" in out, out
    assert "TCP_INFO" in out and "rtt=" in out, out
    assert "MB/s" in out, out


def test_bench_netdiag_pii_free(netdiag_server):
    """security-neg / PII: the netdiag block must leak no path or credential and
    no numeric thresholds are asserted (WSL2 timings are untrustworthy)."""
    port = netdiag_server
    p = subprocess.run([NATIVE_XRDDIAG, "bench", f"root://{url_host(HOST)}:{port}//big.bin"],
                       capture_output=True, text=True, timeout=40)
    assert p.returncode == 0, p.stderr
    # isolate the diagnostic block (phases + family + TCP_INFO lines)
    block = [ln for ln in p.stdout.splitlines()
             if any(k in ln for k in ("phases", "tcp", "tls", "login", "total",
                                      "Connected via", "TCP_INFO", "Flow label"))]
    joined = "\n".join(block)
    for leak in ("BEARER", "x509", "/etc/", "PRIVATE", "subject="):
        assert leak not in joined, f"PII/secret leaked in netdiag: {joined}"
    # rtt is a non-negative integer
    import re
    m = re.search(r"rtt=(\d+) us", p.stdout)
    assert m and int(m.group(1)) >= 0, p.stdout


# --------------------------------------------------------------------------
# WS-I (doctor: POSC/handle-limits) + WS-K (bench --sweep) — writable server
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def doctor_server(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    if not os.path.exists(NATIVE_XRDDIAG):
        proc = subprocess.run(["make", "-C", os.path.join(REPO, "client"), "xrddiag"],
                              capture_output=True, text=True, timeout=180)
        if proc.returncode != 0 or not os.path.exists(NATIVE_XRDDIAG):
            pytest.skip("xrddiag build failed")
    root = tmp_path_factory.mktemp("doctor")
    data = root / "data"
    data.mkdir()
    (data / "obj.bin").write_bytes(os.urandom(800000))
    port = _free_port_local()
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 256; }}
stream {{
    server {{
        listen {BIND_HOST}:{port};
        xrootd on;
        brix_storage_backend posix:{data};
        brix_auth none;
        brix_allow_write on;
    }}
}}
""")
    t = subprocess.run([NGINX_BIN, "-t", "-c", str(conf)], capture_output=True, text=True)
    if t.returncode != 0:
        pytest.skip("nginx -t failed:\n" + t.stderr)
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    for _ in range(50):
        if _port_up(HOST, port):
            break
        time.sleep(0.1)
    yield port
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True)
    time.sleep(0.3)


def test_check_posc_and_handle_limits(doctor_server):
    """WS-I: POSC-atomicity (abandoned upload leaves no file) + handle-limits
    (graceful cap, connection survives)."""
    p = subprocess.run([NATIVE_XRDDIAG, "check", f"root://{url_host(HOST)}:{doctor_server}/"],
                       capture_output=True, text=True, timeout=40)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    out = p.stdout
    assert "[PASS] posc-atomicity" in out, out
    assert "left no file" in out, out                       # security-neg: no partial
    assert "[PASS] handle-limits" in out or "[NOTE] handle-limits" in out, out
    assert "conn alive" in out or "no cap hit" in out, out


def test_check_clock_skew_expired_token(doctor_server):
    """WS-I clock-skew: a planted expired token surfaces EXPIRED in the validity
    block (never silently valid)."""
    import base64
    import json
    hdr = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
    pay = base64.urlsafe_b64encode(
        json.dumps({"sub": "x", "exp": int(time.time()) - 100}).encode()).rstrip(b"=").decode()
    env = dict(_CLEAN_ENV)
    env["BEARER_TOKEN"] = f"{hdr}.{pay}.sig"
    p = subprocess.run([NATIVE_XRDDIAG, "check", f"root://{url_host(HOST)}:{doctor_server}/"],
                       capture_output=True, text=True, timeout=40, env=env)
    assert p.returncode == 0, p.stderr
    assert "Credential validity" in p.stdout and "EXPIRED" in p.stdout, p.stdout


def test_bench_sweep_table(doctor_server):
    """WS-K: --sweep prints a multi-row read-size table (structure only — no
    throughput thresholds, WSL2 timings are untrustworthy)."""
    p = subprocess.run([NATIVE_XRDDIAG, "bench", f"root://{url_host(HOST)}:{doctor_server}//obj.bin",
                        "--sweep"], capture_output=True, text=True, timeout=40)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "Read-size sweep" in p.stdout, p.stdout
    import re
    rows = re.findall(r"^\s+(\d+)\s+([\d.]+)\s*$", p.stdout, re.MULTILINE)
    assert len(rows) >= 3, f"expected >=3 sweep rows:\n{p.stdout}"
    sizes = [int(r[0]) for r in rows]
    assert sizes == sorted(sizes), f"sizes not ascending: {sizes}"


def test_bench_sweep_unreachable_clean_fail(doctor_server):
    p = subprocess.run([NATIVE_XRDDIAG, "bench", f"root://{url_host(HOST)}:1//x", "--sweep"],
                       capture_output=True, text=True, timeout=20)
    assert p.returncode != 0, p.stdout
