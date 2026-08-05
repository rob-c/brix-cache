"""
Native krb5 client ⇆ REAL reference xrootd (`libXrdSeckrb5`) interop — phase-70.

The clean-room client's krb5 module (client/lib/auth/sec/sec_krb5.c) has to date
been proven only against brix's OWN krb5 acceptor (src/auth/krb5/auth.c) — a
same-project pairing.  This gate proves it interoperates with the *reference*
implementation: a stock `xrootd` v5 data server whose `sec.protocol krb5` loads
`libXrdSeckrb5`, validating the client's AP-REQ framing ("krb5" + AP_REQ bytes)
against the very acceptor real WLCG sites run.

It reuses the session KDC (kdc_helpers.py) — the same isolated MIT realm + service
keytab (`xrootd/localhost@NGINX.TEST`) the brix native-krb5 tier uses — so the
service principal the client requests a ticket for is exactly what the reference
server holds.  The server advertises "&P=krb5,<principal>" at login; the client's
`build_server_princ` honours it, so the two agree on the SPN with no DNS coupling.

Self-contained: launches its own `xrootd` on a free port + the session KDC.  Skips
cleanly without the reference server, its krb5 plugin, MIT KDC tooling, or a
krb5-less client build.

Run (serial):
    PYTHONPATH=tests pytest tests/test_krb5_xrootd_interop.py -v -p no:xdist
"""

import hashlib
import os
import shutil
import socket
import subprocess
import tempfile
import time

import pytest

import kdc_helpers
from ephemeral_port import free_port
from settings import (
    HOST,
    KRB5_CCACHE,
    KRB5_CONF,
    KRB5_KEYTAB,
    KRB5_SERVICE_PRINCIPAL,
)

pytestmark = pytest.mark.xdist_group("krb5-xrootd-interop")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")

# The reference server binds settings.HOST; the client uses the advertised SPN,
# so the host it dials need not match the principal's instance name.


def _find_seclib():
    for d in ("/usr/lib64", "/usr/lib/x86_64-linux-gnu", "/usr/lib"):
        for name in ("libXrdSec-5.so", "libXrdSec.so"):
            p = os.path.join(d, name)
            if os.path.exists(p):
                return p
    return None


def _krb5_plugin_present():
    for d in ("/usr/lib64", "/usr/lib/x86_64-linux-gnu", "/usr/lib"):
        if any(os.path.exists(os.path.join(d, n))
               for n in ("libXrdSeckrb5-5.so", "libXrdSeckrb5.so")):
            return True
    return False


def _client_has_krb5():
    if not os.path.exists(XRDFS):
        return False
    if "krb5" not in subprocess.run([XRDFS, "-h"],
                                    capture_output=True, text=True).stderr:
        return False
    linked = subprocess.run(["ldd", XRDFS], capture_output=True, text=True).stdout
    return "libkrb5" in linked


def _wait_port(host, port, deadline):
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture()
def xrootd_krb5(tmp_path):
    xrootd = shutil.which("xrootd")
    if not xrootd:
        pytest.skip("stock xrootd not installed")
    if not _krb5_plugin_present():
        pytest.skip("libXrdSeckrb5 plugin not installed")
    seclib = _find_seclib()
    if not seclib:
        pytest.skip("libXrdSec framework lib not found")
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs", "xrdcp"],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(XRDFS):
        pytest.skip(f"native build failed:\n{proc.stdout}\n{proc.stderr}")
    if not _client_has_krb5():
        pytest.skip("client built without -DBRIX_HAVE_KRB5")
    if not kdc_helpers.krb5_tools_available():
        pytest.skip("MIT KDC tooling not installed (install krb5-server)")
    if not kdc_helpers.up():
        pytest.skip("krb5 realm could not be provisioned")

    data = tmp_path / "data"
    data.mkdir()
    payload = os.urandom(40000)
    (data / "probe.txt").write_bytes(b"krb5-xrootd-ok\n")
    (data / "blob.bin").write_bytes(payload)

    logs = tmp_path / "logs"
    logs.mkdir()
    # xrootd's admin path becomes a unix socket whose sun_path caps at ~108 bytes;
    # a deep pytest tmp_path can overflow it, so anchor admin/pid under a short dir.
    short = tempfile.mkdtemp(prefix="xrk")
    admin = os.path.join(short, "admin")
    run = os.path.join(short, "run")
    os.mkdir(admin)
    os.mkdir(run)

    port = free_port(HOST)
    cfg = tmp_path / "xrootd.cfg"
    cfg.write_text(f"""\
xrd.port {port}
xrd.network nodnr
oss.localroot {data}
all.export /
all.adminpath {admin}
all.pidpath {run}
xrd.sched mint 1 maxt 4 avlt 1
xrd.trace off
xrootd.seclib {seclib}
sec.protocol krb5 {KRB5_SERVICE_PRINCIPAL}
sec.protbind * krb5
""", encoding="utf-8")
    log_path = logs / "xrootd.log"

    # The reference acceptor reads its service key from KRB5_KTNAME and the realm
    # from KRB5_CONFIG — both pinned into the isolated session realm.
    env = os.environ.copy()
    env["KRB5_KTNAME"] = KRB5_KEYTAB
    env["KRB5_CONFIG"] = KRB5_CONF

    srv = subprocess.Popen(
        [xrootd, "-c", str(cfg), "-l", str(log_path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True, env=env)
    try:
        if not _wait_port(HOST, port, time.time() + 20):
            log = log_path.read_text(errors="replace") if log_path.exists() else ""
            pytest.skip(f"reference xrootd did not come up:\n{log[-2000:]}")
        yield {"port": port, "log": log_path}
    finally:
        try:
            os.killpg(os.getpgid(srv.pid), 15)
        except OSError:
            pass
        try:
            srv.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(srv.pid), 9)
        shutil.rmtree(short, ignore_errors=True)
        kdc_helpers.down()


def _client_env(ccache=KRB5_CCACHE):
    env = {k: v for k, v in os.environ.items()}
    env.pop("X509_USER_PROXY", None)
    env.pop("BEARER_TOKEN", None)
    env["KRB5_CONFIG"] = KRB5_CONF
    if ccache is not None:
        env["KRB5CCNAME"] = ccache
    else:
        env.pop("KRB5CCNAME", None)
    return env


class _Result:
    """subprocess result with bytes-safe (errors='replace') text views — a krb5
    auth failure yields non-UTF8 protocol-name bytes on stderr, and text=True
    would raise UnicodeDecodeError inside the harness instead of a clean assert."""

    def __init__(self, cp):
        self.returncode = cp.returncode
        self.stdout = cp.stdout.decode("utf-8", "replace")
        self.stderr = cp.stderr.decode("utf-8", "replace")


def _xrdfs(server, *args, ccache=KRB5_CCACHE, timeout=30):
    url = f"root://{HOST}:{server['port']}"
    return _Result(subprocess.run([XRDFS, "--auth", "krb5", url, *args],
                                  capture_output=True,
                                  env=_client_env(ccache), timeout=timeout))


# --------------------------------------------------------------------------
# the gate: the native client authenticates to the REFERENCE xrootd via krb5
# --------------------------------------------------------------------------

def test_stat_against_reference_xrootd(xrootd_krb5):
    p = _xrdfs(xrootd_krb5, "stat", "/probe.txt")
    assert p.returncode == 0, (
        f"krb5 stat vs reference xrootd failed:\n{p.stdout}\n{p.stderr}\n"
        f"--- xrootd log ---\n{xrootd_krb5['log'].read_text(errors='replace')[-1500:]}")
    assert "Size:" in p.stdout, p.stdout


def test_ls_against_reference_xrootd(xrootd_krb5):
    p = _xrdfs(xrootd_krb5, "ls", "/")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "blob.bin" in p.stdout and "probe.txt" in p.stdout, p.stdout


def test_download_md5_exact(xrootd_krb5, tmp_path):
    # The fixture and this test share the function-scoped tmp_path, so the
    # server's source file is directly readable for a byte-exact comparison.
    src = tmp_path / "data" / "blob.bin"
    out = tmp_path / "blob.out"
    url = f"root://{HOST}:{xrootd_krb5['port']}//blob.bin"
    p = _Result(subprocess.run([XRDCP, "--auth", "krb5", url, str(out)],
                               capture_output=True, env=_client_env(), timeout=30))
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    got = out.read_bytes()
    assert hashlib.md5(got).hexdigest() == hashlib.md5(src.read_bytes()).hexdigest(), \
        f"content mismatch: got {len(got)} bytes"


# --------------------------------------------------------------------------
# security-neg: no Kerberos credential ⇒ the reference server refuses
# --------------------------------------------------------------------------

def test_no_ccache_refused(xrootd_krb5, tmp_path):
    missing = str(tmp_path / "nope.ccache")
    p = _xrdfs(xrootd_krb5, "stat", "/probe.txt", ccache=missing)
    assert p.returncode != 0, p.stdout
