"""
krb5 delegated *cache→origin* fetch, end-to-end — phase-70 §5.7 OUTBOUND leg.

This closes the last krb5 residual.  Three real processes, one session KDC, no
mocks:

    native client ──krb5(+deleg)──▶ brix-cache ──krb5 raw AP-REQ──▶ stock xrootd
      (client/bin)                 (delegate on)                    (libXrdSeckrb5)

* The client authenticates to the cache with native krb5 and *forwards* its TGT
  (kinit -f) in answer to the cache's two-round "fwdtgt" challenge.
* The cache (src/auth/krb5/deleg_capture.c) imports the forwarded TGT into a
  per-connection 0600 ccache and carries it onto the fill task.
* On the cache-miss fill, the origin advertises "&P=krb5,<spn>" at login; the
  cache builds a RAW "krb5\0"+AP-REQ straight from the carried ccache
  (src/auth/krb5/apreq.c, brix_cache_origin_auth_krb5_raw) and presents it.
* The origin is a *stock* xrootd whose `sec.protbind * krb5` makes krb5 the ONLY
  admissible protocol, and it validates the AP-REQ with krb5_rd_req — the exact
  dialect real "&P=krb5" origins speak.  A byte-exact delivery through it is thus
  airtight proof the cache's delegated outbound AP-REQ was accepted end-to-end.

Where test_krb5_delegation_e2e.py proves the INBOUND capture and
test_krb5_xrootd_interop.py proves the client⇆reference dialect, this proves the
whole delegated chain: capture → carry → raw AP-REQ → reference acceptor → data.

Self-contained: its own stock xrootd origin (free port) + lifecycle-harness cache
(delegate template) + the session KDC.  Skips cleanly without the reference
server, its krb5 plugin, MIT KDC tooling, or a krb5-less client build.

Run (serial):
    PYTHONPATH=tests pytest tests/test_krb5_cache_origin_e2e.py -v -p no:xdist
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
from server_registry import NginxInstanceSpec
from settings import (
    BIND_HOST,
    HOST,
    KRB5_CCACHE,
    KRB5_CLIENT_KEYTAB,
    KRB5_CLIENT_PRINCIPAL,
    KRB5_CONF,
    KRB5_KEYTAB,
    KRB5_SERVICE_PRINCIPAL,
    NGINX_BIN,
    url_host,
)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-krb5-cache-origin")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")

# Forwardable ccache (kinit -f); the stock KRB5_CCACHE (kinit -k -t, no -f) is a
# NON-forwardable TGT reused as-is for the security-negative.
FWD_CCACHE = KRB5_CCACHE + ".cacheorigin.fwd"

# Emitted by src/auth/krb5/deleg_capture.c the instant it imports the forwarded
# TGT — the airtight cache-side proof the delegation actually ran.
CAPTURE_MARKER = "krb5 delegation captured forwarded TGT"

PROBE_TEXT = b"krb5-cache-origin-ok\n"


# --------------------------------------------------------------------------
# reference-origin discovery (mirrors test_krb5_xrootd_interop.py)
# --------------------------------------------------------------------------

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
    """The client links libkrb5 only when built -DBRIX_HAVE_KRB5 (deterministic)."""
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


def _kinit_forwardable():
    """kinit a FORWARDABLE alice TGT into FWD_CCACHE (kinit -f), non-interactive."""
    env = {k: v for k, v in os.environ.items()}
    env["KRB5_CONFIG"] = KRB5_CONF
    proc = subprocess.run(
        [shutil.which("kinit") or "kinit", "-f", "-k", "-t", KRB5_CLIENT_KEYTAB,
         "-c", FWD_CCACHE, KRB5_CLIENT_PRINCIPAL],
        capture_output=True, text=True, env=env, timeout=30)
    return proc.returncode == 0


def _start_origin(tmp_path):
    """Launch a stock xrootd krb5-only origin serving PROBE_TEXT + a random blob.
    Returns (popen, port, log_path, data_dir, short_dir).  The caller reaps it."""
    xrootd = shutil.which("xrootd")
    data = tmp_path / "origin-data"
    data.mkdir()
    (data / "probe.txt").write_bytes(PROBE_TEXT)
    (data / "blob.bin").write_bytes(os.urandom(40000))

    logs = tmp_path / "origin-logs"
    logs.mkdir()
    # xrootd's admin path becomes a unix socket capped at ~108 bytes; a deep
    # pytest tmp_path can overflow it, so anchor admin/pid under a short dir.
    short = tempfile.mkdtemp(prefix="xrk-co")
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
xrootd.seclib {_find_seclib()}
sec.protocol krb5 {KRB5_SERVICE_PRINCIPAL}
sec.protbind * krb5
""", encoding="utf-8")
    log_path = logs / "xrootd.log"

    env = os.environ.copy()
    env["KRB5_KTNAME"] = KRB5_KEYTAB      # reference acceptor reads its service key here
    env["KRB5_CONFIG"] = KRB5_CONF        # ... from the isolated session realm

    srv = subprocess.Popen(
        [xrootd, "-c", str(cfg), "-l", str(log_path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True, env=env)
    return srv, port, log_path, data, short


@pytest.fixture()
def cache_origin(lifecycle, tmp_path):
    # --- toolchain / reference-server gates (skip, never fail, when absent) ---
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs", "xrdcp"],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(XRDFS):
        pytest.skip(f"native build failed:\n{proc.stdout}\n{proc.stderr}")
    if not _client_has_krb5():
        pytest.skip("client built without -DBRIX_HAVE_KRB5")
    if shutil.which("xrootd") is None:
        pytest.skip("stock xrootd not installed")
    if not _krb5_plugin_present() or not _find_seclib():
        pytest.skip("libXrdSeckrb5 / libXrdSec framework not installed")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    if not kdc_helpers.krb5_tools_available():
        pytest.skip("MIT KDC tooling not installed (install krb5-server)")
    if not kdc_helpers.up():
        pytest.skip("krb5 realm could not be provisioned")

    os.environ["KRB5_CONFIG"] = KRB5_CONF

    srv = short = None
    try:
        srv, origin_port, origin_log, _data, short = _start_origin(tmp_path)
        if not _wait_port(HOST, origin_port, time.time() + 20):
            tail = origin_log.read_text(errors="replace")[-2000:] \
                if origin_log.exists() else ""
            pytest.skip(f"reference xrootd origin did not come up:\n{tail}")

        cache_store = tmp_path / "cache-store"
        cache_store.mkdir()

        cache_ep = lifecycle.start(NginxInstanceSpec(
            name="lc-krb5-cache-origin",
            template="nginx_lc_krb5_cache_origin.conf",
            protocol="root",
            template_values={
                "BIND_HOST": url_host(BIND_HOST),
                "PRINCIPAL": KRB5_SERVICE_PRINCIPAL,
                "KEYTAB": KRB5_KEYTAB,
                "CACHE_BACKEND": f"root://{url_host(HOST)}:{origin_port}",
                "CACHE_STORE": str(cache_store),
            },
            env={"KRB5_CONFIG": KRB5_CONF, "KRB5_KTNAME": KRB5_KEYTAB},
            reason="krb5 delegated cache→origin fetch"))

        if not _kinit_forwardable():
            pytest.skip("KDC would not issue a forwardable TGT (kinit -f)")

        cache_err = os.path.join(os.path.dirname(cache_ep.pidfile), "error.log")
        yield {"port": cache_ep.port, "cache_error_log": cache_err,
               "origin_log": origin_log}
    finally:
        if srv is not None:
            try:
                os.killpg(os.getpgid(srv.pid), 15)
                srv.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(os.getpgid(srv.pid), 9)
                except OSError:
                    pass
        if short is not None:
            shutil.rmtree(short, ignore_errors=True)
        if os.path.exists(FWD_CCACHE):
            os.unlink(FWD_CCACHE)
        kdc_helpers.down()


def _client_env(ccache):
    env = {k: v for k, v in os.environ.items()}
    env.pop("X509_USER_PROXY", None)
    env.pop("BEARER_TOKEN", None)
    env["KRB5_CONFIG"] = KRB5_CONF
    env["KRB5CCNAME"] = ccache
    return env


class _Result:
    """bytes-safe result view: a krb5 failure emits non-UTF8 protocol-name bytes on
    stderr, and text=True would raise UnicodeDecodeError inside the harness."""

    def __init__(self, cp):
        self.returncode = cp.returncode
        self.stdout = cp.stdout.decode("utf-8", "replace")
        self.stderr = cp.stderr.decode("utf-8", "replace")


def _xrdfs(server, *args, ccache, timeout=40):
    url = f"root://{url_host(HOST)}:{server['port']}"
    return _Result(subprocess.run([XRDFS, "--auth", "krb5", url, *args],
                                  capture_output=True,
                                  env=_client_env(ccache), timeout=timeout))


# --------------------------------------------------------------------------
# the gate: a delegated fetch traverses the whole krb5 chain byte-exact
# --------------------------------------------------------------------------

def test_delegated_fetch_byte_exact(cache_origin, tmp_path):
    """Forwardable TGT → cache captures it → cache presents a raw AP-REQ to the
    krb5-ONLY stock origin → probe delivered byte-exact.  Because the origin
    admits no protocol but krb5, a correct download is airtight proof the cache's
    delegated outbound AP-REQ was accepted by krb5_rd_req end-to-end."""
    out = tmp_path / "probe.out"
    url = f"root://{url_host(HOST)}:{cache_origin['port']}//probe.txt"
    p = _Result(subprocess.run([XRDCP, "-f", "--auth", "krb5", url, str(out)],
                               capture_output=True,
                               env=_client_env(FWD_CCACHE), timeout=40))
    assert p.returncode == 0, (
        f"delegated cache→origin fetch failed:\n{p.stdout}\n{p.stderr}\n"
        f"--- cache log ---\n"
        f"{open(cache_origin['cache_error_log'], errors='replace').read()[-1800:]}")
    assert out.read_bytes() == PROBE_TEXT, "content mismatch through the krb5 chain"


def test_cache_captured_forwarded_tgt(cache_origin):
    """Airtight cache-side proof the delegation ran: the capture marker fires only
    on a successful import of the forwarded KRB_CRED — the credential the outbound
    leg then consumes."""
    out_marker_probe = _xrdfs(cache_origin, "stat", "/probe.txt", ccache=FWD_CCACHE)
    assert out_marker_probe.returncode == 0, \
        f"{out_marker_probe.stdout}\n{out_marker_probe.stderr}"
    with open(cache_origin["cache_error_log"], encoding="utf-8",
              errors="replace") as fh:
        log = fh.read()
    assert CAPTURE_MARKER in log, (
        f"capture marker absent — cache did not import the forwarded TGT:\n"
        f"{log[-2000:]}")


# --------------------------------------------------------------------------
# error path: a missing object through the delegated chain fails cleanly
# --------------------------------------------------------------------------

def test_missing_object_clean_error(cache_origin, tmp_path):
    """A delegated fetch of a non-existent object returns a clean error (not a
    crash / hang) — the composed capture→carry→AP-REQ→origin stack surfaces the
    origin's not-found through the cache rather than wedging."""
    out = tmp_path / "gone.out"
    url = f"root://{url_host(HOST)}:{cache_origin['port']}//nope-missing.dat"
    p = _Result(subprocess.run([XRDCP, "-f", "--auth", "krb5", url, str(out)],
                               capture_output=True,
                               env=_client_env(FWD_CCACHE), timeout=40))
    assert p.returncode != 0, f"missing object unexpectedly succeeded:\n{p.stdout}"
    assert not out.exists() or out.stat().st_size == 0, "partial file left behind"


# --------------------------------------------------------------------------
# security-neg: no forwardable credential ⇒ no delegated origin fetch
# --------------------------------------------------------------------------

def test_nonforwardable_tgt_refused(cache_origin):
    """The stock (non-forwardable) ccache cannot forward a TGT, so the cache has
    no delegated credential to build an origin AP-REQ from: the request fails
    closed rather than silently reaching the origin with a service credential."""
    p = _xrdfs(cache_origin, "stat", "/probe.txt", ccache=KRB5_CCACHE)
    assert p.returncode != 0, (
        f"non-forwardable TGT was accepted under delegation!\n{p.stdout}")
    blob = (p.stderr + p.stdout).lower()
    assert "forward" in blob or "krb5" in blob or "auth" in blob, p.stderr


# --------------------------------------------------------------------------
# path-op leg: a delegated directory listing forwards the krb5 TGT to the
# origin (exercises sd_xroot_session's krb5 credential carry — the non-read
# namespace path, distinct from the read-fill open covered above)
# --------------------------------------------------------------------------

def test_delegated_dirlist_forwards_krb5(cache_origin):
    """A delegated `ls /` must reach the krb5-ONLY origin AS the user and enumerate
    its objects.  opendir on the composed cache relays to the origin through
    sd_xroot_opendir_cred → sd_xroot_session, which (unlike the read-fill open)
    carries the credential via sd_xroot_cred_copy; without krb5 in that copier the
    listing would present no credential and the krb5-only origin would refuse it.
    Enumerating the origin's objects is thus proof the path-op leg forwards the
    forwarded TGT end-to-end."""
    p = _xrdfs(cache_origin, "ls", "/", ccache=FWD_CCACHE)
    assert p.returncode == 0, (
        f"delegated dirlist failed:\n{p.stdout}\n{p.stderr}\n--- cache log ---\n"
        f"{open(cache_origin['cache_error_log'], errors='replace').read()[-1800:]}")
    listing = p.stdout
    assert "probe.txt" in listing and "blob.bin" in listing, (
        f"origin objects absent from the delegated listing:\n{listing}")
