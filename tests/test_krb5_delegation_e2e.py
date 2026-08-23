"""
Native krb5 inbound TGT-delegation, end-to-end — phase-70 §5.7.1 item 1.

Closes the last synchronous krb5 seam with a *live* two-round exchange against a
real MIT KDC: the clean-room client (client/lib/auth/sec/sec_krb5.c, now with a
``more()`` round-2 handler) forwards its TGT in answer to the server's
``kXR_authmore`` "fwdtgt" continuation, and the acceptor
(src/auth/krb5/deleg_capture.c ``brix_krb5_deleg_capture``) decrypts + imports it.

Where test_native_krb5.py proves the *single-round* AP-REQ path, this proves the
*delegation* path is exercised end-to-end and genuinely consumes the forwarded
credential:

* positive — a **forwardable** client TGT (kinit -f) drives the two-round exchange
  to a successful login; the server logs "krb5 delegation captured forwarded TGT"
  (info) once it has imported the KRB_CRED — the airtight proof the capture ran.
* security-neg — a **non-forwardable** TGT (the stock kinit -k -t ccache) cannot
  satisfy the "fwdtgt" challenge: the client fails closed rather than silently
  downgrading, so the login is refused.  This shows the capture is not a no-op —
  the server really requires the forwarded cred when `brix_krb5_delegate on`.

Self-contained: its own nginx (delegate template) on a fixed port + the session
KDC.  Skips cleanly without MIT KDC tooling or a krb5-less client build.

Run (serial):
    PYTHONPATH=tests pytest tests/test_krb5_delegation_e2e.py -v -p no:xdist
"""

import os
import shutil
import subprocess

import pytest

import kdc_helpers
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

def _guard_deleg_server_1():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")

def _guard_deleg_server_2(proc):
    if proc.returncode != 0 or not os.path.exists(XRDFS):
        pytest.skip(f"native build failed:\n{proc.stdout}\n{proc.stderr}")

def _guard_deleg_server_3():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

def _guard_deleg_server_4():
    if not kdc_helpers.krb5_tools_available():
        pytest.skip("MIT KDC tooling not installed (install krb5-server)")

def _guard_deleg_server_5():
    if not kdc_helpers.up():
        pytest.skip("krb5 realm could not be provisioned")

def _guard_deleg_server_6():
    if not _client_has_krb5():
        kdc_helpers.down()
        pytest.skip("client built without -DBRIX_HAVE_KRB5")

def _guard_deleg_server_7():
    if not _kinit_forwardable():
        kdc_helpers.down()
        pytest.skip("KDC would not issue a forwardable TGT (kinit -f)")

def _guard_deleg_server_8():
    if os.path.exists(FWD_CCACHE):
        os.unlink(FWD_CCACHE)


pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-native-krb5-deleg")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")

# Dedicated forwardable ccache — the stock KRB5_CCACHE (kinit -k -t, no -f) is a
# NON-forwardable TGT we reuse as-is for the security-negative.
FWD_CCACHE = KRB5_CCACHE + ".fwd"

CAPTURE_MARKER = "krb5 delegation captured forwarded TGT"


def _client_has_krb5():
    """The client links libkrb5 only when built with -DBRIX_HAVE_KRB5 (the
    deterministic signal); mirrors test_native_krb5._client_has_krb5."""
    if not os.path.exists(XRDFS):
        return False
    ldd = subprocess.run([XRDFS, "-h"], capture_output=True, text=True).stderr
    if "krb5" not in ldd:
        return False
    linked = subprocess.run(["ldd", XRDFS], capture_output=True, text=True).stdout
    return "libkrb5" in linked


def _kinit_forwardable():
    """kinit a FORWARDABLE alice TGT into FWD_CCACHE (kinit -f), non-interactively
    from the client keytab.  Returns True on success."""
    env = {k: v for k, v in os.environ.items()}
    env["KRB5_CONFIG"] = KRB5_CONF
    proc = subprocess.run(
        [shutil.which("kinit") or "kinit", "-f", "-k", "-t", KRB5_CLIENT_KEYTAB,
         "-c", FWD_CCACHE, KRB5_CLIENT_PRINCIPAL],
        capture_output=True, text=True, env=env, timeout=30)
    return proc.returncode == 0


@pytest.fixture()
def deleg_server(lifecycle, tmp_path):
    _guard_deleg_server_1()
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs"],
                          capture_output=True, text=True, timeout=180)
    _guard_deleg_server_2(proc)
    _guard_deleg_server_3()
    _guard_deleg_server_4()
    _guard_deleg_server_5()

    data = tmp_path / "data"
    data.mkdir()
    (data / "probe.txt").write_bytes(b"krb5-deleg-ok\n")

    os.environ["KRB5_CONFIG"] = KRB5_CONF

    try:
        ep = lifecycle.start(NginxInstanceSpec(
            name="lc-native-krb5-deleg",
            template="nginx_lc_native_krb5_delegate.conf",
            protocol="root",
            template_values={
                "BIND_HOST": url_host(BIND_HOST),
                "DATA_DIR": str(data),
                "PRINCIPAL": KRB5_SERVICE_PRINCIPAL,
                "KEYTAB": KRB5_KEYTAB,
            },
            env={"KRB5_CONFIG": KRB5_CONF},
            reason="stream krb5 inbound delegation"))
    except Exception:
        kdc_helpers.down()
        raise

    _guard_deleg_server_6()
    _guard_deleg_server_7()

    error_log = os.path.join(os.path.dirname(ep.pidfile), "error.log")
    try:
        yield {"port": ep.port, "error_log": error_log}
    finally:
        _guard_deleg_server_8()
        kdc_helpers.down()


def _client_env(ccache):
    env = {k: v for k, v in os.environ.items()}
    env.pop("X509_USER_PROXY", None)
    env.pop("BEARER_TOKEN", None)
    env["KRB5_CONFIG"] = KRB5_CONF
    env["KRB5CCNAME"] = ccache
    return env


def _xrdfs(server, *args, ccache, timeout=30):
    url = f"root://{url_host(HOST)}:{server['port']}"
    return subprocess.run([XRDFS, "--auth", "krb5", url, *args],
                          capture_output=True, text=True,
                          env=_client_env(ccache), timeout=timeout)


# --------------------------------------------------------------------------
# the gate: a forwardable TGT drives the two-round capture to a live login
# --------------------------------------------------------------------------

def test_forwardable_tgt_completes_delegation(deleg_server):
    """Forwardable TGT → the client answers "fwdtgt" with a forwarded KRB_CRED,
    the server imports it and the login succeeds."""
    p = _xrdfs(deleg_server, "stat", "/probe.txt", ccache=FWD_CCACHE)
    assert p.returncode == 0, f"delegated stat failed:\n{p.stdout}\n{p.stderr}"
    assert "Size:" in p.stdout, p.stdout


def test_server_logs_capture_marker(deleg_server):
    """Airtight proof the SERVER captured the forwarded TGT (not merely that the
    rounds completed): the info marker only fires on a successful import."""
    p = _xrdfs(deleg_server, "ls", "/", ccache=FWD_CCACHE)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    with open(deleg_server["error_log"], encoding="utf-8", errors="replace") as fh:
        log = fh.read()
    assert CAPTURE_MARKER in log, (
        f"capture marker absent — delegation did not complete server-side:\n{log[-2000:]}")


# --------------------------------------------------------------------------
# security-neg: a non-forwardable TGT cannot satisfy delegation → fail closed
# --------------------------------------------------------------------------

def test_nonforwardable_tgt_refused(deleg_server):
    """The stock (non-forwardable) ccache cannot forward a TGT: the client fails
    closed with a clear message rather than silently logging in undelegated —
    proving the forwarded credential is genuinely required + consumed."""
    p = _xrdfs(deleg_server, "stat", "/probe.txt", ccache=KRB5_CCACHE)
    assert p.returncode != 0, (
        f"non-forwardable TGT was accepted under delegation!\n{p.stdout}")
    blob = (p.stderr + p.stdout).lower()
    assert "forward" in blob or "krb5" in blob, p.stderr
