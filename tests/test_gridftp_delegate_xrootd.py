"""gsiftp → xrootd credential-delegation gateway (phase-82, native loopback E2E).

WHAT THIS PROVES: a gsiftp client that delegates its X.509 proxy on the control
channel drives the brix gateway, which forwards that *same* proxy to an upstream
``root://`` xrootd storage server so the upstream authenticates AS THE USER — the
legacy gsiftp → xrootd storage gateway.  The keystone is not "bytes moved" but
"the native xrootd logged ``CN=Test User``": the user's identity crossed two hops
(client → gateway → storage) end to end.

Topology, all on loopback, real GSI on both legs:

    globus-url-copy  --gsi-->  brix gsiftp gateway  --root:// GSI-->  stock xrootd
    (X509_USER_PROXY)          (forwards the proxy)  (verifies the forwarded proxy)

The upstream is a STOCK ``xrootd`` pointed at the SHARED test PKI ($TEST_ROOT/pki)
so the proxy delegated by the client (minted from that CA) verifies against the
same host cert/CA the gateway trusts.  ``-gridmap:none`` keeps the raw DN as the
identity so the log carries ``CN=Test User`` verbatim.

Three cases (success + error + security-negative, per the change contract):
  * test_delegated_get_authenticates_as_user  — default PASSTHROUGH: GET a file
      placed on the upstream round-trips byte-identical AND the upstream log shows
      the user DN (proxy forwarded, upstream authed the user).
  * test_missing_object_errors                — RETR of an absent object → nonzero
      client rc (backend/gateway error path intact under delegation).
  * test_mode_select_does_not_forward         — a credential block with ``mode
      select`` forwards NOTHING: with no service credential the upstream refuses,
      the transfer fails, and no NEW ``CN=Test User`` login appears — proving the
      credential-block mode gate governs forwarding.

Skips cleanly when the stock GSI toolchain (``xrootd``/``xrdgsiproxy``), the brix
build, ``globus-url-copy``, or the shared PKI are absent.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
        pytest tests/test_gridftp_delegate_xrootd.py -v -s -p no:xdist
"""

import os
import shutil
import subprocess
import time

import pytest

from settings import BIND_HOST, NGINX_BIN, PKI_DIR, free_port
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.slow, pytest.mark.serial,
              pytest.mark.timeout(300), pytest.mark.uses_lifecycle_harness]

GUC = shutil.which("globus-url-copy")
SERVER_CERT = os.path.join(PKI_DIR, "server", "hostcert.pem")
SERVER_KEY = os.path.join(PKI_DIR, "server", "hostkey.pem")
CA_DIR = os.path.join(PKI_DIR, "ca")
USER_PROXY = os.path.join(PKI_DIR, "user", "proxy_std.pem")

# The upstream host cert CN is `localhost` (shared PKI), so the gateway must dial
# the xrootd via that exact name for the GSI host-name/DN check to pass.
REF_HOST = "localhost"
USER_DN_MARK = "CN=Test User"


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=40, **kw)


def _require():
    if GUC is None:
        pytest.skip("globus-url-copy not on PATH")
    if not (shutil.which("xrootd") and shutil.which("xrdgsiproxy")):
        pytest.skip("stock xrootd / xrdgsiproxy not installed")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    for p in (SERVER_CERT, SERVER_KEY, CA_DIR, USER_PROXY):
        if not os.path.exists(p):
            pytest.skip(f"test PKI incomplete: missing {p}")


class _Xrootd:
    """A stock GSI xrootd storage server on the SHARED test PKI, torn down on
    stop().  Exports ``/`` from a private data dir so the gateway's logical paths
    (``/name``) map straight onto it, and logs to a grepable file so the test can
    assert the forwarded user DN reached the upstream."""

    def __init__(self, base):
        self.port = free_port(BIND_HOST)
        self.data = os.path.join(base, "data")
        self.log = os.path.join(base, "xrootd.log")
        os.makedirs(self.data, exist_ok=True)
        cfg = os.path.join(base, "xrootd.cfg")
        with open(cfg, "w") as fh:
            fh.write(
                f"xrd.port {self.port}\n"
                "all.export /\n"
                f"oss.localroot {self.data}\n"
                "xrootd.seclib libXrdSec.so\n"
                f"sec.protocol gsi -certdir:{CA_DIR} "
                f"-cert:{SERVER_CERT} -key:{SERVER_KEY} "
                "-gridmap:none -gmapopt:10 -crl:0 -dlgpxy:0\n"
                "sec.protbind * only gsi\n"
                # Trace the authenticated login so the test can assert the
                # forwarded user DN reached the upstream (default xrootd does not
                # log successful GSI logins).
                "sec.trace 2\n"
                "xrootd.trace login auth\n")
        # No `-n <instance>`: it relocates the `-l` file into an instance
        # subdirectory, hiding the log from log_text().
        self._proc = subprocess.Popen(
            ["xrootd", "-c", cfg, "-l", self.log],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            if _run(["bash", "-c",
                     f"ss -tln | grep -q ':{self.port} '"]).returncode == 0:
                break
            time.sleep(0.1)
        else:
            self.stop()
            pytest.skip("stock xrootd GSI server did not come up")

    def place(self, name, data):
        with open(os.path.join(self.data, name), "wb") as fh:
            fh.write(data)

    def log_text(self):
        try:
            with open(self.log) as fh:
                return fh.read()
        except FileNotFoundError:
            return ""

    def stop(self):
        self._proc.terminate()
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()


class _Gateway:
    """A registry-owned event-engine gsiftp gateway whose storage backend is the
    upstream ``root://`` xrootd, torn down on close()."""

    def __init__(self, harness, name, xrd, cred_mode_line):
        endpoint = harness.start(NginxInstanceSpec(
            name=name,
            template="nginx_gridftp_gsiftp_ev_xrd.conf",
            protocol="root",
            readiness="tcp",
            template_values={
                "BIND_HOST": BIND_HOST,
                "SERVER_CERT": SERVER_CERT,
                "SERVER_KEY": SERVER_KEY,
                "CA_DIR": CA_DIR,
                "REF_HOST": REF_HOST,
                "REF_PORT": str(xrd.port),
                "CRED_MODE_LINE": cred_mode_line,
            },
        ))
        self.harness = harness
        self.port = endpoint.port
        self._log = os.path.join(endpoint.prefix, "logs", "error.log")

    def close(self):
        self.harness.close()

    def error_log(self):
        try:
            with open(self._log) as fh:
                return fh.read()
        except FileNotFoundError:
            return ""


def _guc(*args, timeout=60):
    """globus-url-copy with the grid client env and a delegating (dcpriv) data
    channel — the client forwards its proxy on the control channel."""
    env = dict(os.environ)
    env["X509_CERT_DIR"] = CA_DIR
    env["X509_USER_PROXY"] = USER_PROXY
    return subprocess.run([GUC, "-dcpriv", *args],
                          capture_output=True, text=True, env=env, timeout=timeout)


@pytest.fixture(scope="module")
def xrd(tmp_path_factory):
    _require()
    base = str(tmp_path_factory.mktemp("gsixrd"))
    srv = _Xrootd(base)
    yield srv
    srv.stop()


@pytest.fixture(scope="module")
def gateway(xrd):
    gw = _Gateway(LifecycleHarness(), "gridftp-deleg-xrd", xrd, "")
    yield gw
    gw.close()


def test_delegated_get_authenticates_as_user(gateway, xrd, tmp_path):
    """Default PASSTHROUGH: the client's delegated proxy is forwarded to the
    upstream, which authenticates the user and serves the object byte-identical."""
    payload = b"delegated-through-xrootd \x00\x01\x02 " + os.urandom(4096)
    xrd.place("dl.bin", payload)
    dst = os.path.join(str(tmp_path), "got.bin")
    r = _guc(f"gsiftp://localhost:{gateway.port}/dl.bin", f"file://{dst}")
    assert r.returncode == 0, (
        f"delegated get failed rc={r.returncode}\n{r.stderr}\n"
        f"--- gateway ---\n{gateway.error_log()}\n--- xrootd ---\n{xrd.log_text()}")
    with open(dst, "rb") as fh:
        assert fh.read() == payload
    # Keystone: the user's identity crossed client → gateway → storage.
    assert USER_DN_MARK in xrd.log_text(), (
        "upstream xrootd never logged the forwarded user DN — the proxy did not "
        f"reach the storage server\n{xrd.log_text()}")


def test_missing_object_errors(gateway, xrd):
    """A RETR of an absent object fails with a nonzero client rc even on the
    delegating path (error handling intact under forwarding)."""
    r = _guc(f"gsiftp://localhost:{gateway.port}/does-not-exist.bin",
             "file:///dev/null")
    assert r.returncode != 0, (
        f"missing object unexpectedly succeeded\n{r.stdout}\n{gateway.error_log()}")


def test_mode_select_does_not_forward(xrd, tmp_path):
    """Security-negative: a credential block with ``mode select`` forwards nothing.
    With no service credential the upstream refuses GSI, the transfer fails, and no
    NEW ``CN=Test User`` login is recorded — proving the mode gate governs
    forwarding, not merely reachability."""
    xrd.place("guarded.bin", os.urandom(2048))
    before = xrd.log_text().count(USER_DN_MARK)
    gw = _Gateway(LifecycleHarness(), "gridftp-deleg-xrd-select", xrd,
                  "mode select;")
    try:
        dst = os.path.join(str(tmp_path), "denied.bin")
        r = _guc(f"gsiftp://localhost:{gw.port}/guarded.bin", f"file://{dst}")
        assert r.returncode != 0, (
            "mode select still served the object — the client proxy was forwarded "
            f"despite forwarding being disabled\n{r.stdout}\n{gw.error_log()}")
    finally:
        gw.close()
    after = xrd.log_text().count(USER_DN_MARK)
    assert after == before, (
        "upstream logged a NEW user DN login under `mode select` — the proxy was "
        f"forwarded when it must not have been (before={before} after={after})")
