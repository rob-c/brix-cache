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

import glob
import os
import shutil
import subprocess
import time

import pytest

from settings import BIND_HOST, NGINX_BIN, PKI_DIR, SERVER_HOST
from ephemeral_port import free_port          # native stock-xrootd upstream
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from gridftp_client_env import gsi_client_env

def _phase_init_1(cfg, self):
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

def _phase_init_2(base, self):
    for d in (base, self.data):
        _run(["chmod", "-R", "a+rwX", d])

def _phase_init_3():
    for sub in (PKI_DIR, CA_DIR, os.path.join(PKI_DIR, "server")):
        _guard_init_5(sub)

def _phase_init_4():
    for pem in (SERVER_CERT, *glob.glob(
            os.path.join(CA_DIR, "*.pem"))):
        _guard_init_6(pem)


def _guard_require_1():
    if GUC is None:
        pytest.skip("globus-url-copy not on PATH")

def _guard_require_2():
    if not (shutil.which("xrootd") and shutil.which("xrdgsiproxy")):
        pytest.skip("stock xrootd / xrdgsiproxy not installed")

def _guard_require_3():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

def _guard_require_4(p):
    if not os.path.exists(p):
        pytest.skip(f"test PKI incomplete: missing {p}")

def _guard_init_7(runas):
    if os.path.exists(SERVER_KEY):
        shutil.chown(SERVER_KEY, runas)
        os.chmod(SERVER_KEY, 0o400)

def _guard_init_5(sub):
    if os.path.isdir(sub):
        _run(["chmod", "a+rx", sub])

def _guard_init_6(pem):
    if os.path.exists(pem):
        _run(["chmod", "a+r", pem])


pytestmark = [pytest.mark.slow, pytest.mark.serial,
              pytest.mark.timeout(300), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("gridftp-deleg")]

GUC = shutil.which("globus-url-copy")
SERVER_CERT = os.path.join(PKI_DIR, "server", "hostcert.pem")
SERVER_KEY = os.path.join(PKI_DIR, "server", "hostkey.pem")
CA_DIR = os.path.join(PKI_DIR, "ca")
USER_PROXY = os.path.join(PKI_DIR, "user", "proxy_std.pem")

# The upstream host cert CN is `localhost` (shared PKI), so the gateway must dial
# the xrootd via that exact name for the GSI host-name/DN check to pass.
REF_HOST = SERVER_HOST
USER_DN_MARK = "CN=Test User"


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=40, **kw)


def _require():
    _guard_require_1()
    _guard_require_2()
    _guard_require_3()
    for p in (SERVER_CERT, SERVER_KEY, CA_DIR, USER_PROXY):
        _guard_require_4(p)


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
        _phase_init_1(cfg, self)
        # No `-n <instance>`: it relocates the `-l` file into an instance
        # subdirectory, hiding the log from log_text().
        argv = ["xrootd", "-c", cfg, "-l", self.log]
        # Root-harness privilege drop: stock xrootd refuses to run as superuser
        # ("Security reasons prohibit running as superuser"), so under a root
        # harness we run it via `-R nobody` and pre-open every path that user
        # must then touch — the exported data dir (a+rwX), the log file, and the
        # shared GSI PKI (hostkey.pem 0400-root is unreadable by nobody, which
        # otherwise fails GSI init and the port never opens).
        if os.geteuid() == 0:
            runas = os.environ.get("REF_RUNAS_USER", "nobody")
            _phase_init_2(base, self)
            open(self.log, "w").close()
            shutil.chown(self.log, runas)
            _phase_init_3()
            _phase_init_4()
            _guard_init_7(runas)
            argv += ["-R", runas]
        self._proc = subprocess.Popen(
            argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
        self.data_root = endpoint.data_root   # the gateway's OWN export
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
    env = gsi_client_env(CA_DIR, USER_PROXY)
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
    r = _guc(f"gsiftp://{SERVER_HOST}:{gateway.port}/dl.bin", f"file://{dst}")
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
    r = _guc(f"gsiftp://{SERVER_HOST}:{gateway.port}/does-not-exist.bin",
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
        r = _guc(f"gsiftp://{SERVER_HOST}:{gw.port}/guarded.bin", f"file://{dst}")
        assert r.returncode != 0, (
            "mode select still served the object — the client proxy was forwarded "
            f"despite forwarding being disabled\n{r.stdout}\n{gw.error_log()}")
    finally:
        gw.close()
    after = xrd.log_text().count(USER_DN_MARK)
    assert after == before, (
        "upstream logged a NEW user DN login under `mode select` — the proxy was "
        f"forwarded when it must not have been (before={before} after={after})")


# --------------------------------------------------------------------------- #
# STOR — the write half of the gridftp x xroot cell.                           #
#                                                                              #
# `brix_gridftp_allow_write on` has been in this config since phase 82, but    #
# only RETR was ever driven, so the whole sd_xroot write path (create-open,    #
# chunked write, close) was configured-but-never-executed under delegation.    #
# docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md item 14.  #
# --------------------------------------------------------------------------- #
def _upstream_bytes(xrd, name):
    """Read an object straight off the upstream's export tree.

    Deliberately NOT a RETR back through the gateway: reading it back the same
    way it was written would pass even if the gateway had answered from its own
    export instead of the xrootd, which is the exact confusion this cell exists
    to rule out.
    """
    path = os.path.join(xrd.data, name)
    if not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        return fh.read()


def test_delegated_stor_writes_through_to_the_upstream(gateway, xrd, tmp_path):
    """STOR lands on the UPSTREAM, byte-exact, authenticated as the user.

    Multi-chunk on purpose: a single-buffer upload would not exercise the
    sd_xroot write loop's offset accounting at all.
    """
    payload = b"stored-through-xrootd \x00\xff " + os.urandom(300 * 1024)
    src = os.path.join(str(tmp_path), "put.bin")
    with open(src, "wb") as fh:
        fh.write(payload)
    before = xrd.log_text().count(USER_DN_MARK)

    r = _guc(f"file://{src}", f"gsiftp://{SERVER_HOST}:{gateway.port}/stored.bin")
    assert r.returncode == 0, (
        f"delegated STOR failed rc={r.returncode}\n{r.stderr}\n"
        f"--- gateway ---\n{gateway.error_log()}\n--- xrootd ---\n{xrd.log_text()}")

    got = _upstream_bytes(xrd, "stored.bin")
    assert got is not None, (
        "STOR reported success but nothing reached the upstream export — the "
        f"bytes went somewhere else\n{gateway.error_log()}")
    assert got == payload, f"upstream object differs: {len(got)} vs {len(payload)}"
    assert xrd.log_text().count(USER_DN_MARK) > before, (
        "the write leg logged no user DN — the proxy was not forwarded for STOR")


def test_stored_object_round_trips_back_through_the_gateway(gateway, xrd, tmp_path):
    """The object written over gsiftp reads back identically over gsiftp.

    Closes the STOR→RETR round trip that gridftp x pblock and gridftp x s3
    already had and this cell did not.
    """
    payload = b"round-trip " + os.urandom(64 * 1024)
    src = os.path.join(str(tmp_path), "rt.bin")
    with open(src, "wb") as fh:
        fh.write(payload)
    assert _guc(f"file://{src}",
                f"gsiftp://{SERVER_HOST}:{gateway.port}/rt.bin").returncode == 0
    dst = os.path.join(str(tmp_path), "rt.out")
    r = _guc(f"gsiftp://{SERVER_HOST}:{gateway.port}/rt.bin", f"file://{dst}")
    assert r.returncode == 0, f"{r.stderr}\n{gateway.error_log()}"
    with open(dst, "rb") as fh:
        assert fh.read() == payload


def test_overwriting_an_existing_upstream_object_replaces_it(gateway, xrd,
                                                             tmp_path):
    """A second STOR to the same name truncates rather than appending.

    A write path that opens without truncation leaves the tail of the previous
    object behind — invisible in the success rc, visible in the size.
    """
    xrd.place("clobber.bin", b"O" * 200000)
    payload = b"N" * 5000
    src = os.path.join(str(tmp_path), "clobber.src")
    with open(src, "wb") as fh:
        fh.write(payload)
    r = _guc(f"file://{src}",
             f"gsiftp://{SERVER_HOST}:{gateway.port}/clobber.bin")
    assert r.returncode == 0, f"{r.stderr}\n{gateway.error_log()}"
    assert _upstream_bytes(xrd, "clobber.bin") == payload, (
        "overwrite did not truncate — the previous object's tail survived")


def test_stor_creates_the_parent_chain_on_the_upstream_only(gateway, xrd,
                                                            tmp_path):
    """A STOR whose parent does not exist succeeds by building the chain UPSTREAM.

    Measured, not assumed: the create-open mkpaths on the xrootd, so `no/such/
    dir/orphan.bin` materialises under the upstream's export. The half of this
    that is worth pinning is the *other* half — the gateway has a local
    `brix_gridftp_export` of its own, and a write path that fell back to it
    would look identical from the client (rc 0) while putting the bytes on the
    wrong host entirely. So: present upstream, absent locally.
    """
    payload = b"z" * 1024
    src = os.path.join(str(tmp_path), "orphan.bin")
    with open(src, "wb") as fh:
        fh.write(payload)
    r = _guc(f"file://{src}",
             f"gsiftp://{SERVER_HOST}:{gateway.port}/no/such/dir/orphan.bin")
    assert r.returncode == 0, f"{r.stderr}\n{gateway.error_log()}"
    assert _upstream_bytes(xrd, "no/such/dir/orphan.bin") == payload
    stray = os.path.join(gateway.data_root, "no", "such", "dir", "orphan.bin")
    assert not os.path.exists(stray), (
        f"the write landed on the GATEWAY's local export, not the upstream: {stray}")


def test_stor_traversal_is_refused(gateway, xrd, tmp_path):
    """Security-negative: `..` must not write outside the upstream export.

    The read side of this boundary was never tested either; a write that
    escapes is strictly worse than a read that does.
    """
    src = os.path.join(str(tmp_path), "escape.bin")
    with open(src, "wb") as fh:
        fh.write(b"escaped")
    target = os.path.join(os.path.dirname(xrd.data), "escaped.bin")
    r = _guc(f"file://{src}",
             f"gsiftp://{SERVER_HOST}:{gateway.port}/../escaped.bin")
    assert not os.path.exists(target), (
        f"traversal wrote OUTSIDE the upstream export: {target}")
    if r.returncode == 0:
        # Some clients normalise `..` away before it reaches the wire; then the
        # write must have landed INSIDE the export, never above it.
        assert _upstream_bytes(xrd, "escaped.bin") == b"escaped"
