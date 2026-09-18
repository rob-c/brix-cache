"""
test_official_xrootd_resilience.py — this repo's FUSE client vs a REAL XRootD
server, through an on-the-wire fault injector.

WHAT: Mounts THIS codebase's clean-room FUSE driver (client/xrootdfs, built on
      libbrix — no libXrdCl) against the OFFICIAL `xrootd` daemon, with the
      in-repo TCP fault proxy (brix-fault-proxy) spliced in between, and
      asserts that a file reads back byte-exact under a matrix of wire faults:
      latency, tiny segmentation, sustained packet loss (incl. 12%), single and
      repeated mid-transfer connection drops, and a multi-second outage — plus
      that the mount keeps working afterwards.

WHY:  Two guarantees at once:
        (a) COMPATIBILITY — the native client speaks the XRootD wire protocol to
            a real, unmodified xrootd server (the clean baseline read proves it).
        (b) RESILIENCE — it survives a misbehaving inline firewall (drops/loss/
            hangs) and recovers transparently rather than surfacing EIO.

HOW:  client  ->  brix-fault-proxy  ->  official xrootd
      Faults are toggled over the proxy's control port mid-read.

Skips cleanly when the official `xrootd` is absent or the host has no
unprivileged FUSE (see lib_py/fuse_host.py).

Run:
  PYTHONPATH=tests python3 -m pytest tests/test_official_xrootd_resilience.py -v
"""
import hashlib
import os
import shutil
import socket
import subprocess
from brix_suite.client_build import client_make
from concurrent.futures import ThreadPoolExecutor
import sys
import threading
import time

import pytest
from lib_py import fuse_host
from settings import BIND_HOST, HOST

def _phase_server_1(proc):
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _guard_server_1():
    if XROOTD is None:
        pytest.skip("official `xrootd` not installed")

def _guard_mount_2():
    if not _FUSE_OK:
        pytest.skip(fuse_host.SKIP_REASON)

def _guard_mount_3():
    if not (os.path.exists(AIO) and os.path.exists(FAULT_PROXY)):
        pytest.skip("xrootdfs / brix-fault-proxy not built")

def _guard_mount_4(ready, proxy, mnt):
    if not ready:
        fuse_host.unmount(str(mnt), lazy=True)
        proxy.terminate()
        pytest.skip("mount did not come up")


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
AIO = os.path.join(CLIENT_DIR, "bin", "xrootdfs")
FAULT_PROXY = os.path.join(CLIENT_DIR, "bin", "brix-fault-proxy")

XROOTD = shutil.which("xrootd")
_FUSE_OK = fuse_host.FUSE_READY

pytestmark = pytest.mark.timeout(420)


def _toolchain_env():
    """Inherit env; expose the conda/venv toolchain (codec/krb5 libs + their .pc)
    for the link step and the runtime loader. No-op outside such a prefix."""
    env = dict(os.environ)
    prefix = env.get("CONDA_PREFIX") or sys.prefix
    pcdir = os.path.join(prefix, "lib", "pkgconfig")
    if os.path.isdir(pcdir):
        libdir = os.path.join(prefix, "lib")
        env["LD_LIBRARY_PATH"] = libdir + os.pathsep + env.get("LD_LIBRARY_PATH", "")
        env["PKG_CONFIG_PATH"] = pcdir + os.pathsep + env.get("PKG_CONFIG_PATH", "")
    return env


ENV = _toolchain_env()


def _free_port():
    from ephemeral_port import free_port
    return free_port(BIND_HOST)


def _port_up(port):
    try:
        with socket.create_connection((HOST, port), timeout=1):
            return True
    except OSError:
        return False


def _ctl(port, cmd):
    with socket.create_connection((HOST, port), timeout=3) as s:
        s.sendall((cmd + "\n").encode())
        return s.recv(128).decode().strip()


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    """A real official xrootd serving a random 8 MiB file at /data/med.bin."""
    _guard_server_1()
    root = tmp_path_factory.mktemp("xrdsrv")
    data = root / "data"
    data.mkdir()
    admin = root / "admin"
    admin.mkdir()
    blob = os.urandom(8 * 1024 * 1024)
    (data / "med.bin").write_bytes(blob)
    ref = hashlib.md5(blob).hexdigest()

    port = _free_port()
    cfg = root / "xrootd.cfg"
    cfg.write_text(
        f"xrd.port {port}\n"
        f"all.adminpath {admin}\n"
        f"all.pidpath {admin}\n"
        f"oss.localroot {root}\n"
        f"all.export /data\n"
        f"xrd.network nodnr\n"
    )
    log = root / "xrootd.log"
    argv = [XROOTD, "-c", str(cfg), "-l", str(log)]
    if os.geteuid() == 0:
        # Official xrootd refuses to run as superuser. Drop to an unprivileged
        # account with -R, and pre-open the paths that account must reach: the
        # localroot data tree (readable), the adminpath/pidpath dir (writable),
        # and the log dir (writable). Server is PLAIN (no GSI key) so that's all.
        runas = os.environ.get("REF_RUNAS_USER", "nobody")
        subprocess.run(["chmod", "-R", "a+rwX", str(root)])       # localroot + log dir
        subprocess.run(["chmod", "-R", "a+rwX", str(admin)])      # adminpath / pidpath
        argv += ["-R", runas]
    proc = subprocess.Popen(argv,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if _port_up(port):
                break
            if proc.poll() is not None:
                tail = log.read_text()[-600:] if log.exists() else "(no log written)"
                pytest.skip(f"xrootd failed to start:\n{tail}")
            time.sleep(0.2)
        else:
            pytest.skip("xrootd did not start listening in time")
        yield {"port": port, "ref": ref}
    finally:
        proc.terminate()
        _phase_server_1(proc)


@pytest.fixture(scope="module")
def mount(server, tmp_path_factory):
    """brix-fault-proxy in front of the server + this repo's xrootdfs mounted on it.
    Yields (mountfile_path, ctl) where ctl(cmd) drives the fault levers."""
    _guard_mount_2()
    # Build the FUSE driver + fault proxy (best-effort; skip if the link can't be
    # satisfied in this environment).
    client_make(CLIENT_DIR, "xrootdfs", "brix-fault-proxy", env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
    _guard_mount_3()

    listen, ctlp = _free_port(), _free_port()
    mnt = tmp_path_factory.mktemp("mnt")
    proxy = subprocess.Popen([FAULT_PROXY, str(listen), HOST,
                              str(server["port"]), str(ctlp)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    mlog = open(os.path.join(str(mnt) + ".log"), "w")
    fs = subprocess.Popen(
        [AIO, "--max-stall", "30000", "--keepalive", "3000", "--max-retries", "12",
         f"root://{HOST}:{listen}/", "-f", str(mnt)],
        env=ENV, stdout=mlog, stderr=mlog)
    mfile = os.path.join(str(mnt), "data", "med.bin")
    ready = False
    for _ in range(60):
        time.sleep(0.25)
        if os.path.exists(mfile):
            ready = True
            break
        if fs.poll() is not None:
            break
    _guard_mount_4(ready, proxy, mnt)

    def ctl(cmd):
        return _ctl(ctlp, cmd)

    try:
        yield mfile, ctl, server["ref"]
    finally:
        fuse_host.unmount(str(mnt), lazy=True)
        proxy.terminate()


def _read_md5(path, watchdog=120):
    out = {}

    def run():
        h = hashlib.md5()
        n = 0
        try:
            with open(path, "rb") as f:
                while True:
                    b = f.read(1 << 20)
                    if not b:
                        break
                    h.update(b)
                    n += len(b)
            out["md5"], out["n"], out["err"] = h.hexdigest(), n, None
        except OSError as e:
            out["md5"], out["n"], out["err"] = None, n, str(e)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(watchdog)
    if t.is_alive():
        return None, 0, "watchdog-timeout"
    return out["md5"], out["n"], out["err"]


def _apply_fault_schedule(ctl, schedule):
    for delay, command in schedule:
        time.sleep(delay)
        ctl(command)


def _read_with_faults(path, ctl, schedule):
    """Own the scheduler until it finishes, including when the read fails.

    A detached scheduler can alter the next test's link or contact a proxy
    already torn down. Joining before returning also makes control failures
    fail this test instead of surfacing later as thread-exception warnings.
    """
    with ThreadPoolExecutor(max_workers=1) as pool:
        faults = pool.submit(_apply_fault_schedule, ctl, schedule)
        result = _read_md5(path)
        faults.result()
        return result


def test_baseline_compat(mount):
    """Clean read through the proxy — proves wire-compatibility with real xrootd."""
    mfile, ctl, ref = mount
    ctl("clear")
    md5, n, err = _read_md5(mfile)
    assert md5 == ref, f"n={n} err={err}"


@pytest.mark.parametrize("fault", ["latency 3", "chunk 8192", "lossy 5", "lossy 12"])
def test_degraded_link(mount, fault):
    """High RTT, tiny segmentation, and sustained packet loss (incl. 12%) all read
    back byte-exact — the client rides out the degradation."""
    mfile, ctl, ref = mount
    ctl("clear")
    ctl(fault)
    md5, n, err = _read_md5(mfile)
    ctl("clear")
    assert md5 == ref, f"fault={fault} n={n} err={err}"


def test_drop_mid_transfer(mount):
    """A single connection sever mid-read — reconnect + resume, byte-exact."""
    mfile, ctl, ref = mount
    ctl("clear")
    ctl("latency 2")
    md5, n, err = _read_with_faults(mfile, ctl, [(0.6, "drop")])
    ctl("clear")
    assert md5 == ref, f"n={n} err={err}"


def test_repeated_drops(mount):
    """Three severs during one read — still recovers."""
    mfile, ctl, ref = mount
    ctl("clear")
    ctl("latency 3")
    md5, n, err = _read_with_faults(
        mfile, ctl, [(0.5, "drop"), (1.2, "drop"), (1.9, "drop")])
    ctl("clear")
    assert md5 == ref, f"n={n} err={err}"


def test_outage_then_recovery(mount):
    """A multi-second total outage mid-read is survived (within --max-stall), and
    the very next read succeeds — the mount is not wedged by the outage."""
    mfile, ctl, ref = mount
    ctl("clear")
    ctl("latency 2")
    md5, n, err = _read_with_faults(
        mfile, ctl, [(0.5, "block"), (3.5, "unblock")])
    assert md5 == ref, f"(outage) n={n} err={err}"
    ctl("clear")
    md5b, n2, err2 = _read_md5(mfile)
    assert md5b == ref, f"(post-outage) n={n2} err={err2}"
