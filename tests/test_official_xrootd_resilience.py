"""
test_official_brix_resilience.py — this repo's FUSE client vs a REAL XRootD
server, through an on-the-wire fault injector.

WHAT: Mounts THIS codebase's clean-room FUSE driver (client/xrootdfs, built on
      libbrix — no libXrdCl) against the OFFICIAL `xrootd` daemon, with the
      in-repo TCP fault proxy (tests/c/fault_proxy.c) spliced in between, and
      asserts that a file reads back byte-exact under a matrix of wire faults:
      latency, tiny segmentation, sustained packet loss (incl. 12%), single and
      repeated mid-transfer connection drops, and a multi-second outage — plus
      that the mount keeps working afterwards.

WHY:  Two guarantees at once:
        (a) COMPATIBILITY — the native client speaks the XRootD wire protocol to
            a real, unmodified xrootd server (the clean baseline read proves it).
        (b) RESILIENCE — it survives a misbehaving inline firewall (drops/loss/
            hangs) and recovers transparently rather than surfacing EIO.

HOW:  client  ->  fault_proxy  ->  official xrootd
      Faults are toggled over the proxy's control port mid-read.

Skips cleanly when the official `xrootd`, /dev/fuse, or fusermount3 is absent.

Run:
  PYTHONPATH=tests python3 -m pytest tests/test_official_brix_resilience.py -v
"""
import hashlib
import os
import shutil
import socket
import subprocess
import sys
import threading
import time

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
AIO = os.path.join(CLIENT_DIR, "bin", "xrootdfs")
FAULT_PROXY = os.path.join(CLIENT_DIR, "bin", "fault_proxy")

XROOTD = shutil.which("xrootd")
_FUSE_OK = os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None

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
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _port_up(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def _ctl(port, cmd):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        s.sendall((cmd + "\n").encode())
        return s.recv(128).decode().strip()


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    """A real official xrootd serving a random 8 MiB file at /data/med.bin."""
    if XROOTD is None:
        pytest.skip("official `xrootd` not installed")
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
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture(scope="module")
def mount(server, tmp_path_factory):
    """fault_proxy in front of the server + this repo's xrootdfs mounted on it.
    Yields (mountfile_path, ctl) where ctl(cmd) drives the fault levers."""
    if not _FUSE_OK:
        pytest.skip("no /dev/fuse or fusermount3")
    # Build the FUSE driver + fault proxy (best-effort; skip if the link can't be
    # satisfied in this environment).
    subprocess.run(["make", "xrootdfs", "fault-proxy"], cwd=CLIENT_DIR, env=ENV,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
    if not (os.path.exists(AIO) and os.path.exists(FAULT_PROXY)):
        pytest.skip("xrootdfs / fault_proxy not built")

    listen, ctlp = _free_port(), _free_port()
    mnt = tmp_path_factory.mktemp("mnt")
    proxy = subprocess.Popen([FAULT_PROXY, str(listen), "127.0.0.1",
                              str(server["port"]), str(ctlp)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    mlog = open(os.path.join(str(mnt) + ".log"), "w")
    fs = subprocess.Popen(
        [AIO, "--max-stall", "30000", "--keepalive", "3000", "--max-retries", "12",
         f"root://127.0.0.1:{listen}/", "-f", str(mnt)],
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
    if not ready:
        subprocess.run(["fusermount3", "-u", "-z", str(mnt)], capture_output=True)
        proxy.terminate()
        pytest.skip("mount did not come up")

    def ctl(cmd):
        return _ctl(ctlp, cmd)

    try:
        yield mfile, ctl, server["ref"]
    finally:
        subprocess.run(["fusermount3", "-u", "-z", str(mnt)], capture_output=True)
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


def _fire(ctl, schedule):
    """Run (delay, cmd) pairs from a background thread while a read is in flight."""
    def go():
        for d, c in schedule:
            time.sleep(d)
            ctl(c)
    threading.Thread(target=go, daemon=True).start()


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
    _fire(ctl, [(0.6, "drop")])
    md5, n, err = _read_md5(mfile)
    ctl("clear")
    assert md5 == ref, f"n={n} err={err}"


def test_repeated_drops(mount):
    """Three severs during one read — still recovers."""
    mfile, ctl, ref = mount
    ctl("clear")
    ctl("latency 3")
    _fire(ctl, [(0.5, "drop"), (1.2, "drop"), (1.9, "drop")])
    md5, n, err = _read_md5(mfile)
    ctl("clear")
    assert md5 == ref, f"n={n} err={err}"


def test_outage_then_recovery(mount):
    """A multi-second total outage mid-read is survived (within --max-stall), and
    the very next read succeeds — the mount is not wedged by the outage."""
    mfile, ctl, ref = mount
    ctl("clear")
    ctl("latency 2")
    _fire(ctl, [(0.5, "block"), (3.5, "unblock")])
    md5, n, err = _read_md5(mfile)
    assert md5 == ref, f"(outage) n={n} err={err}"
    ctl("clear")
    md5b, n2, err2 = _read_md5(mfile)
    assert md5b == ref, f"(post-outage) n={n2} err={err2}"
