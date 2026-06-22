"""
test_xrootdfs_resilience.py — M6: network-resilience tests for xrootdfs.

WHAT: Mounts the async FUSE driver THROUGH an in-repo TCP fault-proxy
      (tests/c/fault_proxy.c, no root) and asserts that file transfers survive the
      conditions of a bad link — high latency, a mid-transfer connection drop, and a
      short outage window — byte-exact and with NO EIO surfaced to the application.
WHY:  Proves the async core's reconnect (M2) + file-handle resumption (M3) end-to-
      end through the real mount (M4): "survives bad wifi from a laptop abroad".
HOW:  The proxy relays localhost:<listen> → the real anon server; the test pulls
      fault levers over the proxy's control port mid-read.

Run (against a stable private server):
  TEST_ROOT=/tmp/xrd-aio TEST_NGINX_ANON_PORT=11199 TEST_SKIP_SERVER_SETUP=1 \
    PYTHONPATH=tests python3 -m pytest tests/test_xrootdfs_resilience.py -v -p no:xdist
"""
import hashlib
import os
import shutil
import socket
import subprocess
import threading
import time

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST, HOST, BIND_HOST

pytestmark = pytest.mark.timeout(180)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XROOTDFS = os.path.join(CLIENT_DIR, "bin", "xrootdfs")
FAULT_PROXY_SRC = os.path.join(REPO, "tests", "c", "fault_proxy.c")
FAULT_PROXY = os.path.join(CLIENT_DIR, "bin", "fault_proxy")

_FUSE_OK = os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _ctl(port, cmd):
    """Send a control command to the fault proxy; return its reply."""
    with socket.create_connection((HOST, port), timeout=3) as s:
        s.sendall((cmd + "\n").encode())
        return s.recv(256).decode()


@pytest.fixture(scope="module")
def built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    if not _FUSE_OK:
        pytest.skip("FUSE unavailable (/dev/fuse or fusermount3 missing)")
    # async driver + the static client lib
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrootdfs"],
                          capture_output=True, text=True, timeout=240)
    if proc.returncode != 0 or not os.path.exists(XROOTDFS):
        pytest.skip(f"xrootdfs build failed:\n{proc.stdout}\n{proc.stderr}")
    # the fault proxy (standalone)
    cc = shutil.which("cc") or shutil.which("gcc")
    proc = subprocess.run([cc, "-O2", "-pthread", FAULT_PROXY_SRC, "-o", FAULT_PROXY],
                          capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        pytest.skip(f"fault_proxy build failed:\n{proc.stderr}")
    if not _port_up(SERVER_HOST, NGINX_ANON_PORT):
        pytest.skip("anon server not running")
    return True


@pytest.fixture()
def proxy(built):
    """A running fault proxy: localhost:<listen> -> the real anon server."""
    listen = _free_port()
    control = _free_port()
    p = subprocess.Popen([FAULT_PROXY, str(listen), SERVER_HOST,
                          str(NGINX_ANON_PORT), str(control)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # wait for the proxy to be listening
    for _ in range(50):
        if _port_up(HOST, listen) and _port_up(HOST, control):
            break
        time.sleep(0.05)
    else:
        p.kill()
        pytest.skip("fault proxy did not come up")
    yield listen, control
    p.kill()
    p.wait()


@pytest.fixture()
def mount(proxy):
    """xrootdfs mounted through the proxy. Yields the mountpoint."""
    listen, _control = proxy
    mnt = subprocess.check_output(["mktemp", "-d", os.path.join(os.environ["TMPDIR"], "xrdfsres.XXXXXX")]).decode().strip()
    url = f"root://{HOST}:{listen}/"
    argv = [XROOTDFS, "--max-stall", "30000", "--keepalive", "3000", url, mnt, "-f"]
    p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        if os.path.ismount(mnt):
            break
        time.sleep(0.1)
    else:
        p.kill()
        subprocess.run(["fusermount3", "-u", mnt], capture_output=True)
        os.rmdir(mnt)
        pytest.skip("xrootdfs failed to mount through the proxy")
    yield mnt
    subprocess.run(["fusermount3", "-u", mnt], capture_output=True)
    p.wait(timeout=10)
    try:
        os.rmdir(mnt)
    except OSError:
        pass


@pytest.fixture()
def big_file():
    """A multi-MiB random file in the served data root. Yields (name, md5)."""
    name = f"_resil_{os.getpid()}_{int(time.time()*1000)}.bin"
    payload = os.urandom(8 * 1024 * 1024)
    path = os.path.join(DATA_ROOT, name)
    with open(path, "wb") as fh:
        fh.write(payload)
    yield name, hashlib.md5(payload).hexdigest()
    try:
        os.unlink(path)
    except OSError:
        pass


def _read_all(mnt, name, chunk=65536, on_chunk=None):
    """Read a mounted file chunk-by-chunk; call on_chunk(i) after chunk i."""
    h = hashlib.md5()
    total = 0
    with open(os.path.join(mnt, name), "rb") as f:
        i = 0
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
            total += len(b)
            i += 1
            if on_chunk is not None:
                on_chunk(i)
    return total, h.hexdigest()


# ==========================================================================

def test_baseline_passthrough(mount, big_file):
    """Sanity: a clean proxy relays a transfer byte-exact."""
    name, md5 = big_file
    total, got = _read_all(mount, name)
    assert total == 8 * 1024 * 1024
    assert got == md5


def test_latency_high_rtt(mount, proxy, big_file):
    """A high-latency link still transfers byte-exact."""
    _listen, control = proxy
    name, md5 = big_file
    _ctl(control, "latency 3")
    try:
        total, got = _read_all(mount, name)
    finally:
        _ctl(control, "clear")
    assert total == 8 * 1024 * 1024
    assert got == md5


def test_drop_mid_read(mount, proxy, big_file):
    """A connection RESET mid-transfer is recovered transparently, byte-exact."""
    _listen, control = proxy
    name, md5 = big_file
    fired = {"done": False}

    def on_chunk(i):
        if i == 8 and not fired["done"]:
            fired["done"] = True
            _ctl(control, "drop")     # sever the live proxied connection

    total, got = _read_all(mount, name, on_chunk=on_chunk)
    assert fired["done"], "drop was never triggered"
    assert total == 8 * 1024 * 1024
    assert got == md5, "data corrupted across a mid-read connection drop"


def test_outage_window(mount, proxy, big_file):
    """An outage (refuse + drop) for a couple seconds is ridden out within
    --max-stall; the in-progress read completes byte-exact with no EIO."""
    _listen, control = proxy
    name, md5 = big_file
    fired = {"done": False}

    def restore_later():
        time.sleep(2.0)
        _ctl(control, "unblock")

    def on_chunk(i):
        if i == 8 and not fired["done"]:
            fired["done"] = True
            threading.Thread(target=restore_later, daemon=True).start()
            _ctl(control, "block")    # drop + refuse new for ~2s

    total, got = _read_all(mount, name, on_chunk=on_chunk)
    assert fired["done"], "outage was never triggered"
    assert total == 8 * 1024 * 1024
    assert got == md5, "data corrupted across an outage window"
