"""
test_compression_fuse_resilience.py — phase-42 W4 inline read compression through
the async FUSE driver, including network-fault resilience.

WHAT: Mounts xrootdfs with `--compress zstd` THROUGH the in-repo TCP fault
      proxy (brix-fault-proxy, no root) against the anon root:// server and
      asserts that compressed reads are byte-exact (a) on a clean link, (b) across
      a mid-read connection RESET, and (c) across a short outage window.
WHY:  This is the one path the rest of the suite does not cover: the ASYNC client
      decompression added this phase (client/lib/aio_mgr.c brix_mfile_pread decodes
      each frame) AND the reopen-re-learns-codec contract (mfile_do_open re-reads
      cptype on every (re)open, so a fault mid-transfer transparently re-negotiates
      compression and the read still completes byte-exact with no EIO).  A bug in
      either — undecoded frames, or a reopen that forgot the codec — would corrupt
      the file exactly here and nowhere else in the suite.
HOW:  A COMPRESSIBLE payload is served so the server genuinely compresses (proven
      by the 'z=' access-log marker); md5 over the FUSE-read bytes then proves the
      async client decoded every frame correctly, including across the injected
      fault. The proxy's control port pulls the fault levers mid-read.

Model: test_xrootdfs_resilience.py (same fixtures, plus --compress + a compressible
payload + a compression-engaged assertion).
"""
import hashlib
import os
import shutil
import socket
import subprocess
import threading
import time

import pytest

from settings import (DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST, HOST, BIND_HOST,
                      LOG_DIR)

pytestmark = pytest.mark.timeout(180)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XROOTDFS = os.path.join(CLIENT_DIR, "bin", "xrootdfs")
FAULT_PROXY = os.path.join(CLIENT_DIR, "bin", "brix-fault-proxy")
ANON_ACCESS_LOG = os.path.join(LOG_DIR, "brix_access_anon.log")

SIZE = 8 * 1024 * 1024
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
    with socket.create_connection((HOST, port), timeout=3) as s:
        s.sendall((cmd + "\n").encode())
        return s.recv(256).decode()


def _compressible(n):
    """Highly compressible but content-rich payload: a repeating lorem block with
    a per-block counter, so it compresses well yet every byte is determinate."""
    block = (b"the quick brown fox jumps over the lazy dog 0123456789 "
             b"lorem ipsum dolor sit amet consectetur ")
    buf = bytearray()
    i = 0
    while len(buf) < n:
        buf += b"%08d " % i
        buf += block
        i += 1
    return bytes(buf[:n])


@pytest.fixture(scope="module")
def built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    if not _FUSE_OK:
        pytest.skip("FUSE unavailable (/dev/fuse or fusermount3 missing)")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrootdfs"],
                          capture_output=True, text=True, timeout=240)
    if proc.returncode != 0 or not os.path.exists(XROOTDFS):
        pytest.skip(f"xrootdfs build failed:\n{proc.stdout}\n{proc.stderr}")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "brix-fault-proxy"],
                          capture_output=True, text=True, timeout=60)
    if proc.returncode != 0 or not os.path.exists(FAULT_PROXY):
        pytest.skip(f"brix-fault-proxy build failed:\n{proc.stdout}\n{proc.stderr}")
    if not _port_up(SERVER_HOST, NGINX_ANON_PORT):
        pytest.skip("anon server not running")
    return True


@pytest.fixture()
def proxy(built):
    listen = _free_port()
    control = _free_port()
    p = subprocess.Popen([FAULT_PROXY, str(listen), SERVER_HOST,
                          str(NGINX_ANON_PORT), str(control)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
    """xrootdfs mounted through the proxy WITH --compress zstd."""
    listen, _control = proxy
    mnt = subprocess.check_output(["mktemp", "-d", os.path.join(os.environ["TMPDIR"], "xrdfscmp.XXXXXX")]).decode().strip()
    url = f"root://{HOST}:{listen}/"
    argv = [XROOTDFS, "--compress", "zstd", "--max-stall", "30000",
            "--keepalive", "3000", url, mnt, "-f"]
    p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        if os.path.ismount(mnt):
            break
        time.sleep(0.1)
    else:
        p.kill()
        subprocess.run(["fusermount3", "-u", mnt], capture_output=True)
        os.rmdir(mnt)
        pytest.skip("xrootdfs --compress failed to mount through the proxy")
    yield mnt
    subprocess.run(["fusermount3", "-u", mnt], capture_output=True)
    p.wait(timeout=10)
    try:
        os.rmdir(mnt)
    except OSError:
        pass


@pytest.fixture()
def cmp_file():
    """A multi-MiB COMPRESSIBLE file in the served data root. Yields (name, md5)."""
    name = f"_cmpresil_{os.getpid()}_{int(time.time()*1000)}.bin"
    payload = _compressible(SIZE)
    path = os.path.join(DATA_ROOT, name)
    with open(path, "wb") as fh:
        fh.write(payload)
    yield name, hashlib.md5(payload).hexdigest()
    try:
        os.unlink(path)
    except OSError:
        pass


def _read_all(mnt, name, chunk=65536, on_chunk=None):
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


def _log_has_compressed_read(name):
    """The anon access log shows a compressed READ (z= marker) for `name`."""
    for _ in range(30):
        try:
            with open(ANON_ACCESS_LOG, "r", errors="replace") as fh:
                for line in fh:
                    if "READ" in line and name in line and "z=" in line:
                        return True
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    return False


# ==========================================================================

def test_compressed_fuse_read_byte_exact(mount, cmp_file):
    """Happy path: a compressed read through the async FUSE driver is byte-exact,
    and the server actually compressed (z= marker) — proving brix_mfile_pread
    decoded the frames rather than the codec being silently skipped."""
    name, md5 = cmp_file
    total, got = _read_all(mount, name)
    assert total == SIZE
    assert got == md5, "compressed FUSE read not byte-exact"
    assert _log_has_compressed_read(name), \
        "no compressed READ (z=) logged — async FUSE path did not negotiate compression"


def test_compressed_read_survives_drop(mount, proxy, cmp_file):
    """A connection RESET mid-read is recovered transparently AND byte-exact —
    exercises mfile reopen + re-learn-codec on a compression-mode handle."""
    _listen, control = proxy
    name, md5 = cmp_file
    fired = {"done": False}

    def on_chunk(i):
        if i == 16 and not fired["done"]:
            fired["done"] = True
            _ctl(control, "drop")

    total, got = _read_all(mount, name, on_chunk=on_chunk)
    assert fired["done"], "drop was never triggered"
    assert total == SIZE
    assert got == md5, \
        "compressed data corrupted across a mid-read drop (reopen lost the codec?)"


def test_compressed_read_survives_outage(mount, proxy, cmp_file):
    """A short outage (block + restore) is ridden out within --max-stall and the
    compressed read completes byte-exact with no EIO."""
    _listen, control = proxy
    name, md5 = cmp_file
    fired = {"done": False}

    def restore_later():
        time.sleep(2.0)
        _ctl(control, "unblock")

    def on_chunk(i):
        if i == 16 and not fired["done"]:
            fired["done"] = True
            threading.Thread(target=restore_later, daemon=True).start()
            _ctl(control, "block")

    total, got = _read_all(mount, name, on_chunk=on_chunk)
    assert fired["done"], "outage was never triggered"
    assert total == SIZE
    assert got == md5, "compressed data corrupted across an outage window"
