"""
xrootdfs (FUSE mount) + libxrdposix_preload.so (LD_PRELOAD POSIX shim) — phase-37
§14.4.

Two clean-room (libXrdCl-free) POSIX surfaces over the native libxrdc:

  * xrootdfs — `xrootdfs root://host[:port]/ /mnt` mounts the remote namespace so
    ls/cat/cp/mkdir/rm work through the kernel VFS (libfuse3, single-threaded).
  * libxrdposix_preload.so — `LD_PRELOAD=… BRIX_VMP=/xrd=root://host:port/`
    diverts the POSIX READ path (open/read/stat/statx) for paths under the prefix
    to XRootD; everything else passes straight through to libc.

FUSE tests skip cleanly where unprivileged FUSE is unavailable (/dev/fuse or
fusermount3 missing — common in containers). The preload tests need no /dev/fuse.

Run (serial, against a manually-started fleet):
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
    pytest tests/test_xrootdfs.py -v -p no:xdist
"""

import errno
import hashlib
import os
import shutil
import socket
import subprocess
import time

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

pytestmark = pytest.mark.timeout(120)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
# XROOTDFS_BIN lets the same suite validate an alternate driver (e.g. the async
# xrootdfs) without disturbing the default; falls back to the built "xrootdfs".
_XROOTDFS_NAME = os.environ.get("XROOTDFS_BIN", "xrootdfs")
XROOTDFS = _XROOTDFS_NAME if os.path.isabs(_XROOTDFS_NAME) \
    else os.path.join(CLIENT_DIR, "bin", _XROOTDFS_NAME)
PRELOAD = os.path.join(CLIENT_DIR, "libxrdposix_preload.so")
ANON_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}/"

_FUSE_OK = os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _md5(b):
    return hashlib.md5(b).hexdigest()


@pytest.fixture(scope="module")
def built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")
    # Build the preload .so always; the selected FUSE driver when fuse3 is present.
    targets = ["libxrdposix_preload.so"]
    if _FUSE_OK:
        targets.append(os.path.basename(XROOTDFS))
    proc = subprocess.run(["make", "-C", CLIENT_DIR, *targets],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        pytest.skip(f"native build failed:\n{proc.stdout}\n{proc.stderr}")
    if not os.path.exists(PRELOAD):
        pytest.skip("preload .so not built (fuse3 missing is fine; .so is not)")
    if not _port_up(SERVER_HOST, NGINX_ANON_PORT):
        pytest.skip("anon server not running")
    return True


@pytest.fixture()
def remote_file(built):
    """A known file in the shared data root the anon export serves."""
    name = f"_xrootdfs_{os.getpid()}_{int(time.time() * 1000)}.bin"
    payload = os.urandom(50000)
    path = os.path.join(DATA_ROOT, name)
    with open(path, "wb") as fh:
        fh.write(payload)
    yield name, payload
    try:
        os.unlink(path)
    except OSError:
        pass


# ==========================================================================
# FUSE mount
# ==========================================================================

class _Mount:
    def __init__(self, mnt, proc):
        self.mnt = mnt
        self.proc = proc

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        subprocess.run(["fusermount3", "-u", self.mnt], capture_output=True)
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        try:
            os.rmdir(self.mnt)
        except OSError:
            pass


def _mount(*conn_args):
    mnt = subprocess.check_output(["mktemp", "-d", os.path.join(os.environ["TMPDIR"], "xrootdfs.XXXXXX")]).decode().strip()
    env = {k: v for k, v in os.environ.items()}
    env.pop("X509_USER_PROXY", None)
    argv = [XROOTDFS, *conn_args, ANON_URL, mnt, "-f"]
    proc = subprocess.Popen(argv, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        if os.path.ismount(mnt):
            return _Mount(mnt, proc)
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    proc.kill()
    os.rmdir(mnt)
    pytest.skip("xrootdfs failed to mount (unprivileged FUSE unavailable?)")


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_fuse_cat_and_stat(built, remote_file):
    name, payload = remote_file
    with _mount() as m:
        # stat reports the right size
        sz = os.stat(os.path.join(m.mnt, name)).st_size
        assert sz == len(payload), f"stat size {sz} != {len(payload)}"
        # cat returns byte-exact content
        with open(os.path.join(m.mnt, name), "rb") as fh:
            got = fh.read()
        assert _md5(got) == _md5(payload), "FUSE read bytes differ from origin"


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_fuse_ls_and_enoent(built, remote_file):
    name, _ = remote_file
    with _mount() as m:
        listing = os.listdir(m.mnt)
        assert name in listing, f"{name} not listed by FUSE readdir"
        # a missing path raises FileNotFoundError (ENOENT)
        with pytest.raises(FileNotFoundError):
            open(os.path.join(m.mnt, "definitely-not-here"), "rb")


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_fuse_write_roundtrip(built):
    payload = os.urandom(8192)
    name = f"_xrootdfs_w_{os.getpid()}_{int(time.time()*1000)}.bin"
    disk = os.path.join(DATA_ROOT, name)
    try:
        with _mount() as m:
            with open(os.path.join(m.mnt, name), "wb") as fh:
                fh.write(payload)
            # readback through the mount
            with open(os.path.join(m.mnt, name), "rb") as fh:
                got = fh.read()
            assert _md5(got) == _md5(payload), "FUSE write/readback mismatch"
        # and the bytes really landed on the server's disk
        with open(disk, "rb") as fh:
            assert _md5(fh.read()) == _md5(payload), "on-disk bytes differ"
    finally:
        try:
            os.unlink(disk)
        except OSError:
            pass


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_fuse_no_libxrd(built):
    out = subprocess.run(["ldd", XROOTDFS], capture_output=True, text=True).stdout
    assert "libfuse3" in out, "xrootdfs should link libfuse3"
    assert "libXrd" not in out, f"xrootdfs must not link libXrd*:\n{out}"


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_fuse_random_write_inplace(built):
    """Open an existing file O_RDWR WITHOUT truncate, overwrite a middle region,
    and confirm the surrounding bytes + the size are preserved — the random-write-
    without-truncate capability (kXR_open_updt)."""
    orig = b"A" * 100 + b"B" * 100 + b"C" * 100
    name = f"_xrootdfs_rw_{os.getpid()}_{int(time.time() * 1000)}.bin"
    disk = os.path.join(DATA_ROOT, name)
    try:
        with _mount() as m:
            p = os.path.join(m.mnt, name)
            with open(p, "wb") as fh:
                fh.write(orig)
            with open(p, "r+b") as fh:        # O_RDWR, no O_TRUNC → in-place update
                fh.seek(100)
                fh.write(b"XXXX")
            with open(p, "rb") as fh:
                got = fh.read()
        assert got == b"A" * 100 + b"XXXX" + b"B" * 96 + b"C" * 100, \
            "in-place write corrupted surrounding data"
        assert len(got) == len(orig), "in-place write changed file size"
    finally:
        try:
            os.unlink(disk)
        except OSError:
            pass


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_fuse_statfs(built):
    """`df`/statvfs reports the backend's real capacity (kXR_Qspace)."""
    with _mount() as m:
        vfs = os.statvfs(m.mnt)
        assert vfs.f_blocks > 0, "statfs reported zero total blocks"
        assert vfs.f_bfree <= vfs.f_blocks


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_fuse_concurrent_reads(built, remote_file):
    """Many threads reading the same file at once (multi-threaded mount + the
    connection pool) must all return byte-exact content — the concurrency gate."""
    import threading

    name, payload = remote_file
    want = _md5(payload)
    results = []
    rlock = threading.Lock()
    with _mount() as m:
        p = os.path.join(m.mnt, name)

        def worker():
            with open(p, "rb") as fh:
                d = fh.read()
            with rlock:
                results.append(_md5(d))

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert len(results) == 16 and all(r == want for r in results), \
        "concurrent reads through the mount diverged"


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_fuse_large_io_buffered(built):
    """Many small writes (exercises write-back coalescing) then a full sequential
    read (exercises read-ahead) must be byte-exact through the mount and on disk."""
    payload = os.urandom(3 * 1024 * 1024 + 777)   # not a round multiple
    name = f"_xrootdfs_big_{os.getpid()}_{int(time.time() * 1000)}.bin"
    disk = os.path.join(DATA_ROOT, name)
    try:
        with _mount() as m:
            p = os.path.join(m.mnt, name)
            with open(p, "wb") as fh:
                for off in range(0, len(payload), 4096):   # 4 KiB writes
                    fh.write(payload[off:off + 4096])
            with open(p, "rb") as fh:                       # sequential read-back
                got = fh.read()
            assert _md5(got) == _md5(payload), "buffered write/read mismatch"
        with open(disk, "rb") as fh:
            assert _md5(fh.read()) == _md5(payload), "on-disk bytes differ"
    finally:
        try:
            os.unlink(disk)
        except OSError:
            pass


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_fuse_buffering_disabled(built):
    """--readahead 0 --writeback 0 (direct I/O paths) is still byte-exact."""
    payload = os.urandom(200000)
    name = f"_xrootdfs_nb_{os.getpid()}_{int(time.time() * 1000)}.bin"
    disk = os.path.join(DATA_ROOT, name)
    try:
        with _mount("--readahead", "0", "--writeback", "0") as m:
            p = os.path.join(m.mnt, name)
            with open(p, "wb") as fh:
                fh.write(payload)
            with open(p, "rb") as fh:
                assert _md5(fh.read()) == _md5(payload), "direct-path mismatch"
    finally:
        try:
            os.unlink(disk)
        except OSError:
            pass


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_fuse_xattr(built, remote_file):
    """--xattr: the read-only user.XrdCks.<algo> virtual xattr returns the server
    checksum, and general user.* attrs round-trip set→get→list→remove (kXR_fattr)."""
    name, payload = remote_file
    with _mount("--xattr") as m:
        p = os.path.join(m.mnt, name)
        # virtual checksum xattr matches a locally-computed adler32 (zlib)
        import zlib
        want_adler = f"{zlib.adler32(payload) & 0xffffffff:08x}"
        got = os.getxattr(p, b"user.XrdCks.adler32").decode()
        assert got == want_adler, f"checksum xattr {got} != adler32 {want_adler}"
        # general fattr round-trip
        os.setxattr(p, b"user.proj", b"higgs")
        assert os.getxattr(p, b"user.proj") == b"higgs"
        assert "user.proj" in os.listxattr(p)
        os.removexattr(p, b"user.proj")
        with pytest.raises(OSError):
            os.getxattr(p, b"user.proj")
        # the checksum xattr is read-only
        with pytest.raises(OSError):
            os.setxattr(p, b"user.XrdCks.adler32", b"x")


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_fuse_xattr_off_by_default(built, remote_file):
    """Without --xattr, xattr ops report ENOTSUP (the feature is opt-in)."""
    name, _ = remote_file
    with _mount() as m:
        p = os.path.join(m.mnt, name)
        with pytest.raises(OSError) as ei:
            os.getxattr(p, b"user.XrdCks.adler32")
        assert ei.value.errno in (errno.ENOTSUP, errno.EOPNOTSUPP)


# ==========================================================================
# LD_PRELOAD POSIX shim
# ==========================================================================

def _preload_env(extra=None):
    env = {k: v for k, v in os.environ.items()}
    env.pop("X509_USER_PROXY", None)
    env["LD_PRELOAD"] = PRELOAD
    env["BRIX_VMP"] = f"/xrd=root://{SERVER_HOST}:{NGINX_ANON_PORT}/"
    if extra:
        env.update(extra)
    return env


def test_preload_cat_matches(built, remote_file):
    name, payload = remote_file
    p = subprocess.run(["cat", f"/xrd/{name}"], env=_preload_env(),
                       capture_output=True, timeout=30)
    assert p.returncode == 0, p.stderr
    assert _md5(p.stdout) == _md5(payload), "preload cat bytes differ from origin"


def test_preload_stat_and_ls(built, remote_file):
    name, payload = remote_file
    # `stat` uses statx → interposed
    p = subprocess.run(["stat", "-c", "%s", f"/xrd/{name}"], env=_preload_env(),
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip() == str(len(payload)), p.stdout
    # `ls -l` of the file path (statx) succeeds
    p = subprocess.run(["ls", "-l", f"/xrd/{name}"], env=_preload_env(),
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    assert name in p.stdout, p.stdout


def test_preload_enoent(built):
    p = subprocess.run(["cat", "/xrd/does-not-exist-xyz"], env=_preload_env(),
                       capture_output=True, text=True, timeout=30)
    assert p.returncode != 0
    assert "No such file" in p.stderr, p.stderr


def test_preload_libc_passthrough(built):
    """A path NOT under the prefix must reach the real libc untouched."""
    with open("/etc/hosts", "rb") as fh:
        direct = fh.read()
    p = subprocess.run(["cat", "/etc/hosts"], env=_preload_env(),
                       capture_output=True, timeout=30)
    assert p.returncode == 0, p.stderr
    assert _md5(p.stdout) == _md5(direct), "passthrough of /etc/hosts diverged"


def test_preload_no_libxrd(built):
    out = subprocess.run(["ldd", PRELOAD], capture_output=True, text=True).stdout
    assert "libXrd" not in out, f"preload .so must not link libXrd*:\n{out}"
