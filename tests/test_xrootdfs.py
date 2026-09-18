"""
xrootdfs (FUSE mount) + libbrixposix_preload.{so,dylib} (the LD_PRELOAD /
DYLD_INSERT_LIBRARIES POSIX shim) — phase-37 §14.4.

Two clean-room (libXrdCl-free) POSIX surfaces over the native libbrix:

  * xrootdfs — `xrootdfs root://host[:port]/ /mnt` mounts the remote namespace so
    ls/cat/cp/mkdir/rm work through the kernel VFS (libfuse3, single-threaded).
  * libbrixposix_preload.so — `LD_PRELOAD=… BRIX_VMP=/xrd=root://host:port/`
    diverts the POSIX READ path (open/read/stat/statx) for paths under the prefix
    to XRootD; everything else passes straight through to libc.  On macOS the
    same shim is a .dylib inserted with DYLD_INSERT_LIBRARIES (lib_py.preload_shim
    picks the variable, the artifact name and interposable host programs).

FUSE tests skip cleanly where unprivileged FUSE is unavailable (see
lib_py.fuse_host: /dev/fuse + fusermount3, or the macFUSE bundle). The preload
tests need no FUSE.

Run (serial, against a manually-started fleet):
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
    pytest tests/test_xrootdfs.py -v -p no:xdist
"""

import errno
import hashlib
import os
import shutil
import socket
import stat
import subprocess
import sys
from brix_suite.client_build import client_make
import time

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST
from lib_py import fuse_host, preload_shim

def _guard_built_1():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")

def _guard_built_2(targets):
    if _FUSE_OK:
        targets.append(os.path.basename(XROOTDFS))

def _guard_built_3(proc):
    if proc.returncode != 0:
        pytest.skip(f"native build failed:\n{proc.stdout}\n{proc.stderr}")

def _guard_built_4():
    if not os.path.exists(PRELOAD):
        pytest.skip("preload .so not built (fuse3 missing is fine; .so is not)")

def _guard_built_5():
    if not _port_up(SERVER_HOST, NGINX_ANON_PORT):
        pytest.skip("anon server not running")

def _check_test_fuse_concurrent_reads_1(results, want):
    assert len(results) == 16 and all(r == want for r in results), \
        "concurrent reads through the mount diverged"


pytestmark = pytest.mark.timeout(120)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
# XROOTDFS_BIN lets the same suite validate an alternate driver (e.g. the async
# xrootdfs) without disturbing the default; falls back to the built "xrootdfs".
_XROOTDFS_NAME = os.environ.get("XROOTDFS_BIN", "xrootdfs")
XROOTDFS = _XROOTDFS_NAME if os.path.isabs(_XROOTDFS_NAME) \
    else os.path.join(CLIENT_DIR, "bin", _XROOTDFS_NAME)
PRELOAD = preload_shim.SHIM_PATH
ANON_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}/"

_FUSE_OK = fuse_host.FUSE_READY
#: XNU allows mknod(2) of a regular file to the superuser only (EPERM before
#: the request reaches any filesystem, FUSE included), so the mknod cells are
#: a Linux contract.
_MKNOD_IS_ROOT_ONLY = sys.platform == "darwin"


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
    _guard_built_1()
    # Build the preload .so always; the selected FUSE driver when fuse3 is present.
    targets = [preload_shim.SHIM_NAME]
    _guard_built_2(targets)
    proc = client_make(CLIENT_DIR, *targets, capture_output=True, text=True, timeout=180)
    _guard_built_3(proc)
    _guard_built_4()
    _guard_built_5()
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
        fuse_host.unmount(self.mnt)
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


@pytest.mark.skipif(not _FUSE_OK, reason=fuse_host.SKIP_REASON)
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


@pytest.mark.skipif(not _FUSE_OK, reason=fuse_host.SKIP_REASON)
def test_fuse_ls_and_enoent(built, remote_file):
    name, _ = remote_file
    with _mount() as m:
        listing = os.listdir(m.mnt)
        assert name in listing, f"{name} not listed by FUSE readdir"
        # a missing path raises FileNotFoundError (ENOENT)
        with pytest.raises(FileNotFoundError):
            open(os.path.join(m.mnt, "definitely-not-here"), "rb")


@pytest.mark.skipif(not _FUSE_OK, reason=fuse_host.SKIP_REASON)
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


@pytest.mark.skipif(not _FUSE_OK, reason=fuse_host.SKIP_REASON)
@pytest.mark.skipif(_MKNOD_IS_ROOT_ONLY, reason="mknod(2) of a regular file is root-only on this kernel")
def test_fuse_mknod_creates_empty_file(built):
    """(success) mknod(2) of a regular file creates an EMPTY file that lands on
    the server (zero length) and reads back empty through the mount. Before this
    the op was unimplemented, so `mknod`/`mknodat` returned ENOSYS."""
    name = f"_xrootdfs_mknod_{os.getpid()}_{int(time.time()*1000)}.bin"
    disk = os.path.join(DATA_ROOT, name)
    try:
        with _mount() as m:
            p = os.path.join(m.mnt, name)
            os.mknod(p, 0o644)                 # S_IFREG by default
            assert os.stat(p).st_size == 0, "mknod file should be empty"
            with open(p, "rb") as fh:
                assert fh.read() == b"", "mknod file should read back empty"
        assert os.path.exists(disk), "mknod file did not land on the server"
        assert os.path.getsize(disk) == 0, "server file should be zero-length"
    finally:
        try:
            os.unlink(disk)
        except OSError:
            pass


@pytest.mark.skipif(not _FUSE_OK, reason=fuse_host.SKIP_REASON)
@pytest.mark.skipif(_MKNOD_IS_ROOT_ONLY, reason="mknod(2) of a regular file is root-only on this kernel")
def test_fuse_mknod_then_write(built):
    """(success) the real use: mknod pre-creates the node, a later
    open(O_WRONLY)+write fills it, and the content lands on the server."""
    payload = os.urandom(4096)
    name = f"_xrootdfs_mknodw_{os.getpid()}_{int(time.time()*1000)}.bin"
    disk = os.path.join(DATA_ROOT, name)
    try:
        with _mount() as m:
            p = os.path.join(m.mnt, name)
            os.mknod(p, 0o644)
            with open(p, "wb") as fh:
                fh.write(payload)
            with open(p, "rb") as fh:
                assert _md5(fh.read()) == _md5(payload), "mknod+write readback mismatch"
        with open(disk, "rb") as fh:
            assert _md5(fh.read()) == _md5(payload), "on-disk bytes differ"
    finally:
        try:
            os.unlink(disk)
        except OSError:
            pass


@pytest.mark.skipif(not _FUSE_OK, reason=fuse_host.SKIP_REASON)
def test_fuse_mknod_fifo_refused(built):
    """(security-neg) a non-regular type (FIFO) is refused with EPERM — a remote
    xrootd/WebDAV store holds regular files only — and no file is created for it,
    never silently substituted by a plain file."""
    name = f"_xrootdfs_fifo_{os.getpid()}_{int(time.time()*1000)}"
    disk = os.path.join(DATA_ROOT, name)
    try:
        with _mount() as m:
            p = os.path.join(m.mnt, name)
            with pytest.raises(OSError) as ei:
                os.mknod(p, stat.S_IFIFO | 0o644)
            assert ei.value.errno == errno.EPERM, \
                f"expected EPERM for a FIFO, got errno {ei.value.errno}"
        assert not os.path.exists(disk), \
            "a refused FIFO must not leave a file on the server"
    finally:
        try:
            os.unlink(disk)
        except OSError:
            pass


@pytest.mark.skipif(not _FUSE_OK, reason=fuse_host.SKIP_REASON)
def test_fuse_no_libxrd(built):
    out = linked_libraries(XROOTDFS)
    assert "libfuse3" in out, "xrootdfs should link libfuse3"
    assert "libXrd" not in out, f"xrootdfs must not link libXrd*:\n{out}"


@pytest.mark.skipif(not _FUSE_OK, reason=fuse_host.SKIP_REASON)
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


@pytest.mark.skipif(not _FUSE_OK, reason=fuse_host.SKIP_REASON)
def test_fuse_statfs(built):
    """`df`/statvfs reports the backend's real capacity (kXR_Qspace)."""
    with _mount() as m:
        vfs = os.statvfs(m.mnt)
        assert vfs.f_blocks > 0, "statfs reported zero total blocks"
        assert vfs.f_bfree <= vfs.f_blocks


@pytest.mark.skipif(not _FUSE_OK, reason=fuse_host.SKIP_REASON)
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
    _check_test_fuse_concurrent_reads_1(results, want)


@pytest.mark.skipif(not _FUSE_OK, reason=fuse_host.SKIP_REASON)
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


@pytest.mark.skipif(not _FUSE_OK, reason=fuse_host.SKIP_REASON)
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


@pytest.mark.skipif(not _FUSE_OK, reason=fuse_host.SKIP_REASON)
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


@pytest.mark.skipif(not _FUSE_OK, reason=fuse_host.SKIP_REASON)
def test_fuse_xattr_off_by_default(built, remote_file):
    """Without --xattr, xattr ops report ENOTSUP (the feature is opt-in)."""
    name, _ = remote_file
    with _mount() as m:
        p = os.path.join(m.mnt, name)
        with pytest.raises(OSError) as ei:
            os.getxattr(p, b"user.XrdCks.adler32")
        # The driver answers ENOTSUP; macFUSE's kernel side reports an
        # unsupported-by-fs attribute as ENOATTR, which the xattr shim maps
        # to ENODATA (see lib_py/xattr_shim.py), so on Darwin that is the
        # "off" answer a program sees.
        assert ei.value.errno in (errno.ENOTSUP, errno.EOPNOTSUPP) + (
            (errno.ENODATA,) if sys.platform == "darwin" else ())


# ==========================================================================
# The POSIX preload shim (LD_PRELOAD / DYLD_INSERT_LIBRARIES)
# ==========================================================================

from sanitizer_preload import sanitizer_runtimes
from lib_py.util import linked_libraries

_ASAN_RT = sanitizer_runtimes(PRELOAD)
_CAT = preload_shim.posix_tool("cat")

# GNU stat(1) prints the fields straight from statx; on macOS the coreutils
# are SIP-protected (no insertion) and BSD stat has other flags, so the same
# fields come from the interposable python's os.stat.
_STAT_PY = ("import os, sys; st = os.stat(sys.argv[1]); "
            "print(st.st_ino, st.st_blksize, st.st_blocks, st.st_size)")


def _stat_fields(path, env):
    """(returncode, stdout, stderr) for 'ino blksize blocks size' of `path`
    through the shim, via whichever stat tool the insertion reaches."""
    if preload_shim.IS_DARWIN:
        argv = [preload_shim.interposable_python(), "-c", _STAT_PY, path]
    else:
        argv = ["stat", "-c", "%i %o %b %s", path]
    p = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30)
    return p.returncode, p.stdout, p.stderr


def _preload_env(extra=None):
    """The host's insertion variable with the sanitizer runtimes (empty on a
    plain build) prepended so the ASan/UBSan shim loads into the
    uninstrumented host process instead of aborting on an undefined
    __asan_*/__ubsan_* symbol."""
    env = preload_shim.preload_env(None, _ASAN_RT)
    env.pop("X509_USER_PROXY", None)
    if _ASAN_RT:
        env.setdefault("ASAN_OPTIONS", "detect_leaks=0:verify_asan_link_order=0")
    env["BRIX_VMP"] = f"/xrd=root://{SERVER_HOST}:{NGINX_ANON_PORT}/"
    if extra:
        env.update(extra)
    return env


def test_preload_cat_matches(built, remote_file):
    name, payload = remote_file
    p = subprocess.run([*_CAT, f"/xrd/{name}"], env=_preload_env(),
                       capture_output=True, timeout=30)
    assert p.returncode == 0, p.stderr
    assert _md5(p.stdout) == _md5(payload), "preload cat bytes differ from origin"


def test_preload_stat_and_ls(built, remote_file):
    name, payload = remote_file
    # `stat` (statx on glibc, stat$INODE64 on Darwin) → interposed
    rc, out, err = _stat_fields(f"/xrd/{name}", _preload_env())
    assert rc == 0, err
    assert out.split()[-1] == str(len(payload)), out
    # a listing of the parent (opendir/readdir) names the file
    ls = [preload_shim.interposable_python(), "-c",
          "import os, sys; print('\\n'.join(os.listdir(sys.argv[1])))", "/xrd"]
    p = subprocess.run(ls, env=_preload_env(), capture_output=True, text=True,
                       timeout=30)
    assert p.returncode == 0, p.stderr
    assert name in p.stdout.split(), p.stdout


def test_preload_stat_identity_fields(built, remote_file):
    """(success) statx maps through the shared posix_map helper: stable nonzero
    inode, 1 MiB blksize hint, 512-byte block count. The hand-rolled fill_stat
    this replaced under-filled all three (parity-audit §9.2) — every remote
    file presented as inode 0, so inode-tracking tools (find -samefile, rsync,
    tar) saw one shared identity."""
    name, payload = remote_file
    rc, out, err = _stat_fields(f"/xrd/{name}", _preload_env())
    assert rc == 0, err
    ino, blksize, blocks, size = out.split()
    assert int(size) == len(payload), p.stdout
    assert int(ino) != 0, "remote file presented as inode 0"
    assert int(blksize) == 1048576, f"blksize hint not 1 MiB: {blksize}"
    assert int(blocks) == (len(payload) + 511) // 512, p.stdout


def test_preload_stat_enoent_after_map(built):
    """(error) statx of a missing remote path still surfaces ENOENT — the
    mapping change must not disturb the error path."""
    rc, _out, err = _stat_fields("/xrd/does-not-exist-xyz", _preload_env())
    assert rc != 0
    assert "No such file" in err, err


def test_preload_stat_passthrough_untouched(built):
    """(security-neg) a path OUTSIDE the prefix reaches the real libc statx —
    its inode matches an uninterposed os.stat, proving the remote mapping
    (and its synthesized inode) never applies outside the configured prefix."""
    real_ino = os.stat("/etc/hosts").st_ino
    rc, out, err = _stat_fields("/etc/hosts", _preload_env())
    assert rc == 0, err
    assert int(out.split()[0]) == real_ino, \
        "passthrough statx inode diverged from the real filesystem"


def test_preload_enoent(built):
    p = subprocess.run([*_CAT, "/xrd/does-not-exist-xyz"], env=_preload_env(),
                       capture_output=True, text=True, timeout=30)
    assert p.returncode != 0
    assert "No such file" in p.stderr, p.stderr


def test_preload_libc_passthrough(built):
    """A path NOT under the prefix must reach the real libc untouched."""
    with open("/etc/hosts", "rb") as fh:
        direct = fh.read()
    p = subprocess.run([*_CAT, "/etc/hosts"], env=_preload_env(),
                       capture_output=True, timeout=30)
    assert p.returncode == 0, p.stderr
    assert _md5(p.stdout) == _md5(direct), "passthrough of /etc/hosts diverged"


def test_preload_no_libxrd(built):
    out = linked_libraries(PRELOAD)
    assert "libXrd" not in out, f"the preload shim must not link libXrd*:\n{out}"
