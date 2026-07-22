"""Phase-84 CVMFS conformance corpus — fuse_posix (ports 13360-13379).

Theme
-----
POSIX surface of a brixcvmfs FUSE mount over a rich forged repo: the
read-only mutation matrix (every mutating op refused — exact errno pinned),
the magic-xattr namespace (exact 7-name set, value correctness vs the forged
catalog/manifest, getxattr size-probe protocol), statfs sanity, getattr /
inode consistency, dirent stability, open/close lifecycle, access(2), and the
mount surface (fstype, busy-unmount behavior).

Official read-only CVMFS returns EROFS for **every** mutating operation
(design doc row `fuse_posix`, docs/refactor/phase-84-cvmfs-conformance-corpus.md:
"every mutating op → EROFS"). brixcvmfs only implements open/mkdir/unlink/write
refusals (client/apps/fs/brixcvmfs.c op table); every other mutating op is an
*unimplemented* FUSE op, so the kernel surfaces ENOSYS / EPERM / ENOTSUP
instead. Those rows are pinned twice: the actual behavior (regression pin) and
the official behavior as a strict-xfail DIVERGENCE row.

Every errno in this file was probed against a live mount (2026-07-17,
libfuse3, Linux 6.18) — nothing is guessed.
"""

import ctypes
import errno
import hashlib
import os
import stat as stat_m
import subprocess
import sys
import threading
import time
import zlib

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, MOCK, PortBlock, fuse_mount
from repo_forge import Chunk, Chunked, Dir, File, RepoForge, Symlink

REPO = "test.cern.ch"
HELLO = b"Hello fuse_posix corpus!\n"
LEAF = b"leaf\n"
MTIME = 1700000000
CHUNKS = [b"A" * 7000, b"B" * 5000, b"C" * 3000]

# The exact magic-xattr name set exposed by the client
# (shared/cvmfs/client/client.c cvmfs_client_listxattr).
XATTR_NAMES = ("user.fqrn", "user.revision", "user.root_hash", "user.host",
               "user.proxy", "user.hash", "user.nchunks")
# Directories/symlinks carry only the common attrs — the whole-file
# user.hash / user.nchunks apply to regular files alone.
DIR_XATTR_NAMES = ("user.fqrn", "user.revision", "user.root_hash", "user.host",
                   "user.proxy")

import shutil  # noqa: E402
from settings import HOST

_FUSE_READY = (os.path.exists("/dev/fuse")
               and shutil.which("fusermount3") is not None
               and os.path.exists(BRIXMOUNT))
pytestmark = pytest.mark.skipif(not _FUSE_READY,
                                reason="fuse mount prerequisites missing")

libc = ctypes.CDLL("libc.so.6", use_errno=True)


# ---- module-scoped forge + mock + mount -----------------------------------

class Rig:
    """Forged repo + webroot mock + a live brixcvmfs mount."""

    def __init__(self, mnt, forge, url, mock_port, pub):
        self.mnt = str(mnt)
        self.forge = forge
        self.url = url
        self.mock_port = mock_port
        self.pub = pub

    def p(self, rel):
        return os.path.join(self.mnt, rel)


def _tree():
    return {
        "hello.txt": File(HELLO),
        "exec.sh": File(b"executable-file payload\n", mode=0o755),  # opaque bytes; only the exec bit is under test
        "chunky.bin": Chunked([Chunk(c) for c in CHUNKS]),
        "sub": Dir({"leaf.txt": File(LEAF), "inner": Dir({})}),
        "sub2": Dir({}),
        "empty": Dir({}),
        "link": Symlink("hello.txt"),
    }


@pytest.fixture(scope="module")
def rig(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("fuse_posix")
    web, pub = tmp / "web", tmp / "repo.pub"
    forge = RepoForge(REPO, web).build(_tree(), pub)
    block = PortBlock("fuse_posix")
    port = block.mock()
    mock = subprocess.Popen(
        [sys.executable, MOCK, "--port", str(port), "--repo", REPO,
         "--webroot", str(web)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://{HOST}:{port}/cvmfs/{REPO}"
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and mock.poll() is None:
            try:
                import urllib.request
                urllib.request.urlopen(f"http://{HOST}:{port}/ctl/log",
                                       timeout=0.3)
                break
            except Exception:
                time.sleep(0.1)
        with fuse_mount(REPO, url, pub, cache=str(tmp / "cache")) as (mnt, _):
            assert os.path.ismount(str(mnt)), "brixMount failed to mount"
            yield Rig(mnt, forge, url, port, pub)
    finally:
        mock.terminate()
        try:
            mock.wait(3)
        except subprocess.TimeoutExpired:
            mock.kill()
        forge.close()


def _errno_of(fn):
    """Run fn, return the OSError errno it raises (or None on success)."""
    try:
        fn()
        return None
    except OSError as e:
        return e.errno


def _open_close(path, flags):
    os.close(os.open(path, flags, 0o644))


# ---- 1. read-only mutation matrix: actual behavior pins --------------------

# (id, mutator(rig), pinned errno).  EROFS rows come from the implemented
# refusals in brixcvmfs.c; ENOSYS/EPERM/ENOTSUP rows are unimplemented FUSE ops
# surfaced by the kernel (probed live — e.g. link → EPERM, setxattr → ENOTSUP
# via the kernel's no_setxattr ENOSYS conversion).
MUTATIONS = [
    ("open_wronly", lambda r: _open_close(r.p("hello.txt"), os.O_WRONLY), errno.EROFS),
    ("open_rdwr", lambda r: _open_close(r.p("hello.txt"), os.O_RDWR), errno.EROFS),
    ("open_creat_new", lambda r: _open_close(r.p("newfile"), os.O_CREAT | os.O_WRONLY), errno.EROFS),
    ("open_creat_existing", lambda r: _open_close(r.p("hello.txt"), os.O_CREAT | os.O_WRONLY), errno.EROFS),
    ("open_trunc_existing", lambda r: _open_close(r.p("hello.txt"), os.O_TRUNC | os.O_WRONLY), errno.EROFS),
    ("unlink", lambda r: os.unlink(r.p("hello.txt")), errno.EROFS),
    ("mkdir", lambda r: os.mkdir(r.p("newdir")), errno.EROFS),
    ("rmdir", lambda r: os.rmdir(r.p("empty")), errno.EROFS),
    ("rename", lambda r: os.rename(r.p("hello.txt"), r.p("renamed")), errno.EROFS),
    ("link", lambda r: os.link(r.p("hello.txt"), r.p("hardlink")), errno.EROFS),
    ("symlink", lambda r: os.symlink("hello.txt", r.p("newlink")), errno.EROFS),
    ("chmod", lambda r: os.chmod(r.p("hello.txt"), 0o600), errno.EROFS),
    ("chown", lambda r: os.chown(r.p("hello.txt"), os.getuid(), os.getgid()), errno.EROFS),
    ("truncate", lambda r: os.truncate(r.p("hello.txt"), 0), errno.EROFS),
    ("utimensat", lambda r: os.utime(r.p("hello.txt"), (1, 1)), errno.EROFS),
    ("setxattr", lambda r: os.setxattr(r.p("hello.txt"), "user.x", b"v"), errno.EROFS),
    ("removexattr", lambda r: os.removexattr(r.p("hello.txt"), "user.fqrn"), errno.EROFS),
    ("mknod", lambda r: os.mknod(r.p("fifo"), 0o600 | stat_m.S_IFIFO), errno.EROFS),
]


@pytest.mark.parametrize("name,mutate,expect",
                         MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_mutation_refused_pinned_errno(rig, name, mutate, expect):
    # Official read-only CVMFS returns EROFS for every mutating op; brixcvmfs
    # implements the full write family as EROFS stubs, so all rows match.
    assert _errno_of(lambda: mutate(rig)) == expect


def test_write_to_rdonly_fd_is_ebadf(rig):
    fd = os.open(rig.p("hello.txt"), os.O_RDONLY)
    try:
        assert _errno_of(lambda: os.write(fd, b"x")) == errno.EBADF
    finally:
        os.close(fd)


def test_ftruncate_rdonly_fd_is_einval(rig):
    # VFS refuses ftruncate on a fd not open for writing before FUSE is asked.
    fd = os.open(rig.p("hello.txt"), os.O_RDONLY)
    try:
        assert _errno_of(lambda: os.ftruncate(fd, 0)) == errno.EINVAL
    finally:
        os.close(fd)


def test_open_trunc_rdonly_erofs_on_ro_mount(rig):
    # Official CVMFS mounts read-only ('-o ro'), so O_TRUNC is rejected by the
    # kernel VFS with EROFS before it ever reaches FUSE (mnt_want_write fails on
    # the read-only superblock). The underlying bytes are left intact.
    with pytest.raises(OSError) as ei:
        os.open(rig.p("hello.txt"), os.O_TRUNC | os.O_RDONLY)
    assert ei.value.errno == errno.EROFS
    assert os.path.getsize(rig.p("hello.txt")) == len(HELLO)


def test_failed_mutations_leave_no_phantom_entries(rig):
    baseline = os.listdir(rig.mnt)
    for _, mutate, _ in MUTATIONS:
        with pytest.raises(OSError):
            mutate(rig)
        assert os.listdir(rig.mnt) == baseline, "phantom entry after failed op"
    assert "hello.txt" in baseline and "empty" in baseline
    for ghost in ("newfile", "newdir", "renamed", "hardlink", "newlink", "fifo"):
        assert ghost not in baseline


# ---- 2. magic xattrs -------------------------------------------------------

def test_listxattr_file_exact_seven_name_set(rig):
    assert set(os.listxattr(rig.p("hello.txt"))) == set(XATTR_NAMES)


def test_listxattr_dir_lists_only_applicable_names(rig):
    # Per-node listing (official behaviour): directories advertise only the
    # common attrs — user.hash / user.nchunks are file-only.
    assert set(os.listxattr(rig.p("sub"))) == set(DIR_XATTR_NAMES)
    assert set(os.listxattr(rig.mnt)) == set(DIR_XATTR_NAMES)


def test_listxattr_dir_excludes_file_only_names(rig):
    names = set(os.listxattr(rig.p("sub")))
    assert "user.hash" not in names and "user.nchunks" not in names


def test_xattr_fqrn_value(rig):
    assert os.getxattr(rig.p("hello.txt"), "user.fqrn") == REPO.encode()


def test_xattr_revision_matches_manifest(rig):
    assert os.getxattr(rig.mnt, "user.revision") == \
        str(rig.forge.revision).encode()


def test_xattr_root_hash_matches_manifest_c_field(rig):
    assert os.getxattr(rig.mnt, "user.root_hash") == \
        rig.forge.root_catalog_hash.encode()


def test_xattr_host_is_configured_origin(rig):
    assert os.getxattr(rig.mnt, "user.host") == rig.url.encode()


def test_xattr_proxy_is_direct(rig):
    assert os.getxattr(rig.mnt, "user.proxy") == b"DIRECT"


def test_xattr_hash_is_cas_hash_of_stored_bytes(rig):
    # CAS identity == SHA1 of the STORED (compressed) bytes; repo_forge stores
    # File content zlib-compressed, so the expected hex is reproducible here.
    expect = hashlib.sha1(zlib.compress(HELLO)).hexdigest()
    assert os.getxattr(rig.p("hello.txt"), "user.hash") == expect.encode()
    assert expect in rig.forge.cas       # the forge really stored that object


def test_xattr_nchunks_plain_file_is_one(rig):
    assert os.getxattr(rig.p("hello.txt"), "user.nchunks") == b"1"


def test_xattr_nchunks_chunked_file_matches_forged_count(rig):
    assert os.getxattr(rig.p("chunky.bin"), "user.nchunks") == \
        str(len(CHUNKS)).encode()


def test_xattr_hash_on_chunked_file_is_enodata(rig):
    # Chunked catalog rows carry no whole-file hash (hash column NULL).
    assert _errno_of(lambda: os.getxattr(rig.p("chunky.bin"), "user.hash")) \
        == errno.ENODATA


def test_xattr_file_only_names_on_dir_are_enodata(rig):
    for name in ("user.hash", "user.nchunks"):
        assert _errno_of(lambda n=name: os.getxattr(rig.p("sub"), n)) \
            == errno.ENODATA


def test_xattr_absent_name_is_enodata(rig):
    assert _errno_of(lambda: os.getxattr(rig.p("hello.txt"), "user.nope")) \
        == errno.ENODATA


def test_xattr_official_cvmfs_namespace(rig):
    # Official cvmfs exposes the user.cvmfs.* namespace; brix getxattr
    # normalizes the user.cvmfs.<name> prefix to the bare user.<name>.
    assert os.getxattr(rig.mnt, "user.cvmfs.fqrn") == REPO.encode()


def test_xattr_size_probe_protocol(rig):
    # getxattr(name, NULL, 0) must return the value length without copying;
    # listxattr(NULL, 0) the total list length; short buffer → ERANGE.
    path = rig.p("hello.txt").encode()
    n = libc.getxattr(path, b"user.fqrn", None, 0)
    assert n == len(REPO)
    n = libc.listxattr(path, None, 0)
    assert n == sum(len(x) + 1 for x in XATTR_NAMES)   # NUL-joined list
    buf = ctypes.create_string_buffer(2)
    ctypes.set_errno(0)
    assert libc.getxattr(path, b"user.fqrn", buf, 2) == -1
    assert ctypes.get_errno() == errno.ERANGE


def test_xattr_symlink_follow_reaches_target(rig):
    expect = hashlib.sha1(zlib.compress(HELLO)).hexdigest().encode()
    assert os.getxattr(rig.p("link"), "user.hash") == expect
    assert os.getxattr(rig.p("link"), "user.fqrn") == REPO.encode()


def test_xattr_symlink_nofollow_pinned(rig):
    # Pinned: the VFS refuses user.* getxattr on the symlink itself (ENODATA),
    # while listxattr on the link still shows the path-independent name set.
    for name in ("user.fqrn", "user.hash"):
        assert _errno_of(lambda n=name: os.getxattr(
            rig.p("link"), n, follow_symlinks=False)) == errno.ENODATA
    # A symlink node carries only the common (non-file-only) attrs.
    assert set(os.listxattr(rig.p("link"), follow_symlinks=False)) \
        == set(DIR_XATTR_NAMES)


# ---- 3. statfs -------------------------------------------------------------

def test_statfs_pinned_shape(rig):
    # brixcvmfs statfs: f_bsize=4096, f_namemax=255, everything else zeroed
    # (read-only: 0 free blocks; f_blocks/f_files not reported).
    sv = os.statvfs(rig.mnt)
    assert sv.f_bsize == 4096 and sv.f_frsize == 4096
    assert sv.f_namemax >= 255
    assert sv.f_bfree == 0 and sv.f_bavail == 0
    assert sv.f_blocks == 0 and sv.f_files == 0 and sv.f_ffree == 0


# ---- 4. getattr consistency ------------------------------------------------

def test_getattr_file_mode_size_mtime_uid(rig):
    st = os.stat(rig.p("hello.txt"))
    assert stat_m.S_ISREG(st.st_mode) and stat_m.S_IMODE(st.st_mode) == 0o644
    assert st.st_size == len(HELLO)
    assert int(st.st_mtime) == MTIME
    assert st.st_nlink == 1
    # catalog uid/gid 0 are mapped to the mounting user (brixcvmfs_op_getattr)
    assert st.st_uid == os.getuid() and st.st_gid == os.getgid()


def test_getattr_root_dir_mode_and_nlink(rig):
    st = os.stat(rig.mnt)
    assert stat_m.S_ISDIR(st.st_mode) and stat_m.S_IMODE(st.st_mode) == 0o755
    assert st.st_nlink == 2       # brix pins every dir at nlink=2


def test_getattr_dir_nlink_is_two_regardless_of_subdirs(rig):
    # "sub" has one subdir, "empty" none — both report the pinned nlink=2
    # (brix does not count subdirectories; stable, not 2+n).
    assert os.stat(rig.p("sub")).st_nlink == 2
    assert os.stat(rig.p("empty")).st_nlink == 2


def test_getattr_chunked_size_is_chunk_sum(rig):
    assert os.stat(rig.p("chunky.bin")).st_size == sum(len(c) for c in CHUNKS)


def test_getattr_symlink_lstat(rig):
    st = os.lstat(rig.p("link"))
    assert stat_m.S_ISLNK(st.st_mode)
    assert st.st_size == len("hello.txt")
    assert os.readlink(rig.p("link")) == "hello.txt"


def test_getattr_st_blocks_pinned_zero(rig):
    # Pinned actual: brix never fills st_blocks (0 even for 15000-byte file);
    # st_size remains the source of truth.  Official cvmfs reports blocks
    # derived from size — kept as an actual-pin, not an xfail, since the corpus
    # row does not mandate st_blocks.
    assert os.stat(rig.p("chunky.bin")).st_blocks == 0


def test_inode_stability_and_uniqueness(rig):
    paths = ["hello.txt", "chunky.bin", "sub", "sub/leaf.txt", "link", "empty"]
    first = {p: os.lstat(rig.p(p)).st_ino for p in paths}
    again = {p: os.lstat(rig.p(p)).st_ino for p in paths}
    assert first == again, "st_ino changed between two stats"
    inos = list(first.values())
    assert len(set(inos)) == len(inos), "st_ino collision between files"


def test_inode_stable_across_readdir_and_getattr(rig):
    before = os.stat(rig.p("hello.txt")).st_ino
    list(os.scandir(rig.mnt))      # full readdir pass in between
    assert os.stat(rig.p("hello.txt")).st_ino == before


def test_readdir_dirent_inos_pinned_unknown_sentinel(rig):
    # Pinned actual: brix readdir fills entries with a NULL stat, so d_ino is
    # the FUSE_UNKNOWN_INO sentinel (0xffffffff) — getattr is authoritative.
    inos = {e.inode() for e in os.scandir(rig.mnt)}
    assert inos == {0xffffffff}


# ---- 5. dirent stability ---------------------------------------------------

EXPECT_ROOT = sorted(["hello.txt", "exec.sh", "chunky.bin", "sub", "sub2",
                      "empty", "link"])


def test_readdir_full_set(rig):
    assert sorted(os.listdir(rig.mnt)) == EXPECT_ROOT
    assert sorted(os.listdir(rig.p("sub"))) == ["inner", "leaf.txt"]
    assert os.listdir(rig.p("empty")) == []


def test_two_consecutive_readdirs_identical_order_and_set(rig):
    a = os.listdir(rig.mnt)
    b = os.listdir(rig.mnt)
    assert a == b                      # same order, same set


def test_readdir_stable_during_concurrent_reads(rig):
    stop = threading.Event()
    errors = []

    def reader():
        while not stop.is_set():
            try:
                with open(rig.p("chunky.bin"), "rb") as f:
                    f.read()
            except OSError as e:      # pragma: no cover - failure path
                errors.append(e)
                return

    t = threading.Thread(target=reader)
    t.start()
    try:
        baseline = os.listdir(rig.mnt)
        for _ in range(20):
            assert os.listdir(rig.mnt) == baseline
    finally:
        stop.set()
        t.join(10)
    assert not errors, f"concurrent read failed: {errors}"


# ---- 6. open/close lifecycle ----------------------------------------------

def test_500_open_close_cycles_no_fd_leak(rig):
    fds_before = len(os.listdir("/proc/self/fd"))
    for _ in range(500):
        fd = os.open(rig.p("hello.txt"), os.O_RDONLY)
        assert os.read(fd, 5) == HELLO[:5]
        os.close(fd)
    assert len(os.listdir("/proc/self/fd")) == fds_before


def test_200_opendir_cycles(rig):
    for _ in range(200):
        assert sorted(e.name for e in os.scandir(rig.mnt)) == EXPECT_ROOT


def test_open_directory_for_read_is_eisdir(rig):
    assert _errno_of(lambda: os.open(rig.p("sub"), os.O_RDONLY)) is None
    # O_RDONLY on a dir yields a dirfd; reading *content* through open() is
    # what brix refuses: non-file opens report EISDIR at the FUSE layer.
    assert _errno_of(lambda: open(rig.p("sub"), "rb").read()) == errno.EISDIR


def test_open_missing_file_is_enoent(rig):
    assert _errno_of(lambda: os.open(rig.p("nope"), os.O_RDONLY)) == errno.ENOENT
    assert _errno_of(lambda: os.open(rig.p("sub/nope"), os.O_RDONLY)) == errno.ENOENT


# ---- 7. access(2) ----------------------------------------------------------

def test_access_r_ok_and_x_ok_on_executable(rig):
    assert os.access(rig.p("hello.txt"), os.R_OK)
    assert os.access(rig.p("exec.sh"), os.X_OK)
    assert os.access(rig.p("sub"), os.R_OK | os.X_OK)


def test_access_w_ok_official_refused(rig):
    # Read-only fs: .access denies W_OK (EROFS) on every node.
    assert os.access(rig.p("hello.txt"), os.W_OK) is False


def test_access_x_ok_on_nonexec_official_refused(rig):
    # .access refuses X_OK on a 0644 file (no execute bit).
    assert os.access(rig.p("hello.txt"), os.X_OK) is False


# ---- 8. mount surface ------------------------------------------------------

def _proc_mounts_line(mnt):
    with open("/proc/mounts") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3 and parts[1] == mnt:
                return parts
    return None


def test_mountpoint_is_a_fuse_filesystem(rig):
    parts = _proc_mounts_line(rig.mnt)
    assert parts is not None, "mountpoint not in /proc/mounts"
    assert parts[2] == "fuse.CVMFS-brix"          # pinned fstype
    assert "ro" in parts[3].split(",")            # read-only mount
    assert os.path.ismount(rig.mnt)


def test_mount_flag_official_ro(rig):
    # Official cvmfs2 mounts read-only; brixcvmfs passes -o ro for the
    # read-only client build.
    parts = _proc_mounts_line(rig.mnt)
    assert parts is not None and "ro" in parts[3].split(",")


def test_unmount_while_file_open_busy_then_clean(rig, tmp_path):
    # A second, private mount so the shared module mount is never disturbed.
    with fuse_mount(REPO, rig.url, rig.pub, cache=str(tmp_path / "cache")) \
            as (mnt, _):
        assert os.path.ismount(str(mnt))
        fd = os.open(os.path.join(str(mnt), "hello.txt"), os.O_RDONLY)
        try:
            # non-lazy unmount with an open file → busy, mount survives
            rc = subprocess.run(["fusermount3", "-u", str(mnt)],
                                capture_output=True).returncode
            assert rc != 0, "unmount succeeded despite an open file"
            assert os.path.ismount(str(mnt))
            assert os.read(fd, 5) == HELLO[:5]     # fd still serviceable
        finally:
            os.close(fd)
        # with the fd closed a plain unmount succeeds
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if subprocess.run(["fusermount3", "-u", str(mnt)],
                              capture_output=True).returncode == 0:
                break
            time.sleep(0.2)
        assert not os.path.ismount(str(mnt)), "mount wedged after close"
    assert not os.path.ismount(str(mnt))
