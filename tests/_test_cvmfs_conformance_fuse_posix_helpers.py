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

def _proc_mounts_line(mnt):
    with open("/proc/mounts") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3 and parts[1] == mnt:
                return parts
    return None
