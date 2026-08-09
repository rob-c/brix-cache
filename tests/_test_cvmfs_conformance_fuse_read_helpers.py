"""Phase-84 fuse conformance: read/chunk semantics of the brixcvmfs client.

Theme
-----
Byte-exactness and error discipline of ``cvmfs_client_read`` (plain files via
``read_whole``, chunked files via ``chunk_read_cb`` reassembly —
shared/cvmfs/client/client.c:305-368) as observed through a real libfuse3 mount
(client/apps/fs/brixcvmfs.c ``brixcvmfs_op_read`` → ``-EIO`` on any client-read
failure). Repos are forged with tests/cvmfs/repo_forge.py and served by the
webroot-mode mock Stratum-1; offsets are driven with ``os.pread`` on raw fds.

Coverage
--------
* Plain reads: whole-file byte-exact for sizes {0,1,4095,4096,4097,64K,~1M};
  pread at {0,1,mid,len-1}; at/straddling/past EOF; zero-length reads;
  sequential-small-read reassembly; O_RDONLY reopen stability; empty file.
* Compression: zlib-stored vs uncompressed-stored objects (fetch.c
  decode_and_verify inflate-or-raw fallback), incompressible plaintext,
  stat.st_size == plaintext length for both storage modes (catalog `size`
  column is plaintext size, never stored size).
* Chunked files: 3×64K+tail layout — whole == concat, per-chunk preads,
  first/last byte of every chunk, 2- and 3-chunk spanning reads, tail chunk;
  single-chunk chunked vs plain equivalence; forged chunk-list GAP / OVERLAP /
  lying total size (behavior pinned from observation — see per-test comments);
  missing chunk CAS object.
* Failure paths: deleted CAS object and flipped stored byte → EIO, never wrong
  bytes; corrupt-after-warm still serves cached plaintext (cache-first,
  fetch.c:63-65); healthy-sibling isolation (warm-first — a failed fetch
  blacklists the origin route, see fetch.c:106, so cold reads after a failure
  legitimately go offline).
* Concurrency: two reader processes through the single-threaded mount.

NOTE the Wave-1 ENOENT-vs-EIO divergence does NOT apply to the read path:
``brixcvmfs_op_read`` maps every ``cvmfs_client_read`` failure to ``-EIO``
(brixcvmfs.c:252), matching the official client. Pinned as plain asserts here.

Ports: fuse_read block 13380-13399 (conformance_common.PORT_BLOCKS).
"""

import errno
import hashlib
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import zlib
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, PortBlock, fuse_mount
from repo_forge import Chunk, Chunked, File, RepoForge
from settings import HOST

REPO = "read.test.cern.ch"
CH = 64 * 1024                      # chunk quantum for the chunked corpus
MOCK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs", "mock_stratum1.py")

_FUSE_READY = (os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None
               and os.path.exists(BRIXMOUNT))
pytestmark = pytest.mark.skipif(not _FUSE_READY, reason="fuse mount prerequisites missing")

_BLOCK = PortBlock("fuse_read")


# --------------------------------------------------------------------------- #
# Content + CAS helpers
# --------------------------------------------------------------------------- #
def blob(tag: str, n: int) -> bytes:
    """Deterministic pseudo-random (incompressible) bytes, unique per tag."""
    out = bytearray()
    c = 0
    while len(out) < n:
        out += hashlib.sha256(f"{tag}:{c}".encode()).digest()
        c += 1
    return bytes(out[:n])


def cas_key(content: bytes, suffix: str = "", compressed: bool = True) -> str:
    """CAS identity = SHA1 of the STORED bytes (repo_forge._write_cas)."""
    stored = zlib.compress(content) if compressed else content
    return hashlib.sha1(stored).hexdigest() + suffix


@contextmanager
def rdfd(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        yield fd
    finally:
        os.close(fd)


def outcome(path):
    """('ok', bytes) or ('err', errno) — for determinism checks on hostile files."""
    try:
        return ("ok", Path(path).read_bytes())
    except OSError as e:
        return ("err", e.errno)


# --------------------------------------------------------------------------- #
# Forge + mock + mount plumbing (module-scoped; local by design — shared
# conformance_common must not be edited during parallel Wave-3 authoring)
# --------------------------------------------------------------------------- #
def _start_mock(web: Path, port: int) -> subprocess.Popen:
    proc = subprocess.Popen([sys.executable, MOCK, "--port", str(port), "--repo", REPO,
                             "--webroot", str(web)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://{HOST}:{port}/ctl/log", timeout=0.3)
            return proc
        except Exception:
            time.sleep(0.1)
    proc.terminate()
    raise RuntimeError(f"webroot mock did not start on {port}")


def _repo_fixture(tmp_path_factory, name: str, tree: dict, mutate=None):
    """Build a forged repo, serve it, return (info, finalizer-iterable)."""
    base = tmp_path_factory.mktemp(name)
    web, pub = base / "web", base / "repo.pub"
    forge = RepoForge(REPO, web).build(tree, pub)
    if mutate:
        mutate(forge)
    port = _BLOCK.mock()
    proc = _start_mock(web, port)
    info = SimpleNamespace(forge=forge, web=web, pub=pub, port=port, proc=proc,
                           url=f"http://{HOST}:{port}/cvmfs/{REPO}")
    return info


def _teardown_repo(info):
    info.proc.terminate()
    try:
        info.proc.wait(3)
    except subprocess.TimeoutExpired:
        info.proc.kill()
    info.forge.close()


@contextmanager
def mounted(info, **kw):
    # One bounded retry: under heavy parallel authoring load a first mount
    # attempt has been observed to miss the 15s readiness window.
    for attempt in (0, 1):
        with fuse_mount(REPO, info.url, info.pub, **kw) as (mnt, _proc):
            if os.path.ismount(str(mnt)):
                yield mnt
                return
        assert attempt == 0, "brixMount failed to mount the forged repo (2 attempts)"
        time.sleep(1)


# --------------------------------------------------------------------------- #
# Repo 1: plain files + storage modes (one long-lived mount)
# --------------------------------------------------------------------------- #
SIZES = [0, 1, 4095, 4096, 4097, 65536, 1000003]
PLAIN = {f"sz{n}": blob(f"sz{n}", n) for n in SIZES}
TEXT64K = (b"The quick brown fox jumps over the lazy dog %06d\n" * 1400)[:64 * 1024]
RAND16K = blob("rand-shared", 16384)
UNCOMP = {"u1": blob("u1", 1), "u4096": blob("u4096", 4096), "u64k": blob("u64k", CH)}


@pytest.fixture(scope="module")
def plain(tmp_path_factory):
    tree = {n: File(c) for n, c in PLAIN.items()}
    tree["text64k"] = File(TEXT64K)
    tree["crand"] = File(RAND16K)                              # zlib-stored, incompressible
    tree["urand"] = File(RAND16K + b"u", compressed=False)     # unique content, raw-stored
    tree.update({n: File(c, compressed=False) for n, c in UNCOMP.items()})
    info = _repo_fixture(tmp_path_factory, "fuse_read_plain", tree)
    try:
        with mounted(info) as mnt:
            yield SimpleNamespace(mnt=mnt, **vars(info))
    finally:
        _teardown_repo(info)


# ---- whole-file reads ------------------------------------------------------

# --------------------------------------------------------------------------- #
# Repo 2 corpus: chunked files.  Defined here (with the `chunky` fixture that
# consumes them) so the fixture resolves them in this module's namespace;
# split_continuation.reexport re-exports them into the test module too, where
# the test bodies reference C3T / C3T_CAT / C1 directly.
# --------------------------------------------------------------------------- #
C3T = [blob("c3t0", CH), blob("c3t1", CH), blob("c3t2", CH), blob("c3tail", 1234)]
C3T_CAT = b"".join(C3T)
C1 = blob("c1", CH)
GAP0, GAP1 = blob("gap0", CH), blob("gap1", CH)           # hole at [CH, 2*CH)
OVL0, OVL1 = blob("ovl0", CH), blob("ovl1", CH)           # OVL1 at offset CH//2
LIE_B = [blob("lb0", CH), blob("lb1", CH)]                # catalog size 200000 > 131072
LIE_S = [blob("ls0", CH), blob("ls1", CH)]                # catalog size 100000 < 131072


@pytest.fixture(scope="module")
def chunky(tmp_path_factory):
    tree = {
        "c3t": Chunked([Chunk(p) for p in C3T]),
        "cone": Chunked([Chunk(C1)]),
        "plain_twin": File(C1),                # same plaintext as cone, plain row
        "gap": Chunked([Chunk(GAP0), Chunk(GAP1, offset=2 * CH)]),
        "ovl": Chunked([Chunk(OVL0), Chunk(OVL1, offset=CH // 2)]),
        "lie_big": Chunked([Chunk(p) for p in LIE_B], size=200000),
        "lie_small": Chunked([Chunk(p) for p in LIE_S], size=100000),
    }
    info = _repo_fixture(tmp_path_factory, "fuse_read_chunky", tree)
    try:
        with mounted(info) as mnt:
            yield SimpleNamespace(mnt=mnt, **vars(info))
    finally:
        _teardown_repo(info)


def _chunk_bounds(i):
    """(start, end) of chunk i in the c3t layout."""
    start = i * CH
    return start, start + len(C3T[i])


# ---- well-formed chunked file ---------------------------------------------

# Repo 3 corpus: hostile CAS states.  Defined here alongside the `evil` fixture
# that consumes them (reexported into the test module for the test bodies).
MISS = blob("missing-object", 5000)
MISSCHUNK = [blob("mc0", CH), blob("mc1", CH), blob("mc2", CH)]
BAD = blob("corrupt-object", 5000)
HEALTHY = blob("healthy-sibling", 3000)


@pytest.fixture(scope="module")
def evil(tmp_path_factory):
    def mutate(forge):
        forge.delete_cas(cas_key(MISS))
        forge.delete_cas(cas_key(MISSCHUNK[1], "P"))
        forge.flip_byte(cas_key(BAD), 10)          # corrupt STORED bytes
    tree = {
        "miss": File(MISS),
        "misschunk": Chunked([Chunk(p) for p in MISSCHUNK]),
        "bad": File(BAD),
        "healthy": File(HEALTHY),
    }
    info = _repo_fixture(tmp_path_factory, "fuse_read_evil", tree, mutate=mutate)
    try:
        yield info
    finally:
        _teardown_repo(info)



@pytest.fixture(scope="module")
def warmrepo(tmp_path_factory):
    info = _repo_fixture(tmp_path_factory, "fuse_read_warm",
                         {"warmfile": File(blob("warm-then-corrupt", 20000))})
    try:
        yield info
    finally:
        _teardown_repo(info)



def _spawn_reader(path):
    return subprocess.Popen([sys.executable, "-c", _READER, str(path)],
                            stdout=subprocess.PIPE, text=True)


def _expect(proc, data):
    out, _ = proc.communicate(timeout=20)      # timeout guard: no deadlock
    assert proc.returncode == 0
    assert out.split() == [str(len(data)), hashlib.sha1(data).hexdigest()]
