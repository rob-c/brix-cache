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
            urllib.request.urlopen(f"http://127.0.0.1:{port}/ctl/log", timeout=0.3)
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
                           url=f"http://127.0.0.1:{port}/cvmfs/{REPO}")
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
@pytest.mark.parametrize("name", list(PLAIN))
def test_whole_file_byte_exact(plain, name):
    assert (plain.mnt / name).read_bytes() == PLAIN[name]


@pytest.mark.parametrize("name", list(PLAIN))
def test_stat_size_is_plaintext_len(plain, name):
    # catalog `size` column carries the PLAINTEXT length (repo_forge writes
    # len(content); stored zlib form is longer/shorter) — st_size must match it.
    assert os.stat(plain.mnt / name).st_size == len(PLAIN[name])


# ---- pread offset precision ------------------------------------------------
@pytest.mark.parametrize("name", ["sz4095", "sz4097", "sz65536", "sz1000003"])
@pytest.mark.parametrize("where", ["start", "one", "mid", "last"])
def test_pread_at_offset(plain, name, where):
    data = PLAIN[name]
    off = {"start": 0, "one": 1, "mid": len(data) // 2, "last": len(data) - 1}[where]
    with rdfd(plain.mnt / name) as fd:
        assert os.pread(fd, 1024, off) == data[off:off + 1024]


@pytest.mark.parametrize("name", ["sz1", "sz4096", "sz65536", "sz1000003"])
def test_pread_exactly_at_eof_returns_empty(plain, name):
    with rdfd(plain.mnt / name) as fd:
        assert os.pread(fd, 4096, len(PLAIN[name])) == b""


@pytest.mark.parametrize("name", ["sz4095", "sz4097", "sz65536"])
def test_pread_straddling_eof_is_truncated(plain, name):
    data = PLAIN[name]
    with rdfd(plain.mnt / name) as fd:
        assert os.pread(fd, 100, len(data) - 37) == data[-37:]


@pytest.mark.parametrize("name", ["sz1", "sz65536"])
def test_pread_fully_past_eof_returns_empty(plain, name):
    with rdfd(plain.mnt / name) as fd:
        assert os.pread(fd, 4096, len(PLAIN[name]) + 10_000) == b""


@pytest.mark.parametrize("name", ["sz0", "sz65536"])
def test_zero_length_read(plain, name):
    with rdfd(plain.mnt / name) as fd:
        assert os.pread(fd, 0, 0) == b""


def test_empty_file_stat_and_read(plain):
    p = plain.mnt / "sz0"
    assert os.stat(p).st_size == 0
    assert p.read_bytes() == b""
    with rdfd(p) as fd:
        assert os.pread(fd, 4096, 0) == b""


def test_sequential_small_reads_reassemble(plain):
    # odd 997-byte steps → every FUSE request boundary misaligned with pages.
    chunks = []
    with rdfd(plain.mnt / "sz65536") as fd:
        while True:
            part = os.read(fd, 997)
            if not part:
                break
            chunks.append(part)
    assert b"".join(chunks) == PLAIN["sz65536"]


@pytest.mark.parametrize("name", ["sz4097", "sz65536"])
def test_reopen_reread_stable(plain, name):
    ref = PLAIN[name]
    for _ in range(3):
        with rdfd(plain.mnt / name) as fd:
            assert os.pread(fd, len(ref) + 10, 0) == ref


# ---- storage modes ---------------------------------------------------------
def test_compressible_text_roundtrip(plain):
    assert (plain.mnt / "text64k").read_bytes() == TEXT64K


@pytest.mark.parametrize("name", list(UNCOMP))
def test_uncompressed_store_byte_exact(plain, name):
    # raw-stored object: hash-of-plain identity, decode falls back to raw serve
    # (fetch.c:48-54) — and st_size is still the plaintext (== stored) length.
    assert (plain.mnt / name).read_bytes() == UNCOMP[name]
    assert os.stat(plain.mnt / name).st_size == len(UNCOMP[name])


def test_incompressible_random_compressed_roundtrip(plain):
    # zlib expands incompressible plaintext: stored form ≠ plaintext, stat and
    # read must still be plaintext-shaped.
    assert (plain.mnt / "crand").read_bytes() == RAND16K
    assert os.stat(plain.mnt / "crand").st_size == len(RAND16K)


def test_incompressible_random_uncompressed_roundtrip(plain):
    assert (plain.mnt / "urand").read_bytes() == RAND16K + b"u"


def test_storage_modes_agree_on_identical_shape(plain):
    # same length, both modes: byte-for-byte plaintext regardless of storage.
    a = (plain.mnt / "sz4096").read_bytes()
    b = (plain.mnt / "u4096").read_bytes()
    assert len(a) == len(b) == 4096
    assert a == PLAIN["sz4096"] and b == UNCOMP["u4096"]


# --------------------------------------------------------------------------- #
# Repo 2: chunked files (one long-lived mount)
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
def test_chunked_whole_read_equals_concat(chunky):
    assert (chunky.mnt / "c3t").read_bytes() == C3T_CAT


def test_chunked_stat_size_is_chunk_span(chunky):
    assert os.stat(chunky.mnt / "c3t").st_size == len(C3T_CAT)


@pytest.mark.parametrize("i", range(4))
def test_pread_exactly_one_chunk(chunky, i):
    lo, hi = _chunk_bounds(i)
    with rdfd(chunky.mnt / "c3t") as fd:
        assert os.pread(fd, hi - lo, lo) == C3T[i]


@pytest.mark.parametrize("i", range(4))
def test_chunk_edge_bytes(chunky, i):
    lo, hi = _chunk_bounds(i)
    with rdfd(chunky.mnt / "c3t") as fd:
        assert os.pread(fd, 1, lo) == C3T[i][:1]
        assert os.pread(fd, 1, hi - 1) == C3T[i][-1:]


@pytest.mark.parametrize("boundary", [1, 2, 3])
def test_read_spanning_two_chunks(chunky, boundary):
    off = boundary * CH - 100
    with rdfd(chunky.mnt / "c3t") as fd:
        assert os.pread(fd, 200, off) == C3T_CAT[off:off + 200]


def test_read_spanning_three_chunks(chunky):
    off, n = CH - 50, CH + 100          # covers tail of c0, all of c1, head of c2
    with rdfd(chunky.mnt / "c3t") as fd:
        assert os.pread(fd, n, off) == C3T_CAT[off:off + n]


def test_pread_partial_tail_chunk(chunky):
    lo, hi = _chunk_bounds(3)
    with rdfd(chunky.mnt / "c3t") as fd:
        assert os.pread(fd, 500, lo + 300) == C3T[3][300:800]
        assert os.pread(fd, 4096, hi - 34) == C3T[3][-34:]   # truncates at EOF


# ---- single-chunk vs plain equivalence ------------------------------------
def test_single_chunk_file_equals_plain_file(chunky):
    a = (chunky.mnt / "cone").read_bytes()
    b = (chunky.mnt / "plain_twin").read_bytes()
    assert a == b == C1
    assert os.stat(chunky.mnt / "cone").st_size == os.stat(chunky.mnt / "plain_twin").st_size


def test_single_chunk_pread_equals_plain_pread(chunky):
    with rdfd(chunky.mnt / "cone") as fa, rdfd(chunky.mnt / "plain_twin") as fb:
        for off in (0, 1, CH // 2, CH - 1):
            assert os.pread(fa, 777, off) == os.pread(fb, 777, off) == C1[off:off + 777]


# ---- forged GAP in the chunk list -----------------------------------------
# Official CVMFS treats a holey chunk list as undefined (the publisher never
# emits one). Pinned brix behavior (observed): the read stops SHORT at the hole
# — a whole-file read returns exactly the bytes before the gap, a pread inside
# the hole returns b"" (chunk_read_cb finds no intersecting chunk → got=0 →
# EOF-style short read), a pread beyond the hole returns the real chunk bytes.
# No crash, fully deterministic.
def test_gap_stat_size_is_last_chunk_end(chunky):
    assert os.stat(chunky.mnt / "gap").st_size == 3 * CH


def test_gap_whole_read_stops_short_at_hole(chunky):
    assert (chunky.mnt / "gap").read_bytes() == GAP0


def test_gap_read_is_deterministic(chunky):
    assert outcome(chunky.mnt / "gap") == outcome(chunky.mnt / "gap") == ("ok", GAP0)


def test_gap_pread_inside_hole_returns_empty(chunky):
    with rdfd(chunky.mnt / "gap") as fd:
        assert os.pread(fd, 512, CH + 4096) == b""


def test_gap_pread_beyond_hole_cold_returns_chunk_bytes(chunky):
    # cold kernel state (fresh mount): a pread landing on the post-hole chunk
    # returns its real bytes (chunk_read_cb intersects the offset=2*CH row).
    with mounted(chunky) as mnt:
        with rdfd(mnt / "gap") as fd:
            assert os.pread(fd, 4096, 2 * CH) == GAP1[:4096]


def test_gap_pread_beyond_hole_after_whole_read_never_garbage(chunky):
    # page-cache history matters: once a whole-file read hit the EOF-style
    # short read at the hole, the kernel pins EOF there and a beyond-hole pread
    # returns b"" (observed). Either the real chunk bytes (cold) or b"" (warm)
    # are acceptable — garbage never is.
    (chunky.mnt / "gap").read_bytes()
    with rdfd(chunky.mnt / "gap") as fd:
        assert os.pread(fd, 4096, 2 * CH) in (GAP1[:4096], b"")


# ---- forged OVERLAP in the chunk list -------------------------------------
# Also undefined officially. Pinned brix behavior (observed): chunk_read_cb
# sums per-chunk copied byte counts, so overlapping definitions make the op
# return MORE bytes than requested → libfuse rejects the reply → EIO. Never
# wrong bytes, never a crash, mount stays healthy.
def test_overlap_whole_read_fails_eio_no_crash(chunky):
    with pytest.raises(OSError) as ei:
        (chunky.mnt / "ovl").read_bytes()
    assert ei.value.errno == errno.EIO
    assert os.path.ismount(str(chunky.mnt))


def test_overlap_outcome_is_deterministic(chunky):
    assert outcome(chunky.mnt / "ovl") == outcome(chunky.mnt / "ovl") == ("err", errno.EIO)


def test_overlap_does_not_poison_siblings(chunky):
    # same mount, same catalog: a well-formed chunked file still reads exactly.
    assert (chunky.mnt / "c3t").read_bytes() == C3T_CAT


# ---- catalog size disagrees with sum(chunks) ------------------------------
# Pinned brix behavior (observed): st_size is ALWAYS the catalog row's size
# column; reads clamp to the intersection of st_size and actual chunk data.
def test_size_larger_than_chunks_stat(chunky):
    assert os.stat(chunky.mnt / "lie_big").st_size == 200000


def test_size_larger_than_chunks_read_stops_at_data_end(chunky):
    # bytes [131072, 200000) have no chunk → short read at real data end.
    assert (chunky.mnt / "lie_big").read_bytes() == b"".join(LIE_B)


def test_size_smaller_than_chunks_stat(chunky):
    assert os.stat(chunky.mnt / "lie_small").st_size == 100000


def test_size_smaller_than_chunks_read_clamped_to_stat(chunky):
    # kernel clamps at i_size: trailing chunk bytes beyond 100000 unreachable.
    assert (chunky.mnt / "lie_small").read_bytes() == b"".join(LIE_S)[:100000]
    with rdfd(chunky.mnt / "lie_small") as fd:
        assert os.pread(fd, 4096, 100000) == b""


# --------------------------------------------------------------------------- #
# Repo 3: hostile CAS states — fresh mount per test: a failed fetch blacklists
# the (only) origin route (fetch.c:106), so state must not leak across tests.
# --------------------------------------------------------------------------- #
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


def test_missing_object_read_fails(evil):
    with mounted(evil) as mnt:
        with pytest.raises(OSError):
            (mnt / "miss").read_bytes()


def test_missing_object_errno_is_eio(evil):
    # Official client surfaces I/O-level fetch failure as EIO. brixcvmfs agrees
    # on the READ path (op_read → -EIO, brixcvmfs.c:252): the Wave-1
    # ENOENT-divergence does not apply here.
    with mounted(evil) as mnt:
        with pytest.raises(OSError) as ei:
            (mnt / "miss").read_bytes()
        assert ei.value.errno == errno.EIO


def test_missing_object_stat_still_works(evil):
    # metadata comes from the catalog, not the (absent) object.
    with mounted(evil) as mnt:
        assert os.stat(mnt / "miss").st_size == len(MISS)


def test_missing_chunk_whole_read_fails_eio(evil):
    with mounted(evil) as mnt:
        with pytest.raises(OSError) as ei:
            (mnt / "misschunk").read_bytes()
        assert ei.value.errno == errno.EIO


def test_missing_chunk_never_serves_wrong_bytes(evil):
    # any read touching the file may fail (kernel readahead spans into the
    # missing chunk) — but bytes that DO come back must be exact.
    with mounted(evil) as mnt:
        with rdfd(mnt / "misschunk") as fd:
            try:
                data = os.pread(fd, 4096, 0)
            except OSError as e:
                assert e.errno == errno.EIO
            else:
                assert data == MISSCHUNK[0][:4096]


def test_missing_chunk_warm_sibling_unaffected(evil):
    # warm-first: the sibling is cached before the failure blacklists the
    # origin, so it keeps serving from cache afterwards (fetch.c cache-first).
    with mounted(evil) as mnt:
        assert (mnt / "healthy").read_bytes() == HEALTHY
        with pytest.raises(OSError):
            (mnt / "misschunk").read_bytes()
        assert (mnt / "healthy").read_bytes() == HEALTHY


def test_corrupt_object_read_fails_never_wrong_bytes(evil):
    # hash-verify is over stored bytes BEFORE inflate (fetch.c:40): a flipped
    # byte must never decode into served plaintext.
    with mounted(evil) as mnt:
        try:
            data = (mnt / "bad").read_bytes()
        except OSError as e:
            assert e.errno == errno.EIO
        else:
            pytest.fail(f"corrupt object served {len(data)} bytes as clean")


def test_corrupt_object_warm_sibling_unaffected(evil):
    with mounted(evil) as mnt:
        assert (mnt / "healthy").read_bytes() == HEALTHY
        with pytest.raises(OSError):
            (mnt / "bad").read_bytes()
        assert (mnt / "healthy").read_bytes() == HEALTHY


def test_healthy_cold_read_on_fresh_mount(evil):
    # baseline: with no prior failures the mutated repo's intact file is fine.
    with mounted(evil) as mnt:
        assert (mnt / "healthy").read_bytes() == HEALTHY


# ---- corrupt AFTER warm read: cache-first keeps serving --------------------
@pytest.fixture(scope="module")
def warmrepo(tmp_path_factory):
    info = _repo_fixture(tmp_path_factory, "fuse_read_warm",
                         {"warmfile": File(blob("warm-then-corrupt", 20000))})
    try:
        yield info
    finally:
        _teardown_repo(info)


def test_corrupt_after_warm_read_serves_cached_plaintext(warmrepo):
    ref = blob("warm-then-corrupt", 20000)
    with mounted(warmrepo) as mnt:
        assert (mnt / "warmfile").read_bytes() == ref          # warm the cache
        warmrepo.forge.flip_byte(cas_key(ref), 42)             # corrupt origin copy
        # cache-first (fetch.c:63-65): the verified plaintext already in the
        # local CAS cache serves; the corrupted origin copy is never consulted.
        with rdfd(mnt / "warmfile") as fd:
            assert os.pread(fd, len(ref), 0) == ref


# --------------------------------------------------------------------------- #
# Concurrency through the single-threaded mount
# --------------------------------------------------------------------------- #
_READER = ("import sys,hashlib;"
           "d=open(sys.argv[1],'rb').read();"
           "print(len(d), hashlib.sha1(d).hexdigest())")


def _spawn_reader(path):
    return subprocess.Popen([sys.executable, "-c", _READER, str(path)],
                            stdout=subprocess.PIPE, text=True)


def _expect(proc, data):
    out, _ = proc.communicate(timeout=20)      # timeout guard: no deadlock
    assert proc.returncode == 0
    assert out.split() == [str(len(data)), hashlib.sha1(data).hexdigest()]


@pytest.mark.timeout(60)
def test_two_processes_read_different_files_concurrently(plain):
    a = _spawn_reader(plain.mnt / "sz1000003")
    b = _spawn_reader(plain.mnt / "sz65536")
    _expect(a, PLAIN["sz1000003"])
    _expect(b, PLAIN["sz65536"])


@pytest.mark.timeout(60)
def test_two_processes_read_same_file_concurrently(plain):
    a = _spawn_reader(plain.mnt / "sz1000003")
    b = _spawn_reader(plain.mnt / "sz1000003")
    _expect(a, PLAIN["sz1000003"])
    _expect(b, PLAIN["sz1000003"])
