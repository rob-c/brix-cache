from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_fuse_read_helpers")

pytestmark = pytest.mark.xdist_group("test_cvmfs_conformance_fuse_read")

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
# Repo 2: chunked files (one long-lived mount).  The corpus constants (C3T,
# C1, GAP*, OVL*, LIE_*) and the `chunky` fixture live in the helper module so
# the fixture resolves them in its own namespace; they are re-exported here.
# --------------------------------------------------------------------------- #

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
# The corpus constants (MISS, MISSCHUNK, BAD, HEALTHY) and the `evil` fixture
# live in the helper module and are re-exported here.
# --------------------------------------------------------------------------- #

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
