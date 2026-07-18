"""
Read-cache partial-fill behavior across modular backends. See
docs/superpowers/specs/2026-07-01-read-cache-partial-fill-tests-design.md.

Group 1 asserts real sparse fill over a root:// (xroot) origin — the only path
currently wired for slice/partial fill. Other backends do whole-file fill
(Group 2, xfail-marked pending the generic-slice wiring).
"""
import pytest
from _cache_partial_helpers import (
    make_cache_node, read_range, residency, seed_origin, kill_origin,
    backend_available, raw_open_frame,
)

# Each test stands up its OWN dedicated cache + origin nginx (2 per xroot test)
# through the registry lifecycle harness, and the slice-cache origin read path
# SIGSEGVs under heavy concurrency — so this suite runs in the suite runner's
# SERIAL lane, not the -n12 parallel pool.
pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness]

BLK = 1024 * 1024  # 1 MiB slice granule (matches the proven brix_cache_slice 1m)


# ===========================================================================
# Group 1 — xroot origin sparse partial fill (real PARTIAL asserts)
# ===========================================================================

def test_single_block_range_marks_one_block(lifecycle, tmp_path):
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path, lifecycle=lifecycle) as node:
        seed_origin(node, "/f.bin", 5 * BLK - 12000)   # 5 blocks (last partial)
        read_range(node.cache_port, "/f.bin", 0, BLK)   # exactly block 0
        r = residency(node.store_dir, "f.bin")
        assert r["flags"] == ["PARTIAL"]
        assert r["present_blocks"] == [0]
        assert r["complete"] is False


def test_midfile_range_marks_correct_index(lifecycle, tmp_path):
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path, lifecycle=lifecycle) as node:
        seed_origin(node, "/f.bin", 5 * BLK)
        read_range(node.cache_port, "/f.bin", 2 * BLK, BLK)   # block 2 only
        r = residency(node.store_dir, "f.bin")
        assert r["present_blocks"] == [2] and r["flags"] == ["PARTIAL"]


def test_cross_boundary_range_marks_two_blocks(lifecycle, tmp_path):
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path, lifecycle=lifecycle) as node:
        seed_origin(node, "/f.bin", 5 * BLK)
        read_range(node.cache_port, "/f.bin", BLK // 2, BLK)   # spans blocks 0,1
        r = residency(node.store_dir, "f.bin")
        assert r["present_blocks"] == [0, 1]


def test_whole_file_read_marks_complete(lifecycle, tmp_path):
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path, lifecycle=lifecycle) as node:
        seed_origin(node, "/f.bin", 4 * BLK)
        read_range(node.cache_port, "/f.bin", 0, 4 * BLK)
        r = residency(node.store_dir, "f.bin")
        assert r["complete"] is True and r["present_count"] == 4


def test_two_disjoint_ranges_accumulate(lifecycle, tmp_path):
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path, lifecycle=lifecycle) as node:
        seed_origin(node, "/f.bin", 4 * BLK)
        read_range(node.cache_port, "/f.bin", 0, BLK)
        read_range(node.cache_port, "/f.bin", 3 * BLK, BLK)
        r = residency(node.store_dir, "f.bin")
        assert r["present_blocks"] == [0, 3]


def test_eof_partial_last_block(lifecycle, tmp_path):
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path, lifecycle=lifecycle) as node:
        seed_origin(node, "/f.bin", 3 * BLK + 100)   # 4 blocks, last tiny
        read_range(node.cache_port, "/f.bin", 3 * BLK, 100)
        r = residency(node.store_dir, "f.bin")
        assert r["present_blocks"] == [3] and r["flags"] == ["PARTIAL"]


def test_slice_size_reflected_in_cinfo(lifecycle, tmp_path):
    # The cinfo block_size records the configured slice granule, and a fixed
    # range maps to the block computed from it. NOTE: brix_cache_slice must be
    # a positive multiple of 1 MiB, and the per-slice fill pulls slice_size bytes
    # from the origin in one read (so >1 MiB exceeds the origin read cap) — 1 MiB
    # is the practical granule, which is why run_root_slice_fill.sh uses it.
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path, lifecycle=lifecycle) as node:
        seed_origin(node, "/f.bin", 6 * BLK)
        read_range(node.cache_port, "/f.bin", 2 * BLK, BLK)   # exactly block 2
        r = residency(node.store_dir, "f.bin")
        assert r["block_size"] == BLK and r["present_blocks"] == [2]


@pytest.mark.parametrize("origin_backend", ["posix", "pblock"])
def test_partial_fill_independent_of_origin_backend(lifecycle, tmp_path, origin_backend):
    with make_cache_node("xroot", slice_size=BLK, origin_backend=origin_backend,
                         tmp=tmp_path, lifecycle=lifecycle) as node:
        seed_origin(node, "/f.bin", 3 * BLK)
        read_range(node.cache_port, "/f.bin", BLK, BLK)
        r = residency(node.store_dir, "f.bin")
        assert r["present_blocks"] == [1] and r["flags"] == ["PARTIAL"]


# ===========================================================================
# Group 2 — whole-file backends (posix/pblock) + the slice-ignored gap
# ===========================================================================

@pytest.mark.parametrize("backend", ["posix", "pblock"])
def test_generic_backend_partial_read_is_whole_file(lifecycle, tmp_path, backend):
    """Documents SP1: a range read over a non-xroot backend caches the WHOLE
    file (COMPLETE), not just the touched blocks."""
    with make_cache_node(backend, tmp=tmp_path, lifecycle=lifecycle) as node:
        seed_origin(node, "/f.bin", 4 * BLK)
        read_range(node.cache_port, "/f.bin", 0, BLK)   # only block 0 requested
        r = residency(node.store_dir, "f.bin")
        assert r["complete"] is True


@pytest.mark.parametrize("backend", ["posix", "pblock"])
def test_generic_backend_slice_partial_fills(lifecycle, tmp_path, backend):
    """Generic-backend slice (§14 landed): brix_cache_slice_size on a LOCAL
    (posix/pblock) storage backend partial-fills — a one-block read caches only
    block 0 (PARTIAL), not the whole file. (Formerly a strict xfail: the legacy
    brix_cache_slice directive never reached the composed sd_cache policy.)"""
    with make_cache_node(backend, slice_size=BLK, tmp=tmp_path, lifecycle=lifecycle) as node:
        seed_origin(node, "/f.bin", 4 * BLK)
        read_range(node.cache_port, "/f.bin", 0, BLK)
        r = residency(node.store_dir, "f.bin")
        assert r["flags"] == ["PARTIAL"] and r["present_blocks"] == [0]


# ===========================================================================
# Group 3 — size + admission negatives (composable path)
#
# NOTE: the admission filter (deny/include) and max_object gate the COMPOSABLE
# fill path (cache_admit.c); the legacy slice branch (cache_origin + cache_slice)
# caches per-block regardless of file size and bypasses admission — so these
# config gates are exercised on the composable (posix backend) path.
# ===========================================================================

def test_oversized_file_not_cached(lifecycle, tmp_path):
    with make_cache_node("posix", max_object=2 * BLK, tmp=tmp_path, lifecycle=lifecycle) as node:
        seed_origin(node, "/big.bin", 8 * BLK)   # > max_object
        read_range(node.cache_port, "/big.bin", 0, BLK)
        assert residency(node.store_dir, "big.bin") == {"absent": True}


def test_within_cap_is_cached(lifecycle, tmp_path):
    with make_cache_node("posix", max_object=8 * BLK, tmp=tmp_path, lifecycle=lifecycle) as node:
        seed_origin(node, "/ok.bin", 3 * BLK)
        read_range(node.cache_port, "/ok.bin", 0, BLK)
        assert residency(node.store_dir, "ok.bin")["complete"] is True


def test_admission_prefix_regex_gating(lifecycle, tmp_path):
    # A denied prefix is served from the origin but NOT cached: the composable
    # sd_cache read-fill now enforces the admission policy (deny/allow prefix +
    # include regex), bridged from the srv conf into the tier policy at
    # finalisation — parity with write-through and the legacy cache_origin admit.
    with make_cache_node("xroot", deny_prefix="/private", tmp=tmp_path, lifecycle=lifecycle) as node:
        seed_origin(node, "/private/x.bin", 3 * BLK)
        read_range(node.cache_port, "/private/x.bin", 0, BLK)
        assert residency(node.store_dir, "private/x.bin") == {"absent": True}


def test_admission_include_regex_gating(lifecycle, tmp_path):
    # An include regex is a whitelist: a path whose basename does not match is
    # served from the origin but never cached, while a matching sibling caches.
    with make_cache_node("xroot", include_regex=r"\.root$", tmp=tmp_path,
                         lifecycle=lifecycle) as node:
        seed_origin(node, "/skip.bin", 3 * BLK)     # non-matching -> not cached
        read_range(node.cache_port, "/skip.bin", 0, BLK)
        assert residency(node.store_dir, "skip.bin") == {"absent": True}
        seed_origin(node, "/keep.root", 3 * BLK)    # matching -> cached
        read_range(node.cache_port, "/keep.root", 0, BLK)
        assert residency(node.store_dir, "keep.root").get("absent") is not True


# ===========================================================================
# Group 4 — behavioral confirm (backend hidden)
# ===========================================================================

def test_warm_block_hit_is_byte_exact(lifecycle, tmp_path):
    """A cached block is served byte-exact on a second (warm) read, and the
    bitmap still shows exactly that block — the cache serves the cached data."""
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path, lifecycle=lifecycle) as node:
        data = seed_origin(node, "/f.bin", 4 * BLK)
        cold = read_range(node.cache_port, "/f.bin", 2 * BLK, BLK)   # cold fill
        assert cold == data[2 * BLK:3 * BLK]
        assert residency(node.store_dir, "f.bin")["present_blocks"] == [2]
        warm = read_range(node.cache_port, "/f.bin", 2 * BLK, BLK)   # warm hit
        assert warm == data[2 * BLK:3 * BLK]


def test_complete_file_serves_offline(lifecycle, tmp_path):
    """A FULLY cached (COMPLETE) file serves with the origin gone — open uses the
    cached metadata. (A PARTIAL cache does NOT: its open re-validates against the
    origin, so offline serving is a property of COMPLETE residency only.)"""
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path, lifecycle=lifecycle) as node:
        data = seed_origin(node, "/f.bin", 4 * BLK)
        read_range(node.cache_port, "/f.bin", 0, 4 * BLK)   # fill all blocks
        assert residency(node.store_dir, "f.bin")["complete"] is True
        kill_origin(node)
        got = read_range(node.cache_port, "/f.bin", 3 * BLK, BLK)   # any range
        assert got == data[3 * BLK:4 * BLK]


# ===========================================================================
# Group 5 — gated heavier backends (skip when env absent)
#
# These need an external origin: http -> XRD_TEST_HTTP_ORIGIN, s3 ->
# XRD_TEST_S3_ENDPOINT, rados -> XRD_TEST_RADOS_POOL. When present, the harness
# builder + seeding must be extended for that backend (make_cache_node raises a
# clear NotImplemented-style error until then). On a bare box all three skip.
# ===========================================================================

@pytest.mark.parametrize("backend", ["http", "s3", "rados"])
def test_gated_backend_partial_read_is_whole_file(lifecycle, tmp_path, backend):
    if not backend_available(backend):
        pytest.skip(f"{backend} origin/env not available")
    with make_cache_node(backend, tmp=tmp_path, lifecycle=lifecycle) as node:
        seed_origin(node, "/f.bin", 4 * BLK)
        read_range(node.cache_port, "/f.bin", 0, BLK)
        # current behavior: non-xroot backends do whole-file fill (COMPLETE);
        # flips to PARTIAL when generic-slice wiring lands (see phase-64 doc).
        assert residency(node.store_dir, "f.bin")["complete"] is True


def test_http_cold_open_frame_has_no_log_leak(lifecycle, tmp_path):
    """Regression: a cold open over the http backend triggers a whole-file fill on
    a worker thread; the driver's endpoint-selection audit ("http origin switched
    to ...") logs from that thread. It must reach the error log, NEVER the client
    socket. It used to: the instance is built at postconfig and its captured log
    pointer dangled to the config-phase cycle log, whose fd is reused as the
    accepted connection in the worker — so the NOTICE was spliced ahead of the
    kXR_open response, corrupting the wire (a crafted origin could inject bytes
    into a peer's stream). The open frame must be a clean protocol frame: a 0-status
    header with a 4-byte fhandle body and no ASCII log text."""
    if not backend_available("http"):
        pytest.skip("http origin/env not available")
    with make_cache_node("http", tmp=tmp_path, lifecycle=lifecycle) as node:
        seed_origin(node, "/f.bin", 4 * BLK)
        frame = raw_open_frame(node.cache_port, "/f.bin")
        status = int.from_bytes(frame[2:4], "big")
        dlen = int.from_bytes(frame[4:8], "big")
        assert status == 0, f"open status={status}, frame={frame[:32]!r}"
        assert dlen == 4, f"open dlen={dlen} (want 4-byte fhandle), frame={frame[:32]!r}"
        assert len(frame) == 8 + 4, f"trailing bytes on open frame: {frame!r}"
        assert b"brix:" not in frame and b"origin switched" not in frame, (
            f"server log text leaked onto the client socket: {frame!r}")
