# tests/test_cvmfs_tiered_client.py — Phase-87 G5: client `-o cache_tiering`.
#
# Theme: on a packed cache (`-o cache_format=packed`, G4) the tiering knob
# makes the store zstd-compress entries at PUT time when that actually shrinks
# them (cold packing, fmt=1) and re-append a raw copy once an entry proves hot
# (BRIX_PACK_PROMOTE_HITS get()s — promotion, so the log's FIFO eviction
# approximates LRU).  Tiering is a WRITE-side knob only: the read path always
# understands both formats, so a tiering mount's cache replays fine in a
# plain packed mount and vice versa.  Integrity is unchanged — pack crc32 over
# the stored form + the fetch layer's sidecar re-verify on every hit.
#
# Coverage (3-test ritual + promotion):
#   * success: compressible corpus is cold-packed (no plaintext in any
#     segment, pack far smaller than the corpus), serves byte-identical,
#     offline too, and replays refetch-free in a NON-tiering packed remount;
#   * success: a hot file (read past the promotion threshold) is re-appended
#     raw — its plaintext appears in the log — and stays byte-identical;
#   * error/boundary: an incompressible body is stored raw immediately
#     (tiering must never inflate), via the $BRIXCVMFS_CACHE_TIERING toggle;
#   * security-neg: a bit-flipped record (object + sidecar both hit) is never
#     served — detected on remount and refetched genuine from the origin.
#
# Contract citations: tiering = shared/cache/cas_pack.c (TIER_MIN, fmt byte,
# BRIX_PACK_PROMOTE_HITS + store-level units in cas_pack_unittest.c); gate =
# client/apps/fs/brixcvmfs.c (cache_tiering opt) + shared/cvmfs/client/client.c.

import hashlib
import os
import random
import shutil
import sys
import tempfile
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, _unmount, _wait_mounted  # noqa: E402, F401
from repo_forge import Dir, File, RepoForge  # noqa: E402
from test_cvmfs_packed_client import (  # noqa: E402 — same origin/mount idiom
    REPO, TTL, _data_gets, _start_origin, _stop_origin, pk_mount)

_FUSE_READY = (os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None
               and os.path.exists(BRIXMOUNT))
pytestmark = pytest.mark.skipif(not _FUSE_READY, reason="fuse mount prerequisites missing")

TIER_OPTS = ",cache_format=packed,cache_tiering"

# Compressible bodies (distinct needles) + one incompressible control.
BODIES = {f"t{i}.bin": (f"tier-{i}-line-{'x' * 24}\n" * 400).encode() for i in range(4)}
BODIES["r.bin"] = random.Random(875).randbytes(6000)


def _cas_rel(body: bytes) -> str:
    h = hashlib.sha1(zlib.compress(body)).hexdigest()
    return f"{h[:2]}/{h[2:]}"


RELS = {name: _cas_rel(body) for name, body in BODIES.items()}


def _forge(tmp_path):
    tree = {"pkg": Dir({name: File(body) for name, body in BODIES.items()})}
    return RepoForge(REPO, tmp_path / "web", ttl=TTL, revision=1).build(
        tree, tmp_path / "repo.pub")


def _read_all(mnt, log):
    for name, body in BODIES.items():
        assert (mnt / "pkg" / name).read_bytes() == body, \
            f"{name}: " + log.read_text(errors="replace")


def _seg_blob(cache: Path) -> bytes:
    return b"".join(p.read_bytes()
                    for p in sorted((cache / "pack").glob("seg-*.dat")))


@pytest.fixture
def workdir():
    """Private mkdtemp instead of pytest tmp_path: concurrent sessions rotate
    the shared basetemp and delete each other's live forge webroots."""
    d = Path(tempfile.mkdtemp(prefix="cvmfs_tc_forge."))
    (d / "cache").mkdir()
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ============================================================================
# Success: cold packing.  Every compressible object is stored zstd (its
# plaintext appears in NO segment), the pack is far smaller than the corpus,
# serving is byte-identical (offline too), and a NON-tiering packed remount
# replays every object refetch-free — the format is self-describing.
# ============================================================================

@pytest.mark.timeout(120)
def test_tiered_cold_pack_serves_and_replays(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web")
    cache = workdir / "cache"
    origin_up = True
    try:
        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache,
                      opts_extra=TIER_OPTS) as (mnt, proc, log):
            _read_all(mnt, log)

            blob = _seg_blob(cache)
            for i in range(4):
                assert BODIES[f"t{i}.bin"][:32] not in blob, \
                    f"t{i}.bin must be cold-packed (no plaintext in the log)"
            corpus = sum(len(b) for b in BODIES.values())
            assert len(blob) < corpus, \
                f"pack ({len(blob)}) must undercut the corpus ({corpus})"

            _stop_origin(httpd)
            origin_up = False
            _read_all(mnt, log)              # decompress path serves offline
            assert proc.poll() is None

        httpd2 = _start_origin(workdir / "web")
        try:
            with pk_mount(workdir / "repo.pub", httpd2.server_address[1],
                          cache) as (mnt, proc, log):   # packed, NO tiering
                _read_all(mnt, log)
                for name, rel in RELS.items():
                    assert _data_gets(httpd2, rel) == 0, \
                        f"{name} must replay from the tiered pack, not refetch"
                assert proc.poll() is None
        finally:
            _stop_origin(httpd2)
    finally:
        if origin_up:
            _stop_origin(httpd)
        forge.close()


# ============================================================================
# Success: hot promotion.  Reading one file past BRIX_PACK_PROMOTE_HITS
# (each open invalidates the FUSE page cache, so every read reaches the
# store) re-appends it raw — its plaintext appears in the log while the
# cold neighbours stay compressed — and bytes stay identical throughout.
# ============================================================================

@pytest.mark.timeout(120)
def test_tiered_hot_promotion_rewrites_raw(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web")
    cache = workdir / "cache"
    hot, cold = "t0.bin", "t1.bin"
    try:
        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache,
                      opts_extra=TIER_OPTS) as (mnt, proc, log):
            _read_all(mnt, log)
            for _ in range(6):
                assert (mnt / "pkg" / hot).read_bytes() == BODIES[hot], \
                    log.read_text(errors="replace")

            blob = _seg_blob(cache)
            assert BODIES[hot][:32] in blob, \
                "hot entry must be promoted to a raw copy in the log"
            assert BODIES[cold][:32] not in blob, \
                "cold neighbour must stay compressed"
            assert _data_gets(httpd, RELS[hot]) == 1, \
                "promotion is a cache rewrite, never a refetch"
            assert proc.poll() is None
    finally:
        _stop_origin(httpd)
        forge.close()


# ============================================================================
# Error/boundary: an incompressible body must be stored raw immediately —
# tiering never inflates an entry just to stamp it fmt=1.  Also covers the
# $BRIXCVMFS_CACHE_TIERING env toggle (no `-o cache_tiering`).
# ============================================================================

@pytest.mark.timeout(120)
def test_tiered_incompressible_stays_raw(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web")
    cache = workdir / "cache"
    try:
        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache,
                      opts_extra=",cache_format=packed",
                      env_extra={"BRIXCVMFS_CACHE_TIERING": "1"}) \
                as (mnt, proc, log):
            _read_all(mnt, log)
            blob = _seg_blob(cache)
            assert BODIES["r.bin"][:32] in blob, \
                "incompressible entry must be stored raw on first put"
            assert BODIES["t0.bin"][:32] not in blob, \
                "env toggle must arm tiering for compressible entries"
            assert proc.poll() is None
    finally:
        _stop_origin(httpd)
        forge.close()


# ============================================================================
# Security-neg: flip a byte after EVERY occurrence of the victim's storage
# key in the log (that covers its compressed object record and its sidecar
# record).  The remount must never serve damaged bytes — pack crc32 and the
# sidecar re-verify both stand in the way — and refetches genuine content.
# ============================================================================

@pytest.mark.timeout(120)
def test_tiered_tampered_record_never_served(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web")
    cache = workdir / "cache"
    victim = "t2.bin"
    hexkey = RELS[victim].replace("/", "").encode()
    try:
        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache,
                      opts_extra=TIER_OPTS) as (mnt, proc, log):
            _read_all(mnt, log)
        before = _data_gets(httpd, RELS[victim])

        flipped = 0
        for seg in sorted((cache / "pack").glob("seg-*.dat")):
            data = bytearray(seg.read_bytes())
            i = 0
            while (i := data.find(hexkey, i)) >= 0:
                data[i + 48] ^= 0x40      # 8 bytes into the record's payload
                i += len(hexkey)
                flipped += 1
            seg.write_bytes(bytes(data))
        assert flipped >= 2, "expected the object record and its sidecar"

        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache,
                      opts_extra=TIER_OPTS) as (mnt, proc, log):
            assert (mnt / "pkg" / victim).read_bytes() == BODIES[victim], \
                "tampered record must be detected and refetched, never served"
            assert _data_gets(httpd, RELS[victim]) == before + 1, \
                "detection must surface as exactly one origin refetch"
            assert proc.poll() is None
    finally:
        _stop_origin(httpd)
        forge.close()
