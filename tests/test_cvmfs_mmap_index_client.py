# tests/test_cvmfs_mmap_index_client.py — Phase-87 G6: client `-o index=mmap`.
#
# Theme: with `-o index=mmap` / $BRIXCVMFS_INDEX=mmap the mount builds (or
# reloads) a pinned-revision mmap'd index of the ENTIRE merged namespace from
# its OWN verified catalog walk (shared/cvmfs/index/pathidx.c + client hooks
# in shared/cvmfs/client/client.c), persisted as the `pathidx.bxi` cache
# sidecar.  resolve/readdir/read then answer with ZERO catalog (SQLite)
# opens; unchunked reads go straight to CAS with the index's hash.
#
# Coverage (3-test ritual):
#   * success: the index answers nested-catalog metadata AFTER the nested
#     catalog object is deleted from cache AND origin — while a control mount
#     without the index loses that subtree (proof the catalogs are truly out
#     of the fast path); listings/symlinks/bytes all identical; sidecar
#     round-trips ("built from verified walk" → "loaded from sidecar");
#   * error: a sidecar built for revision A is REFUSED after the repo
#     publishes revision B (root-hash guard) — the mount rebuilds from a
#     fresh verified walk and serves B's namespace;
#   * security-neg: a tampered sidecar ENTRY (wrong content hash — outside
#     the header crc by lazy-paging design) is caught at first read by the
#     CAS verify-fetch: the wrong hash is never served, the index is dropped,
#     and the catalog path serves the genuine bytes.
#
# Contract citations: format/lookup = shared/cvmfs/index/pathidx.c (+
# pathidx_unittest.c store-level corpus); lifecycle =
# shared/cvmfs/client/client_pathidx.c; gate/sidecar =
# client/apps/fs/brixcvmfs.c (index=mmap opt, brixcvmfs_pathidx_setup).

import hashlib
import os
import random
import shutil
import struct
import sys
import tempfile
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, _unmount, _wait_mounted  # noqa: E402, F401
from repo_forge import Dir, File, RepoForge, Symlink  # noqa: E402
from test_cvmfs_packed_client import (  # noqa: E402 — same origin/mount idiom
    REPO, TTL, _data_gets, _start_origin, _stop_origin, pk_mount)

_FUSE_READY = (os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None
               and os.path.exists(BRIXMOUNT))
pytestmark = pytest.mark.skipif(not _FUSE_READY, reason="fuse mount prerequisites missing")

IDX_OPTS = ",index=mmap"
SIDECAR = "pathidx.bxi"

# Small unchunked bodies (index-resolved reads bypass the catalogs entirely;
# chunk tables would keep chunked files on the catalog path by design).
BODIES = {f"f{i}.bin": random.Random(876 + i).randbytes(2000 + 128 * i) for i in range(3)}
NBODIES = {f"n{i}.bin": random.Random(976 + i).randbytes(1500 + 64 * i) for i in range(2)}


def _cas_rel(body: bytes) -> str:
    h = hashlib.sha1(zlib.compress(body)).hexdigest()
    return f"{h[:2]}/{h[2:]}"


RELS = {name: _cas_rel(body) for name, body in BODIES.items()}


def _forge(tmp_path, *, revision=1, extra=None):
    pkg = {name: File(body) for name, body in BODIES.items()}
    if extra:
        pkg.update(extra)
    tree = {
        "pkg": Dir(pkg),
        "nested": Dir({name: File(body) for name, body in NBODIES.items()},
                      nested=True),
        "ln": Symlink("pkg/f0.bin"),
    }
    return RepoForge(REPO, tmp_path / "web", ttl=TTL, revision=revision).build(
        tree, tmp_path / "repo.pub")


def _read_all(mnt, log):
    for name, body in BODIES.items():
        assert (mnt / "pkg" / name).read_bytes() == body, \
            f"{name}: " + log.read_text(errors="replace")
    for name, body in NBODIES.items():
        assert (mnt / "nested" / name).read_bytes() == body, \
            f"{name}: " + log.read_text(errors="replace")


def _check_namespace(mnt):
    assert sorted(os.listdir(mnt)) == ["ln", "nested", "pkg"]
    assert sorted(os.listdir(mnt / "pkg")) == sorted(BODIES)
    assert sorted(os.listdir(mnt / "nested")) == sorted(NBODIES)
    assert os.readlink(mnt / "ln") == "pkg/f0.bin"


@pytest.fixture
def workdir():
    """Private mkdtemp instead of pytest tmp_path: concurrent sessions rotate
    the shared basetemp and delete each other's live forge webroots."""
    d = Path(tempfile.mkdtemp(prefix="cvmfs_ix_forge."))
    (d / "cache").mkdir()
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _delete_nested_catalog(forge, cache: Path):
    """Remove the nested catalog object from the origin webroot AND the mount's
    flat cache (data object + any .chk sidecar) — after this only the mmap
    index can answer for the nested subtree."""
    nested_keys = [k for k in forge.cas
                   if k.endswith("C") and not k.startswith(forge.root_catalog_hash)]
    assert len(nested_keys) == 1, f"expected exactly one nested catalog: {nested_keys}"
    nhex = nested_keys[0][:-1]
    os.unlink(forge.cas[nested_keys[0]])
    victims = [p for p in cache.rglob("*") if p.is_file() and nhex[2:] in p.name]
    assert victims, "nested catalog must have been cached by the verified walk"
    for p in victims:
        p.unlink()


# ============================================================================
# Success: the mmap index carries nested-catalog metadata on its own.  Delete
# the nested catalog everywhere — an indexed remount still resolves, lists
# and reads the nested subtree (content is cached CAS, metadata is the
# index), while a control mount without the index loses it.  Also covers the
# build→sidecar→reload round-trip and full-namespace listing/symlink parity.
# ============================================================================

@pytest.mark.timeout(120)
def test_index_serves_namespace_without_catalogs(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web")
    cache = workdir / "cache"
    try:
        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache,
                      opts_extra=IDX_OPTS) as (mnt, proc, log):
            assert "pathidx built from verified walk" in log.read_text(errors="replace")
            _check_namespace(mnt)
            _read_all(mnt, log)          # caches every content object
            assert proc.poll() is None
        assert (cache / SIDECAR).is_file(), "index must persist as a cache sidecar"

        _delete_nested_catalog(forge, cache)

        # Indexed remount: nested metadata comes from the mmap index, bytes
        # from the CAS cache — the deleted catalog is never needed.
        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache,
                      opts_extra=IDX_OPTS) as (mnt, proc, log):
            assert "pathidx loaded from sidecar" in log.read_text(errors="replace")
            _check_namespace(mnt)
            _read_all(mnt, log)
            assert proc.poll() is None

        # Control (no index): descending into the nested subtree needs the
        # catalog we deleted — the subtree is gone (empty listing, ENOENT).
        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache,
                      opts_extra="") as (mnt, proc, log):
            try:
                nested_entries = os.listdir(mnt / "nested")
            except OSError:
                nested_entries = []          # EIO on descent is equally "gone"
            assert nested_entries == [], \
                "control run must prove the nested catalog is truly gone"
            with pytest.raises(OSError):
                (mnt / "nested" / "n0.bin").read_bytes()
            assert proc.poll() is None
    finally:
        _stop_origin(httpd)
        forge.close()


# ============================================================================
# Error: a FAILED index build must be a clean no-op.  The build's verified
# walk fetches every nested catalog; on a repo whose nested catalog is broken
# those (expected) failures used to blacklist the single origin host in the
# shared failover engine — pushing the WHOLE mount offline and taking the
# catalog fallback down with it.  Pin the fix: build fails, transport health
# is untouched, intact subtrees keep serving, no sidecar is written.
# ============================================================================

@pytest.mark.timeout(120)
def test_index_build_failure_leaves_transport_alive(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web")
    cache = workdir / "cache"
    nested_keys = [k for k in forge.cas
                   if k.endswith("C") and not k.startswith(forge.root_catalog_hash)]
    os.unlink(forge.cas[nested_keys[0]])     # nested catalog gone BEFORE mount
    try:
        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache,
                      opts_extra=IDX_OPTS) as (mnt, proc, log):
            text = log.read_text(errors="replace")
            assert "pathidx unavailable — catalog lookups stay live" in text, text
            # Intact subtrees serve via live catalogs — the failed build must
            # not have blacklisted the origin.
            for name, body in BODIES.items():
                assert (mnt / "pkg" / name).read_bytes() == body
            with pytest.raises(OSError):     # the broken subtree really is broken
                (mnt / "nested" / "n0.bin").read_bytes()
            assert proc.poll() is None
        assert not (cache / SIDECAR).exists(), \
            "a failed build must never persist a partial index"
    finally:
        _stop_origin(httpd)
        forge.close()


# ============================================================================
# Error: root-hash guard.  A sidecar built for revision 1 must never answer
# for revision 2 — the remount refuses it, rebuilds from a fresh verified
# walk of the new root, and serves revision 2's namespace (new file listed
# and readable).
# ============================================================================

@pytest.mark.timeout(120)
def test_index_sidecar_refused_across_revisions(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web")
    cache = workdir / "cache"
    new_body = random.Random(1076).randbytes(1800)
    try:
        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache,
                      opts_extra=IDX_OPTS) as (mnt, proc, log):
            assert "pathidx built from verified walk" in log.read_text(errors="replace")
            _read_all(mnt, log)
        forge.close()

        forge = _forge(workdir, revision=2, extra={"new.bin": File(new_body)})
        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache,
                      opts_extra=IDX_OPTS) as (mnt, proc, log):
            text = log.read_text(errors="replace")
            assert "pathidx loaded from sidecar" not in text, \
                "a revision-1 index must be refused for revision 2"
            assert "pathidx built from verified walk" in text
            assert sorted(os.listdir(mnt / "pkg")) == sorted([*BODIES, "new.bin"])
            assert (mnt / "pkg" / "new.bin").read_bytes() == new_body
            _read_all(mnt, log)
            assert proc.poll() is None
    finally:
        _stop_origin(httpd)
        forge.close()


# ============================================================================
# Security-neg: tamper one ENTRY's content hash inside the sidecar.  Entry
# payloads are outside the header crc by design (lazy paging), so the load
# succeeds — but the first read of the victim fetches BY THE WRONG HASH,
# the CAS verify-fetch refuses to produce it, the client drops the index and
# the catalog path serves the genuine bytes.  The wrong bytes are never
# served.  (Also covers the $BRIXCVMFS_INDEX=mmap env gate.)
# ============================================================================

def _tamper_entry_hash(sidecar: Path, victim_path: bytes) -> str:
    """Flip bit 0x40 of the victim entry's first hash byte; return the
    resulting WRONG contiguous-hex key the client will fetch by."""
    data = bytearray(sidecar.read_bytes())
    magic, _ver, hash_sz, ent_sz = struct.unpack_from("<IIII", data, 0)
    assert magic == 0x49505842, "BXPI"
    (count, _nb, ents_off, _bo, blob_off, _bl, _fl) = struct.unpack_from(
        "<QQQQQQQ", data, 16 + hash_sz)
    hoff = None
    for i in range(count):
        e = ents_off + i * ent_sz
        path_off, path_len = struct.unpack_from("<QI", data, e)
        if data[blob_off + path_off: blob_off + path_off + path_len] == victim_path:
            hoff = e + (ent_sz - hash_sz) + 4      # hash struct → bytes[20]
            break
    assert hoff is not None, "victim entry not found in sidecar"
    data[hoff] ^= 0x40
    wrong = bytes(data[hoff: hoff + 20]).hex()
    sidecar.write_bytes(bytes(data))
    return wrong


@pytest.mark.timeout(120)
def test_index_tampered_entry_never_served(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web")
    cache = workdir / "cache"
    victim, vbody = "f1.bin", BODIES["f1.bin"]
    try:
        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache,
                      opts_extra=IDX_OPTS) as (mnt, proc, log):
            assert "pathidx built from verified walk" in log.read_text(errors="replace")
            _read_all(mnt, log)
        before = _data_gets(httpd, RELS[victim])

        wrong = _tamper_entry_hash(cache / SIDECAR, b"/pkg/" + victim.encode())

        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache,
                      opts_extra="", env_extra={"BRIXCVMFS_INDEX": "mmap"}) \
                as (mnt, proc, log):
            assert "pathidx loaded from sidecar" in log.read_text(errors="replace")
            assert (mnt / "pkg" / victim).read_bytes() == vbody, \
                "tampered index entry must fall back to genuine catalog bytes"
            # The index WAS consulted: the wrong hash hit the origin and was
            # refused; the genuine object then came from the CAS cache.
            assert _data_gets(httpd, f"{wrong[:2]}/{wrong[2:]}") >= 1, \
                "read must have first tried the index's (tampered) hash"
            assert _data_gets(httpd, RELS[victim]) == before, \
                "genuine bytes replay from cache — no refetch needed"
            # Index dropped, catalogs live: the rest of the tree still serves.
            _read_all(mnt, log)
            assert proc.poll() is None
    finally:
        _stop_origin(httpd)
        forge.close()
