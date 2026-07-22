# tests/test_cvmfs_prewarm.py — Phase-85 F5: repo prewarm (client-side sweep).
# `brixMount cvmfs --prewarm <repo>` verifies the trust chain, walks the WHOLE
# snapshot (the pin when $BRIXCVMFS_PIN is set) via the content-aware core and
# pulls every referenced CAS object into the local cache — a site sharing that
# cache dir is fully warm before a job wave.  No mount, no FUSE.
# Origins on OS-assigned ephemeral ports (no PortBlock claim).
#
# Contract (docs/refactor/phase-85-cvmfs-swiss-army-features.md § F5):
#   * a clean prewarm lands EVERY object (files, chunks, nested catalogs),
#     prints per-sweep counts and exits 0 ("WARM");
#   * a missing upstream object is counted, the rest of the sweep still lands,
#     and the exit is nonzero ("INCOMPLETE") — no silent truncation;
#   * a tampered nested catalog aborts the walk (hash-verified fetch), exits
#     nonzero, and the tampered subtree's objects are never cached.
#
# Source contracts pinned from:
#   client/apps/fs/brixcvmfs.c   — brixcvmfs_prewarm summary lines + exit code.
#   shared/cvmfs/walk/walk.c     — cvmfs_walk_catalog verified descent.
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT  # noqa: E402
from repo_forge import Dir, File, RepoForge  # noqa: E402
from test_cvmfs_prefetch import _start_origin, _stop_origin  # noqa: E402
from settings import HOST

REPO = "test.cern.ch"

pytestmark = pytest.mark.skipif(not os.path.exists(BRIXMOUNT),
                                reason="brixMount binary missing")

A_BODY = b"prewarm-a\n" * 600
B_BODY = b"prewarm-b\n" * 800
TOP_BODY = b"prewarm-top\n" * 100


def _cas_hex(body: bytes) -> str:
    return hashlib.sha1(zlib.compress(body)).hexdigest()


def _cas_rel(body: bytes, suffix: str = "") -> str:
    h = _cas_hex(body)
    return f"{h[:2]}/{h[2:]}{suffix}"


def _tree():
    return {
        "pkg": Dir({"a.bin": File(A_BODY), "b.bin": File(B_BODY)}, nested=True),
        "top.txt": File(TOP_BODY),
    }


def _forge(tmp_path):
    return RepoForge(REPO, tmp_path / "web", revision=1).build(
        _tree(), tmp_path / "repo.pub")


@pytest.fixture
def workdir():
    """Private mkdtemp instead of pytest tmp_path: concurrent sessions share
    the pytest basetemp and their startup rotation renames/deletes each
    other's live numbered dirs mid-test (the forge webroot vanishes)."""
    d = Path(tempfile.mkdtemp(prefix="cvmfs_prewarm."))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _nested_catalog_keys(forge):
    """CAS keys ('<hex>C') of every non-root catalog object."""
    return [k for k in forge.cas
            if k.endswith("C") and k != forge.root_catalog_hash + "C"]


def _run_prewarm(tmp_path, port, cache: Path):
    cache.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("BRIXCVMFS_")}
    for k in ("http_proxy", "https_proxy", "all_proxy",
              "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        env.pop(k, None)
    env["BRIXCVMFS_PUBKEY"] = str(tmp_path / "repo.pub")
    env["BRIXCVMFS_TMP"] = str(tmp_path / "tmp")
    env["BRIXCVMFS_CACHE"] = str(cache)
    env["BRIXCVMFS_SERVER"] = f"http://{HOST}:{port}/cvmfs/{REPO}"
    (tmp_path / "tmp").mkdir(exist_ok=True)
    return subprocess.run([BRIXMOUNT, "cvmfs", "--prewarm", REPO],
                          env=env, capture_output=True, text=True, timeout=90)


# ============================================================================
# Success: every object lands (files across the nested boundary + both
# catalogs), counts reported, exit 0.
# ============================================================================

@pytest.mark.timeout(120)
def test_prewarm_lands_full_snapshot(workdir):
    forge = _forge(workdir)
    cache = workdir / "cache"
    try:
        httpd = _start_origin(workdir / "web")
        try:
            r = _run_prewarm(workdir, httpd.server_address[1], cache)
        finally:
            _stop_origin(httpd)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "WARM" in r.stdout
        assert "objects ........ 3 fetched" in r.stdout, r.stdout
        for body in (A_BODY, B_BODY, TOP_BODY):
            assert (cache / _cas_rel(body)).exists(), r.stdout
        # the walk itself caches the catalogs it descends (root + nested)
        assert (cache / _cas_rel_key(forge.root_catalog_hash + "C")).exists()
        for k in _nested_catalog_keys(forge):
            assert (cache / _cas_rel_key(k)).exists()
    finally:
        forge.close()


def _cas_rel_key(key: str) -> str:
    return f"{key[:2]}/{key[2:]}"


# ============================================================================
# Error path: a missing upstream object is counted, the rest still lands,
# exit is nonzero — no silent truncation.
# ============================================================================

@pytest.mark.timeout(120)
def test_prewarm_counts_missing_object_and_warms_rest(workdir):
    forge = _forge(workdir)
    forge.delete_cas(_cas_hex(A_BODY))
    cache = workdir / "cache"
    try:
        httpd = _start_origin(workdir / "web")
        try:
            r = _run_prewarm(workdir, httpd.server_address[1], cache)
        finally:
            _stop_origin(httpd)
        assert r.returncode != 0
        assert "INCOMPLETE" in r.stdout, r.stdout
        assert "errors ......... 1" in r.stdout, r.stdout
        assert not (cache / _cas_rel(A_BODY)).exists()
        for body in (B_BODY, TOP_BODY):
            assert (cache / _cas_rel(body)).exists(), r.stdout
    finally:
        forge.close()


# ============================================================================
# Security-negative: a tampered nested catalog aborts the walk — nonzero exit,
# and the tampered subtree's objects never reach the cache.
# ============================================================================

@pytest.mark.timeout(120)
def test_prewarm_tampered_nested_catalog_aborts(workdir):
    forge = _forge(workdir)
    nested = _nested_catalog_keys(forge)
    assert len(nested) == 1
    forge.flip_byte(nested[0], 40)
    cache = workdir / "cache"
    try:
        httpd = _start_origin(workdir / "web")
        try:
            r = _run_prewarm(workdir, httpd.server_address[1], cache)
        finally:
            _stop_origin(httpd)
        assert r.returncode != 0
        assert "INCOMPLETE" in r.stdout, r.stdout
        assert "walk aborted" in r.stdout, r.stdout
        # the tampered catalog's children must never land
        assert not (cache / _cas_rel(A_BODY)).exists()
        assert not (cache / _cas_rel(B_BODY)).exists()
    finally:
        forge.close()
