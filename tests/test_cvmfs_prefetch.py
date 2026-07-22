# tests/test_cvmfs_prefetch.py — Phase-85 F4: predictive prefetch.
# `-o prefetch=<depth>` (or $BRIXCVMFS_PREFETCH) starts a background worker that,
# on the FIRST readdir of a directory, walks that subtree via the content-aware
# core (cvmfs_walk_subtree) and pre-pulls its file/chunk objects into the local
# cache.  `-o prefetch_budget=<bytes>` caps the total prefetched plaintext; the
# cap emits exactly ONE `signal=prefetchcap` audit line and never affects the
# foreground.  Origins on OS-assigned ephemeral ports (no PortBlock claim).
#
# Contract (docs/refactor/phase-85-cvmfs-swiss-army-features.md § F4):
#   * listing a directory warms its whole subtree: never-opened files are then
#     readable with the origin DOWN (cache-first fetch, no network on a hit);
#   * prefetch is scoped to the listed subtree — unrelated objects stay cold;
#   * a hit budget stops the sweep with one `signal=prefetchcap` audit line;
#     the foreground keeps working;
#   * a missing/broken CAS object is swallowed by the sweep — the rest of the
#     subtree still lands and the foreground never notices.
#
# Source contracts pinned from:
#   client/apps/fs/brixcvmfs.c    — pf_enqueue at op_readdir, pf_main worker
#       (own curl handle / failover snapshot / CAS handle), pf_visit budget cap
#       audit line `signal=prefetchcap`.
#   shared/cvmfs/walk/walk.c      — cvmfs_walk_subtree nested-mountpoint descent.
#   shared/cache/cas_store.c      — cache layout <cache>/<2hex>/<rest><suffix>.
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, _unmount, _wait_mounted  # noqa: E402
from repo_forge import Dir, File, RepoForge  # noqa: E402
from settings import BIND_HOST, HOST

REPO = "test.cern.ch"

_FUSE_READY = (os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None
               and os.path.exists(BRIXMOUNT))
pytestmark = pytest.mark.skipif(not _FUSE_READY, reason="fuse mount prerequisites missing")

class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


def _start_origin(webroot):
    """Non-contextmanager origin (the offline test shuts it down MID-mount) on
    an OS-assigned ephemeral port — immune to cross-session PortBlock-tile
    collisions (another session's test.cern.ch origin on a fixed port fails
    OUR trust chain with its foreign keys). Port via httpd.server_address."""
    handler = partial(_QuietHandler, directory=str(webroot))
    httpd = ThreadingHTTPServer((BIND_HOST, 0), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _stop_origin(httpd):
    httpd.shutdown()
    httpd.server_close()


@contextmanager
def pf_mount(pubkey, port, *, prefetch, budget=None, timeout=15):
    """brixMount with `-o prefetch=`; yields (mnt, proc, log, cache_dir) — the
    cache dir is exposed so tests can watch prefetched objects arrive."""
    workdir = Path(tempfile.mkdtemp(prefix="cvmfs_pf."))
    mnt = workdir / "mnt"
    for d in ("mnt", "tmp", "cache"):
        (workdir / d).mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("BRIXCVMFS_")}
    for k in ("http_proxy", "https_proxy", "all_proxy",
              "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        env.pop(k, None)
    env["BRIXCVMFS_PUBKEY"] = str(pubkey)
    env["BRIXCVMFS_TMP"] = str(workdir / "tmp")
    env["BRIXCVMFS_CACHE"] = str(workdir / "cache")
    env["BRIXCVMFS_SERVER"] = f"http://{HOST}:{port}/cvmfs/{REPO}"

    opts = f"auto_unmount,attr_timeout=0,entry_timeout=0,retries=1,prefetch={prefetch}"
    if budget is not None:
        opts += f",prefetch_budget={budget}"
    log = workdir / "brixmount.log"
    with open(log, "wb") as lf:
        proc = subprocess.Popen([BRIXMOUNT, "cvmfs", REPO, str(mnt), "-o", opts, "-f"],
                                env=env, stdout=lf, stderr=lf)
    try:
        _wait_mounted(mnt, timeout)
        yield mnt, proc, log, workdir / "cache"
    finally:
        if not os.path.ismount(mnt) and log.exists():
            keep = Path(tempfile.gettempdir()) / "brixcvmfs_mount_failures"
            keep.mkdir(exist_ok=True)
            shutil.copy(log, keep / f"{workdir.name}.log")
        _unmount(mnt)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(3)
            except subprocess.TimeoutExpired:
                proc.kill()
        _unmount(mnt)
        shutil.rmtree(workdir, ignore_errors=True)


# ---- CAS identity: object key = sha1 of the STORED (zlib) form -------------

def _cas_hex(body: bytes) -> str:
    return hashlib.sha1(zlib.compress(body)).hexdigest()


def _cas_rel(body: bytes) -> str:
    h = _cas_hex(body)
    return f"{h[:2]}/{h[2:]}"


def _wait_cached(cache_dir: Path, rels, timeout=25) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if all((cache_dir / r).exists() for r in rels):
            return True
        time.sleep(0.2)
    return False


def _wait_in_log(log: Path, needle: str, timeout=25) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if needle in log.read_text(errors="replace"):
            return True
        time.sleep(0.2)
    return False


A_BODY = b"prefetch-a\n" * 700
B_BODY = b"prefetch-b\n" * 900
C_BODY = b"prefetch-c\n" * 500
OTHER_BODY = b"never-listed-so-never-prefetched\n"

TTL = 3600   # no TTL refresh interference during any test


def _tree():
    return {
        "pkg": Dir({"a.bin": File(A_BODY), "b.bin": File(B_BODY)}),
        "pkg2": Dir({"c.bin": File(C_BODY)}),
        "other.txt": File(OTHER_BODY),
    }


def _forge(tmp_path):
    return RepoForge(REPO, tmp_path / "web", ttl=TTL, revision=1).build(
        _tree(), tmp_path / "repo.pub")


@pytest.fixture
def workdir():
    """Private mkdtemp instead of pytest tmp_path: concurrent sessions share
    the pytest basetemp and their startup rotation renames/deletes each
    other's live numbered dirs mid-test (the forge webroot vanishes)."""
    d = Path(tempfile.mkdtemp(prefix="cvmfs_pf_forge."))
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ============================================================================
# Success: listing /pkg warms its subtree — never-opened files read back
# correctly with the origin DOWN, and the sweep never touches /other.txt.
# ============================================================================

@pytest.mark.timeout(120)
def test_prefetch_serves_unopened_files_offline(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web")
    origin_up = True
    try:
        with pf_mount(workdir / "repo.pub", httpd.server_address[1], prefetch=8) \
                as (mnt, _, log, cache):
            os.listdir(mnt / "pkg")     # the ONLY foreground touch of /pkg
            assert _wait_cached(cache, [_cas_rel(A_BODY), _cas_rel(B_BODY)]), \
                "prefetch never landed pkg objects:\n" + log.read_text(errors="replace")
            # scoped: the un-listed sibling file stays cold
            assert not (cache / _cas_rel(OTHER_BODY)).exists()

            _stop_origin(httpd)
            origin_up = False
            assert (mnt / "pkg" / "a.bin").read_bytes() == A_BODY
            assert (mnt / "pkg" / "b.bin").read_bytes() == B_BODY
            assert "signal=prefetchcap" not in log.read_text(errors="replace")
    finally:
        if origin_up:
            _stop_origin(httpd)
        forge.close()


# ============================================================================
# Budget bound: a hit cap stops the sweep with exactly ONE audit line — across
# further enqueues too — and the foreground keeps working.
# ============================================================================

@pytest.mark.timeout(120)
def test_prefetch_budget_cap_audits_once_and_spares_foreground(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web")
    try:
        with pf_mount(workdir / "repo.pub", httpd.server_address[1], prefetch=8, budget=1) \
                as (mnt, proc, log, _cache):
            os.listdir(mnt / "pkg")
            assert _wait_in_log(log, "signal=prefetchcap"), \
                "budget cap never audited:\n" + log.read_text(errors="replace")
            os.listdir(mnt / "pkg2")    # further enqueues drain silently
            time.sleep(1.5)
            cap_lines = [ln for ln in log.read_text(errors="replace").splitlines()
                         if "signal=prefetchcap" in ln]
            assert len(cap_lines) == 1, log.read_text(errors="replace")
            assert f"repo={REPO}" in cap_lines[0]
            # foreground unaffected: reads still work, mount still alive
            assert (mnt / "pkg" / "a.bin").read_bytes() == A_BODY
            assert (mnt / "other.txt").read_bytes() == OTHER_BODY
            assert proc.poll() is None
    finally:
        _stop_origin(httpd)
        forge.close()


# ============================================================================
# Error path (security-neg twin): a CAS object missing from the origin is
# swallowed by the sweep — the rest of the subtree still lands, the foreground
# never notices, and no cap audit fires.
# ============================================================================

@pytest.mark.timeout(120)
def test_prefetch_swallows_missing_object(workdir):
    forge = _forge(workdir)
    forge.delete_cas(_cas_hex(A_BODY))          # a.bin's object vanishes upstream
    httpd = _start_origin(workdir / "web")
    try:
        with pf_mount(workdir / "repo.pub", httpd.server_address[1], prefetch=8) \
                as (mnt, proc, log, cache):
            os.listdir(mnt / "pkg")
            assert _wait_cached(cache, [_cas_rel(B_BODY)]), \
                "sweep died on the missing object:\n" + log.read_text(errors="replace")
            # foreground healthy: the intact file reads, the mount survives
            assert (mnt / "pkg" / "b.bin").read_bytes() == B_BODY
            assert (mnt / "other.txt").read_bytes() == OTHER_BODY
            assert proc.poll() is None
            assert "signal=prefetchcap" not in log.read_text(errors="replace")
    finally:
        _stop_origin(httpd)
        forge.close()
