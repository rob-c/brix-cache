# tests/test_cvmfs_packed_client.py — Phase-87 G4: client `-o cache_format=packed`.
#
# Theme: with `-o cache_format=packed` / $BRIXCVMFS_CACHE_FORMAT=packed the
# mount's CAS cache is a log-structured store (shared/cache/cas_pack.c):
# append-only segments under <cache>/pack/ plus a replayable journal, instead
# of one file per object.  The gate is honoured BEFORE the mount, so the
# brix_cas_* call sites are unchanged and every existing integrity property
# holds: entries re-verify against their .chk sidecar on every hit, so a
# damaged pack record is a purge+refetch, never a wrong serving.
# $BRIXCVMFS_CACHE_SEG_BYTES shrinks segments so rollover is exercisable.
#
# Coverage (3-test ritual):
#   * success: packed mount serves byte-identical files; the cache is pack/
#     ONLY (no flat-store fan-out dirs); segments rolled; entries serve with
#     the origin DOWN; a remount (via the env toggle) replays the journal and
#     serves the same objects with ZERO refetches;
#   * error: a torn tail — garbage appended to the active segment AND a
#     truncated journal — is recovered on remount; every file stays
#     byte-identical (replayed or transparently refetched), the mount lives;
#   * security-neg: a bit-flipped object record inside a segment is never
#     served — the remount detects it (pack crc + sidecar re-verify) and
#     refetches the genuine bytes from the origin.
#
# Contract citations: store = shared/cache/cas_pack.c (+ cas_pack_unittest.c
# for the store-level corpus); dispatch = shared/cache/cas_store.c; gate =
# client/apps/fs/brixcvmfs.c (cache_format opt) + shared/cvmfs/client/client.c
# (cvmfs_client_cache_config); sidecar re-verify = shared/cvmfs/fetch/fetch.c.

import hashlib
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import zlib
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

def _expression_1():
    return (
        {k: v for k, v in os.environ.items() if not k.startswith("BRIXCVMFS_")}
    )

def _expression_2(mnt, log):
    return (
        not os.path.ismount(mnt) and log.exists()
    )


def _guard_pk_mount_1(env_extra, env):
    if env_extra:
        env.update(env_extra)

def _guard_pk_mount_2(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(3)
        except subprocess.TimeoutExpired:
            proc.kill()


sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, _unmount, _wait_mounted  # noqa: E402
from repo_forge import Dir, File, RepoForge  # noqa: E402
from settings import BIND_HOST, HOST

REPO = "test.cern.ch"
TTL = 3600
SEG_BYTES = "8192"          # tiny segments: 4 x ~6KiB objects force rollover

_FUSE_READY = (os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None
               and os.path.exists(BRIXMOUNT))
pytestmark = pytest.mark.skipif(not _FUSE_READY, reason="fuse mount prerequisites missing")


# ---- origin: static GET, records every path for refetch/replay asserts -----

class _Handler(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.server.gets.append(self.path)
        super().do_GET()


def _start_origin(webroot: Path):
    httpd = ThreadingHTTPServer((BIND_HOST, 0), partial(_Handler, directory=str(webroot)))
    httpd.daemon_threads = True
    httpd.gets = []
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _stop_origin(httpd):
    httpd.shutdown()
    httpd.server_close()


def _data_gets(httpd, rel: str) -> int:
    return httpd.gets.count(f"/cvmfs/{REPO}/data/{rel}")


# ---- mount helper (test_cvmfs_dict_client.py idiom + packed cache) ---------

@contextmanager
def pk_mount(pubkey, port, cache, *, opts_extra=",cache_format=packed",
             env_extra=None, timeout=15):
    """Like the dict-client helper, but the CACHE DIR is caller-owned so the
    same packed cache can be remounted (replay) and corrupted between mounts."""
    workdir = Path(tempfile.mkdtemp(prefix="cvmfs_pc."))
    mnt = workdir / "mnt"
    mnt.mkdir()
    (workdir / "tmp").mkdir()
    env = _expression_1()
    for k in ("http_proxy", "https_proxy", "all_proxy",
              "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        env.pop(k, None)
    env["BRIXCVMFS_PUBKEY"] = str(pubkey)
    env["BRIXCVMFS_TMP"] = str(workdir / "tmp")
    env["BRIXCVMFS_CACHE"] = str(cache)
    env["BRIXCVMFS_SERVER"] = f"http://{HOST}:{port}/cvmfs/{REPO}"
    env["BRIXCVMFS_CACHE_SEG_BYTES"] = SEG_BYTES
    _guard_pk_mount_1(env_extra, env)

    opts = "auto_unmount,attr_timeout=0,entry_timeout=0,retries=1" + opts_extra
    log = workdir / "brixmount.log"
    with open(log, "wb") as lf:
        proc = subprocess.Popen([BRIXMOUNT, "cvmfs", REPO, str(mnt), "-o", opts, "-f"],
                                env=env, stdout=lf, stderr=lf)
    try:
        _wait_mounted(mnt, timeout)
        yield mnt, proc, log
    finally:
        if _expression_2(mnt, log):
            keep = Path(tempfile.gettempdir()) / "brixcvmfs_mount_failures"
            keep.mkdir(exist_ok=True)
            shutil.copy(log, keep / f"{workdir.name}.log")
        _unmount(mnt)
        _guard_pk_mount_2(proc)
        _unmount(mnt)
        shutil.rmtree(workdir, ignore_errors=True)


# ---- corpus: incompressible bodies so tiny segments actually roll ----------

_RNG = random.Random(87)
BODIES = {f"f{i}.bin": _RNG.randbytes(6000 + 256 * i) for i in range(4)}


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


@pytest.fixture
def workdir():
    """Private mkdtemp instead of pytest tmp_path: concurrent sessions rotate
    the shared basetemp and delete each other's live forge webroots."""
    d = Path(tempfile.mkdtemp(prefix="cvmfs_pc_forge."))
    (d / "cache").mkdir()
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ============================================================================
# Success: packed layout (pack/ only, rolled segments, a journal), files
# byte-identical, cache hits with the origin DOWN, and a remount via the env
# toggle replays the journal — the file objects are never refetched.
# ============================================================================

@pytest.mark.timeout(120)
def test_packed_mount_serves_replays_no_flat_fanout(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web")
    cache = workdir / "cache"
    origin_up = True
    try:
        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache) \
                as (mnt, proc, log):
            _read_all(mnt, log)

            # Layout: the packed store owns the cache dir — no flat fan-out.
            assert set(os.listdir(cache)) == {"pack"}, \
                "packed cache must hold pack/ only (no per-object fan-out dirs)"
            segs = sorted((cache / "pack").glob("seg-*.dat"))
            assert len(segs) >= 2, f"tiny segments must have rolled: {segs}"
            assert (cache / "pack" / "index.log").is_file()

            _stop_origin(httpd)
            origin_up = False
            _read_all(mnt, log)              # serving continues offline
            assert proc.poll() is None

        # Remount the SAME cache via the env toggle: journal replay must serve
        # every file object without a single data refetch.
        httpd2 = _start_origin(workdir / "web")
        try:
            with pk_mount(workdir / "repo.pub", httpd2.server_address[1], cache,
                          opts_extra="",
                          env_extra={"BRIXCVMFS_CACHE_FORMAT": "packed"}) \
                    as (mnt, proc, log):
                _read_all(mnt, log)
                for name, rel in RELS.items():
                    assert _data_gets(httpd2, rel) == 0, \
                        f"{name} must replay from the pack, not refetch"
                assert proc.poll() is None
        finally:
            _stop_origin(httpd2)
    finally:
        if origin_up:
            _stop_origin(httpd)
        forge.close()


# ============================================================================
# Error: torn tail — garbage appended to the active segment and a journal cut
# mid-record (the crash shape batched fsync can leave).  The remount recovers:
# replay stops at the tear, the garbage tail is truncated, and every file is
# byte-identical again (replayed or transparently refetched).
# ============================================================================

@pytest.mark.timeout(120)
def test_packed_torn_tail_recovered_on_remount(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web")
    cache = workdir / "cache"
    try:
        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache) \
                as (mnt, proc, log):
            _read_all(mnt, log)

        active = sorted((cache / "pack").glob("seg-*.dat"))[-1]
        with open(active, "ab") as f:
            f.write(b"\x5a" * 97)                    # torn data tail
        idx = cache / "pack" / "index.log"
        with open(idx, "r+b") as f:
            f.truncate(idx.stat().st_size - 30)      # journal cut mid-record

        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache) \
                as (mnt, proc, log):
            _read_all(mnt, log)
            assert proc.poll() is None
    finally:
        _stop_origin(httpd)
        forge.close()


# ============================================================================
# Security-neg: one bit of a stored object record is flipped inside its
# segment.  The remount must never serve the flipped bytes — the pack's crc
# and the fetch layer's sidecar re-verify both stand between the record and
# the mount — and the genuine object is refetched from the origin.
# ============================================================================

@pytest.mark.timeout(120)
def test_packed_bitflip_never_served_refetched(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web")
    cache = workdir / "cache"
    victim, vbody = "f0.bin", BODIES["f0.bin"]
    try:
        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache) \
                as (mnt, proc, log):
            _read_all(mnt, log)
        before = _data_gets(httpd, RELS[victim])

        # The cache stores verified PLAINTEXT, so the victim's record data is
        # findable verbatim in exactly one segment; flip one byte inside it.
        needle = vbody[:32]
        flipped = 0
        for seg in sorted((cache / "pack").glob("seg-*.dat")):
            data = bytearray(seg.read_bytes())
            i = data.find(needle)
            if i >= 0:
                data[i + 8] ^= 0x40
                seg.write_bytes(bytes(data))
                flipped += 1
        assert flipped == 1, "victim record must live in exactly one segment"

        with pk_mount(workdir / "repo.pub", httpd.server_address[1], cache) \
                as (mnt, proc, log):
            def _assert_test_packed_bitflip_never_served_refetched_1():
                assert (mnt / "pkg" / victim).read_bytes() == vbody, \
                    "flipped record must be detected and refetched, never served"
                assert _data_gets(httpd, RELS[victim]) == before + 1, \
                    "detection must surface as exactly one origin refetch"

            _assert_test_packed_bitflip_never_served_refetched_1()
            # An untouched neighbour still replays without a refetch.
            other = "f1.bin"
            def _assert_test_packed_bitflip_never_served_refetched_2():
                assert (mnt / "pkg" / other).read_bytes() == BODIES[other]
                assert _data_gets(httpd, RELS[other]) == 1, \
                    "neighbour records must be unaffected by the flip"

            _assert_test_packed_bitflip_never_served_refetched_2()
            assert proc.poll() is None
    finally:
        _stop_origin(httpd)
        forge.close()
