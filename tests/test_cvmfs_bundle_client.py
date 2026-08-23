# tests/test_cvmfs_bundle_client.py — Phase-87 G2: client `-o bundle` consumer.
#
# Theme: the F4 prefetch worker batches its walk items and fetches them in ONE
# `POST <server>/.cvmfs-bundle` round-trip (wire: "BXB1" | u32 count | items of
# u32 path_len | path | u64 data_len | data; data_len UINT64_MAX = miss).  The
# bundle is a pure RTT optimization and carries NO trust: every member is
# CAS-verified against its own path-derived hash by the SAME decode/verify/store
# path as single fetches (shared/cvmfs/fetch/fetch_bundle.c), and every bundle
# failure — server without the endpoint, malformed frame, tampered member —
# degrades silently to the existing per-object GET behavior.
#
# Coverage (3-test ritual):
#   * success: one POST per batch, zero data-object GETs, objects served
#     offline afterwards — bundle members are real verified cache entries;
#   * error: origin without POST support (501) → sweep completes via single
#     GETs; a garbage frame → full fallback; the mount never notices either;
#   * security-neg: a tampered bundle member is rejected (never cached from
#     the frame) and transparently refetched clean via a single GET — the
#     genuine bytes are served, the tampered ones never land.
#
# Contract citations: docs/refactor/phase-87-cvmfs-next-gen-storage-and-
# distribution.md § G2; server twin = tests/test_cvmfs_bundle.py (nginx
# endpoint), codec/ingest units = shared/cvmfs/fetch/fetch_unittest.c +
# shared/cvmfs/bundle/bundle_unittest.c.
#
# The origin here is a Python mock that IMPLEMENTS the bundle wire format
# (encode side), so the client contract is pinned independently of the nginx
# implementation.

import hashlib
import os
import shutil
import struct
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

def _expression_1():
    return (
        {k: v for k, v in os.environ.items() if not k.startswith("BRIXCVMFS_")}
    )

def _expression_2(mnt, log):
    return (
        not os.path.ismount(mnt) and log.exists()
    )


def _guard_encode_bundle_1(data, out):
    if data is None:
        out.append(struct.pack("<Q", MISS))
    else:
        out.append(struct.pack("<Q", len(data)))
        out.append(data)

def _guard_bd_mount_2(env_extra, env):
    if env_extra:
        env.update(env_extra)

def _guard_bd_mount_3(proc):
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
MISS = 0xFFFFFFFFFFFFFFFF

_FUSE_READY = (os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None
               and os.path.exists(BRIXMOUNT))
pytestmark = pytest.mark.skipif(not _FUSE_READY, reason="fuse mount prerequisites missing")


# ---- origin: static GET + wire-conformant bundle POST ----------------------

def _encode_bundle(repo_dir: Path, want: bytes, tamper_rel=None) -> bytes:
    """Server-side BXB1 encoder: resolve each want line against the forge
    webroot; absent object → miss marker; `tamper_rel` (a want line) gets its
    last data byte flipped — the frame stays well-formed, only the member's
    bytes no longer match the hash its path claims."""
    items = []
    for raw in want.decode("ascii", "replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        f = repo_dir / line
        if f.is_file():
            data = f.read_bytes()
            if line == tamper_rel:
                data = data[:-1] + bytes([data[-1] ^ 0xFF])
            items.append((line.encode(), data))
        else:
            items.append((line.encode(), None))
    out = [b"BXB1", struct.pack("<I", len(items))]
    for path, data in items:
        out.append(struct.pack("<I", len(path)))
        out.append(path)
        _guard_encode_bundle_1(data, out)
    return b"".join(out)


class _Handler(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.server.gets.append(self.path)
        super().do_GET()

    def do_POST(self):
        self.server.posts.append(self.path)
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        if self.server.bundle_mode == "off" or not self.path.endswith("/.cvmfs-bundle"):
            self.send_error(501)
            return
        if self.server.bundle_mode == "garbage":
            payload = b"NOTB" + b"\x00" * 64
        else:
            payload = _encode_bundle(self.server.repo_dir, body,
                                     tamper_rel=self.server.tamper_rel)
        self.send_response(200)
        self.send_header("Content-Type", "application/x-cvmfs-bundle")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _start_origin(webroot: Path, *, bundle_mode="on", tamper_rel=None):
    """Ephemeral-port origin (immune to cross-session port-tile collisions);
    records every GET/POST path for the batching assertions."""
    handler = partial(_Handler, directory=str(webroot))
    httpd = ThreadingHTTPServer((BIND_HOST, 0), handler)
    httpd.daemon_threads = True
    httpd.gets, httpd.posts = [], []
    httpd.bundle_mode = bundle_mode
    httpd.tamper_rel = tamper_rel
    httpd.repo_dir = webroot / "cvmfs" / REPO
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _stop_origin(httpd):
    httpd.shutdown()
    httpd.server_close()


# ---- mount helper (test_cvmfs_prefetch.py idiom + `bundle`) ----------------

@contextmanager
def bd_mount(pubkey, port, *, opts_extra=",bundle", env_extra=None, timeout=15):
    workdir = Path(tempfile.mkdtemp(prefix="cvmfs_bd."))
    mnt = workdir / "mnt"
    for d in ("mnt", "tmp", "cache"):
        (workdir / d).mkdir()
    env = _expression_1()
    for k in ("http_proxy", "https_proxy", "all_proxy",
              "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        env.pop(k, None)
    env["BRIXCVMFS_PUBKEY"] = str(pubkey)
    env["BRIXCVMFS_TMP"] = str(workdir / "tmp")
    env["BRIXCVMFS_CACHE"] = str(workdir / "cache")
    env["BRIXCVMFS_SERVER"] = f"http://{HOST}:{port}/cvmfs/{REPO}"
    _guard_bd_mount_2(env_extra, env)

    opts = "auto_unmount,attr_timeout=0,entry_timeout=0,retries=1,prefetch=8" + opts_extra
    log = workdir / "brixmount.log"
    with open(log, "wb") as lf:
        proc = subprocess.Popen([BRIXMOUNT, "cvmfs", REPO, str(mnt), "-o", opts, "-f"],
                                env=env, stdout=lf, stderr=lf)
    try:
        _wait_mounted(mnt, timeout)
        yield mnt, proc, log, workdir / "cache"
    finally:
        if _expression_2(mnt, log):
            keep = Path(tempfile.gettempdir()) / "brixcvmfs_mount_failures"
            keep.mkdir(exist_ok=True)
            shutil.copy(log, keep / f"{workdir.name}.log")
        _unmount(mnt)
        _guard_bd_mount_3(proc)
        _unmount(mnt)
        shutil.rmtree(workdir, ignore_errors=True)


# ---- CAS identity: object key = sha1 of the STORED (zlib) form -------------

A_BODY = b"bundle-a\n" * 700
B_BODY = b"bundle-b\n" * 900
OTHER_BODY = b"never-listed-so-never-bundled\n"


def _cas_rel(body: bytes) -> str:
    h = hashlib.sha1(zlib.compress(body)).hexdigest()
    return f"{h[:2]}/{h[2:]}"


def _data_get_count(httpd, rel: str) -> int:
    return httpd.gets.count(f"/cvmfs/{REPO}/data/{rel}")


def _wait_cached(cache_dir: Path, rels, timeout=25) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if all((cache_dir / r).exists() for r in rels):
            return True
        time.sleep(0.2)
    return False


def _forge(tmp_path):
    tree = {
        "pkg": Dir({"a.bin": File(A_BODY), "b.bin": File(B_BODY)}),
        "other.txt": File(OTHER_BODY),
    }
    return RepoForge(REPO, tmp_path / "web", ttl=TTL, revision=1).build(
        tree, tmp_path / "repo.pub")


@pytest.fixture
def workdir():
    """Private mkdtemp instead of pytest tmp_path: concurrent sessions rotate
    the shared basetemp and delete each other's live forge webroots."""
    d = Path(tempfile.mkdtemp(prefix="cvmfs_bd_forge."))
    yield d
    shutil.rmtree(d, ignore_errors=True)


REL_A, REL_B, REL_OTHER = _cas_rel(A_BODY), _cas_rel(B_BODY), _cas_rel(OTHER_BODY)


# ============================================================================
# Success: one POST warms the listed subtree with ZERO data-object GETs; the
# members are verified cache entries — they serve with the origin DOWN.
# ============================================================================

@pytest.mark.timeout(120)
def test_bundle_one_post_zero_gets_serves_offline(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web")
    origin_up = True
    try:
        with bd_mount(workdir / "repo.pub", httpd.server_address[1]) \
                as (mnt, proc, log, cache):
            os.listdir(mnt / "pkg")     # the ONLY foreground touch of /pkg
            assert _wait_cached(cache, [REL_A, REL_B]), \
                "bundle sweep never landed pkg objects:\n" + log.read_text(errors="replace")
            assert len(httpd.posts) == 1, httpd.posts
            assert _data_get_count(httpd, REL_A) == 0
            assert _data_get_count(httpd, REL_B) == 0
            # scoped: the un-listed sibling stays cold
            assert not (cache / REL_OTHER).exists()

            _stop_origin(httpd)
            origin_up = False
            assert (mnt / "pkg" / "a.bin").read_bytes() == A_BODY
            assert (mnt / "pkg" / "b.bin").read_bytes() == B_BODY
            assert proc.poll() is None
    finally:
        if origin_up:
            _stop_origin(httpd)
        forge.close()


# ============================================================================
# Error: an origin WITHOUT the endpoint (501 on POST) — the sweep degrades to
# per-object GETs and still lands everything.  Also covers the
# $BRIXCVMFS_BUNDLE=1 env toggle (no `-o bundle`).
# ============================================================================

@pytest.mark.timeout(120)
def test_bundle_unsupported_origin_falls_back_to_gets(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web", bundle_mode="off")
    try:
        with bd_mount(workdir / "repo.pub", httpd.server_address[1],
                      opts_extra="", env_extra={"BRIXCVMFS_BUNDLE": "1"}) \
                as (mnt, proc, log, cache):
            os.listdir(mnt / "pkg")
            assert _wait_cached(cache, [REL_A, REL_B]), \
                "fallback sweep never completed:\n" + log.read_text(errors="replace")
            assert len(httpd.posts) == 1          # it TRIED the bundle once
            assert _data_get_count(httpd, REL_A) == 1
            assert _data_get_count(httpd, REL_B) == 1
            assert (mnt / "pkg" / "a.bin").read_bytes() == A_BODY
            assert proc.poll() is None
    finally:
        _stop_origin(httpd)
        forge.close()


# ============================================================================
# Error twin: a garbage frame (bad magic) — whole-stream distrust, full
# fallback, mount unaffected.
# ============================================================================

@pytest.mark.timeout(120)
def test_bundle_garbage_frame_full_fallback(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web", bundle_mode="garbage")
    try:
        with bd_mount(workdir / "repo.pub", httpd.server_address[1]) \
                as (mnt, proc, log, cache):
            os.listdir(mnt / "pkg")
            assert _wait_cached(cache, [REL_A, REL_B]), \
                "garbage-frame fallback never completed:\n" + log.read_text(errors="replace")
            assert _data_get_count(httpd, REL_A) == 1
            assert _data_get_count(httpd, REL_B) == 1
            assert (mnt / "pkg" / "b.bin").read_bytes() == B_BODY
            assert proc.poll() is None
    finally:
        _stop_origin(httpd)
        forge.close()


# ============================================================================
# Security-neg: a tampered member inside an otherwise well-formed frame is
# rejected by per-object CAS verification — never cached from the bundle,
# transparently refetched clean by a single GET; the good member still rides
# the bundle (zero GETs).  The tampered bytes never reach the mount.
# ============================================================================

@pytest.mark.timeout(120)
def test_bundle_tampered_member_rejected_and_refetched_clean(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web", tamper_rel=f"data/{REL_A}")
    origin_up = True
    try:
        with bd_mount(workdir / "repo.pub", httpd.server_address[1]) \
                as (mnt, proc, log, cache):
            os.listdir(mnt / "pkg")
            assert _wait_cached(cache, [REL_A, REL_B]), \
                "tamper-recovery sweep never completed:\n" + log.read_text(errors="replace")
            assert len(httpd.posts) == 1
            assert _data_get_count(httpd, REL_A) == 1   # clean refetch, single GET
            assert _data_get_count(httpd, REL_B) == 0   # good member rode the bundle

            _stop_origin(httpd)
            origin_up = False
            assert (mnt / "pkg" / "a.bin").read_bytes() == A_BODY   # genuine bytes
            assert (mnt / "pkg" / "b.bin").read_bytes() == B_BODY
            assert proc.poll() is None
    finally:
        if origin_up:
            _stop_origin(httpd)
        forge.close()
