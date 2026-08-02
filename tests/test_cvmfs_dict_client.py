# tests/test_cvmfs_dict_client.py — Phase-87 G3: client `-o dict` consumer.
#
# Theme: with `-o dict` / $BRIXCVMFS_DICT=1 the mount pulls the proxy's
# trained zstd dictionary ONCE (GET <server>/.cvmfs-dict/current), self-
# certifies it (sha1(body) must equal X-Brix-Dict-Id), then offers the id via
# an `X-Brix-Dict` request header on CAS data GETs only.  A response marked
# `Content-Encoding: zstd-dict` is decoded back to the STORED bytes before the
# SAME CAS decode/verify/store path runs — the id check is transport integrity
# only, TRUST stays with CAS verify.  Every dict failure — endpoint absent,
# id mismatch, undecodable coded body — degrades to identity fetches; the
# mount never notices and never spends more than one dict GET per mount.
#
# Coverage (3-test ritual):
#   * success: dict fetched exactly once, every data GET offers the id, every
#     serving comes back coded and decodes — files byte-correct, members are
#     real verified cache entries (served with the origin DOWN);
#   * error: origin without the endpoint (404) → dict disabled for the mount
#     lifetime, all data GETs identity WITHOUT the header, files correct;
#   * security-neg: a dict whose advertised id does not match its bytes is
#     discarded at fetch time (never offered, nothing ever coded); an
#     undecodable coded body is dropped and transparently refetched identity
#     — the garbage never reaches CAS verify, let alone the mount.
#
# Contract citations: client codepath = client/apps/fs/brixcvmfs.c (G3 block:
# brix_dict_fetch/ensure + the hw.zstd_dict decode branch); codec units =
# shared/cvmfs/dict/dict_unittest.c; server twin = tests/test_cvmfs_dict.py.
#
# The origin is a Python mock that IMPLEMENTS the dict wire (train/serve/code
# with the `zstandard` module), so the client contract is pinned independently
# of the nginx implementation.

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

zstandard = pytest.importorskip("zstandard")

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, _unmount, _wait_mounted  # noqa: E402
from repo_forge import Dir, File, RepoForge  # noqa: E402
from settings import BIND_HOST, HOST

REPO = "test.cern.ch"
TTL = 3600
DICT_PATH = f"/cvmfs/{REPO}/.cvmfs-dict/current"

_FUSE_READY = (os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None
               and os.path.exists(BRIXMOUNT))
pytestmark = pytest.mark.skipif(not _FUSE_READY, reason="fuse mount prerequisites missing")


# ---- a genuine trained dictionary (validity is what matters, not fit) ------

def _train_dict() -> bytes:
    rng = random.Random(87)
    words = ["catalog", "manifest", "revision", "chunk", "stratum", "lease"]
    samples = []
    for i in range(120):
        lines = [f"# corpus {i}\n"]
        for _ in range(rng.randint(60, 120)):
            lines.append(f"{rng.choice(words)}.{rng.randint(0, 9999)} = "
                         f"{rng.randint(0, 999999)} ; tier=hot\n")
        samples.append("".join(lines).encode())
    return zstandard.train_dictionary(112640, samples).as_bytes()


DICT_BYTES = _train_dict()
DICT_ID = hashlib.sha1(DICT_BYTES).hexdigest()
_CDICT = zstandard.ZstdCompressionDict(DICT_BYTES)


# ---- origin: static GET + dict endpoint + dict-coded data servings ---------

class _Handler(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body: bytes, headers: dict):
        self.send_response(200)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        srv = self.server
        offered = self.headers.get("X-Brix-Dict")
        srv.gets.append((self.path, offered))

        if self.path == DICT_PATH:
            if srv.dict_mode == "absent":
                self.send_error(404)
                return
            claim = "1" * 40 if srv.dict_mode == "tampered" else DICT_ID
            self._send(DICT_BYTES, {"X-Brix-Dict-Id": claim,
                                    "Content-Type": "application/octet-stream"})
            return

        if (offered == DICT_ID and srv.dict_mode in ("on", "junk")
                and self.path.startswith(f"/cvmfs/{REPO}/data/")):
            f = srv.webroot / self.path.lstrip("/")
            if f.is_file():
                stored = f.read_bytes()
                if srv.dict_mode == "junk":
                    coded = b"JUNK" * 16          # no zstd magic — must not decode
                else:
                    coded = zstandard.ZstdCompressor(
                        dict_data=_CDICT).compress(stored)
                srv.coded.append(self.path)
                self._send(coded, {"Content-Encoding": "zstd-dict",
                                   "X-Brix-Dict-Id": DICT_ID})
                return

        super().do_GET()


def _start_origin(webroot: Path, *, dict_mode="on"):
    """Ephemeral-port origin (immune to cross-session port-tile collisions);
    records every GET (path, offered-dict-id) for the negotiation asserts."""
    handler = partial(_Handler, directory=str(webroot))
    httpd = ThreadingHTTPServer((BIND_HOST, 0), handler)
    httpd.daemon_threads = True
    httpd.gets, httpd.coded = [], []
    httpd.dict_mode = dict_mode
    httpd.webroot = Path(webroot)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _stop_origin(httpd):
    httpd.shutdown()
    httpd.server_close()


def _dict_gets(httpd) -> int:
    return sum(1 for p, _ in httpd.gets if p == DICT_PATH)


def _data_gets(httpd, rel: str):
    """[(offered-id-or-None), ...] for every GET of this CAS object."""
    want = f"/cvmfs/{REPO}/data/{rel}"
    return [h for p, h in httpd.gets if p == want]


# ---- mount helper (test_cvmfs_bundle_client.py idiom + `dict`) -------------

@contextmanager
def dm_mount(pubkey, port, *, opts_extra=",dict", env_extra=None, timeout=15):
    workdir = Path(tempfile.mkdtemp(prefix="cvmfs_dc."))
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
    if env_extra:
        env.update(env_extra)

    opts = "auto_unmount,attr_timeout=0,entry_timeout=0,retries=1" + opts_extra
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

A_BODY = b"dict-a\n" * 700
B_BODY = b"dict-b\n" * 900


def _cas_rel(body: bytes) -> str:
    h = hashlib.sha1(zlib.compress(body)).hexdigest()
    return f"{h[:2]}/{h[2:]}"


REL_A, REL_B = _cas_rel(A_BODY), _cas_rel(B_BODY)


def _forge(tmp_path):
    tree = {"pkg": Dir({"a.bin": File(A_BODY), "b.bin": File(B_BODY)})}
    return RepoForge(REPO, tmp_path / "web", ttl=TTL, revision=1).build(
        tree, tmp_path / "repo.pub")


@pytest.fixture
def workdir():
    """Private mkdtemp instead of pytest tmp_path: concurrent sessions rotate
    the shared basetemp and delete each other's live forge webroots."""
    d = Path(tempfile.mkdtemp(prefix="cvmfs_dc_forge."))
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ============================================================================
# Success: one dict GET per mount; EVERY data GET offers the id and comes
# back coded; decoded members are verified cache entries — they serve with
# the origin DOWN.
# ============================================================================

@pytest.mark.timeout(120)
def test_dict_mount_decodes_coded_servings(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web")
    origin_up = True
    try:
        with dm_mount(workdir / "repo.pub", httpd.server_address[1]) \
                as (mnt, proc, log, cache):
            assert (mnt / "pkg" / "a.bin").read_bytes() == A_BODY, \
                log.read_text(errors="replace")
            assert (mnt / "pkg" / "b.bin").read_bytes() == B_BODY

            assert _dict_gets(httpd) == 1, "dict must be fetched exactly once"
            # Plain CAS file objects offer the id; suffixed metadata objects
            # (catalog …C, whitelist …X) stay identity by design — they exceed
            # the dict size class and the proxy would decline anyway.
            for rel in (REL_A, REL_B):
                assert _data_gets(httpd, rel) == [DICT_ID], \
                    f"file object {rel} must be fetched once, offering the id"
            assert sorted(httpd.coded) == sorted(
                f"/cvmfs/{REPO}/data/{r}" for r in (REL_A, REL_B)), \
                "exactly the offered file objects should have been served coded"
            assert (cache / REL_A).exists() and (cache / REL_B).exists()

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
# Error: origin without the endpoint (404) — one attempt, dict disabled for
# the mount lifetime, all data GETs identity WITHOUT the header.  Also covers
# the $BRIXCVMFS_DICT=1 env toggle (no `-o dict`).
# ============================================================================

@pytest.mark.timeout(120)
def test_dict_absent_origin_identity_fallback(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web", dict_mode="absent")
    try:
        with dm_mount(workdir / "repo.pub", httpd.server_address[1],
                      opts_extra="", env_extra={"BRIXCVMFS_DICT": "1"}) \
                as (mnt, proc, log, cache):
            assert (mnt / "pkg" / "a.bin").read_bytes() == A_BODY, \
                log.read_text(errors="replace")
            assert (mnt / "pkg" / "b.bin").read_bytes() == B_BODY

            assert _dict_gets(httpd) == 1, \
                "a dict-less proxy costs exactly one extra GET per mount"
            data = [(p, h) for p, h in httpd.gets
                    if p.startswith(f"/cvmfs/{REPO}/data/")]
            assert data and all(h is None for _, h in data), \
                f"no data GET may offer a dict the mount doesn't hold: {data}"
            assert httpd.coded == []
            assert proc.poll() is None
    finally:
        _stop_origin(httpd)
        forge.close()


# ============================================================================
# Security-neg: the advertised id does not match the served bytes — the dict
# is discarded at fetch time (self-certification), never offered, nothing is
# ever coded; the mount serves genuine bytes via identity.
# ============================================================================

@pytest.mark.timeout(120)
def test_dict_tampered_id_discarded_never_offered(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web", dict_mode="tampered")
    try:
        with dm_mount(workdir / "repo.pub", httpd.server_address[1]) \
                as (mnt, proc, log, cache):
            assert (mnt / "pkg" / "a.bin").read_bytes() == A_BODY, \
                log.read_text(errors="replace")
            assert (mnt / "pkg" / "b.bin").read_bytes() == B_BODY

            assert _dict_gets(httpd) == 1
            data = [(p, h) for p, h in httpd.gets
                    if p.startswith(f"/cvmfs/{REPO}/data/")]
            assert data and all(h is None for _, h in data), \
                f"a dict that fails self-certification must never be offered: {data}"
            assert httpd.coded == []
            assert proc.poll() is None
    finally:
        _stop_origin(httpd)
        forge.close()


# ============================================================================
# Security-neg twin: the dict verifies but every coded body is garbage — the
# decode fails, the object is transparently refetched identity (exactly one
# offered GET + one plain GET per object); the garbage never reaches CAS
# verify and the mount serves genuine bytes.
# ============================================================================

@pytest.mark.timeout(120)
def test_dict_undecodable_coded_body_identity_refetch(workdir):
    forge = _forge(workdir)
    httpd = _start_origin(workdir / "web", dict_mode="junk")
    try:
        with dm_mount(workdir / "repo.pub", httpd.server_address[1]) \
                as (mnt, proc, log, cache):
            assert (mnt / "pkg" / "a.bin").read_bytes() == A_BODY, \
                log.read_text(errors="replace")
            assert (mnt / "pkg" / "b.bin").read_bytes() == B_BODY

            for rel in (REL_A, REL_B):
                offers = _data_gets(httpd, rel)
                assert offers.count(DICT_ID) == 1 and offers.count(None) == 1 \
                    and len(offers) == 2, \
                    f"expected one coded attempt + one identity refetch for {rel}: {offers}"
            assert proc.poll() is None
    finally:
        _stop_origin(httpd)
        forge.close()
