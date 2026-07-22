"""test_backend_async_root.py — durable async backend-op queue over root://.

`brix_backend_async on` routes namespace **mutations** (kXR_rm / kXR_rmdir) through
a per-worker coalescing queue: the op is journalled + enqueued and the client is
*parked* (its recv loop yields in XRD_ST_WAITING_BAQ) until the batch flushes in
bulk to the backend, at which point the client receives the *real* result on the
original streamid. Reads/stats pass through synchronously — only mutations queue.

Coverage (success + error + security-neg + the batch-size trigger):
  * rm of an existing file is deferred, flushes on the time trigger, removes the
    backend file, and returns kXR_ok.
  * rmdir of an empty directory flushes and removes it.
  * rmdir of a missing directory is idempotent (kXR_ok, ENOENT squashed).
  * rm of a missing file surfaces the real error (kXR_error).
  * two concurrent mutations with a long wait flush promptly via the SIZE trigger
    (batch=2) — proving the size path, not the time backstop, released them.
  * with `brix_allow_write off` the mutation is rejected by the auth gate BEFORE
    it can enqueue (kXR_error) and the file survives — fail-closed, no evict.

Self-provisioning via the registry lifecycle harness; skips when the nginx binary
is absent or was built without the queue.
"""

import os
import pathlib
import struct
import subprocess
import threading
import time

import pytest

from settings import BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec
from _cache_partial_helpers import _session, _read_frame

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-backend-async")]

# Wire constants (XProtocol.hh).
kXR_mv = 3009
kXR_rm = 3014
kXR_rmdir = 3015
kXR_ok = 0
kXR_error = 4003


def _have_nginx():
    if not os.path.exists(NGINX_BIN):
        return False
    try:
        syms = subprocess.run(["nm", NGINX_BIN], capture_output=True, text=True)
        return "brix_baq_enqueue" in syms.stdout
    except Exception:
        return True


def _mutate(port, opcode, path):
    """Open a fresh session, send a single kXR_rm/kXR_rmdir, return its status.

    The reply arrives only *after* the queued op is flushed — the recv here blocks
    until the batch drains, which is exactly the parked-until-flush contract.
    """
    s = _session(port)
    try:
        pb = path.encode()
        s.sendall(struct.pack("!2sH16sI", b"\x00\x07", opcode, b"\x00" * 16,
                              len(pb)) + pb)
        status, _ = _read_frame(s)
        return status
    finally:
        s.close()


def _mv(port, src, dst):
    """Open a fresh session, send a single kXR_mv (src -> dst), return its status.

    Wire (wire_codec_ns.c): the 16-byte request body is reserved(14) + arg1len(2,
    big-endian source length); the payload is src + ' ' + dst. The reply arrives
    only after the queued rename flushes — the parked-until-flush contract.
    """
    s = _session(port)
    try:
        sb = src.encode()
        db = dst.encode()
        payload = sb + b" " + db
        body = b"\x00" * 14 + struct.pack("!H", len(sb))
        s.sendall(struct.pack("!2sH", b"\x00\x07", kXR_mv) + body
                  + struct.pack("!I", len(payload)) + payload)
        status, _ = _read_frame(s)
        return status
    finally:
        s.close()


class _Server:
    """A throwaway root:// posix tier with the async backend queue configured."""

    def __init__(self, lifecycle, tmp_path, allow_write="on", batch="64",
                 wait="400ms", name="lc-backend-async"):
        self._lifecycle = lifecycle
        self._name = name
        self._allow_write = allow_write
        self._batch = batch
        self._wait = wait
        self.data = pathlib.Path(tmp_path) / "data"
        self.data.mkdir(parents=True, exist_ok=True)
        self.journal = pathlib.Path(tmp_path) / "journal"
        self.journal.mkdir(parents=True, exist_ok=True)
        self.port = None

    def file(self, relpath, data=b"payload\n"):
        full = self.data / relpath.lstrip("/")
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(data)
        return full

    def dir(self, relpath):
        full = self.data / relpath.lstrip("/")
        full.mkdir(parents=True, exist_ok=True)
        return full

    def start(self):
        ep = self._lifecycle.start(NginxInstanceSpec(
            name=self._name,
            template="nginx_lc_backend_async_stream.conf",
            protocol="root",
            template_values={
                "BIND_HOST": BIND_HOST,
                "DATA_DIR": str(self.data),
                "ALLOW_WRITE": self._allow_write,
                "ASYNC": "on",
                "BATCH": self._batch,
                "WAIT": self._wait,
                "JOURNAL_DIR": str(self.journal),
            },
            reason="throwaway root:// tier exercising the async backend-op queue",
        ))
        self.port = ep.port
        return self


@pytest.fixture()
def make_server(lifecycle, tmp_path):
    if not _have_nginx():
        pytest.skip("nginx binary unavailable or built without the async queue")

    def _factory(**kw):
        return _Server(lifecycle, tmp_path, **kw)

    return _factory


# --------------------------------------------------------------------------- #
# Success — mutation deferred, flushed, applied                               #
# --------------------------------------------------------------------------- #

def test_rm_deferred_then_flushed(make_server):
    """rm is queued + parked, flushes on the time trigger, removes the file."""
    srv = make_server().start()
    target = srv.file("d/doomed.txt")
    assert target.exists()

    assert _mutate(srv.port, kXR_rm, "/d/doomed.txt") == kXR_ok
    assert not target.exists(), "backend file should be gone after the flush"


def test_rmdir_empty_flushed(make_server):
    """rmdir of an empty directory flushes and removes it."""
    srv = make_server().start()
    d = srv.dir("d/empty")
    assert d.is_dir()

    assert _mutate(srv.port, kXR_rmdir, "/d/empty") == kXR_ok
    assert not d.exists()


def test_rmdir_missing_is_idempotent(make_server):
    """rmdir of a non-existent directory reports success (ENOENT squashed)."""
    srv = make_server().start()
    srv.dir("d")   # parent exists, child does not

    assert _mutate(srv.port, kXR_rmdir, "/d/never-existed") == kXR_ok


def test_mv_fresh_dest_deferred_then_flushed(make_server):
    """mv to a non-existent destination is queued + parked, flushes on the time
    trigger, renames the backend file, and returns kXR_ok — the fresh-destination
    async branch (a dst-exists rename stays synchronous)."""
    srv = make_server().start()
    src = srv.file("d/mv-src.txt", data=b"payload\n")
    dst = srv.data / "d" / "mv-dst.txt"
    assert src.exists() and not dst.exists()

    assert _mv(srv.port, "/d/mv-src.txt", "/d/mv-dst.txt") == kXR_ok
    assert not src.exists(), "source must be gone after the flush"
    assert dst.read_bytes() == b"payload\n", "destination holds the moved bytes"


def test_mv_existing_file_dest_stays_synchronous(make_server):
    """With `brix_backend_async on`, an mv onto an *existing file* destination is NOT
    queued: the intercept's dst probe finds the target and routes to the synchronous
    mv_execute. File-onto-file rename overwrites atomically (stock XRootD parity —
    overwrite=0 only guards a *directory* dest), so the result is kXR_ok with the
    destination holding the source bytes, identical to async-off. Proves the fresh-
    destination scope guard preserves overwrite semantics when async is enabled."""
    srv = make_server().start()
    src = srv.file("d/e-src.txt", data=b"src-content\n")
    dst = srv.file("d/e-dst.txt", data=b"dst-content\n")

    assert _mv(srv.port, "/d/e-src.txt", "/d/e-dst.txt") == kXR_ok
    assert not src.exists(), "source must be gone after an overwrite move"
    assert dst.read_bytes() == b"src-content\n", \
        "destination must be overwritten with the source bytes"


def test_mv_dir_dest_stays_synchronous(make_server):
    """With async ON, an mv of a file onto an *existing directory* is NOT queued:
    the dst probe finds the directory and routes to the synchronous mv_execute,
    whose rename fails (EISDIR -> kXR_isDirectory) and leaves both intact. Exercises
    the *error* return of the scope guard, complementing the file-overwrite case."""
    srv = make_server().start()
    src = srv.file("d/dsrc.txt", data=b"file\n")
    dst = srv.dir("d/ddst")

    assert _mv(srv.port, "/d/dsrc.txt", "/d/ddst") == kXR_error
    assert src.read_bytes() == b"file\n", "source must survive a rejected mv"
    assert dst.is_dir(), "destination directory must be untouched"


# --------------------------------------------------------------------------- #
# Error — a real backend failure surfaces to the parked client               #
# --------------------------------------------------------------------------- #

def test_rm_missing_file_errors(make_server):
    """rm of a non-existent file surfaces the real error after the flush."""
    srv = make_server().start()
    srv.dir("d")

    assert _mutate(srv.port, kXR_rm, "/d/absent.txt") == kXR_error


def test_mv_fresh_dest_backend_error_surfaces(make_server):
    """A queued fresh-destination mv whose backend rename is denied at drain (EACCES)
    surfaces the real error to the parked client (kXR_error) via baq_root_done's
    *error* arm — the async failure path, complementing the success/idempotent arms
    (which are the only ones the missing-file/missing-dir tests reach). Revoking
    write on the *parent* directory (0500 = r-x) denies the queued rename at drain
    while path resolution (execute-only) still succeeds, so both endpoints survive."""
    srv = make_server().start()
    locked = srv.dir("locked")
    src = srv.file("locked/mv-src.txt", data=b"stays\n")
    os.chmod(locked, 0o500)              # deny rename in the dir, keep traversal
    try:
        assert _mv(srv.port, "/locked/mv-src.txt", "/locked/mv-dst.txt") == kXR_error
        assert src.exists(), "a denied backend rename must not remove the source"
        assert not (srv.data / "locked" / "mv-dst.txt").exists(), \
            "no destination must be created on a denied move"
    finally:
        os.chmod(locked, 0o700)         # let pytest's tmp teardown remove the tree


# --------------------------------------------------------------------------- #
# Batch-size trigger — two concurrent ops flush without the time backstop     #
# --------------------------------------------------------------------------- #

def test_size_trigger_releases_batch(make_server):
    """batch=2 + a 30s wait: two concurrent rms release each other on SIZE.

    If only the time trigger worked they would each block ~30s; the harness
    socket timeout (5s) would fire first. Both returning kXR_ok well inside that
    window proves the queue flushed the moment its depth reached the batch size.
    """
    srv = make_server(batch="2", wait="30000ms").start()
    srv.file("d/a.txt")
    srv.file("d/b.txt")

    results = {}

    def _worker(tag, path):
        results[tag] = _mutate(srv.port, kXR_rm, path)

    t0 = time.monotonic()
    threads = [threading.Thread(target=_worker, args=(t, p))
               for t, p in (("a", "/d/a.txt"), ("b", "/d/b.txt"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not any(t.is_alive() for t in threads), "a mutation never flushed"
    assert results == {"a": kXR_ok, "b": kXR_ok}
    assert time.monotonic() - t0 < 10, "batch did not flush on the size trigger"
    assert not (srv.data / "d" / "a.txt").exists()
    assert not (srv.data / "d" / "b.txt").exists()


# --------------------------------------------------------------------------- #
# Security-neg — the write gate rejects before the op can enqueue             #
# --------------------------------------------------------------------------- #

def test_write_denied_never_enqueues(make_server):
    """`brix_allow_write off`: rm is denied by the auth gate; the file survives."""
    srv = make_server(allow_write="off", name="lc-backend-async").start()
    target = srv.file("d/protected.txt")

    assert _mutate(srv.port, kXR_rm, "/d/protected.txt") == kXR_error
    assert target.exists(), "denied mutation must not touch the backend"
