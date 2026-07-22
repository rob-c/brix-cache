"""test_backend_async_webdav.py — durable async backend-op queue over WebDAV.

`brix_backend_async on` routes WebDAV DELETE and fresh-destination MOVE through the
same per-worker coalescing queue the root:// and S3 planes use: the unlink / rmdir /
rename is journalled + enqueued and the HTTP request is *parked*
(r->main->count++, NGX_DONE) until the batch flushes, at which point the real
204 / 201 / 409 / 500 is rendered on the event loop and the request finalised.
GET/PUT/PROPFIND pass through synchronously — only the mutation queues. The
allow_write gate runs at the access phase, *before* the enqueue, so a denied
mutation never reaches the queue.

Scope note: async MOVE covers the *fresh-destination, non-directory* case only —
the queue's rename applies overwrite=0 and models a single leaf rename, which
exactly matches a create (201). Overwrite:T replacement and collection-tree moves
stay on the synchronous dispatch, so no behaviour diverges.

Coverage (success + error + security-neg + the batch-size trigger):
  * DELETE of an existing file is deferred, flushes on the time trigger, removes
    the backend object, and returns 204.
  * MOVE to a fresh destination is deferred, flushes, renames the backend object,
    and returns 201 Created.
  * DELETE of a non-empty collection surfaces ENOTEMPTY as a 409 *through the async
    render* — the error branch, not just success.
  * DELETE / MOVE whose backend op is denied at drain (EACCES) surface as 403 through
    webdav_delete_respond / webdav_move_async_render — the async error ladders,
    distinct from the 204/201/404/409 branches.
  * two concurrent DELETEs with a long wait flush promptly via the SIZE trigger
    (batch=2) — proving the size path released them, not the time backstop.
  * with `brix_allow_write off` the DELETE is rejected by the write gate BEFORE it
    can enqueue (403 Forbidden) and the object survives — fail-closed.

Self-provisioning via the registry lifecycle harness (anonymous auth + write);
skips when the nginx binary is absent or was built without the queue.
"""

import os
import pathlib
import subprocess
import threading
import time
import uuid

import pytest
import requests

from settings import BIND_HOST, HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-backend-async-webdav")]


def _have_nginx():
    if not os.path.exists(NGINX_BIN):
        return False
    try:
        syms = subprocess.run(["nm", NGINX_BIN], capture_output=True, text=True)
        return "brix_baq_enqueue" in syms.stdout
    except Exception:
        return True


class _Server:
    """A throwaway WebDAV posix tier with the async backend queue configured."""

    def __init__(self, lifecycle, tmp_path, allow_write="on", batch="64",
                 wait="400ms", name="lc-backend-async-webdav"):
        self._lifecycle = lifecycle
        self._name = name
        self._allow_write = allow_write
        self._batch = batch
        self._wait = wait
        self.data = pathlib.Path(tmp_path) / "data"
        self.data.mkdir(parents=True, exist_ok=True)
        self.journal = pathlib.Path(tmp_path) / "journal"
        self.journal.mkdir(parents=True, exist_ok=True)
        self.base = None

    def start(self):
        ep = self._lifecycle.start(NginxInstanceSpec(
            name=self._name,
            template="nginx_lc_backend_async_webdav.conf",
            protocol="webdav",
            template_values={
                "BIND_HOST": BIND_HOST,
                "DATA_DIR": str(self.data),
                "ALLOW_WRITE": self._allow_write,
                "ASYNC": "on",
                "BATCH": self._batch,
                "WAIT": self._wait,
                "JOURNAL_DIR": str(self.journal),
            },
            reason="throwaway WebDAV tier exercising the async backend-op queue",
        ))
        self.base = f"http://{HOST}:{ep.port}"
        return self

    def url(self, name=None):
        return f"{self.base}/{name or uuid.uuid4().hex}"


@pytest.fixture()
def make_server(lifecycle, tmp_path):
    if not _have_nginx():
        pytest.skip("nginx binary unavailable or built without the async queue")

    def _factory(**kw):
        return _Server(lifecycle, tmp_path, **kw)

    return _factory


# --------------------------------------------------------------------------- #
# Success — DELETE deferred, flushed, applied                                 #
# --------------------------------------------------------------------------- #

def test_delete_deferred_then_flushed(make_server):
    """DELETE is queued + parked, flushes on the time trigger, removes the file
    and returns 204 — the request only completes after the backend unlink."""
    srv = make_server().start()
    url = srv.url("doomed.txt")
    assert requests.put(url, data=os.urandom(2048), timeout=15).status_code in (
        200, 201), "seed PUT"
    assert (srv.data / "doomed.txt").exists()

    r = requests.delete(url, timeout=15)
    assert r.status_code == 204, r.text
    assert not (srv.data / "doomed.txt").exists(), \
        "backend file should be gone after the flush"


# --------------------------------------------------------------------------- #
# Success — MOVE (fresh destination, non-directory) deferred, flushed          #
# --------------------------------------------------------------------------- #

def test_move_fresh_dest_deferred_then_flushed(make_server):
    """MOVE to a non-existent destination is queued + parked, flushes, renames the
    backend file and returns 201 Created — the fresh-destination async branch."""
    srv = make_server().start()
    src = srv.url("mv-src.txt")
    dst_name = "mv-dst.txt"
    assert requests.put(src, data=b"payload\n", timeout=15).status_code in (
        200, 201), "seed PUT"

    r = requests.request("MOVE", src, timeout=15,
                         headers={"Destination": srv.url(dst_name)})
    assert r.status_code == 201, r.text
    assert not (srv.data / "mv-src.txt").exists(), "source must be gone"
    assert (srv.data / dst_name).read_bytes() == b"payload\n", \
        "destination must hold the moved bytes after the flush"


def test_delete_empty_collection_flushed(make_server):
    """DELETE of an *empty* collection maps to the RMDIR arm of the async intercept
    (dir → BRIX_BAQ_RMDIR), flushes, removes the directory and returns 204 — the
    file-delete tests only cover the UNLINK arm."""
    srv = make_server().start()
    assert requests.request("MKCOL", f"{srv.base}/empty-coll",
                            timeout=15).status_code == 201
    assert (srv.data / "empty-coll").is_dir()

    r = requests.delete(f"{srv.base}/empty-coll", timeout=15)
    assert r.status_code == 204, r.text
    assert not (srv.data / "empty-coll").exists(), \
        "empty collection should be gone after the flush"


# --------------------------------------------------------------------------- #
# Scope guard — async ON must NOT hijack the cases that stay synchronous       #
# --------------------------------------------------------------------------- #

def test_move_overwrite_existing_stays_synchronous(make_server):
    """With `brix_backend_async on`, a MOVE onto an *existing* destination is NOT
    queued (the intercept requires !dst_existed): it runs on the synchronous
    dispatch, replaces the target, and returns 204 No Content. Proves the scope
    guard routes an overwrite move to the sync path even when async is enabled."""
    srv = make_server().start()
    src = srv.url("ovr-src.txt")
    dst = srv.url("ovr-dst.txt")
    assert requests.put(src, data=b"new\n", timeout=15).status_code in (200, 201)
    assert requests.put(dst, data=b"old\n", timeout=15).status_code in (200, 201)

    # Overwrite defaults to T (RFC 4918 §9.9.3), so an existing dst is replaced.
    r = requests.request("MOVE", src, timeout=15, headers={"Destination": dst})
    assert r.status_code == 204, r.text
    assert not (srv.data / "ovr-src.txt").exists(), "source must be gone"
    assert (srv.data / "ovr-dst.txt").read_bytes() == b"new\n", \
        "destination must hold the moved bytes (overwritten)"


def test_move_collection_stays_synchronous(make_server):
    """With async ON, a *collection* (directory) MOVE is NOT queued (the intercept
    requires !S_ISDIR(src)): it runs on the synchronous collection-offload dispatch
    and returns 201 for a fresh destination. Proves the scope guard routes a
    directory move to the sync path even when async is enabled."""
    srv = make_server().start()
    assert requests.request("MKCOL", f"{srv.base}/coll",
                            timeout=15).status_code == 201
    assert requests.put(f"{srv.base}/coll/child.txt",
                        data=b"kid\n", timeout=15).status_code in (200, 201)

    r = requests.request("MOVE", f"{srv.base}/coll", timeout=15,
                         headers={"Destination": srv.url("coll2")})
    assert r.status_code == 201, r.text
    assert not (srv.data / "coll").exists(), "source collection must be gone"
    assert (srv.data / "coll2" / "child.txt").read_bytes() == b"kid\n", \
        "moved collection must carry its child"


# --------------------------------------------------------------------------- #
# Error — a real backend failure surfaces to the parked client                #
# --------------------------------------------------------------------------- #

def test_delete_nonempty_collection_conflicts(make_server):
    """A DELETE whose target is a non-empty collection surfaces ENOTEMPTY as a 409
    *through the async render* — the error branch, not just success. WebDAV DELETE
    is non-recursive (require-empty), so the rmdir fails and the child survives."""
    srv = make_server().start()
    # WebDAV PUT needs the parent collection to exist (RFC 4918 §9.7.1); MKCOL it
    # first, then populate it so the DELETE hits a non-empty rmdir.
    assert requests.request("MKCOL", f"{srv.base}/d1",
                            timeout=15).status_code == 201
    assert requests.put(f"{srv.base}/d1/keep.txt",
                        data=b"x", timeout=15).status_code in (200, 201)
    r = requests.delete(f"{srv.base}/d1", timeout=15)
    assert r.status_code == 409, r.text
    assert (srv.data / "d1" / "keep.txt").exists(), "the child must be untouched"


def test_delete_backend_error_forbidden(make_server):
    """A queued DELETE whose backend unlink is denied at drain (EACCES) surfaces as
    403 Forbidden *through the async render* — the EACCES arm of
    webdav_delete_respond, distinct from the 204/404/409 branches. Revoking write on
    the *parent* directory (0500 = r-x) denies the queued unlink while path
    resolution (execute-only) still succeeds, so the file survives."""
    srv = make_server().start()
    locked = srv.data / "locked"
    locked.mkdir()
    victim = locked / "obj.txt"
    victim.write_bytes(b"stays\n")
    os.chmod(locked, 0o500)             # deny unlink of the child, keep traversal
    try:
        r = requests.delete(f"{srv.base}/locked/obj.txt", timeout=15)
        assert r.status_code == 403, r.text
        assert victim.exists(), "a denied backend unlink must not remove the file"
    finally:
        os.chmod(locked, 0o700)        # let pytest's tmp teardown remove the tree


def test_move_backend_error_forbidden(make_server):
    """A queued fresh-destination MOVE whose backend rename is denied at drain
    (EACCES) surfaces as 403 Forbidden through webdav_move_async_render's EACCES arm
    — the async *error* ladder, complementing the 201 success case. The destination
    is fresh (so the async branch is taken) and shares the write-revoked parent, so
    the drain rename is denied and both endpoints survive."""
    srv = make_server().start()
    locked = srv.data / "locked"
    locked.mkdir()
    src = locked / "mv-src.txt"
    src.write_bytes(b"stays\n")
    os.chmod(locked, 0o500)
    try:
        r = requests.request(
            "MOVE", f"{srv.base}/locked/mv-src.txt", timeout=15,
            headers={"Destination": f"{srv.base}/locked/mv-dst.txt"})
        assert r.status_code == 403, r.text
        assert src.exists(), "a denied backend rename must not remove the source"
        assert not (locked / "mv-dst.txt").exists(), "no destination on a denied move"
    finally:
        os.chmod(locked, 0o700)


# --------------------------------------------------------------------------- #
# Batch-size trigger — two concurrent DELETEs flush without the time backstop  #
# --------------------------------------------------------------------------- #

def test_size_trigger_releases_batch(make_server):
    """batch=2 + a 30s wait: two concurrent DELETEs release each other on SIZE.

    With only the time trigger they would each block ~30s; both returning 204 well
    inside a 10s join proves the queue flushed the moment its depth hit the batch.
    """
    srv = make_server(batch="2", wait="30000ms").start()
    urls = [srv.url(f"batch-{i}.txt") for i in range(2)]
    for u in urls:
        assert requests.put(u, data=b"z", timeout=15).status_code in (200, 201)

    results = {}

    def _worker(tag, url):
        results[tag] = requests.delete(url, timeout=15).status_code

    t0 = time.monotonic()
    threads = [threading.Thread(target=_worker, args=(i, u))
               for i, u in enumerate(urls)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not any(t.is_alive() for t in threads), "a DELETE never flushed"
    assert results == {0: 204, 1: 204}, results
    assert time.monotonic() - t0 < 10, "batch did not flush on the size trigger"


# --------------------------------------------------------------------------- #
# Security-neg — the write gate rejects before the op can enqueue              #
# --------------------------------------------------------------------------- #

def test_write_denied_never_enqueues(make_server):
    """`brix_allow_write off`: DELETE is denied by the write gate (403) and the
    backend file survives — the op never reaches the queue."""
    srv = make_server(allow_write="off").start()
    # Seed the file directly on the backend (PUT is write-gated too).
    target = srv.data / "protected.txt"
    target.write_bytes(b"keep me\n")

    r = requests.delete(srv.url("protected.txt"), timeout=15)
    assert r.status_code == 403, r.text
    assert target.exists(), "denied DELETE must not touch the backend"
