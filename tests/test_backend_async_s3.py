"""test_backend_async_s3.py — durable async backend-op queue over the S3 plane.

`brix_backend_async on` routes the object DELETE through the same per-worker
coalescing queue the root:// plane uses: the unlink is journalled + enqueued and
the HTTP request is *parked* (r->main->count++, NGX_DONE) until the batch flushes,
at which point the real 204 / 409 / 500 is rendered on the event loop and the
request finalised. GET/PUT/list pass through synchronously — only the mutation
queues. The write gate (`brix_allow_write`) runs *before* the enqueue, so a denied
DELETE never reaches the queue.

Coverage (success + error + security-neg + the batch-size trigger):
  * DELETE of an existing object is deferred, flushes on the time trigger, removes
    the backend object, and returns 204.
  * DELETE of a missing key is idempotent (204, ENOENT squashed by the async
    render — the same mapping the sync path uses).
  * DELETE of a non-empty directory key surfaces the real error through the async
    render (409 BucketNotEmpty from the ENOTEMPTY branch).
  * DELETE whose backend unlink is denied at drain (EACCES) surfaces as 500 through
    the async render — the generic-error arm of s3_delete_respond + its
    INTERNAL_ERROR metric, distinct from the 204/404/409 branches.
  * two concurrent DELETEs with a long wait flush promptly via the SIZE trigger
    (batch=2) — proving the size path released them, not the time backstop.
  * with `brix_allow_write off` the DELETE is rejected by the write gate BEFORE it
    can enqueue (403 AccessDenied) and the object survives — fail-closed.

Self-provisioning via the registry lifecycle harness (anonymous + write); skips
when the nginx binary is absent or was built without the queue.
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
              pytest.mark.xdist_group("lc-backend-async-s3")]

BUCKET = "asyncbucket"


def _have_nginx():
    if not os.path.exists(NGINX_BIN):
        return False
    try:
        syms = subprocess.run(["nm", NGINX_BIN], capture_output=True, text=True)
        return "brix_baq_enqueue" in syms.stdout
    except Exception:
        return True


class _Server:
    """A throwaway S3 posix tier with the async backend queue configured."""

    def __init__(self, lifecycle, tmp_path, allow_write="on", batch="64",
                 wait="400ms", name="lc-backend-async-s3"):
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
            template="nginx_lc_backend_async_s3.conf",
            protocol="s3",
            template_values={
                "BIND_HOST": BIND_HOST,
                "DATA_DIR": str(self.data),
                "BUCKET": BUCKET,
                "ALLOW_WRITE": self._allow_write,
                "ASYNC": "on",
                "BATCH": self._batch,
                "WAIT": self._wait,
                "JOURNAL_DIR": str(self.journal),
            },
            reason="throwaway S3 tier exercising the async backend-op queue",
        ))
        self.base = f"http://{HOST}:{ep.port}"
        return self

    def key(self, name=None):
        return f"{self.base}/{BUCKET}/{name or uuid.uuid4().hex}"


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
    """DELETE is queued + parked, flushes on the time trigger, removes the object
    and returns 204 — the request only completes after the backend unlink."""
    srv = make_server().start()
    url = srv.key("doomed.txt")
    assert requests.put(url, data=os.urandom(2048), timeout=15).status_code == 200
    assert (srv.data / "doomed.txt").exists()

    r = requests.delete(url, timeout=15)
    assert r.status_code == 204, r.text
    assert not (srv.data / "doomed.txt").exists(), \
        "backend object should be gone after the flush"


def test_delete_missing_is_idempotent(make_server):
    """DELETE of a key that never existed is idempotent (204) through the async
    render — the ENOENT-squash mapping matches the synchronous path."""
    srv = make_server().start()
    r = requests.delete(srv.key("never-existed"), timeout=15)
    assert r.status_code == 204, r.text


# --------------------------------------------------------------------------- #
# Error — a real backend failure surfaces to the parked client                #
# --------------------------------------------------------------------------- #

def test_delete_nonempty_dir_conflicts(make_server):
    """A DELETE whose target is a non-empty directory surfaces ENOTEMPTY as a 409
    BucketNotEmpty *through the async render* — the error branch, not just success.
    """
    srv = make_server().start()
    # PUT under d1/ materialises the directory; deleting the bare d1 key hits the
    # non-empty rmdir path in brix_vfs_unlink -> ENOTEMPTY.
    assert requests.put(f"{srv.base}/{BUCKET}/d1/keep.txt",
                        data=b"x", timeout=15).status_code == 200
    r = requests.delete(f"{srv.base}/{BUCKET}/d1", timeout=15)
    assert r.status_code == 409, r.text
    assert b"BucketNotEmpty" in r.content
    assert (srv.data / "d1" / "keep.txt").exists(), "the child must be untouched"


def test_delete_backend_error_returns_500(make_server):
    """A queued DELETE whose backend unlink fails with a non-benign errno (EACCES)
    surfaces as 500 *through the async render* — the generic-error arm of
    s3_delete_respond (and its INTERNAL_ERROR metric), the branch the 204/404/409
    cases never reach. Revoking write on the *parent* directory (0500 = r-x) denies
    the queued unlink at drain while path resolution (execute-only) still succeeds,
    so the object survives and the parked client still gets a definite reply."""
    srv = make_server().start()
    locked = srv.data / "locked"
    locked.mkdir()
    victim = locked / "obj.txt"
    victim.write_bytes(b"stays\n")
    os.chmod(locked, 0o500)              # deny unlink of the child, keep traversal
    try:
        r = requests.delete(srv.key("locked/obj.txt"), timeout=15)
        assert r.status_code == 500, r.text
        assert victim.exists(), "a denied backend unlink must not remove the object"
    finally:
        os.chmod(locked, 0o700)         # let pytest's tmp teardown remove the tree


# --------------------------------------------------------------------------- #
# Batch-size trigger — two concurrent DELETEs flush without the time backstop  #
# --------------------------------------------------------------------------- #

def test_size_trigger_releases_batch(make_server):
    """batch=2 + a 30s wait: two concurrent DELETEs release each other on SIZE.

    With only the time trigger they would each block ~30s; both returning 204 well
    inside a 10s join proves the queue flushed the moment its depth hit the batch.
    """
    srv = make_server(batch="2", wait="30000ms").start()
    urls = [srv.key(f"batch-{i}.txt") for i in range(2)]
    for u in urls:
        assert requests.put(u, data=b"z", timeout=15).status_code == 200

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
    backend object survives — the op never reaches the queue."""
    srv = make_server(allow_write="off").start()
    # Seed the object directly on the backend (PUT is write-gated too).
    target = srv.data / "protected.txt"
    target.write_bytes(b"keep me\n")

    r = requests.delete(srv.key("protected.txt"), timeout=15)
    assert r.status_code == 403, r.text
    assert target.exists(), "denied DELETE must not touch the backend"
