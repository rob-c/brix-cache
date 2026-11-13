"""test_backend_async_webdav.py — durable async backend-op queue over WebDAV.

`brix_backend_async on` routes WebDAV DELETE through the same per-worker
coalescing queue the root:// and S3 planes use: the unlink / rmdir is journalled
and enqueued and the HTTP request is *parked*
(r->main->count++, NGX_DONE) until the batch flushes, at which point the real
204 / 409 / 500 is rendered on the event loop and the request finalised.
GET/PUT/PROPFIND/MOVE pass through synchronously. The
allow_write gate runs at the access phase, *before* the enqueue, so a denied
mutation never reaches the queue.

Security note: MOVE intentionally stays on the identity-aware VFS path even when
the async option is enabled. A durable replay has no request identity or policy
generation with which to reproduce the independently authorized source and
Destination decisions; refusing that optimization keeps restart replay from
silently widening caller authority.

Coverage (success + error + security-neg + the batch-size trigger):
  * DELETE of an existing file is deferred, flushes on the time trigger, removes
    the backend object, and returns 204.
  * MOVE to a fresh destination remains functional through the synchronous,
    identity-aware path and returns 201 Created.
  * DELETE of a non-empty collection surfaces ENOTEMPTY as a 409 *through the async
    render* — the error branch, not just success.
  * DELETE denied at drain (EACCES) surfaces as 403 through the async renderer;
    MOVE denied by the identity-aware VFS path also returns 403.
  * two concurrent DELETEs with a long wait flush promptly via the SIZE trigger
    (batch=2) — proving the size path released them, not the time backstop.
  * with `brix_allow_write off` the DELETE is rejected by the write gate BEFORE it
    can enqueue (403 Forbidden) and the object survives — fail-closed.

  * scoped-token MOVE requires authority on both source and Destination; a
    source-only token is rejected before any durable record is created.
  * XrdAcc distinguishes destination Insert from Update, and overwriting an
    existing destination additionally requires Delete.

Self-provisioning via the registry lifecycle harness; skips when the nginx binary
is absent or was built without the queue.
"""

import os
import pathlib
import subprocess
import threading
import time
import uuid

import pytest
import requests
import urllib3

from settings import (BIND_HOST, CA_CERT, HOST, NGINX_BIN, SERVER_CERT,
                      SERVER_KEY)
from server_registry import NginxInstanceSpec
from brix_suite.nginx_capabilities import nginx_has_symbol
from utils.make_token import TokenIssuer

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _expression_1(srv):
    return (
        [srv.url(f"batch-{i}.txt") for i in range(2)]
    )

def _expression_2(urls, worker):
    return (
        [threading.Thread(target=worker, args=(i, u))
                       for i, u in enumerate(urls)]
    )


def _check_test_size_trigger_releases_batch_2(t0):
    assert time.monotonic() - t0 < 10, "batch did not flush on the size trigger"

def _check_test_size_trigger_releases_batch_1(u):
    assert requests.put(u, data=b"z", timeout=15).status_code in (200, 201)


pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-backend-async-webdav")]


def _have_nginx():
    return nginx_has_symbol("brix_baq_enqueue")


class _Server:
    """A throwaway WebDAV posix tier with the async backend queue configured."""

    def __init__(self, lifecycle, tmp_path, allow_write="on", batch="64",
                 wait="400ms", name="lc-backend-async-webdav",
                 token_auth=False, xrdacc_rules=None,
                 authz_backstop="observe"):
        self._lifecycle = lifecycle
        self._name = name
        self._allow_write = allow_write
        self._batch = batch
        self._wait = wait
        self._token_auth = token_auth
        self._xrdacc_rules = xrdacc_rules
        self._authz_backstop = authz_backstop
        self.data = pathlib.Path(tmp_path) / "data"
        self.data.mkdir(parents=True, exist_ok=True)
        self.journal = pathlib.Path(tmp_path) / "journal"
        self.journal.mkdir(parents=True, exist_ok=True)
        self.issuer = None
        if token_auth:
            self.issuer = TokenIssuer(str(pathlib.Path(tmp_path) / "tokens"))
            self.issuer.init_keys()
        self.authdb = pathlib.Path(tmp_path) / "authdb"
        if xrdacc_rules is not None:
            self.authdb.write_text(xrdacc_rules)
        self.base = None

    def _template(self):
        """Select the authentication-specific fixture configuration."""
        if self._token_auth:
            return "nginx_lc_backend_async_webdav_token.conf"
        if self._xrdacc_rules is not None:
            return "nginx_lc_backend_async_webdav_xrdacc.conf"
        return "nginx_lc_backend_async_webdav.conf"

    def start(self):
        template = self._template()
        ep = self._lifecycle.start(NginxInstanceSpec(
            name=self._name,
            template=template,
            protocol="webdav",
            template_values={
                "BIND_HOST": BIND_HOST,
                "DATA_DIR": str(self.data),
                "ALLOW_WRITE": self._allow_write,
                "ASYNC": "on",
                "BATCH": self._batch,
                "WAIT": self._wait,
                "JOURNAL_DIR": str(self.journal),
                "CA_CERT": CA_CERT,
                "SERVER_CERT": SERVER_CERT,
                "SERVER_KEY": SERVER_KEY,
                "JWKS": self.issuer.jwks_path if self.issuer else "unused",
                "ISSUER": self.issuer.issuer if self.issuer else "unused",
                "AUDIENCE": self.issuer.audience if self.issuer else "unused",
                "AUTHDB": str(self.authdb),
                "AUTHZ_BACKSTOP": self._authz_backstop,
            },
            reason="throwaway WebDAV tier exercising the async backend-op queue",
        ))
        scheme = "https" if self._token_auth else "http"
        self.base = f"{scheme}://{HOST}:{ep.port}"
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
# Success — MOVE remains identity-aware when backend async is enabled          #
# --------------------------------------------------------------------------- #

def test_move_fresh_dest_uses_identity_aware_path(make_server):
    """MOVE stays functional through the identity-aware VFS path and returns 201
    even when the endpoint enables asynchronous backend operations."""
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
        "destination must hold the moved bytes after the synchronous MOVE"


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
    """With `brix_backend_async on`, MOVE onto an existing destination remains
    identity-aware: it replaces the target and returns 204 No Content."""
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
    """With async ON, a collection MOVE uses the identity-aware collection
    offload and returns 201 for a fresh destination."""
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
    the *parent* directory (0555 = r-x for the worker) denies the queued unlink while path
    resolution (execute-only) still succeeds, so the file survives."""
    srv = make_server().start()
    locked = srv.data / "locked"
    locked.mkdir()
    victim = locked / "obj.txt"
    victim.write_bytes(b"stays\n")
    os.chmod(locked, 0o555)             # deny unlink of the child, keep traversal
    try:
        r = requests.delete(f"{srv.base}/locked/obj.txt", timeout=15)
        assert r.status_code == 403, r.text
        assert victim.exists(), "a denied backend unlink must not remove the file"
    finally:
        os.chmod(locked, 0o700)        # let pytest's tmp teardown remove the tree


def test_move_backend_error_forbidden(make_server):
    """A fresh-destination MOVE whose identity-aware VFS rename is denied with
    EACCES returns 403 and leaves both names unchanged."""
    srv = make_server().start()
    locked = srv.data / "locked"
    locked.mkdir()
    src = locked / "mv-src.txt"
    src.write_bytes(b"stays\n")
    os.chmod(locked, 0o555)
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
    urls = _expression_1(srv)
    for u in urls:
        _check_test_size_trigger_releases_batch_1(u)

    results = {}

    def _worker(tag, url):
        results[tag] = requests.delete(url, timeout=15).status_code

    t0 = time.monotonic()
    threads = _expression_2(urls, _worker)
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    def _assert_test_size_trigger_releases_batch_1():
        assert not any(t.is_alive() for t in threads), "a DELETE never flushed"
        assert results == {0: 204, 1: 204}, results

    _assert_test_size_trigger_releases_batch_1()
    _check_test_size_trigger_releases_batch_2(t0)


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


# --------------------------------------------------------------------------- #
# Resource-complete MOVE authorization                                        #
# --------------------------------------------------------------------------- #

def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _journal_records(srv):
    return list(srv.journal.rglob("*.req"))


def test_move_token_authorized_for_both_operands_succeeds(make_server):
    """Success: a token covering source and Destination can MOVE normally."""
    srv = make_server(token_auth=True, wait="30000ms").start()
    src_dir = srv.data / "move-source"
    dst_dir = srv.data / "move-target"
    src_dir.mkdir()
    dst_dir.mkdir()
    source = src_dir / "allowed.txt"
    source.write_bytes(b"authorized\n")
    token = srv.issuer.generate(
        scope="storage.write:/move-source storage.write:/move-target")

    response = requests.request(
        "MOVE", f"{srv.base}/move-source/allowed.txt",
        headers={**_bearer(token),
                 "Destination": f"{srv.base}/move-target/allowed.txt"},
        verify=False, timeout=15)

    assert response.status_code == 201, response.text
    assert not source.exists()
    assert (dst_dir / "allowed.txt").read_bytes() == b"authorized\n"
    assert not _journal_records(srv), "MOVE must not create replayable records"


def test_move_source_only_token_cannot_cross_destination_scope(make_server):
    """SECURITY-NEG: source authority never implies Destination authority."""
    srv = make_server(token_auth=True, wait="30000ms").start()
    src_dir = srv.data / "move-source"
    dst_dir = srv.data / "other-tenant"
    src_dir.mkdir()
    dst_dir.mkdir()
    source = src_dir / "secret.txt"
    source.write_bytes(b"stay\n")
    token = srv.issuer.generate(scope="storage.write:/move-source")

    started = time.monotonic()
    response = requests.request(
        "MOVE", f"{srv.base}/move-source/secret.txt",
        headers={**_bearer(token),
                 "Destination": f"{srv.base}/other-tenant/stolen.txt"},
        verify=False, timeout=15)

    assert response.status_code == 403, response.text
    assert time.monotonic() - started < 5, "denial was parked in async replay"
    assert source.read_bytes() == b"stay\n"
    assert not (dst_dir / "stolen.txt").exists()
    assert not _journal_records(srv), "denied MOVE reached the durable queue"


def test_move_malformed_destination_fails_without_side_effects(make_server):
    """Error: an absolute Destination without a path is 400 and never queues."""
    srv = make_server(token_auth=True, wait="30000ms").start()
    src_dir = srv.data / "move-source"
    src_dir.mkdir()
    source = src_dir / "bad-destination.txt"
    source.write_bytes(b"stay\n")
    token = srv.issuer.generate(scope="storage.write:/move-source")

    response = requests.request(
        "MOVE", f"{srv.base}/move-source/bad-destination.txt",
        headers={**_bearer(token), "Destination": srv.base},
        verify=False, timeout=15)

    assert response.status_code == 400, response.text
    assert source.read_bytes() == b"stay\n"
    assert not _journal_records(srv)


# --------------------------------------------------------------------------- #
# XrdAcc operation-complete MOVE authorization                                #
# --------------------------------------------------------------------------- #

def _xrdacc_move_server(make_server, destination_privileges):
    rules = ("u * /move-source n "
             f"/move-target {destination_privileges}\n")
    return make_server(xrdacc_rules=rules, wait="30000ms").start()


def test_move_xrdacc_insert_only_destination_succeeds(make_server):
    """Success: a fresh destination requires Insert, matching root:// MOVE."""
    srv = _xrdacc_move_server(make_server, "i")
    src_dir = srv.data / "move-source"
    dst_dir = srv.data / "move-target"
    src_dir.mkdir()
    dst_dir.mkdir()
    source = src_dir / "insert.txt"
    source.write_bytes(b"insert-only\n")

    response = requests.request(
        "MOVE", f"{srv.base}/move-source/insert.txt",
        headers={"Destination": f"{srv.base}/move-target/insert.txt"},
        timeout=15)

    assert response.status_code == 201, response.text
    assert not source.exists()
    assert (dst_dir / "insert.txt").read_bytes() == b"insert-only\n"


def test_move_xrdacc_overwrite_without_delete_is_forbidden(make_server):
    """SECURITY-NEG: Insert authority cannot remove an existing destination."""
    srv = _xrdacc_move_server(make_server, "i")
    src_dir = srv.data / "move-source"
    dst_dir = srv.data / "move-target"
    src_dir.mkdir()
    dst_dir.mkdir()
    source = src_dir / "replace.txt"
    target = dst_dir / "replace.txt"
    source.write_bytes(b"new\n")
    target.write_bytes(b"old\n")

    response = requests.request(
        "MOVE", f"{srv.base}/move-source/replace.txt",
        headers={"Destination": f"{srv.base}/move-target/replace.txt"},
        timeout=15)

    assert response.status_code == 403, response.text
    assert source.read_bytes() == b"new\n"
    assert target.read_bytes() == b"old\n"
    assert not _journal_records(srv)


def test_move_xrdacc_insert_and_delete_can_overwrite(make_server):
    """Control: Insert plus Delete permits replacement and returns 204."""
    srv = _xrdacc_move_server(make_server, "id")
    src_dir = srv.data / "move-source"
    dst_dir = srv.data / "move-target"
    src_dir.mkdir()
    dst_dir.mkdir()
    source = src_dir / "replace.txt"
    target = dst_dir / "replace.txt"
    source.write_bytes(b"new\n")
    target.write_bytes(b"old\n")

    response = requests.request(
        "MOVE", f"{srv.base}/move-source/replace.txt",
        headers={"Destination": f"{srv.base}/move-target/replace.txt"},
        timeout=15)

    assert response.status_code == 204, response.text
    assert not source.exists()
    assert target.read_bytes() == b"new\n"
    assert not _journal_records(srv)
