"""
test_audit15g_reload_during_fill.py — `nginx -s reload` lands while a cache
fill is in flight (audit §C, carried unchanged from the 2026-08-04 pass:
"reload during cache-fill (no test)").

Reload is the most routine thing an operator does to a running cache — a
certificate rotation, a new export, a log path — and it is the one moment when
two generations of worker exist at once.  The suite tests reload semantics
(test_reload.py) and it tests cache fills, never both: nothing had ever asked
what happens to a fill that is halfway to the origin when the master forks a
new worker and tells the old one to retire.

The origin is a `PacedSource` rather than an nginx instance precisely so the
"halfway" is real: the object is exactly one BRIX_CACHE_FETCH_CHUNK
(fs/cache/cache_internal.h:53), so the tier pulls it in ONE GET (asserted by the
control case below), `hold` freezes that GET mid-body, the reload is injected
into the frozen window, and only then is the origin released.  Without that the
reload races the fill and a passing test would prove nothing.

Reload must preserve the retiring worker's kXR sessions, including a session
that is parked between requests or waiting for an offloaded cache fill.  Two
mechanisms are involved:

  * `brix_recv_frame_maybe_park` (protocols/root/connection/recv_frame.c:120-152)
    deliberately declines the `ngx_exiting` fast teardown and leaves
    `c->idle = 0` when the session holds an open file, with the comment "Let the
    active transfer finish on the old worker (bounded by
    worker_shutdown_timeout)".  That guard does its job:
    `ngx_close_idle_connections()` skips the connection.
  * but nothing keeps the retiring WORKER alive to serve it.  A kXR session
    parked at a request boundary carries no timer by design (connection/
    deadline.h: an idle keepalive "is deliberately left alone so long-lived
    xrdcp sessions that pause between operations are not killed"), so
    `ngx_event_no_timers_left()` is satisfied the moment the listen sockets
    close, and nginx runs `ngx_worker_process_exit()` at once — logging
    `*N open socket #fd left in connection M` and `aborting`, and taking the
    session's socket down with the process.

The connection must remain owned by the retiring worker until the request
finishes or `worker_shutdown_timeout` bounds the wait.  Both halves are pinned
below: a fill in flight and a parked session holding an open handle with no fill
outstanding at all.

Cases:
  * success      — a paced fill completes byte-exact, lands in the store, and
                   costs exactly one HEAD + one whole-object GET (control, and
                   the proof that "mid-fill" is a window that exists)
  * success/pin  — a reload mid-fill keeps the in-flight session alive while
                   the origin is still frozen
  * success/pin  — a parked session holding an open handle remains usable after
                   reload, which isolates the mechanism from anything the origin
                   does
  * security-neg — the damage is bounded: a fill killed by the reload never
                   leaves a TRUNCATED object in the store for the next reader to
                   be served as if it were complete
  * success      — a filled object survives the reload with the origin gone, and
                   the reload's config change is live on the wire (the control
                   that says the reload itself is healthy)
"""

import os
import pathlib
import threading

import pytest

from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, BIND_HOST
from _test_audit15g_helpers import (ReadHandle, XERR_IO_ERROR, pattern,
                                    read_whole, serve_paced, wait_until,
                                    write_open)

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15g-fill")]

NAME = "lc-audit15g-fill"
MOCK_PORT = LIFECYCLE_SHARED_PORTS[NAME]["extra"]["MOCK_PORT"]

# Exactly one BRIX_CACHE_FETCH_CHUNK (fs/cache/cache_internal.h:53): the fill is
# then a single origin GET, so "the reload landed mid-fill" is unambiguous.
SIZE = 1024 * 1024
CHUNK = 64 * 1024
ORIGIN_CHUNK = 64 * 1024
# 16 origin chunks at 50 ms is ~0.8 s of fill — long enough that a reload lands
# inside it once the origin has been frozen, short enough to run 5 times.
PACE = 0.05

PATH = "/objs/paced.bin"
PAYLOAD = pattern(SIZE, 5)

XERR_FS_READONLY = 3025


class Origin:
    """The paced http:// source plus the freeze/release control the tests aim
    the reload with.  `stop()` is idempotent so a test may kill the origin and
    the fixture can still tear down."""

    def __init__(self, port, payload):
        self._server = serve_paced(port, payload, chunk=ORIGIN_CHUNK,
                                   delay=PACE)
        self._stopped = False

    @property
    def requests(self):
        return [(r["method"], r["range"]) for r in self._server.recorded]

    @property
    def gets(self):
        return [r for r in self._server.recorded if r["method"] == "GET"]

    def freeze(self):
        self._server.hold.clear()

    def release(self):
        self._server.hold.set()

    def stop(self):
        if self._stopped:
            return
        self._stopped = True
        self._server.hold.set()          # never leave a thread parked in wait()
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def fill(lifecycle, tmp_path):
    """(endpoint, store, origin) — the tier and the paced origin behind it."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    export = tmp_path / "export"
    store = tmp_path / "store"
    for path in (export, store):
        path.mkdir()
        os.chmod(path, 0o777)
    os.chmod(tmp_path, 0o777)

    origin = Origin(MOCK_PORT, PAYLOAD)
    try:
        endpoint = lifecycle.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit15g_fill.conf",
            protocol="root",
            readiness="tcp",
            data_root=str(store),
            template_values={
                "BIND_HOST": BIND_HOST,
                "EXPORT": str(export),
                "STORE": str(store),
                "ALLOW_WRITE": "off"},
            reason="audit-15g reload during a cache fill"))
        yield endpoint, store, origin
    finally:
        origin.stop()


def _stored(store):
    return os.path.join(str(store), PATH.lstrip("/"))


def _store_size(store):
    try:
        return os.path.getsize(_stored(store))
    except FileNotFoundError:
        return None


def _errlog(endpoint):
    """The instance's error log.  Instance logs are wiped at teardown, so the
    pin below quotes the line it depends on rather than pointing at a path."""
    try:
        return pathlib.Path(endpoint.prefix, "logs", "error.log").read_text()
    except FileNotFoundError:
        return ""


def _read_in_background(port, path=PATH, size=SIZE):
    """Start a whole-object read on its own thread and hand back
    (thread, result) — the fill has to be in flight while the test reloads."""
    result = {}

    def run():
        try:
            result["bytes"] = read_whole(port, path, size, chunk=CHUNK)
        except BaseException as exc:            # noqa: BLE001 - reported below
            result["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, result


def _reload(lifecycle, allow_write="on"):
    """Re-render with a witnessable change and reload."""
    lifecycle.reconfigure(NAME, ALLOW_WRITE=allow_write)
    lifecycle.reload(NAME)


def _workers(lifecycle):
    return {pid for pid, command in lifecycle.process_snapshot(NAME)
            if "worker process" in command}


# --------------------------------------------------------------------------- #

def test_a_paced_fill_completes_and_lands_in_the_store(fill):
    """success (control): nothing is injected.  The request SHAPE is asserted,
    not just the bytes — the object is one fetch window, so the tier pulls it in
    a single ranged GET at open time, which makes "the reload landed mid-fill" a
    window that really exists rather than a story about interleaved fetches."""
    endpoint, store, origin = fill
    assert read_whole(endpoint.port, PATH, SIZE, chunk=CHUNK) == PAYLOAD
    assert origin.requests == [("HEAD", None), ("GET", f"bytes=0-{SIZE - 1}")], \
        origin.requests
    assert _store_size(store) == SIZE, "the fill did not land complete"


def test_a_reload_mid_fill_preserves_the_in_flight_session(fill, lifecycle):
    """Freeze the origin inside the fill's GET, inject reload, and verify the
    client session remains alive until the origin is released."""
    endpoint, store, origin = fill
    origin.freeze()
    thread, result = _read_in_background(endpoint.port)
    wait_until(lambda: origin.gets, timeout=15,
               what="the fill reaching the origin")

    _reload(lifecycle)
    thread.join(timeout=1)               # the origin is STILL frozen
    assert thread.is_alive(), "reload retired the worker during the fill"
    origin.release()
    thread.join(timeout=30)
    assert not thread.is_alive(), "the fill did not finish after release"
    assert result.get("bytes") == PAYLOAD, repr(result)
    assert "error" not in result, repr(result)


def test_a_reload_preserves_a_parked_session_holding_an_open_handle(fill,
                                                                    lifecycle):
    """A parked session with an open handle remains usable across reload."""
    endpoint, _store, origin = fill
    handle = ReadHandle(endpoint.port, PATH, timeout=30)
    assert handle.read(0, CHUNK) == PAYLOAD[:CHUNK]
    assert origin.gets, "the fill never happened; the open handle proves nothing"

    _reload(lifecycle)
    assert handle.read(CHUNK, CHUNK) == PAYLOAD[CHUNK:2 * CHUNK]
    assert "left in connection" not in _errlog(endpoint)
    assert handle.close() == 0


def test_a_reload_never_leaves_a_truncated_cache_object(fill, lifecycle):
    """Security-negative: reload overlap must never expose a short cache file
    under the complete object's name."""
    endpoint, store, origin = fill
    origin.freeze()
    thread, _result = _read_in_background(endpoint.port)
    wait_until(lambda: origin.gets, timeout=15,
               what="the fill reaching the origin")

    _reload(lifecycle)
    thread.join(timeout=1)
    assert thread.is_alive(), "reload retired the worker during the fill"
    origin.release()
    thread.join(timeout=30)
    assert not thread.is_alive(), "the fill did not finish after release"

    size = _store_size(store)
    assert size in (None, SIZE), \
        f"a reloaded fill left a {size}-byte object under a complete name"
    assert read_whole(endpoint.port, PATH, SIZE, chunk=CHUNK) == PAYLOAD, \
        "the object was not served correctly after the reload"
    assert _store_size(store) == SIZE


def test_a_filled_object_survives_the_reload_without_the_origin(fill,
                                                                lifecycle):
    """success, and the control for both pins above: the reload itself is
    healthy.  A cache that forgot its store on reload would not be one — the
    object is filled, the origin is taken away, the reload happens, and the read
    is still answered from the store, which also pins that reload does not
    revalidate against the origin.  The flipped `brix_allow_write` is asserted
    on the wire as well, so "the reload took" is witnessed rather than assumed:
    without it a reload that silently did nothing would satisfy this file."""
    endpoint, store, origin = fill
    assert write_open(endpoint.port, "/objs/pre.bin") == XERR_FS_READONLY, \
        "the plane started writable — the reload witness would prove nothing"
    assert read_whole(endpoint.port, PATH, SIZE, chunk=CHUNK) == PAYLOAD
    assert _store_size(store) == SIZE

    origin.stop()
    _reload(lifecycle)
    wait_until(lambda: len(_workers(lifecycle)) == 1, timeout=15,
               what="the new generation settling to a single worker")

    assert read_whole(endpoint.port, PATH, SIZE, chunk=CHUNK) == PAYLOAD, \
        "the store did not survive the reload once the origin was gone"
    # This export has no writable stage and the origin is intentionally gone,
    # so a permitted write reaches the backend and fails with I/O error.  The
    # important distinction is that it no longer stops at the read-only gate.
    assert write_open(endpoint.port, "/objs/post.bin") == XERR_IO_ERROR, \
        "the reload did not expose the new config's writable policy"
