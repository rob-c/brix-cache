"""
test_audit15g_sd_http_deadline.py — what an http:// origin's misbehaviour costs
the client (audit §C: "the sd_http deadline (hardcoded, untested)").

An origin can fail in four ways that look identical from the outside and must
not be answered identically: it can say the object is gone (404), it can not be
there at all (connection refused), it can accept the connection and then go
silent forever, and it can promise N bytes and deliver fewer.  The suite had
tests for a healthy http:// origin and none for any of these, so the whole
mapping from "the origin did something" to "the client was told something" was
unpinned — and that mapping is the part a grid client acts on.

The distinction that matters most is kXR_NotFound versus everything else.  A
client that is told a file does not exist is entitled to act on it destructively
— drop the replica, fail the job permanently, remove the catalogue entry — where
an I/O error means "try again or try elsewhere".  An origin that is merely
unreachable must therefore never surface as kXR_NotFound; sd_http_head_size
(fs/backend/http/sd_http_read.c:67-90) gets this right, mapping only a real 404
to ENOENT, and both halves are pinned below so a later refactor cannot quietly
collapse them.

THE DEADLINE, and why this file can only measure it rather than configure it:
`sd_http_inst_state.timeout_ms` is initialised from the caller's config or, as
here, from BRIX_SD_HTTP_DEFAULT_TIMEOUT_MS = 60000 (fs/backend/http/sd_http.h:40),
and no directive reaches it.  It becomes CURLOPT_TIMEOUT_MS — a whole
connect+transfer ceiling, not an idle timer — in s3o_apply_timeouts
(fs/cache/origin/s3_transport_setup.c:349-365).  The three fast-fail bounds that
would turn a silent origin into a prompt error (CONNECTTIMEOUT_MS, LOW_SPEED_TIME,
LOW_SPEED_LIMIT) are left at libcurl's defaults — i.e. off — unless
`brix_s3_origin_timeouts_set` has been called, and its only caller applies the
cvmfs location's `brix_cvmfs_origin_*` values `if (conf->cvmfs.enable)`
(protocols/cvmfs/cvmfs_module_merge.c:263-269), process-globally.  So on a
stream-only kXR plane a stalled origin pins a fill thread and a client for a
full minute, and an operator has no knob at all.  That is measured here as a
bound, not asserted as a wish: if the constant changes, or a directive is added,
this test says so.

Cases:
  * success      — a fill through the http:// origin lands complete, in exactly
                   one HEAD + one whole-object GET (the control)
  * error        — a 404 origin is the one case that IS kXR_NotFound
  * error/sec-neg— an unreachable origin must NOT be kXR_NotFound: an I/O error
                   is retryable, a missing file is acted on destructively
  * deadline     — a connected-but-silent origin is abandoned on the compiled-in
                   60 s ceiling, with the bound measured both ways
  * security-neg — an origin that hangs up owing bytes it advertised never
                   leaves a short object published under the complete name
"""

import os
import time

import pytest

from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, BIND_HOST
from _test_audit15g_helpers import (XERR_IO_ERROR, XERR_NOT_FOUND, open_fails,
                                    pattern, read_whole, serve_paced,
                                    wait_until)

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15g-sdhttp")]

NAME = "lc-audit15g-sdhttp"
MOCK_PORT = LIFECYCLE_SHARED_PORTS[NAME]["extra"]["MOCK_PORT"]

SIZE = 512 * 1024
CHUNK = 64 * 1024
# BRIX_CACHE_FETCH_CHUNK (fs/cache/cache_internal.h:53) — the fill window, which
# is what the origin is asked for regardless of how big the object turned out to
# be.  An object smaller than the window is fetched with a range that runs past
# EOF and is clamped by the origin.
FETCH_CHUNK = 1024 * 1024
PATH = "/objs/origin.bin"
GONE = "/objs/gone.bin"
PAYLOAD = pattern(SIZE, 7)

# fs/backend/http/sd_http.h:40 — the whole subject of the deadline case.
SD_HTTP_DEADLINE_S = 60.0


@pytest.fixture
def tier(lifecycle, tmp_path):
    """(endpoint, store, origin) — a plain http:// tier and its origin."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    export = tmp_path / "export"
    store = tmp_path / "store"
    for path in (export, store):
        path.mkdir()
        os.chmod(path, 0o777)
    os.chmod(tmp_path, 0o777)

    origin = serve_paced(MOCK_PORT, PAYLOAD, chunk=CHUNK, delay=0.0)
    stopped = []

    def stop():
        if stopped:
            return
        stopped.append(True)
        origin.hold.set()               # never leave a thread parked in wait()
        origin.shutdown()
        origin.server_close()

    origin.stop = stop
    try:
        endpoint = lifecycle.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit15g_sdhttp.conf",
            protocol="root",
            readiness="tcp",
            data_root=str(store),
            template_values={
                "BIND_HOST": BIND_HOST,
                "EXPORT": str(export),
                "STORE": str(store)},
            reason="audit-15g sd_http origin failures and the fill deadline"))
        yield endpoint, store, origin
    finally:
        stop()


def _store_size(store, path=PATH):
    try:
        return os.path.getsize(os.path.join(str(store), path.lstrip("/")))
    except FileNotFoundError:
        return None


def _gets(origin):
    return [r for r in origin.recorded if r["method"] == "GET"]


# --------------------------------------------------------------------------- #

def test_a_fill_through_the_http_origin_lands_complete(tier):
    """success (control): the healthy path, asserted by SHAPE as well as by
    bytes.  One HEAD for the size and one GET for the first fetch window is
    what makes every failure case below a single, aimable request rather than a
    race between several.

    The range is the fetch window, not the object: this 512 KiB object is asked
    for as `bytes=0-1048575`, half of which is past EOF.  That is legal — the
    origin clamps — but it is also the reason a test cannot infer object size
    from the range it sees, so the shape is pinned as the window."""
    endpoint, store, origin = tier
    assert read_whole(endpoint.port, PATH, SIZE, chunk=CHUNK) == PAYLOAD
    assert [(r["method"], r["range"]) for r in origin.recorded] == \
        [("HEAD", None), ("GET", f"bytes=0-{FETCH_CHUNK - 1}")], origin.recorded
    assert _store_size(store) == SIZE


def test_a_404_at_the_origin_is_the_one_honest_not_found(tier):
    """error: the origin answers 404, which is the single case where "the file
    does not exist" is a true statement about the world — sd_http_head_size maps
    that status, and only that status, to ENOENT.  Pinning the honest case is
    what gives the next test its teeth: without it, a server that answered
    kXR_NotFound to absolutely everything would pass that one."""
    endpoint, store, origin = tier
    origin.absent.add(GONE)

    assert open_fails(endpoint.port, GONE) == XERR_NOT_FOUND
    assert _store_size(store, GONE) is None, "a 404 was cached as an object"
    assert [r["method"] for r in origin.recorded][:1] == ["HEAD"]


def test_an_unreachable_origin_is_not_reported_as_a_missing_file(tier):
    """security-negative: the origin is gone — every connection is refused —
    and the answer must be an I/O error, never kXR_NotFound.  The two are one
    status code apart on the wire and worlds apart in consequence: a grid client
    told "not found" is entitled to drop the replica from its catalogue, so a
    reachability failure that impersonates a missing file turns a transient
    network fault into permanent data loss.

    The healthy object is filled first, so this is provably the origin being
    unreachable and not the object being unknown."""
    endpoint, store, origin = tier
    assert read_whole(endpoint.port, "/objs/warm.bin", SIZE, chunk=CHUNK) \
        == PAYLOAD
    origin.stop()

    errcode = open_fails(endpoint.port, PATH)
    assert errcode != XERR_NOT_FOUND, \
        "an unreachable origin was reported to the client as a missing file"
    assert errcode == XERR_IO_ERROR, errcode
    assert _store_size(store) is None


@pytest.mark.timeout(200)
def test_a_silent_origin_is_abandoned_on_the_compiled_in_deadline(tier):
    """The deadline itself.  The origin accepts the connection, answers the HEAD
    (so the size probe succeeds and the fill commits), then goes silent inside
    the GET body and never speaks again.  Nothing else can end this: no
    low-speed bound is configured, no connect timeout applies to an established
    connection, and the kXR read deadline is not armed in XRD_ST_AIO
    (protocols/root/connection/deadline.h).  Only CURLOPT_TIMEOUT_MS is left,
    and it is the compile-time 60 s.

    Both bounds are asserted.  The lower one is the point: an operator cannot
    make this fail faster, so a silent origin holds a fill thread and a client
    for a full minute per request.  The upper one catches the opposite
    regression — a deadline that stopped applying at all would hang the worker
    until the client gave up.  Adjust both, and the docstring, if
    BRIX_SD_HTTP_DEFAULT_TIMEOUT_MS ever changes or grows a directive."""
    endpoint, store, origin = tier
    origin.hold.clear()

    started = time.monotonic()
    errcode = open_fails(endpoint.port, PATH,
                         timeout=SD_HTTP_DEADLINE_S * 2 + 20)
    elapsed = time.monotonic() - started
    origin.hold.set()

    assert errcode != 0, "the fill somehow completed against a silent origin"
    assert _gets(origin), "the GET never reached the origin; nothing stalled"
    assert elapsed >= SD_HTTP_DEADLINE_S * 0.75, (
        f"the fill was abandoned after {elapsed:.1f}s — faster than the "
        f"{SD_HTTP_DEADLINE_S:.0f}s constant, so something else ended it")
    assert elapsed <= SD_HTTP_DEADLINE_S * 1.6, (
        f"a silent origin held the client for {elapsed:.1f}s; the "
        f"{SD_HTTP_DEADLINE_S:.0f}s ceiling is not being applied")
    assert _store_size(store) is None, "a stalled fill was published anyway"


def test_a_truncated_origin_body_never_publishes_a_short_object(tier):
    """security-negative, and the one that outlives every deadline change: the
    origin promises the full Content-Length and then hangs up halfway.  The
    fill must fail — a short object published under the complete name would be
    served to every later reader with a success status and no way to tell it
    from the real thing, and the origin's own copy would not be consulted
    again.  Afterwards, with the origin honest, the object must arrive whole."""
    endpoint, store, origin = tier
    origin.truncate_at = SIZE // 2

    errcode = open_fails(endpoint.port, PATH)
    assert errcode != 0, "a truncated origin body was accepted as a fill"
    assert errcode != XERR_NOT_FOUND, \
        "a truncated transfer was reported as a missing file"
    assert _store_size(store) is None, \
        f"a {_store_size(store)}-byte object was published under a whole name"

    origin.truncate_at = None
    wait_until(lambda: read_whole(endpoint.port, PATH, SIZE, chunk=CHUNK)
               == PAYLOAD, timeout=30,
               what="the object arriving whole once the origin behaved")
    assert _store_size(store) == SIZE
