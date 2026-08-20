"""
test_audit15g_evict_during_read.py — the cache reaper and a reader reach for
the same object at the same time (audit §C, carried unchanged from the
2026-08-04 pass: "cache eviction during active read (no test)").

The suite has plenty of eviction tests and plenty of read tests, and they never
overlap.  That matters because nothing in the eviction path asks whether anyone
is reading: `reap_classify` (cache_reap.c) consults the cinfo state and the
file's age, and `brix_cache_purge_to_target` walks LRU candidates — neither
consults an open handle.  The only thing standing between a purge and a
half-delivered transfer is POSIX inode lifetime, which is exactly the kind of
implicit guarantee worth a test.

Two planes, one per reaper, because the two are wired completely differently
and only one of them can be aimed:

  * the WATERMARK reaper (`reap_watermark.c`) re-arms at
    `brix_cache_reap_interval`, so with a 1-second interval and a high mark any
    real filesystem is already past, it purges the store once a second.  That
    is the deterministic trigger the mid-read cases need.
  * the COLD reaper (`cache_reap.c`, `brix_cache_cold_max_age`) is armed by the
    same directive block but paced by neither of its directives.

DEFECT CANDIDATE #18, pinned by the last two cases: `brix_cache_reap_interval`
does NOT pace the cold/dirty reaper.  `brix_init_server_cache_reap_timer`
(process_server_init.c:222) arms it at BRIX_CACHE_REAP_FIRST_MS and
`brix_cache_reap_handler` (process_timers.c:174) re-arms it at
BRIX_CACHE_REAP_INTERVAL_MS — a compiled-in 3600000, i.e. hourly — while the
directive reaches only `brix_cache_watermark_timer_handler`.  So a site that
sets `brix_cache_cold_max_age 300` gets one purge sweep an hour whatever it
sets the interval to: the horizon is honoured but its resolution is not, and
the first sweep after a reload is the only prompt one.  Both halves are pinned
— the 5-second first sweep fires, and the second one does not come.

Cases:
  * success      — a filled object is purged by the watermark reaper (control:
                   the trigger is real, not assumed)
  * success      — a purge landing mid-read still delivers every byte
  * success      — ... and the next opener is re-filled from the origin
  * security-neg — purge mid-read plus a stopped origin: the in-flight handle
                   finishes, and the next opener is refused rather than served
                   a truncated object
  * success      — the cold reaper's first sweep purges an aged read-fill
  * error/pin    — DEFECT CANDIDATE #18: with `brix_cache_reap_interval 1` and
                   `brix_cache_cold_max_age 1`, no second sweep comes
"""

import os
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, BIND_HOST
from _test_audit15g_helpers import (ReadHandle, XERR_IO_ERROR, pattern,
                                    read_whole, seed_tree, wait_until)

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15g-evict")]

SIZE = 512 * 1024
CHUNK = 64 * 1024

# The watermark timer first fires at BRIX_CACHE_REAP_FIRST_MS (5 s) plus a
# per-worker jitter of up to 1 s, then re-arms at brix_cache_reap_interval.
FIRST_SWEEP = 12.0
# Long enough that a 1-second cadence would have swept several times over.
NO_SECOND_SWEEP = 10.0

OBJECTS = {f"/objs/o{n}.bin": pattern(SIZE, 7 + n) for n in range(4)}
NAMES = sorted(OBJECTS)


@pytest.fixture
def evict(lifecycle, tmp_path):
    """The origin plus the two reaper planes over it.  Returns
    (endpoint, watermark_store, cold_store)."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    origin_root = tmp_path / "origin"
    dirs = {name: tmp_path / name for name in
            ("wm-export", "wm-store", "cold-export", "cold-store")}
    origin_root.mkdir()
    for path in dirs.values():
        path.mkdir()
        os.chmod(path, 0o777)
    seed_tree(origin_root, OBJECTS)
    os.chmod(tmp_path, 0o777)

    origin = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15g-mtorigin",
        template="nginx_lc_cache_partial_origin.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(origin_root),
        template_values={
            "BIND_HOST": BIND_HOST,
            "ORIGIN_STORAGE": f"brix_export {origin_root};",
            "ORIGIN_ALLOW_WRITE": ""},
        reason="audit-15g eviction origin"))

    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15g-evict",
        template="nginx_audit15g_evict.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(dirs["wm-store"]),
        template_values={
            "BIND_HOST": BIND_HOST,
            "ORIGIN_PORT": str(origin.port),
            "WM_EXPORT": str(dirs["wm-export"]),
            "WM_STORE": str(dirs["wm-store"]),
            "COLD_EXPORT": str(dirs["cold-export"]),
            "COLD_STORE": str(dirs["cold-store"])},
        reason="audit-15g eviction racing an active read"))
    return endpoint, dirs["wm-store"], dirs["cold-store"]


def _stored(store, path):
    return os.path.exists(os.path.join(str(store), path.lstrip("/")))


def _drain(handle, start, size, chunk=CHUNK):
    out = b""
    while start + len(out) < size:
        out += handle.read(start + len(out), min(chunk, size - start - len(out)))
    return out


def _fill(port, name):
    """Read an object whole so the tier lays it down, and hand back its bytes."""
    return read_whole(port, name, SIZE)


# --------------------------------------------------------------------------- #
# The watermark reaper — the aimable one.                                     #
# --------------------------------------------------------------------------- #
def test_the_watermark_reaper_purges_a_filled_object(evict):
    """success (control): every mid-read case below depends on this trigger
    actually firing, so it is asserted on its own first.  A test that waited
    for an eviction that never came would otherwise fail as a timeout and read
    like a product bug."""
    endpoint, store, _cold = evict
    name = NAMES[0]
    assert _fill(endpoint.port, name) == OBJECTS[name]
    assert _stored(store, name)
    wait_until(lambda: not _stored(store, name), timeout=FIRST_SWEEP,
               what="the watermark reaper's first sweep")


def test_a_purge_landing_mid_read_still_delivers_every_byte(evict):
    """success: the reaper removes the object with the read half-done.  The
    handle holds the inode, so the remaining bytes must arrive complete and
    unchanged — the purge is invisible to a transfer already in flight."""
    endpoint, store, _cold = evict
    name = NAMES[1]
    assert _fill(endpoint.port, name) == OBJECTS[name]

    with ReadHandle(endpoint.port, name) as handle:
        head = handle.read(0, CHUNK)
        wait_until(lambda: not _stored(store, name), timeout=FIRST_SWEEP,
                   what="the purge under an open handle")
        tail = _drain(handle, CHUNK, SIZE)
    assert len(head) + len(tail) == SIZE, (len(head), len(tail))
    assert head + tail == OBJECTS[name]


def test_the_purged_object_is_refilled_for_the_next_opener(evict):
    """success: with the origin still up the next open re-fills, which is also
    the non-vacuity proof that the object really left the store."""
    endpoint, store, _cold = evict
    name = NAMES[2]
    _fill(endpoint.port, name)
    wait_until(lambda: not _stored(store, name), timeout=FIRST_SWEEP,
               what="the purge")
    assert _fill(endpoint.port, name) == OBJECTS[name]
    assert _stored(store, name), "the tier did not re-fill after the purge"


def test_a_purge_with_the_origin_gone_is_refused_not_truncated(evict, lifecycle):
    """security-negative: the object is purged mid-read AND the origin is
    stopped, so nothing holds a complete copy by name any more.  The in-flight
    handle must still finish — and the next opener must be refused with an I/O
    error rather than served whatever the store had, because a short read with
    a success status is indistinguishable from a complete transfer."""
    endpoint, store, _cold = evict
    name = NAMES[3]
    _fill(endpoint.port, name)

    with ReadHandle(endpoint.port, name) as handle:
        head = handle.read(0, CHUNK)
        wait_until(lambda: not _stored(store, name), timeout=FIRST_SWEEP,
                   what="the purge under an open handle")
        lifecycle.stop("lc-audit15g-mtorigin")
        tail, errcode = handle.try_read(CHUNK, SIZE - CHUNK)

    assert errcode == 0, f"the in-flight handle lost its own inode ({errcode})"
    assert head + tail == OBJECTS[name], "short read reported as a success"

    try:
        ReadHandle(endpoint.port, name).close()
        pytest.fail("a purged object was still served with the origin gone")
    except AssertionError as exc:
        assert getattr(exc, "errcode", 0) == XERR_IO_ERROR, exc


# --------------------------------------------------------------------------- #
# The cold reaper — armed, but not paced by the directive that looks like it.  #
# --------------------------------------------------------------------------- #
def test_the_cold_reaper_purges_an_aged_read_fill(evict):
    """success: the cold horizon is 1 s and the first sweep is at 5 s, so a
    fill from the start of the test is well past it by the time the sweep
    runs.  This is the half of DEFECT CANDIDATE #18 that works."""
    endpoint, _store, cold = evict
    cold_port = endpoint.extra_ports["COLD_PORT"]
    name = NAMES[0]
    assert _fill(cold_port, name) == OBJECTS[name]
    assert _stored(cold, name)
    wait_until(lambda: not _stored(cold, name), timeout=FIRST_SWEEP,
               what="the cold reaper's first sweep")


def test_the_cold_reaper_never_sweeps_a_second_time(evict):
    """DEFECT CANDIDATE #18 — `brix_cache_reap_interval 1` is configured on
    this plane and does nothing for it.

    The first sweep above proves the reaper is armed and the horizon is
    honoured.  This one re-fills straight afterwards and watches for the whole
    of NO_SECOND_SWEEP: at the configured cadence that is ten sweeps' worth,
    and the object should be gone within one.  It survives, because
    `brix_cache_reap_handler` re-arms at the compiled-in
    BRIX_CACHE_REAP_INTERVAL_MS (hourly) and never reads the directive — which
    the watermark plane, wired to the same directive, does read.

    Invert this test when the cadence is fixed: the object should then be gone
    inside a second or two, and this assertion is what will say so."""
    endpoint, _store, cold = evict
    cold_port = endpoint.extra_ports["COLD_PORT"]
    name = NAMES[1]
    _fill(cold_port, name)
    wait_until(lambda: not _stored(cold, name), timeout=FIRST_SWEEP,
               what="the cold reaper's first sweep")

    assert _fill(cold_port, name) == OBJECTS[name]
    assert _stored(cold, name)
    time.sleep(NO_SECOND_SWEEP)
    assert _stored(cold, name), (
        "a second cold sweep ran within "
        f"{NO_SECOND_SWEEP}s — defect candidate #18 is fixed, invert this test")
