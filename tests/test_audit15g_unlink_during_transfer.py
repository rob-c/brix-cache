"""
test_audit15g_unlink_during_transfer.py — the object disappears under an open
handle (audit §C, carried unchanged from the 2026-08-04 pass: "unlink during
active transfer (no test)").

Every mid-transfer test the suite already has removes the SERVER — a reload, a
worker kill, a failover leg — and all of them are posix.  Nothing removes the
OBJECT.  That is a different question with a different answer at each layer,
which is why this file drives two planes:

  * a plain posix export, where the removal is of the exported file itself; and
  * a read-cache tier over a root:// origin, where the removal is of the CACHED
    COPY while the origin still holds the truth.

The success cases are not the interesting part — POSIX keeps an unlinked inode
alive for whoever holds it open, so a correct server simply finishes.  The
interesting part is the pair of failures that would be invisible without an
explicit length assertion:

  * a SHORT read reported as a complete one.  The client cannot tell the
    difference; a transfer that silently ends early and exits 0 is the single
    worst outcome in this whole area, so every assertion here checks the byte
    count as well as the status.
  * a PATH SWAP.  Unlink is not the only way to make a path stop meaning what
    it meant at open time — replacing it is the sharper version, and a server
    that re-resolved the path per read would hand the client the attacker's
    bytes in the middle of somebody else's transfer.  Pinned as the security
    negative on the direct plane.

Cases:
  * success      — a clean read through the export is byte-exact (control)
  * success      — unlinking the object mid-read still delivers every byte
  * error        — ... and the next opener is refused with kXR "file not found"
  * security-neg — a path REPLACED mid-read never leaks the replacement's bytes
                   into the open handle
  * success      — the tier fills its store, and dropping the cached copy
                   mid-read still delivers every byte
  * success      — after that drop the next opener is served again, re-filled
                   from the origin (proof the store copy really was gone)
  * security-neg — with the origin stopped as well, the next opener is refused
                   outright rather than served whatever survived in the store,
                   and refused as kXR_IOError — never as kXR_NotFound, which a
                   grid client is entitled to act on destructively
"""

import os

import pytest

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, BIND_HOST
from _test_audit15g_helpers import (ReadHandle, XERR_IO_ERROR, XERR_NOT_FOUND,
                                    open_fails, pattern, read_whole, seed_tree)

# One group for BOTH audit15g mid-transfer files, named for the instance that
# forces it: they share the single fixed-port `lc-audit15g-mtorigin` ledger
# entry (fleet_ports_shared_phase5_b.py), and a fixed-port instance may have
# exactly ONE driver at a time (server_launcher_part3.LifecycleHarness.register).
# In separate groups --dist=loadgroup put the two files on different workers,
# where each fixture's origin start/stop clobbered the other's: the unlink
# plane read /cached/obj.bin off the evict file's origin (kXR 3011 file not
# found) and the evict plane filled from an origin that had just been stopped
# underneath it (kXR 3007 cache fill from source failed).
pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15g-mtorigin")]

# Big enough that a first chunk leaves real work outstanding, small enough that
# every test in the file stays well inside the per-test timeout.
SIZE = 512 * 1024
CHUNK = 64 * 1024

DIRECT = "/direct/obj.bin"
CACHED = "/cached/obj.bin"
SPARE = "/cached/spare.bin"

DIRECT_BLOB = pattern(SIZE, 7)
CACHED_BLOB = pattern(SIZE, 11)
SPARE_BLOB = pattern(SIZE, 13)
# Deliberately a different length AND a marker rather than another `pattern()`:
# consecutive pattern bytes always differ by 131 (mod 256), so a salted pattern
# is a rotation of every other one and its prefix legitimately occurs inside
# them — a useless witness.  No two adjacent bytes of this marker differ by 131,
# so any occurrence of it really is the decoy's bytes.
DECOY_BLOB = (b"DECOY-audit15g!" * (SIZE // 2 // 15 + 1))[:SIZE // 2]


@pytest.fixture
def planes(lifecycle, tmp_path):
    """The origin instance plus the two-plane server in front of it, with both
    trees seeded.  Returns (endpoint, direct_export, cache_store, origin)."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    origin_root = tmp_path / "origin"
    direct_export = tmp_path / "direct-export"
    cache_export = tmp_path / "cache-export"
    cache_store = tmp_path / "cache-store"
    for path in (origin_root, direct_export, cache_export, cache_store):
        path.mkdir()
    seed_tree(origin_root, {CACHED: CACHED_BLOB, SPARE: SPARE_BLOB})
    seed_tree(direct_export, {DIRECT: DIRECT_BLOB})
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
        reason="audit-15g mid-transfer origin"))

    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15g-unlink",
        template="nginx_audit15g_unlink.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(direct_export),
        template_values={
            "BIND_HOST": BIND_HOST,
            "ORIGIN_PORT": str(origin.port),
            "DIRECT_EXPORT": str(direct_export),
            "CACHE_EXPORT": str(cache_export),
            "CACHE_STORE": str(cache_store)},
        reason="audit-15g unlink during an active transfer"))
    return endpoint, direct_export, cache_store, origin


def _drain(handle, start, size, chunk=CHUNK):
    """Read [start, size) through an already-open handle, chunk by chunk."""
    out = b""
    while start + len(out) < size:
        out += handle.read(start + len(out), min(chunk, size - start - len(out)))
    return out


def _stored(store, path):
    """True iff the tier laid the object down: the store key is the request
    path without its leading slash (cstore.c)."""
    return os.path.exists(os.path.join(str(store), path.lstrip("/")))


# --------------------------------------------------------------------------- #
# Plane 1 — a plain posix export.                                             #
# --------------------------------------------------------------------------- #
def test_a_clean_read_through_the_export_is_byte_exact(planes):
    """success (control): with nothing removed, the export serves the whole
    object.  Every damaged twin below is compared against this."""
    endpoint, _direct, _store, _origin = planes
    assert read_whole(endpoint.port, DIRECT, SIZE) == DIRECT_BLOB


def test_unlinking_the_object_mid_read_still_delivers_every_byte(planes):
    """success: the handle was opened before the unlink, so the inode outlives
    the name and the transfer must finish complete and byte-exact."""
    endpoint, direct, _store, _origin = planes
    with ReadHandle(endpoint.port, DIRECT) as handle:
        head = handle.read(0, CHUNK)
        os.unlink(os.path.join(str(direct), DIRECT.lstrip("/")))
        tail = _drain(handle, CHUNK, SIZE)
    assert len(head) + len(tail) == SIZE, (len(head), len(tail))
    assert head + tail == DIRECT_BLOB


def test_the_unlinked_object_is_gone_for_the_next_opener(planes):
    """error: the namespace half.  The surviving inode belongs to the handle
    that held it, not to the path — a later open must be refused, and refused
    as "not found" rather than as some other failure."""
    endpoint, direct, _store, _origin = planes
    with ReadHandle(endpoint.port, DIRECT) as handle:
        handle.read(0, CHUNK)
        os.unlink(os.path.join(str(direct), DIRECT.lstrip("/")))
        assert open_fails(endpoint.port, DIRECT) == XERR_NOT_FOUND


def test_a_path_replaced_mid_read_never_leaks_the_replacement(planes):
    """security-negative: unlink is the blunt version of this fault; replacing
    the path is the sharp one.  A server that re-resolved the path per read —
    rather than serving the handle it opened — would splice the replacement's
    bytes into a transfer already in flight, and the client would have no way
    to notice.  The decoy is both shorter and differently patterned, so either
    kind of leak shows up."""
    endpoint, direct, _store, _origin = planes
    target = os.path.join(str(direct), DIRECT.lstrip("/"))
    with ReadHandle(endpoint.port, DIRECT) as handle:
        head = handle.read(0, CHUNK)
        os.unlink(target)
        with open(target, "wb") as fh:
            fh.write(DECOY_BLOB)
        os.chmod(target, 0o644)
        tail = _drain(handle, CHUNK, SIZE)
    assert head + tail == DIRECT_BLOB, "the open handle served swapped content"
    assert DECOY_BLOB[:64] not in head + tail


# --------------------------------------------------------------------------- #
# Plane 2 — the cached copy vanishes while the origin still has the object.   #
# --------------------------------------------------------------------------- #
def test_dropping_the_cached_copy_mid_read_still_delivers_every_byte(planes):
    """success: the tier filled its store, and the store copy is removed with
    the read half-done.  Whether the rest arrives from the surviving inode or
    from a re-fetch is the server's business; delivering all of it is not."""
    endpoint, _direct, store, _origin = planes
    cache_port = endpoint.extra_ports["CACHE_PORT"]
    assert read_whole(cache_port, CACHED, SIZE) == CACHED_BLOB
    assert _stored(store, CACHED), "the tier never filled its store"

    with ReadHandle(cache_port, CACHED) as handle:
        head = handle.read(0, CHUNK)
        os.unlink(os.path.join(str(store), CACHED.lstrip("/")))
        tail = _drain(handle, CHUNK, SIZE)
    assert len(head) + len(tail) == SIZE, (len(head), len(tail))
    assert head + tail == CACHED_BLOB


def test_the_dropped_cached_copy_is_refilled_for_the_next_opener(planes):
    """success: the origin is still up, so the next open re-fills.  This is
    also the non-vacuity proof for the test above — the store copy really was
    gone, because the tier had to lay it down again."""
    endpoint, _direct, store, _origin = planes
    cache_port = endpoint.extra_ports["CACHE_PORT"]
    read_whole(cache_port, CACHED, SIZE)
    os.unlink(os.path.join(str(store), CACHED.lstrip("/")))
    assert not _stored(store, CACHED)

    assert read_whole(cache_port, CACHED, SIZE) == CACHED_BLOB
    assert _stored(store, CACHED), "the tier did not re-fill after the drop"


def test_with_the_origin_gone_a_dropped_copy_is_refused_not_truncated(
        planes, lifecycle):
    """security-negative: the store copy is removed mid-read AND the origin is
    stopped, so nothing anywhere still holds a complete copy by name.  The
    in-flight handle finishes anyway (it holds the inode), and the NEXT opener
    must be refused rather than served whatever the store had — a short read
    carrying a success status is downstream indistinguishable from a complete
    transfer forever after.

    The refusal code is pinned, not just its existence: an unreachable origin
    is an I/O error, and kXR_NotFound is the one answer that must NOT come back
    here, because a grid client is entitled to act on "the file does not exist"
    destructively.  (The http:// origin path is held to the same line in
    test_audit15g_sd_http_deadline.py, where a 404 — and only a 404 — is
    allowed to become kXR_NotFound.)"""
    endpoint, _direct, store, _origin = planes
    cache_port = endpoint.extra_ports["CACHE_PORT"]
    read_whole(cache_port, SPARE, SIZE)

    with ReadHandle(cache_port, SPARE) as handle:
        head = handle.read(0, CHUNK)
        os.unlink(os.path.join(str(store), SPARE.lstrip("/")))
        lifecycle.stop("lc-audit15g-mtorigin")
        tail, errcode = handle.try_read(CHUNK, SIZE - CHUNK)

    assert errcode == 0, f"the in-flight handle lost its own inode ({errcode})"
    assert head + tail == SPARE_BLOB, "short read reported as a success"

    later, errcode = _try_open_read(cache_port, SPARE, SIZE)
    assert errcode == XERR_IO_ERROR, (errcode, len(later))
    assert errcode != XERR_NOT_FOUND, "an unreachable origin reported as absent"


def _try_open_read(port, path, size):
    """(bytes, errcode) for a whole-object read that is allowed to fail."""
    try:
        handle = ReadHandle(port, path)
    except AssertionError as exc:
        return b"", getattr(exc, "errcode", -1)
    try:
        out = b""
        while len(out) < size:
            chunk, errcode = handle.try_read(len(out), min(CHUNK, size - len(out)))
            if errcode:
                return out, errcode
            out += chunk
        return out, 0
    finally:
        handle.close()
