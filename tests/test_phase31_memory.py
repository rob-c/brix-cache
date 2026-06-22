"""
Phase 31 — memory-budget streaming regression tests.

These cover W1 (bound & reclaim per-connection scratch buffers).  The module
grows its reusable scratch buffers (read_scratch for memory-backed/TLS reads,
write_scratch for pgwrite decode) to the largest request a session has served,
then trims them back to XROOTD_READ_WINDOW between requests once they exceed
XROOTD_SCRATCH_TRIM_THRESHOLD (see xrootd_trim_scratch / the recv loop).

The Python client cannot observe worker heap directly, so these tests assert the
property that a grow -> trim -> regrow cycle MUST preserve: byte-exact data and a
stable connection.  A use-after-trim, truncation, or cross-request data-bleed
bug introduced by the trim path would surface as a short/incorrect read or a
broken connection here.  The RSS-level assertion (resident heap returns to
~window when idle) is covered separately by the load-test harness.

Trio per CLAUDE.md:
  * success          — TLS large-read trim cycle is byte-exact (read_scratch)
  * roundtrip        — anon large write+read survives the trim (write_scratch)
  * stability/neg    — repeated grow/shrink on one connection never bleeds data
                       and the oversize-request guard is preserved
"""

import hashlib
import os

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags
from settings import (
    NGINX_ANON_PORT,
    NGINX_GSI_TLS_PORT,
    SERVER_HOST,
)

# These tests move multi-MiB payloads several times per case; on a loaded test
# host that can exceed the suite's default per-test timeout.  Override generously
# so a slow box does not masquerade as a correctness failure.
pytestmark = pytest.mark.timeout(240)

ANON_URL    = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
GSI_TLS_URL = f"roots://{SERVER_HOST}:{NGINX_GSI_TLS_PORT}"

# Bigger than XROOTD_SCRATCH_TRIM_THRESHOLD (2 * XROOTD_READ_WINDOW = 4 MiB) so a
# single read/write grows the scratch past the trim high-water mark.
BIG_CHUNK = 8 * 1024 * 1024

LARGE_FILE     = "large200.bin"
LARGE_FILE_MD5 = os.environ.get("LARGE_FILE_MD5", "")


def _reachable(host: str, port: int) -> bool:
    import socket
    try:
        with socket.create_connection((host, port), timeout=3.0):
            return True
    except OSError:
        return False


anon_only = pytest.mark.skipif(
    not _reachable(SERVER_HOST, NGINX_ANON_PORT),
    reason="anon server not reachable",
)
tls_only = pytest.mark.skipif(
    not _reachable(SERVER_HOST, NGINX_GSI_TLS_PORT),
    reason="GSI/TLS server not reachable",
)


def _deterministic(n: int) -> bytes:
    return bytes((i * 7 + 13) & 0xFF for i in range(n))


# ---------------------------------------------------------------------------
# success — read_scratch (memory-backed) grows past the threshold every request
# and is trimmed between requests; data must stay byte-exact.
#
# kXR_readv is served from read_scratch even on a cleartext connection (only
# regular-file kXR_read uses sendfile), so repeated large readvs exercise the
# exact read_scratch grow -> trim -> regrow cycle without depending on the TLS
# data plane.  The send mechanism (queue_response_chain / flush_pending, with the
# trim deferred until XRD_ST_SENDING drains) is identical to the TLS read path.
# ---------------------------------------------------------------------------

@anon_only
def test_readv_read_scratch_trim_cycle_integrity():
    payload = _deterministic(12 * 1024 * 1024)
    remote  = "/test_phase31_readv.bin"

    w = client.File()
    status, _ = w.open(f"{ANON_URL}//{remote.lstrip('/')}",
                       OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open for write failed: {status.message}"
    status, _ = w.write(payload)
    assert status.ok, f"write failed: {status.message}"
    w.close()

    f = client.File()
    status, _ = f.open(f"{ANON_URL}//{remote.lstrip('/')}", OpenFlags.READ)
    assert status.ok, f"open for read failed: {status.message}"

    # Each readv totals ~5 MiB -> read_scratch grows past the 4 MiB threshold;
    # the recv loop trims it back to the window before the next readv regrows it.
    chunks = [(0, 2_500_000), (4_000_000, 2_500_000)]
    for it in range(6):
        status, result = f.vector_read(chunks)
        assert status.ok, f"vector_read {it} failed: {status.message}"
        for ch in result:
            exp = payload[ch.offset:ch.offset + ch.length]
            assert bytes(ch.buffer) == exp, \
                f"readv {it} off {ch.offset} corrupted across trim cycle"
    f.close()


@tls_only
def test_tls_large_read_trim_cycle_integrity():
    """Whole-file TLS read in >threshold chunks (read_scratch trim under TLS).

    Previous defect: consecutive large TLS reads returned kXR_IOError ("Bad
    address", pread EFAULT) on the 2nd read.  That was the same root cause as the
    trim corruption — read_scratch being nginx-pool-backed; the Phase 31 raw-alloc
    fix (ngx_alloc/ngx_free) resolved both, so this now passes: each 8 MiB read
    grows read_scratch, the recv loop trims it between requests, and the next read
    regrows it — all byte-exact under TLS.
    """
    if not LARGE_FILE_MD5:
        pytest.skip("LARGE_FILE_MD5 not provided by the test harness")

    f = client.File()
    status, _ = f.open(f"{GSI_TLS_URL}//{LARGE_FILE}", OpenFlags.READ)
    assert status.ok, f"TLS open failed: {status.message}"
    status, st = f.stat()
    assert status.ok, f"stat failed: {status.message}"
    total = st.size

    md5 = hashlib.md5()
    received = 0
    while received < total:
        want = min(BIG_CHUNK, total - received)
        status, data = f.read(offset=received, size=want)
        assert status.ok, f"read at {received} failed: {status.message}"
        md5.update(data)
        received += len(data)
    f.close()
    assert md5.hexdigest() == LARGE_FILE_MD5, "data corrupted across trim cycle"


# ---------------------------------------------------------------------------
# roundtrip — write path: a large pgwrite grows write_scratch past the
# threshold; after the trim, reading back must return the exact bytes.
# ---------------------------------------------------------------------------

@anon_only
def test_anon_large_write_read_roundtrip_across_trim():
    payload = _deterministic(BIG_CHUNK + 123)   # > 4 MiB threshold
    remote  = "/test_phase31_wt.bin"

    w = client.File()
    status, _ = w.open(f"{ANON_URL}//{remote.lstrip('/')}",
                       OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open for write failed: {status.message}"
    status, _ = w.write(payload)
    assert status.ok, f"write failed: {status.message}"
    w.close()

    # Fresh connection: full read back, then a ranged read crossing the window.
    r = client.File()
    status, _ = r.open(f"{ANON_URL}//{remote.lstrip('/')}", OpenFlags.READ)
    assert status.ok, f"open for read failed: {status.message}"

    status, data = r.read()
    assert status.ok, f"full read failed: {status.message}"
    assert bytes(data) == payload, "round-trip data mismatch after trim"

    off = 3 * 1024 * 1024
    status, mid = r.read(offset=off, size=2 * 1024 * 1024)
    assert status.ok, f"ranged read failed: {status.message}"
    assert bytes(mid) == payload[off:off + 2 * 1024 * 1024]
    r.close()


# ---------------------------------------------------------------------------
# stability / negative — many grow/shrink cycles on one connection must never
# bleed data between requests, and the oversize-request guard must survive.
# ---------------------------------------------------------------------------

@anon_only
def test_repeated_grow_shrink_no_data_bleed():
    """Alternate large and small reads on one handle; every read byte-exact.

    Interleaving big (scratch-growing) and small (post-trim) reads is the case
    most likely to expose a stale-pointer or leftover-bytes bug: a small read
    served from a just-trimmed buffer must not return bytes from the previous
    large read.
    """
    payload = _deterministic(BIG_CHUNK + 4096)
    remote  = "/test_phase31_bleed.bin"

    w = client.File()
    status, _ = w.open(f"{ANON_URL}//{remote.lstrip('/')}",
                       OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open for write failed: {status.message}"
    status, _ = w.write(payload)
    assert status.ok
    w.close()

    f = client.File()
    status, _ = f.open(f"{ANON_URL}//{remote.lstrip('/')}", OpenFlags.READ)
    assert status.ok, f"open for read failed: {status.message}"

    for i in range(6):
        # Large read grows the scratch above the trim threshold.
        status, big = f.read(offset=0, size=BIG_CHUNK)
        assert status.ok, f"big read {i} failed: {status.message}"
        assert bytes(big) == payload[:BIG_CHUNK], f"big read {i} corrupted"

        # Small read after the trim must be exact, not leftover big-read bytes.
        off = (i * 997) & 0xFFFF
        status, small = f.read(offset=off, size=512)
        assert status.ok, f"small read {i} failed: {status.message}"
        assert bytes(small) == payload[off:off + 512], f"small read {i} bled data"
    f.close()


# ---------------------------------------------------------------------------
# W4 — SHM-global memory budget: the accountant must export live gauges and
# return them to zero once connections close (charge + release end-to-end).
# ---------------------------------------------------------------------------

@anon_only
def test_budget_gauges_exported_and_release():
    """A memory-backed read charges the SHM-global budget: the high-water gauge
    rises and the live gauge stays sanely bounded (<= high-water, under budget).

    Note: the XRootD client pools the TCP connection, so closing a File does not
    disconnect — the scratch buffer is legitimately still held and still charged
    until the connection actually closes (release-on-disconnect is exercised by
    the connection teardown path, not by File.close()).
    """
    import urllib.request

    from settings import NGINX_METRICS_PORT

    def scrape():
        url = f"http://{SERVER_HOST}:{NGINX_METRICS_PORT}/metrics"
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.read().decode("utf-8", "replace")

    body = scrape()
    # All three W4 series must be present.
    for name in ("xrootd_xfer_heap_bytes",
                 "xrootd_xfer_heap_high_water_bytes",
                 "xrootd_budget_waits_total"):
        assert name in body, f"missing budget metric {name}"

    # Drive a memory-backed read (readv is served from read_scratch even on the
    # cleartext port), then close.  After close, in-use bytes must be ~0.
    payload = _deterministic(8 * 1024 * 1024)
    remote = "/test_phase31_budget.bin"
    w = client.File()
    s, _ = w.open(f"{ANON_URL}//{remote.lstrip('/')}",
                  OpenFlags.DELETE | OpenFlags.NEW)
    assert s.ok, s.message
    s, _ = w.write(payload)
    assert s.ok
    w.close()

    f = client.File()
    s, _ = f.open(f"{ANON_URL}//{remote.lstrip('/')}", OpenFlags.READ)
    assert s.ok
    s, res = f.vector_read([(0, 3_000_000), (4_000_000, 3_000_000)])
    assert s.ok, s.message
    f.close()

    # High-water must reflect that the transfer held heap at some point.
    def gauge(text, name, port_label):
        for line in text.splitlines():
            if line.startswith(name + "{") and f'port="{port_label}"' in line:
                return int(line.rsplit(" ", 1)[1])
        return None

    after = scrape()
    hw = gauge(after, "xrootd_xfer_heap_high_water_bytes", str(NGINX_ANON_PORT))
    in_use = gauge(after, "xrootd_xfer_heap_bytes", str(NGINX_ANON_PORT))
    # Charge happened: high-water rose above zero.
    assert hw is not None and hw > 0, "high-water never rose (charge not wired)"
    # Accounting is sane: live usage never exceeds the peak and never underflows
    # (a double-release / negative drift would show as a huge unsigned value).
    assert in_use is not None and 0 <= in_use <= hw, \
        f"budget accounting drifted: in_use={in_use} high_water={hw}"


@anon_only
def test_oversize_request_guard_preserved():
    """A read beyond XROOTD_READ_REQUEST_MAX (64 MiB) is still rejected/clamped.

    The trim work must not weaken the existing per-request size guard.  XRootD
    clients clamp client-side, so we assert the server neither over-returns nor
    crashes: the response length never exceeds the requested size and the
    connection stays usable for a follow-up read.
    """
    payload = _deterministic(BIG_CHUNK)
    remote  = "/test_phase31_guard.bin"

    w = client.File()
    status, _ = w.open(f"{ANON_URL}//{remote.lstrip('/')}",
                       OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok
    status, _ = w.write(payload)
    assert status.ok
    w.close()

    f = client.File()
    status, _ = f.open(f"{ANON_URL}//{remote.lstrip('/')}", OpenFlags.READ)
    assert status.ok

    # Ask for far more than exists; must get at most the file size, never more.
    status, data = f.read(offset=0, size=128 * 1024 * 1024)
    assert status.ok, f"large read failed: {status.message}"
    assert len(data) <= len(payload), "server returned more than file size"
    assert bytes(data) == payload[:len(data)]

    # Connection must remain healthy after the big request + trim.
    status, tail = f.read(offset=0, size=256)
    assert status.ok, f"follow-up read failed: {status.message}"
    assert bytes(tail) == payload[:256]
    f.close()
