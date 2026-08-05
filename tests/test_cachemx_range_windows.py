"""Extended Range-window accuracy: byte-exact partial reads across window
shapes, planes, and both HTTP dialects (WebDAV + S3).

WHAT: A 2000-byte cached object read through every RFC-7233 window shape
      (prefix, mid, suffix, open tail, clamped overlap, full span), plus
      the degenerate forms (malformed, backwards, beyond-EOF) — asserting
      the exact byte count on the unified read ledger and the right
      result row (full / partial / unsatisfied) on the dialect's range
      family, on dav, davs, davsg, s3 and s3sig.

WHY:  Range arithmetic has per-shape edge cases (clamping at EOF, suffix
      longer than the object, ignored malformed headers).  A wrong clamp
      books phantom bytes; a wrong classification corrupts the range-result
      recording rules operators alarm on.
"""

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

IO = {"proto": "webdav"}
S3 = {"proto": "s3"}
SIZE = 2000


def snap(mx):
    return cx.Snap(mx.metrics)


@pytest.fixture(scope="module")
def davobj(mx):
    """One cached 2000-byte object for the WebDAV-side windows."""
    name = cx.unique_name("rwdav")
    payload = mx.seed_local(name, SIZE)
    assert mx.dav_request("dav", f"/{name}")[0] == 200
    cx.settle()
    return name, payload


@pytest.fixture(scope="module")
def s3obj(mx):
    """One cached 2000-byte object for the S3-side windows."""
    name = cx.unique_name("rws3")
    payload = mx.seed_local(name, SIZE)
    assert mx.s3_request("s3", name)[0] == 200
    cx.settle()
    return name, payload


# --------------------------------------------------------------------------
# dav window shapes — byte-exact
# --------------------------------------------------------------------------

@pytest.mark.parametrize("hdr,lo,n", [
    ("bytes=1-2", 1, 2),           # two bytes, off-origin start
    ("bytes=500-999", 500, 500),   # interior window
    ("bytes=1900-2100", 1900, 100),  # clamped at EOF
    ("bytes=-1", 1999, 1),         # one-byte suffix
    ("bytes=1999-", 1999, 1),      # one-byte open tail
    ("bytes=0-", 0, SIZE),         # open from zero = full span, still 206
])
def test_dav_window_byte_exact(mx, davobj, hdr, lo, n):
    """Each window is 206/partial and moves EXACTLY the window's bytes."""
    name, payload = davobj
    s = snap(mx)
    st, body, _ = mx.dav_request("dav", f"/{name}", headers={"Range": hdr})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 206
    assert body == payload[lo:lo + n]
    assert s.delta("brix_io_bytes_read", IO, after) == n
    assert s.delta("brix_webdav_range_requests_total", {"result": "partial"},
                   after) == 1


def test_dav_suffix_longer_than_object(mx, davobj):
    """A suffix window larger than the object serves the WHOLE object —
    the RFC clamp — and books exactly SIZE bytes."""
    name, payload = davobj
    s = snap(mx)
    st, body, _ = mx.dav_request("dav", f"/{name}",
                                 headers={"Range": "bytes=-5000"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 206 and body == payload
    assert s.delta("brix_io_bytes_read", IO, after) == SIZE
    assert s.delta("brix_webdav_range_requests_total", {"result": "partial"},
                   after) == 1


@pytest.mark.parametrize("hdr", ["bytes=abc", "bytes=500-100"])
def test_dav_malformed_range_serves_full(mx, davobj, hdr):
    """A syntactically invalid (or backwards) Range is IGNORED: 200, the
    full body, result="full", never "partial"."""
    name, payload = davobj
    s = snap(mx)
    st, body, _ = mx.dav_request("dav", f"/{name}", headers={"Range": hdr})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    assert s.delta("brix_io_bytes_read", IO, after) == SIZE
    assert s.delta("brix_webdav_range_requests_total", {"result": "full"},
                   after) == 1
    assert s.delta("brix_webdav_range_requests_total", {"result": "partial"},
                   after) == 0


def test_dav_advertises_accept_ranges(mx, davobj):
    """A 200 GET carries "Accept-Ranges: bytes" (regression pin: range
    handling lives fully in the module — the advertisement must survive
    the core range filter being disabled on this path)."""
    name, _ = davobj
    st, _, hdrs = mx.dav_request("dav", f"/{name}")
    assert st == 200
    low = {k.lower(): v for k, v in hdrs.items()}
    assert low.get("accept-ranges") == "bytes"


def test_dav_head_with_range_books_stat_only(mx, davobj):
    """HEAD answers a Range with 206 headers (mirroring what GET would
    return) but for ACCOUNTING it is pure metadata: one stat, ZERO read
    bytes, no range-result row."""
    name, _ = davobj
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{name}", method="HEAD",
                              headers={"Range": "bytes=0-99"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 206
    assert s.delta("brix_io_ops_total", {**IO, "op": "stat", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_bytes_read", IO, after) == 0
    assert s.delta("brix_webdav_range_requests_total", {"result": "partial"},
                   after) == 0


def test_dav_range_on_absent_object_404(mx):
    """Range on an absent name is a plain 404: not_found stat, no range
    row, zero bytes."""
    name = cx.unique_name("rwabs")
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{name}",
                              headers={"Range": "bytes=0-99"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 404
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "read", "status": "not_found"}, after) == 1
    assert s.delta("brix_webdav_range_requests_total", {"result": "partial"},
                   after) == 0
    assert s.delta("brix_io_bytes_read", IO, after) == 0


# --------------------------------------------------------------------------
# davs / davsg planes — the TLS paths share the window arithmetic
# --------------------------------------------------------------------------

@pytest.mark.parametrize("plane", ["davs", "davsg"])
def test_tls_plane_window_byte_exact(mx, davobj, plane):
    """A mid window over TLS books the same exact bytes as cleartext —
    the userspace-TLS output path must not skew the read ledger."""
    name, payload = davobj
    s = snap(mx)
    st, body, _ = mx.dav_request(plane, f"/{name}",
                                 headers={"Range": "bytes=100-349"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 206 and body == payload[100:350]
    assert s.delta("brix_io_bytes_read", IO, after) == 250
    assert s.delta("brix_webdav_range_requests_total", {"result": "partial"},
                   after) == 1


@pytest.mark.parametrize("plane", ["davs", "davsg"])
def test_tls_plane_beyond_eof_416(mx, davobj, plane):
    """Beyond-EOF over TLS: 416, unsatisfied row, zero bytes."""
    name, _ = davobj
    s = snap(mx)
    st, _, _ = mx.dav_request(plane, f"/{name}",
                              headers={"Range": "bytes=9000-9999"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 416
    assert s.delta("brix_webdav_range_requests_total",
                   {"result": "unsatisfied"}, after) == 1
    assert s.delta("brix_io_bytes_read", IO, after) == 0


# --------------------------------------------------------------------------
# s3 dialect — same shapes on the S3 range family
# --------------------------------------------------------------------------

@pytest.mark.parametrize("hdr,lo,n", [
    ("bytes=0-0", 0, 1),
    ("bytes=100-599", 100, 500),
    ("bytes=-100", 1900, 100),
    ("bytes=1500-", 1500, 500),
])
def test_s3_window_byte_exact(mx, s3obj, hdr, lo, n):
    """Each S3 window is 206/partial with exactly the window's bytes on
    the unified and s3 ledgers."""
    name, payload = s3obj
    s = snap(mx)
    st, body, _ = mx.s3_request("s3", name, headers={"Range": hdr})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 206
    assert body == payload[lo:lo + n]
    assert s.delta("brix_io_bytes_read", S3, after) == n
    assert s.delta("brix_s3_range_requests_total", {"result": "partial"},
                   after) == 1


def test_s3_beyond_eof_416_zero_bytes(mx, s3obj):
    """Beyond-EOF on s3: 416, unsatisfied row, read status="other",
    zero bytes."""
    name, _ = s3obj
    s = snap(mx)
    st, _, _ = mx.s3_request("s3", name,
                             headers={"Range": "bytes=8000-9000"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 416
    assert s.delta("brix_s3_range_requests_total", {"result": "unsatisfied"},
                   after) == 1
    assert s.delta("brix_io_bytes_read", S3, after) == 0


def test_s3_malformed_range_serves_full(mx, s3obj):
    """Malformed Range on s3 is ignored: 200, full body, result="full"."""
    name, payload = s3obj
    s = snap(mx)
    st, body, _ = mx.s3_request("s3", name, headers={"Range": "bytes=zz"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    assert s.delta("brix_io_bytes_read", S3, after) == SIZE
    assert s.delta("brix_s3_range_requests_total", {"result": "full"},
                   after) == 1


def test_s3_signed_window_byte_exact(mx, s3obj):
    """A SigV4-signed range GET books sigv4_ok AND the exact partial
    bytes — auth and range accounting compose."""
    name, payload = s3obj
    s = snap(mx)
    st, body, _ = mx.s3_request("s3sig", name,
                                headers={"Range": "bytes=250-749"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 206 and body == payload[250:750]
    assert s.delta("brix_io_bytes_read", S3, after) == 500
    assert s.delta("brix_s3_range_requests_total", {"result": "partial"},
                   after) == 1
    assert s.delta("brix_s3_auth_total", {"result": "sigv4_ok"}, after) == 1


def test_s3_range_on_absent_key_404(mx):
    """Range on an absent key: 404/NoSuchKey, no range row, zero bytes."""
    name = cx.unique_name("rws3abs")
    s = snap(mx)
    st, _, _ = mx.s3_request("s3", name, headers={"Range": "bytes=0-99"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 404
    assert s.delta("brix_io_ops_total",
                   {**S3, "op": "read", "status": "not_found"}, after) == 1
    assert s.delta("brix_s3_range_requests_total", {"result": "partial"},
                   after) == 0
    assert s.delta("brix_io_bytes_read", S3, after) == 0


def test_range_windows_are_linear(mx, davobj):
    """Three disjoint windows in sequence book cumulative EXACT bytes
    (10+20+30) and three partial rows — no cross-request smearing."""
    name, payload = davobj
    windows = [("bytes=0-9", 0, 10), ("bytes=40-59", 40, 20),
               ("bytes=100-129", 100, 30)]
    s = snap(mx)
    for hdr, lo, n in windows:
        st, body, _ = mx.dav_request("dav", f"/{name}",
                                     headers={"Range": hdr})
        assert st == 206 and body == payload[lo:lo + n]
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_bytes_read", IO, after) == 60
    assert s.delta("brix_webdav_range_requests_total", {"result": "partial"},
                   after) == 3
