"""S3 metric-accuracy conformance across the anonymous and SigV4 planes.

WHAT: Exact op/byte assertions for GET/PUT/DELETE/404 on both planes, plus
      the Bug-D regression set: the SigV4 verification pipeline must stop at
      the FIRST verdict — each failure mode moves exactly its own auth-result
      label and no other (before the fix, s3_send_xml_error returned NGX_OK
      from the output filter and the pipeline kept evaluating, stacking
      several failure labels per request).

WHY:  Auth-failure counters feed abuse detection; a single probe request
      that books two or three failure labels makes rate-based alerting lie.

The S3 planes share the local-posix cache instance with the WebDAV planes,
so every test uses a unique object key.
"""

import os

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401
from settings import HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

AUTH_RESULTS = ("anonymous", "sigv4_ok", "missing", "malformed",
                "bad_access_key", "bad_date", "signature_mismatch",
                "internal_error")


def snap(mx):
    return cx.Snap(mx.metrics)


def assert_auth_singular(s, after, want: str, count: int = 1):
    """Exactly `want` moved (by `count`); every other result label is 0."""
    for result in AUTH_RESULTS:
        got = s.delta("brix_s3_auth_total", {"result": result}, after)
        expect = count if result == want else 0
        assert got == expect, (
            f"result={result}: {got} (expected {expect}) — the verification "
            f"pipeline must book exactly one verdict per request")


def bad_sig_headers(mx, key):
    """Well-formed SigV4 headers computed with the WRONG secret."""
    good = cx.S3_SECRET_KEY
    cx.S3_SECRET_KEY = "wrong-secret"
    try:
        return cx.sigv4_headers("GET", HOST, mx.port("S3_SIG_PORT"),
                                f"/{cx.S3_BUCKET}/{key}")
    finally:
        cx.S3_SECRET_KEY = good


def seed(mx, tag, size):
    name = cx.unique_name(tag)
    payload = mx.seed_local(name, size)
    return name, payload


def cached_copies(mx, name):
    return [p for p in mx.cache_root.rglob(name) if p.is_file()]


# --------------------------------------------------------------------------
# Read path — both planes
# --------------------------------------------------------------------------

def test_anon_get_counts_once(mx):
    """Anonymous GET: one read + one xattr op, one `anonymous` auth verdict,
    exact payload bytes, one 2xx GET row, one full-range classification."""
    name, payload = seed(mx, "s3get", 3100)
    s = snap(mx)
    st, body, _ = mx.s3_request("s3", name)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    io = {"proto": "s3"}
    assert s.delta("brix_io_ops_total", {**io, "op": "read", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_ops_total", {**io, "op": "xattr", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_bytes_read", io, after) == 3100
    assert_auth_singular(s, after, "anonymous")
    assert s.delta("brix_s3_responses_total",
                   {"method": "GET", "status_class": "2xx"}, after) == 1
    assert s.delta("brix_s3_range_requests_total", {"result": "full"},
                   after) == 1
    assert s.delta("brix_io_latency_usec_count", {**io, "op": "read"},
                   after) == 1


def test_signed_get_books_sigv4_ok_exactly(mx):
    """Bug D success case: a correctly signed GET books sigv4_ok exactly
    once and NO failure label."""
    name, payload = seed(mx, "s3sget", 2048)
    s = snap(mx)
    st, body, _ = mx.s3_request("s3sig", name)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    assert_auth_singular(s, after, "sigv4_ok")
    assert s.delta("brix_io_ops_total",
                   {"proto": "s3", "op": "read", "status": "ok"}, after) == 1


def test_get_miss_then_hit(mx):
    """First S3 touch of a name is one s3 miss; the re-GET is one hit."""
    name, payload = seed(mx, "s3mh", 1800)
    s = snap(mx)
    st, _, _ = mx.s3_request("s3", name)
    cx.settle()
    mid = cx.mfetch(mx.metrics)
    assert st == 200
    assert s.delta("brix_cache_misses_total", {"proto": "s3"}, mid) == 1
    assert s.delta("brix_cache_hits_total", {"proto": "s3"}, mid) == 0
    s2 = snap(mx)
    st2, body2, _ = mx.s3_request("s3", name)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st2 == 200 and body2 == payload
    assert s2.delta("brix_cache_hits_total", {"proto": "s3"}, after) == 1
    assert s2.delta("brix_cache_misses_total", {"proto": "s3"}, after) == 0


def test_get_absent_nosuchkey(mx):
    """404: NoSuchKey XML error document, one not_found read, one GET 4xx
    row, one no_such_key event — and no ok-status read."""
    s = snap(mx)
    st, body, _ = mx.s3_request("s3", cx.unique_name("s3ghost"))
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 404
    assert b"<Code>NoSuchKey</Code>" in body
    assert s.delta("brix_io_ops_total",
                   {"proto": "s3", "op": "read", "status": "not_found"},
                   after) == 1
    assert s.delta("brix_io_ops_total",
                   {"proto": "s3", "op": "read", "status": "ok"}, after) == 0
    assert s.delta("brix_s3_responses_total",
                   {"method": "GET", "status_class": "4xx"}, after) == 1
    assert s.delta("brix_s3_events_total", {"event": "no_such_key"},
                   after) == 1


# --------------------------------------------------------------------------
# Write path
# --------------------------------------------------------------------------

@pytest.mark.parametrize("plane", sorted(cx.S3_PLANES))
def test_put_exact_accounting(mx, plane):
    """PUT: one write op, exact written bytes, one in-memory body, one 2xx
    PUT row, one write-latency observation, object bytes exact on disk."""
    size = 2222 if plane == "s3sig" else 1111
    name = cx.unique_name(f"{plane}put")
    payload = os.urandom(size)
    s = snap(mx)
    st, _, _ = mx.s3_request(plane, name, method="PUT", data=payload)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200
    assert (mx.local_data / name).read_bytes() == payload
    io = {"proto": "s3"}
    assert s.delta("brix_io_ops_total", {**io, "op": "write", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_bytes_written", io, after) == size
    assert s.delta("brix_s3_put_bodies_total", {"mode": "memory"},
                   after) == 1
    assert s.delta("brix_s3_responses_total",
                   {"method": "PUT", "status_class": "2xx"}, after) == 1
    assert s.delta("brix_io_latency_usec_count", {**io, "op": "write"},
                   after) == 1


def test_delete_cached_evicts_exact(mx):
    """Signed DELETE of a cached object: one delete op, one 2xx DELETE row,
    the exact cached bytes accounted as evicted, gone from disk and cache."""
    size = 2500
    name, _ = seed(mx, "s3del", size)
    st, _, _ = mx.s3_request("s3sig", name)      # prime the cache
    assert st == 200
    cx.settle()
    assert cached_copies(mx, name)
    s = snap(mx)
    st, _, _ = mx.s3_request("s3sig", name, method="DELETE")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 204
    assert s.delta("brix_io_ops_total",
                   {"proto": "s3", "op": "delete", "status": "ok"},
                   after) == 1
    assert s.delta("brix_s3_responses_total",
                   {"method": "DELETE", "status_class": "2xx"}, after) == 1
    assert s.delta("brix_cache_bytes_evicted_total", {"proto": "s3"},
                   after) == size
    assert not (mx.local_data / name).exists()
    assert not cached_copies(mx, name)


# --------------------------------------------------------------------------
# Bug D — one verdict per request, all four failure modes
# --------------------------------------------------------------------------

def _assert_denied(mx, s, after, verdict):
    assert_auth_singular(s, after, verdict)
    assert s.delta("brix_io_ops_total",
                   {"proto": "s3", "op": "read", "status": "forbidden"},
                   after) == 1
    assert s.delta("brix_io_ops_total",
                   {"proto": "s3", "op": "read", "status": "ok"}, after) == 0
    assert s.delta("brix_io_bytes_read", {"proto": "s3"}, after) == 0


def test_unsigned_get_books_missing_only(mx):
    """No Authorization header on the SigV4 plane: 403, `missing` exactly
    once, no other verdict, no payload served."""
    name, _ = seed(mx, "s3miss", 1024)
    s = snap(mx)
    st, _, _ = mx.s3_request("s3sig", name, signed=False)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 403
    _assert_denied(mx, s, after, "missing")


def test_garbage_auth_books_malformed_only(mx):
    """Unparseable Authorization header: 403, `malformed` exactly once."""
    name, _ = seed(mx, "s3mal", 1024)
    s = snap(mx)
    st, _, _ = cx.http_request(
        mx.s3_url("s3sig", name),
        headers={"Authorization": "AWS4-HMAC-SHA256 garbage"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 403
    _assert_denied(mx, s, after, "malformed")


def test_wrong_secret_books_signature_mismatch_only(mx):
    """Well-formed signature computed with the wrong secret: 403,
    `signature_mismatch` exactly once — NOT also missing/malformed (the
    pre-fix pipeline kept evaluating after the first verdict)."""
    name, _ = seed(mx, "s3sig", 1024)
    s = snap(mx)
    st, _, _ = cx.http_request(mx.s3_url("s3sig", name),
                               headers=bad_sig_headers(mx, name))
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 403
    _assert_denied(mx, s, after, "signature_mismatch")


def test_stale_date_books_bad_date_only(mx):
    """Stale x-amz-date outside the clock-skew window: 403, `bad_date`
    exactly once — the date verdict must not cascade into a signature
    verdict for the same request."""
    name, _ = seed(mx, "s3date", 1024)
    hdrs = cx.sigv4_headers("GET", HOST, mx.port("S3_SIG_PORT"),
                            f"/{cx.S3_BUCKET}/{name}")
    hdrs["x-amz-date"] = "20200101T000000Z"
    s = snap(mx)
    st, _, _ = cx.http_request(mx.s3_url("s3sig", name), headers=hdrs)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 403
    _assert_denied(mx, s, after, "bad_date")


def test_denied_requests_still_book_response_rows(mx):
    """Each 403 also books its GET 4xx response row — three probes, three
    rows, three forbidden reads (rate-based alerting depends on 1:1)."""
    name, _ = seed(mx, "s3rate", 512)
    s = snap(mx)
    for _ in range(3):
        st, _, _ = mx.s3_request("s3sig", name, signed=False)
        assert st == 403
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_s3_responses_total",
                   {"method": "GET", "status_class": "4xx"}, after) == 3
    assert s.delta("brix_io_ops_total",
                   {"proto": "s3", "op": "read", "status": "forbidden"},
                   after) == 3
    assert_auth_singular(s, after, "missing", count=3)
