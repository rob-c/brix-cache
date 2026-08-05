"""Namespace + metadata method accounting: MKCOL, HEAD, PROPFIND, DELETE,
OPTIONS, Range windows, and the s3/stream namespace edges.

WHAT: Exact ledger deltas for every namespace-touching method's success AND
      error arms, byte-exact Range window accounting on a cached object,
      PROPFIND entry counting against a private directory of known size, and
      the s3 HEAD/LIST/DELETE cluster.

WHY:  These are the low-traffic methods where accounting bugs hide — a
      wrong status bucket on MKCOL-over-existing or a phantom delete row on
      DELETE-absent never shows up in throughput dashboards, only in a
      conformance pin.  All deltas calibrated live against the matrix stack.
"""

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

IO = {"proto": "webdav"}
S3 = {"proto": "s3"}


def snap(mx):
    return cx.Snap(mx.metrics)


# --------------------------------------------------------------------------
# MKCOL
# --------------------------------------------------------------------------

def test_mkcol_created_full_ledger(mx):
    """MKCOL of a fresh collection: 201, one mkdir op with latency, one
    MKCOL request row and one 2xx response row."""
    d = cx.unique_name("nsdir").replace(".bin", "")
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{d}", method="MKCOL")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 201
    assert s.delta("brix_io_ops_total", {**IO, "op": "mkdir", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_latency_usec_count", {**IO, "op": "mkdir"},
                   after) == 1
    assert s.delta("brix_webdav_requests_total", {"method": "MKCOL"},
                   after) == 1
    assert s.delta("brix_webdav_responses_total",
                   {"method": "MKCOL", "status_class": "2xx"}, after) == 1


def test_mkcol_existing_405_books_other_status(mx):
    """MKCOL over an existing collection: 405, the mkdir op lands in the
    status="other" bucket (EEXIST is neither ok nor not_found), no ok row."""
    d = cx.unique_name("nsdup").replace(".bin", "")
    st, _, _ = mx.dav_request("dav", f"/{d}", method="MKCOL")
    assert st == 201
    cx.settle()
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{d}", method="MKCOL")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 405
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "mkdir", "status": "other"}, after) == 1
    assert s.delta_or_absent("brix_io_ops_total",
                             {**IO, "op": "mkdir", "status": "ok"},
                             after) == 0
    assert s.delta("brix_webdav_responses_total",
                   {"method": "MKCOL", "status_class": "4xx"}, after) == 1


def test_mkcol_missing_parent_409(mx):
    """MKCOL under a nonexistent parent: 409, mkdir books not_found."""
    s = snap(mx)
    st, _, _ = mx.dav_request(
        "dav", f"/{cx.unique_name('nsnope').replace('.bin', '')}/deep",
        method="MKCOL")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 409
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "mkdir", "status": "not_found"}, after) == 1
    assert s.delta("brix_webdav_responses_total",
                   {"method": "MKCOL", "status_class": "4xx"}, after) == 1


def test_mkcol_escape_path_denied(mx):
    """SECURITY: MKCOL that traverses out of the export root must not
    succeed and must book no ok mkdir."""
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", "/../../../etc/ns_owned",
                              method="MKCOL")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st >= 400
    assert s.delta_or_absent("brix_io_ops_total",
                             {**IO, "op": "mkdir", "status": "ok"},
                             after) == 0


# --------------------------------------------------------------------------
# HEAD
# --------------------------------------------------------------------------

def test_head_cached_is_pure_stat(mx):
    """HEAD of a cached object: exactly one stat op (with latency), zero
    payload bytes on either ledger, one HEAD request + 2xx response."""
    name = cx.unique_name("nshead")
    mx.seed_local(name, 800)
    st, _, _ = mx.dav_request("dav", f"/{name}")     # prime
    assert st == 200
    cx.settle()
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{name}", method="HEAD")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200
    assert s.delta("brix_io_ops_total", {**IO, "op": "stat", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_latency_usec_count", {**IO, "op": "stat"},
                   after) == 1
    assert s.delta("brix_io_bytes_read", IO, after) == 0
    assert s.delta("brix_webdav_bytes_tx_total", after=after) == 0
    assert s.delta("brix_webdav_requests_total", {"method": "HEAD"},
                   after) == 1
    assert s.delta("brix_webdav_responses_total",
                   {"method": "HEAD", "status_class": "2xx"}, after) == 1


def test_head_absent_404_stat_not_found(mx):
    """HEAD of a nonexistent object: 404, one stat not_found, no read."""
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{cx.unique_name('nsheadghost')}",
                              method="HEAD")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 404
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "stat", "status": "not_found"}, after) == 1
    assert s.delta_or_absent("brix_io_ops_total",
                             {**IO, "op": "read", "status": "ok"},
                             after) == 0


# --------------------------------------------------------------------------
# PROPFIND — entry-exact against a private directory
# --------------------------------------------------------------------------

def test_propfind_depth0_byte_and_entry_exact(mx):
    """Depth:0 on a file: 207, exactly one entry, one stat, depth bucket
    "0", and the multistatus body's bytes on BOTH tx ledgers."""
    name = cx.unique_name("nspf0")
    mx.seed_local(name, 640)
    s = snap(mx)
    st, body, _ = mx.dav_request("dav", f"/{name}", method="PROPFIND",
                                 headers={"Depth": "0"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 207
    assert s.delta("brix_io_ops_total", {**IO, "op": "stat", "status": "ok"},
                   after) == 1
    assert s.delta("brix_webdav_propfind_depth_total", {"depth": "0"},
                   after) == 1
    assert s.delta("brix_webdav_propfind_entries_total", after=after) == 1
    assert s.delta("brix_io_bytes_read", IO, after) == len(body)
    assert s.delta("brix_webdav_bytes_tx_total", after=after) == len(body)


def test_propfind_depth1_counts_self_plus_children(mx):
    """Depth:1 on a private directory of K seeded children: entries move by
    exactly K+1 (self + children), one dirlist op, depth bucket "1"."""
    d = cx.unique_name("nspf1").replace(".bin", "")
    st, _, _ = mx.dav_request("dav", f"/{d}", method="MKCOL")
    assert st == 201
    k = 4
    for i in range(k):
        st, _, _ = mx.dav_request("dav", f"/{d}/child{i}.bin", method="PUT",
                                  data=b"x" * (64 + i))
        assert st in (200, 201, 204)
    cx.settle()
    s = snap(mx)
    st, body, _ = mx.dav_request("dav", f"/{d}/", method="PROPFIND",
                                 headers={"Depth": "1"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 207
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "dirlist", "status": "ok"}, after) == 1
    assert s.delta("brix_webdav_propfind_depth_total", {"depth": "1"},
                   after) == 1
    assert s.delta("brix_webdav_propfind_entries_total",
                   after=after) == k + 1
    assert s.delta("brix_webdav_bytes_tx_total", after=after) == len(body)


def test_propfind_absent_404_no_entries(mx):
    """PROPFIND of a nonexistent path: 404 and the entry counter is still."""
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{cx.unique_name('nspfghost')}",
                              method="PROPFIND", headers={"Depth": "0"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 404
    assert s.delta("brix_webdav_propfind_entries_total", after=after) == 0
    assert s.delta("brix_webdav_responses_total",
                   {"method": "PROPFIND", "status_class": "4xx"}, after) == 1


# --------------------------------------------------------------------------
# DELETE
# --------------------------------------------------------------------------

def test_delete_cached_full_ledger(mx):
    """DELETE of a cached object: 204, one delete + one stat op, the cached
    copy's exact bytes on the eviction counter, one 2xx DELETE response."""
    name = cx.unique_name("nsdel")
    size = 900
    mx.seed_local(name, size)
    st, _, _ = mx.dav_request("dav", f"/{name}")     # prime
    assert st == 200
    cx.settle()
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{name}", method="DELETE")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 204
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "delete", "status": "ok"}, after) == 1
    assert s.delta("brix_io_ops_total", {**IO, "op": "stat", "status": "ok"},
                   after) == 1
    assert s.delta("brix_cache_bytes_evicted_total", IO, after) == size
    assert s.delta("brix_webdav_responses_total",
                   {"method": "DELETE", "status_class": "2xx"}, after) == 1


def test_delete_absent_404_stat_only(mx):
    """DELETE of a nonexistent object: 404 with ONLY a stat not_found row —
    no phantom delete op, no eviction movement."""
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{cx.unique_name('nsdelghost')}",
                              method="DELETE")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 404
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "stat", "status": "not_found"}, after) == 1
    assert s.delta_or_absent("brix_io_ops_total",
                             {**IO, "op": "delete", "status": "ok"},
                             after) == 0
    assert s.delta("brix_cache_bytes_evicted_total", IO, after) == 0


def test_delete_empty_collection(mx):
    """DELETE of an empty collection succeeds, books one delete op, and
    moves no eviction bytes (directories hold no cached payload)."""
    d = cx.unique_name("nsdeldir").replace(".bin", "")
    st, _, _ = mx.dav_request("dav", f"/{d}", method="MKCOL")
    assert st == 201
    cx.settle()
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{d}", method="DELETE")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 204
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "delete", "status": "ok"}, after) == 1
    assert s.delta("brix_cache_bytes_evicted_total", IO, after) == 0


# --------------------------------------------------------------------------
# OPTIONS — the null request
# --------------------------------------------------------------------------

def test_options_books_no_auth_no_io(mx):
    """OPTIONS: one request + 2xx response row and NOTHING else — no auth
    outcome, no io op, no cred-selection fallback."""
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", "/", method="OPTIONS")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st in (200, 204)
    assert s.delta("brix_webdav_requests_total", {"method": "OPTIONS"},
                   after) == 1
    assert s.delta("brix_webdav_responses_total",
                   {"method": "OPTIONS", "status_class": "2xx"}, after) == 1
    assert s.delta("brix_webdav_auth_total", {"result": "none"}, after) == 0
    assert s.delta("brix_auth_total",
                   {"proto": "webdav", "method": "none", "status": "ok"},
                   after) == 0
    assert s.delta("brix_cred_select_fallback_total", after=after) == 0
    assert s.delta_or_absent("brix_io_ops_total",
                             {**IO, "op": "stat", "status": "ok"},
                             after) == 0


# --------------------------------------------------------------------------
# Range windows — byte-exact on a 1500-byte cached object
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ranged(mx):
    """One cached 1500-byte object shared by the range-window tests."""
    name = cx.unique_name("nsrange")
    payload = mx.seed_local(name, 1500)
    st, _, _ = mx.dav_request("dav", f"/{name}")
    assert st == 200
    cx.settle()
    return name, payload


@pytest.mark.parametrize("hdr,expect", [
    ("bytes=0-0", 1),          # single first byte
    ("bytes=1400-", 100),      # open-ended tail
    ("bytes=-100", 100),       # suffix form
    ("bytes=0-1499", 1500),    # full span is still a 206/partial
])
def test_range_window_byte_exact(mx, ranged, hdr, expect):
    """Each Range window reads EXACTLY the window's bytes, classifies as
    result="partial", and returns the right slice."""
    name, payload = ranged
    lo = int(hdr.split("=")[1].split("-")[0] or 1500 - expect)
    s = snap(mx)
    st, body, _ = mx.dav_request("dav", f"/{name}",
                                 headers={"Range": hdr})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 206
    assert body == payload[lo:lo + expect]
    assert s.delta("brix_io_bytes_read", IO, after) == expect
    assert s.delta("brix_webdav_range_requests_total", {"result": "partial"},
                   after) == 1
    assert s.delta("brix_webdav_range_requests_total", {"result": "full"},
                   after) == 0


def test_range_unsatisfiable_416_zero_bytes(mx, ranged):
    """A Range beyond EOF: 416, result="unsatisfied", the read op lands in
    status="other", and ZERO payload bytes move."""
    name, _ = ranged
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{name}",
                              headers={"Range": "bytes=5000-6000"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 416
    assert s.delta("brix_webdav_range_requests_total",
                   {"result": "unsatisfied"}, after) == 1
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "read", "status": "other"}, after) == 1
    assert s.delta("brix_io_bytes_read", IO, after) == 0


# --------------------------------------------------------------------------
# s3 namespace edges
# --------------------------------------------------------------------------

def test_s3_head_is_stat_plus_miss(mx):
    """s3 HEAD of an uncached object: 200, one stat op, one decorator miss,
    one HEAD 2xx response, anonymous auth."""
    name = cx.unique_name("nss3head")
    mx.seed_local(name, 900)
    s = snap(mx)
    st, _, _ = mx.s3_request("s3", name, method="HEAD")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200
    assert s.delta("brix_io_ops_total", {**S3, "op": "stat", "status": "ok"},
                   after) == 1
    assert s.delta("brix_cache_misses_total", S3, after) == 1
    assert s.delta("brix_s3_responses_total",
                   {"method": "HEAD", "status_class": "2xx"}, after) == 1
    assert s.delta("brix_s3_auth_total", {"result": "anonymous"}, after) == 1


def test_s3_list_bucket_entry_and_byte_exact(mx):
    """Bucket LIST: one read op, the XML body's bytes on both tx ledgers,
    and list_contents_total moves by exactly the number of <Contents>
    entries in the returned document."""
    mx.seed_local(cx.unique_name("nss3list"), 100)
    s = snap(mx)
    st, body, _ = mx.s3_request("s3", "")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200
    entries = body.decode(errors="replace").count("<Contents>")
    assert entries >= 1
    assert s.delta("brix_io_ops_total", {**S3, "op": "read", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_bytes_read", S3, after) == len(body)
    assert s.delta("brix_s3_bytes_tx_total", after=after) == len(body)
    assert s.delta("brix_s3_list_contents_total", after=after) == entries


def test_s3_delete_evicts_exact(mx):
    """s3 DELETE: 204, one delete op, the object's exact bytes on the s3
    eviction counter."""
    name = cx.unique_name("nss3del")
    size = 1100
    mx.seed_local(name, size)
    st, _, _ = mx.s3_request("s3", name)             # prime the cache
    assert st == 200
    cx.settle()
    s = snap(mx)
    st, _, _ = mx.s3_request("s3", name, method="DELETE")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 204
    assert s.delta("brix_io_ops_total",
                   {**S3, "op": "delete", "status": "ok"}, after) == 1
    assert s.delta("brix_cache_bytes_evicted_total", S3, after) == size


# --------------------------------------------------------------------------
# stream namespace error edge
# --------------------------------------------------------------------------

def test_stream_rm_absent_books_error_rows(mx):
    """kXR_rm of a nonexistent file: op="rm" error ledger row + one delete
    op with status=not_found, and no eviction movement."""
    meta = cx.STREAM_PLANES["none"]
    lbl = {"port": str(mx.port(meta["port_key"])), "auth": meta["auth"]}
    s = snap(mx)
    r = mx.xrdfs("none", "rm", f"/{cx.unique_name('nsrmghost')}")
    assert r.returncode != 0
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "delete", "status": "not_found"},
                   after) == 1
    assert s.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "rm", "status": "error"},
        after) == 1
    assert s.delta("brix_cache_bytes_evicted_total", {"proto": "stream"},
                   after) == 0
