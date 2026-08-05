"""Multi-op sequence accuracy: object lifecycles, cross-protocol cache
interaction, and N-op linearity.

WHAT: Whole-lifecycle chains (PUT -> GET -> DELETE -> 404) per protocol
      family with CUMULATIVE ledger asserts, MOVE-then-GET rebinding,
      cross-dialect cache hits (dav-primed object served to s3 and vice
      versa — the planes share one cache), overwrite semantics, and
      5-op linearity per flow.

WHY:  Single-op tests can pass while sequences drift (state leaking
      between ops, hit/miss misclassification after namespace changes,
      double counts that only show up cumulatively).  Sequences pin the
      ledger algebra, not just the individual increments.
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
# Full lifecycles — cumulative ledger algebra
# --------------------------------------------------------------------------

def test_dav_lifecycle_cumulative(mx):
    """PUT -> GET -> DELETE -> GET(404): one write + one read of exactly
    `size` bytes each, one delete, one final not_found — nothing more."""
    name = cx.unique_name("sqdav")
    size = 1300
    payload = b"L" * size
    s = snap(mx)
    assert mx.dav_request("dav", f"/{name}", method="PUT",
                          data=payload)[0] in (200, 201, 204)
    st, body, _ = mx.dav_request("dav", f"/{name}")
    assert st == 200 and body == payload
    assert mx.dav_request("dav", f"/{name}",
                          method="DELETE")[0] in (200, 204)
    assert mx.dav_request("dav", f"/{name}")[0] == 404
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_bytes_written", IO, after) == size
    assert s.delta("brix_io_bytes_read", IO, after) == size
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "write", "status": "ok"}, after) == 1
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "delete", "status": "ok"}, after) == 1
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "read", "status": "not_found"}, after) == 1


def test_s3_lifecycle_cumulative(mx):
    """The same lifecycle algebra through the S3 dialect."""
    name = cx.unique_name("sqs3")
    size = 2100
    payload = b"M" * size
    s = snap(mx)
    assert mx.s3_request("s3", name, method="PUT", data=payload)[0] == 200
    st, body, _ = mx.s3_request("s3", name)
    assert st == 200 and body == payload
    assert mx.s3_request("s3", name, method="DELETE")[0] in (200, 204)
    assert mx.s3_request("s3", name)[0] == 404
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_bytes_written", S3, after) == size
    assert s.delta("brix_io_bytes_read", S3, after) == size
    assert s.delta("brix_io_ops_total",
                   {**S3, "op": "write", "status": "ok"}, after) == 1
    assert s.delta("brix_io_ops_total",
                   {**S3, "op": "delete", "status": "ok"}, after) == 1
    assert s.delta("brix_io_ops_total",
                   {**S3, "op": "read", "status": "not_found"}, after) == 1


def test_stream_lifecycle_cumulative(mx, tmp_path):
    """put -> get -> rm -> stat(absent) through root://: write and read
    ledgers move by exactly `size` once each, then the name is gone."""
    name = cx.unique_name("sqstrm")
    size = 1700
    payload = b"N" * size
    src = tmp_path / "src.bin"
    src.write_bytes(payload)
    dst = tmp_path / "dst.bin"
    s = snap(mx)
    assert mx.xrdcp_put("none", str(src), f"/{name}").returncode == 0
    assert mx.xrdcp_get("none", f"/{name}", str(dst)).returncode == 0
    assert dst.read_bytes() == payload
    assert mx.xrdfs("none", "rm", f"/{name}").returncode == 0
    assert mx.xrdfs("none", "stat", f"/{name}").returncode != 0
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_bytes_written", {"proto": "stream"},
                   after) == size
    assert s.delta("brix_io_bytes_read", {"proto": "stream"},
                   after) == size
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "write", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "read", "status": "ok"},
                   after) == 1


def test_delete_then_recreate_fresh_ledger(mx):
    """PUT, DELETE, PUT the SAME name, GET: the recreate is a fresh write
    (no stale-cache bytes) and the GET serves the second payload."""
    name = cx.unique_name("sqrecr")
    first, second = b"a" * 800, b"b" * 500
    assert mx.dav_request("dav", f"/{name}", method="PUT",
                          data=first)[0] in (200, 201, 204)
    assert mx.dav_request("dav", f"/{name}",
                          method="DELETE")[0] in (200, 204)
    cx.settle()
    s = snap(mx)
    assert mx.dav_request("dav", f"/{name}", method="PUT",
                          data=second)[0] in (200, 201, 204)
    st, body, _ = mx.dav_request("dav", f"/{name}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200 and body == second
    assert s.delta("brix_io_bytes_written", IO, after) == 500
    assert s.delta("brix_io_bytes_read", IO, after) == 500


def test_overwrite_put_serves_new_bytes(mx):
    """Two PUTs to one name book BOTH write sizes; the GET serves (and
    books) only the second."""
    name = cx.unique_name("sqover")
    first, second = b"x" * 900, b"y" * 400
    s = snap(mx)
    assert mx.dav_request("dav", f"/{name}", method="PUT",
                          data=first)[0] in (200, 201, 204)
    assert mx.dav_request("dav", f"/{name}", method="PUT",
                          data=second)[0] in (200, 201, 204)
    st, body, _ = mx.dav_request("dav", f"/{name}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200 and body == second
    assert s.delta("brix_io_bytes_written", IO, after) == 1300
    assert s.delta("brix_io_bytes_read", IO, after) == 400
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "write", "status": "ok"}, after) == 2


# --------------------------------------------------------------------------
# MOVE rebinding
# --------------------------------------------------------------------------

def test_move_then_get_rebinds_name(mx):
    """After MOVE, the old name is a clean not_found and the new name
    serves the payload byte-exact — one rename, no phantom reads."""
    name = cx.unique_name("sqmv")
    payload = mx.seed_local(name, 600)
    assert mx.dav_request("dav", f"/{name}")[0] == 200   # prime cache
    cx.settle()
    s = snap(mx)
    st, _, _ = mx.dav_request(
        "dav", f"/{name}", method="MOVE",
        headers={"Destination": mx.http_url("dav", f"/dst_{name}")})
    assert st == 201
    assert mx.dav_request("dav", f"/{name}")[0] == 404
    st, body, _ = mx.dav_request("dav", f"/dst_{name}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "rename", "status": "ok"}, after) == 1
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "read", "status": "not_found"}, after) == 1
    assert s.delta("brix_io_bytes_read", IO, after) == 600


# --------------------------------------------------------------------------
# Cross-dialect cache interaction — one cache, two front doors
# --------------------------------------------------------------------------

def test_dav_primed_object_hits_from_s3(mx):
    """An object primed through WebDAV is a cache HIT when fetched through
    S3 — the dialects share the local store, and the hit books on the s3
    proto row."""
    name = cx.unique_name("sqxds")
    payload = mx.seed_local(name, 750)
    assert mx.dav_request("dav", f"/{name}")[0] == 200
    cx.settle()
    s = snap(mx)
    st, body, _ = mx.s3_request("s3", name)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    assert s.delta("brix_cache_hits_total", S3, after) == 1
    assert s.delta("brix_cache_misses_total", S3, after) == 0
    assert s.delta("brix_io_bytes_read", S3, after) == 750


def test_s3_primed_object_hits_from_dav(mx):
    """The mirror direction: s3-primed object served through WebDAV is a
    webdav-proto hit."""
    name = cx.unique_name("sqxsd")
    payload = mx.seed_local(name, 850)
    assert mx.s3_request("s3", name)[0] == 200
    cx.settle()
    s = snap(mx)
    st, body, _ = mx.dav_request("dav", f"/{name}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    assert s.delta("brix_cache_hits_total", IO, after) == 1
    assert s.delta("brix_cache_misses_total", IO, after) == 0
    assert s.delta("brix_io_bytes_read", IO, after) == 850


def test_interleaved_planes_ledger_isolation(mx, tmp_path):
    """One op on each of dav, s3 and stream, interleaved: every proto row
    moves by exactly ITS payload — no cross-proto smearing."""
    a, b, c = (cx.unique_name(t) for t in ("sqia", "sqib", "sqic"))
    mx.seed_local(a, 100)
    mx.seed_local(b, 200)
    mx.seed_origin(c, 300)
    dst = tmp_path / "c.bin"
    s = snap(mx)
    assert mx.dav_request("dav", f"/{a}")[0] == 200
    assert mx.xrdcp_get("none", f"/{c}", str(dst)).returncode == 0
    assert mx.s3_request("s3", b)[0] == 200
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_bytes_read", IO, after) == 100
    assert s.delta("brix_io_bytes_read", S3, after) == 200
    assert s.delta("brix_io_bytes_read", {"proto": "stream"}, after) == 300


# --------------------------------------------------------------------------
# N=5 linearity
# --------------------------------------------------------------------------

@pytest.mark.parametrize("flow", ["dav", "s3"])
def test_http_get_five_op_linearity(mx, flow):
    """Five GETs book exactly 5 read ops and 5x the byte count."""
    name = cx.unique_name(f"sqlin{flow}")
    size = 420
    mx.seed_local(name, size)
    fetch = ((lambda: mx.dav_request("dav", f"/{name}")) if flow == "dav"
             else (lambda: mx.s3_request("s3", name)))
    assert fetch()[0] == 200                          # prime
    cx.settle()
    io = IO if flow == "dav" else S3
    s = snap(mx)
    for _ in range(5):
        assert fetch()[0] == 200
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {**io, "op": "read", "status": "ok"}, after) == 5
    assert s.delta("brix_io_bytes_read", io, after) == 5 * size


def test_stream_stat_five_op_linearity(mx):
    """Five stream stats book exactly 5 stat-ok ops and 5 latency
    observations (VFS-observed op: exactly one histogram count each)."""
    name = cx.unique_name("sqlinst")
    mx.seed_origin(name, 100)
    s = snap(mx)
    for _ in range(5):
        assert mx.xrdfs("none", "stat", f"/{name}").returncode == 0
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "stat", "status": "ok"},
                   after) == 5
    assert s.delta("brix_io_latency_usec_count",
                   {"proto": "stream", "op": "stat"}, after) == 5
