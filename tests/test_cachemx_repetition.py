"""Repetition linearity: N identical operations move every counter by
exactly N times the single-op delta.

WHAT: Each flow is executed three times under one snapshot and the ledgers
      are asserted at exactly 3x the calibrated single-op movement (and the
      stream GET triple at 1 miss + 2 hits).

WHY:  A counter can be correct for one op and still lose or double bookings
      under repetition (idempotent-looking re-inits, per-connection vs
      per-request booking, staged-commit double counts — Bug F's family).
      Linearity is the cheapest oracle for "booked exactly once per op".
"""

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

N = 3


def snap(mx):
    return cx.Snap(mx.metrics)


def test_dav_get_x3_linear(mx):
    """Three GETs of one cached object: 3 read ops, 3x bytes, 3 hits."""
    size = 700
    name = cx.unique_name("rpdget")
    mx.seed_local(name, size)
    assert mx.dav_request("dav", f"/{name}")[0] == 200      # prime
    cx.settle()
    s = snap(mx)
    for _ in range(N):
        assert mx.dav_request("dav", f"/{name}")[0] == 200
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "webdav", "op": "read", "status": "ok"},
                   after) == N
    assert s.delta("brix_io_bytes_read", {"proto": "webdav"},
                   after) == N * size
    assert s.delta("brix_cache_hits_total", {"proto": "webdav"}, after) == N
    assert s.delta("brix_webdav_responses_total",
                   {"method": "GET", "status_class": "2xx"}, after) == N


def test_dav_put_x3_linear(mx):
    """Three PUTs of distinct names, same size: exactly 3 write ops and 3x
    bytes — a staged-commit double count (Bug F) shows as 6x here."""
    size = 900
    s = snap(mx)
    for _ in range(N):
        st, _, _ = mx.dav_request("dav", f"/{cx.unique_name('rpdput')}",
                                  method="PUT", data=b"w" * size)
        assert st in (200, 201, 204)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "webdav", "op": "write", "status": "ok"},
                   after) == N
    assert s.delta("brix_io_bytes_written", {"proto": "webdav"},
                   after) == N * size


def test_s3_get_x3_linear(mx):
    """Three s3 GETs of one cached object: 3 read ops, 3x bytes, 3 hits."""
    size = 1100
    name = cx.unique_name("rpsget")
    mx.seed_local(name, size)
    assert mx.s3_request("s3", name)[0] == 200              # prime
    cx.settle()
    s = snap(mx)
    for _ in range(N):
        assert mx.s3_request("s3", name)[0] == 200
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "s3", "op": "read", "status": "ok"},
                   after) == N
    assert s.delta("brix_io_bytes_read", {"proto": "s3"}, after) == N * size
    assert s.delta("brix_cache_hits_total", {"proto": "s3"}, after) == N


def test_s3_put_x3_linear(mx):
    """Three s3 PUTs of distinct names: 3 write ops, 3x bytes."""
    size = 640
    s = snap(mx)
    for _ in range(N):
        st, _, _ = mx.s3_request("s3", cx.unique_name("rpsput"),
                                 method="PUT", data=b"v" * size)
        assert st == 200
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "s3", "op": "write", "status": "ok"},
                   after) == N
    assert s.delta("brix_io_bytes_written", {"proto": "s3"},
                   after) == N * size


def test_stream_get_x3_one_miss_two_hits(mx, tmp_path):
    """Three stream reads of one origin file: 1 decorator miss + 2 hits,
    3 read ops, 3x payload bytes served."""
    size = 2100
    name = cx.unique_name("rptget")
    mx.seed_origin(name, size)
    s = snap(mx)
    for i in range(N):
        r = mx.xrdcp_get("none", f"/{name}", str(tmp_path / f"c{i}.bin"))
        assert r.returncode == 0, r.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_cache_misses_total", {"proto": "stream"},
                   after) == 1
    assert s.delta("brix_cache_hits_total", {"proto": "stream"},
                   after) == N - 1
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "read", "status": "ok"},
                   after) == N
    assert s.delta("brix_io_bytes_read", {"proto": "stream"},
                   after) == N * size


def test_stream_put_x3_linear(mx, tmp_path):
    """Three stream writes of distinct names: 3 write ops, 3x bytes."""
    size = 1500
    src = tmp_path / "rp.bin"
    src.write_bytes(b"u" * size)
    s = snap(mx)
    for _ in range(N):
        r = mx.xrdcp_put("none", str(src),
                         f"/{cx.unique_name('rptput')}")
        assert r.returncode == 0, r.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "write", "status": "ok"},
                   after) == N
    assert s.delta("brix_io_bytes_written", {"proto": "stream"},
                   after) == N * size


def test_move_chain_x3_linear(mx):
    """A MOVE chain a->b->c->d books exactly 3 rename ops and 3 2xx MOVE
    responses, and the payload survives the full chain."""
    name = cx.unique_name("rpmv")
    payload = mx.seed_local(name, 512)
    s = snap(mx)
    cur = name
    for i in range(N):
        nxt = f"hop{i}_{name}"
        st, _, _ = mx.dav_request(
            "dav", f"/{cur}", method="MOVE",
            headers={"Destination": mx.http_url("dav", f"/{nxt}")})
        assert st == 201
        cur = nxt
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "webdav", "op": "rename", "status": "ok"},
                   after) == N
    assert s.delta("brix_webdav_responses_total",
                   {"method": "MOVE", "status_class": "2xx"}, after) == N
    st, body, _ = mx.dav_request("dav", f"/{cur}")
    assert st == 200 and body == payload


def test_delete_x3_evicts_3x(mx):
    """Deleting three cached objects of one size retires exactly 3x the
    size on the eviction counter and books 3 delete ops."""
    size = 800
    names = [cx.unique_name("rpdel") for _ in range(N)]
    for n in names:
        mx.seed_local(n, size)
        assert mx.dav_request("dav", f"/{n}")[0] == 200     # prime
    cx.settle()
    s = snap(mx)
    for n in names:
        assert mx.dav_request("dav", f"/{n}", method="DELETE")[0] == 204
    cx.settle()
    after = cx.mfetch(mx.metrics)
    def _assert_test_delete_x3_evicts_3x_1():
        assert s.delta("brix_io_ops_total",
                       {"proto": "webdav", "op": "delete", "status": "ok"},
                       after) == N
        assert s.delta("brix_cache_bytes_evicted_total", {"proto": "webdav"},
                       after) == N * size

    _assert_test_delete_x3_evicts_3x_1()


def test_mkcol_x3_linear(mx):
    """Three MKCOLs: 3 mkdir ops, 3 2xx MKCOL responses."""
    s = snap(mx)
    for _ in range(N):
        d = cx.unique_name("rpmk").replace(".bin", "")
        assert mx.dav_request("dav", f"/{d}", method="MKCOL")[0] == 201
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "webdav", "op": "mkdir", "status": "ok"},
                   after) == N
    assert s.delta("brix_webdav_responses_total",
                   {"method": "MKCOL", "status_class": "2xx"}, after) == N


def test_propfind_depth0_x3_linear(mx):
    """Three Depth:0 PROPFINDs of one object: 3 depth-bucket bookings and
    exactly 3 entries emitted."""
    name = cx.unique_name("rppf")
    mx.seed_local(name, 256)
    s = snap(mx)
    for _ in range(N):
        st, _, _ = mx.dav_request("dav", f"/{name}", method="PROPFIND",
                                  headers={"Depth": "0"})
        assert st == 207
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_webdav_propfind_depth_total", {"depth": "0"},
                   after) == N
    assert s.delta("brix_webdav_propfind_entries_total", after=after) == N


def test_head_x3_linear(mx):
    """Three HEADs of one cached object: 3 stat ops, zero payload bytes."""
    name = cx.unique_name("rphead")
    mx.seed_local(name, 300)
    assert mx.dav_request("dav", f"/{name}")[0] == 200      # prime
    cx.settle()
    s = snap(mx)
    for _ in range(N):
        assert mx.dav_request("dav", f"/{name}", method="HEAD")[0] == 200
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "webdav", "op": "stat", "status": "ok"},
                   after) == N
    assert s.delta("brix_io_bytes_read", {"proto": "webdav"}, after) == 0


def test_options_x3_linear(mx):
    """Three OPTIONS: 3 request rows, still no auth and no io movement."""
    s = snap(mx)
    for _ in range(N):
        assert mx.dav_request("dav", "/", method="OPTIONS")[0] in (200, 204)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_webdav_requests_total", {"method": "OPTIONS"},
                   after) == N
    assert s.delta("brix_webdav_auth_total", {"result": "none"}, after) == 0
    assert s.delta_or_absent("brix_io_ops_total",
                             {"proto": "webdav", "op": "stat",
                              "status": "ok"}, after) == 0
