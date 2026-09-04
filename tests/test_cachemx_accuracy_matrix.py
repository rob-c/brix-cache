"""Byte-accuracy matrix: exact io-byte and op-count deltas for every
transfer flow x a size ladder spanning four orders of magnitude.

WHAT: For each flow (dav GET/PUT, s3 GET/PUT, stream GET/PUT) and each size
      in {1, 511, 4096, 65536}, assert the unified byte ledgers move by
      EXACTLY the payload size and the op ledgers by exactly one — plus the
      zero-byte edge for each protocol family.

WHY:  Byte counters that are correct at one size can still be wrong at
      another (block rounding, header inclusion, chunk splits, sendfile vs
      buffered paths).  A size ladder catches off-by-header and
      rounded-to-block accounting that a single-size test never sees.

Sizes deliberately straddle: 1 (sub-header), 511 (odd, sub-block),
4096 (exactly one page), 65536 (multi-chunk).
"""

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

SIZES = [1, 511, 4096, 65536]


def snap(mx):
    return cx.Snap(mx.metrics)


# --------------------------------------------------------------------------
# dav
# --------------------------------------------------------------------------

@pytest.mark.parametrize("size", SIZES)
def test_dav_get_bytes_exact(mx, size, tmp_path):
    """A cached dav GET reads exactly `size` bytes: the unified read
    ledger and the returned body agree."""
    name = cx.unique_name(f"axdg{size}")
    payload = mx.seed_local(name, size)
    st, _, _ = mx.dav_request("dav", f"/{name}")     # prime the cache
    assert st == 200
    cx.settle()
    s = snap(mx)
    st, body, _ = mx.dav_request("dav", f"/{name}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    assert s.delta("brix_io_ops_total",
                   {"proto": "webdav", "op": "read", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_bytes_read", {"proto": "webdav"}, after) == size


@pytest.mark.parametrize("size", SIZES)
def test_dav_put_bytes_exact(mx, size):
    """A dav PUT writes exactly `size` bytes ONCE (Bug F pinned the staged
    -commit double count): the unified write ledger and the stored object
    agree."""
    name = cx.unique_name(f"axdp{size}")
    payload = b"P" * size
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{name}", method="PUT", data=payload)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st in (200, 201, 204)
    assert s.delta("brix_io_ops_total",
                   {"proto": "webdav", "op": "write", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_bytes_written", {"proto": "webdav"},
                   after) == size
    assert (mx.local_data / name).read_bytes() == payload


# --------------------------------------------------------------------------
# s3
# --------------------------------------------------------------------------

@pytest.mark.parametrize("size", SIZES)
def test_s3_get_bytes_exact(mx, size):
    """A cached s3 GET reads exactly `size` bytes on the unified read
    ledger."""
    name = cx.unique_name(f"axsg{size}")
    payload = mx.seed_local(name, size)
    st, _, _ = mx.s3_request("s3", name)             # prime the cache
    assert st == 200
    cx.settle()
    s = snap(mx)
    st, body, _ = mx.s3_request("s3", name)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    assert s.delta("brix_io_ops_total",
                   {"proto": "s3", "op": "read", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_bytes_read", {"proto": "s3"}, after) == size


@pytest.mark.parametrize("size", SIZES)
def test_s3_put_bytes_exact(mx, size):
    """An s3 PUT writes exactly `size` bytes once, and the object lands
    byte-identical on the backing store."""
    name = cx.unique_name(f"axsp{size}")
    payload = b"S" * size
    s = snap(mx)
    st, _, _ = mx.s3_request("s3", name, method="PUT", data=payload)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200
    assert s.delta("brix_io_ops_total",
                   {"proto": "s3", "op": "write", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_bytes_written", {"proto": "s3"}, after) == size
    assert (mx.local_data / name).read_bytes() == payload


# --------------------------------------------------------------------------
# stream
# --------------------------------------------------------------------------

@pytest.mark.parametrize("size", SIZES)
def test_stream_get_bytes_exact(mx, size, tmp_path):
    """A cold stream read moves exactly `size` bytes on the unified read
    ledger and delivers them intact."""
    name = cx.unique_name(f"axtg{size}")
    payload = mx.seed_origin(name, size)
    dst = tmp_path / name
    s = snap(mx)
    r = mx.xrdcp_get("none", f"/{name}", str(dst))
    assert r.returncode == 0, r.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert dst.read_bytes() == payload
    assert s.delta("brix_io_bytes_read", {"proto": "stream"}, after) == size
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "read", "status": "ok"},
                   after) == 1


@pytest.mark.parametrize("size", SIZES)
def test_stream_put_bytes_exact(mx, size, tmp_path):
    """A stream write moves exactly `size` bytes on the unified write ledger
    and materializes intact at the origin."""
    name = cx.unique_name(f"axtp{size}")
    payload = b"T" * size
    src = tmp_path / name
    src.write_bytes(payload)
    s = snap(mx)
    r = mx.xrdcp_put("none", str(src), f"/{name}")
    assert r.returncode == 0, r.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_bytes_written", {"proto": "stream"},
                   after) == size
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "write", "status": "ok"},
                   after) == 1
    assert (mx.origin_data / name).read_bytes() == payload


# --------------------------------------------------------------------------
# zero-byte edges — the accounting null case per protocol
# --------------------------------------------------------------------------

def test_dav_put_zero_byte_books_empty_mode(mx):
    """A zero-byte PUT succeeds, books the "empty" body mode, and moves NO
    write bytes."""
    name = cx.unique_name("axz0put")
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{name}", method="PUT", data=b"")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st in (200, 201, 204)
    assert s.delta("brix_io_bytes_written", {"proto": "webdav"}, after) == 0
    assert s.delta("brix_webdav_put_bodies_total", {"mode": "empty"},
                   after) == 1
    assert (mx.local_data / name).stat().st_size == 0


def test_dav_get_zero_byte_reads_nothing(mx):
    """GET of a zero-byte object: 200, empty body, ZERO read bytes."""
    name = cx.unique_name("axz0get")
    mx.seed_local(name, 0)
    s = snap(mx)
    st, body, _ = mx.dav_request("dav", f"/{name}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200 and body == b""
    assert s.delta("brix_io_bytes_read", {"proto": "webdav"}, after) == 0


def test_stream_get_zero_byte_reads_nothing(mx, tmp_path):
    """Cold stream read of a zero-byte origin file moves zero payload bytes
    on the unified ledger."""
    name = cx.unique_name("axz0strm")
    mx.seed_origin(name, 0)
    dst = tmp_path / name
    s = snap(mx)
    r = mx.xrdcp_get("none", f"/{name}", str(dst))
    assert r.returncode == 0, r.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert dst.read_bytes() == b""
    assert s.delta("brix_io_bytes_read", {"proto": "stream"}, after) == 0
