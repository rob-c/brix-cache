"""Extended byte-accuracy size ladder: five more sizes x every transfer
flow, reaching into the multi-megabyte chunked regime.

WHAT: For each flow (dav GET/PUT, s3 GET/PUT, stream GET/PUT) and each
      size in {3, 1024, 8192, 131072, 1048576}, assert the unified byte
      ledgers move by EXACTLY the payload size and the op ledgers by
      exactly one.

WHY:  The base matrix stops at 64 KiB.  1 MiB crosses the chunk-split and
      sendfile-batching thresholds (and the >1 MiB origin-read path fixed
      in the remote-backend work); 128 KiB is the classic socket-buffer
      boundary; 3 and 1024 are the odd-tail and exactly-1K calibration
      points.  Byte accounting that survives one regime can still break
      in the next.
"""

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

SIZES = [3, 1024, 8192, 131072, 1048576]


def snap(mx):
    return cx.Snap(mx.metrics)


@pytest.mark.parametrize("size", SIZES)
def test_dav_get_bytes_exact(mx, size):
    """Cached dav GET at `size`: the read ledger and the body agree."""
    name = cx.unique_name(f"exdg{size}")
    payload = mx.seed_local(name, size)
    assert mx.dav_request("dav", f"/{name}")[0] == 200   # prime
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
    """dav PUT at `size` writes exactly once and lands byte-identical."""
    name = cx.unique_name(f"exdp{size}")
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


@pytest.mark.parametrize("size", SIZES)
def test_s3_get_bytes_exact(mx, size):
    """Cached s3 GET at `size`: the unified read ledger is byte-exact."""
    name = cx.unique_name(f"exsg{size}")
    payload = mx.seed_local(name, size)
    assert mx.s3_request("s3", name)[0] == 200           # prime
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
    """s3 PUT at `size` writes exactly once and lands byte-identical."""
    name = cx.unique_name(f"exsp{size}")
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


@pytest.mark.parametrize("size", SIZES)
def test_stream_get_bytes_exact(mx, size, tmp_path):
    """Cold stream read at `size`: the unified read ledger is exact and the
    payload intact (1 MiB exercises the multi-chunk origin fill)."""
    name = cx.unique_name(f"extg{size}")
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
    """Stream write at `size`: the unified write ledger is exact and the
    origin object intact."""
    name = cx.unique_name(f"extp{size}")
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
    # The stream op ledger counts WIRE write requests: xrdcp splits large
    # uploads into client-chosen chunks (e.g. 16 ops at 128 KiB), so only
    # the byte ledgers are size-exact.  Small payloads land in one request.
    ops = s.delta("brix_io_ops_total",
                  {"proto": "stream", "op": "write", "status": "ok"}, after)
    if size <= 65536:
        assert ops == 1
    else:
        assert ops >= 1
    assert (mx.origin_data / name).read_bytes() == payload
