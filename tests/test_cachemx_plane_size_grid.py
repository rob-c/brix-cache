"""Byte-exact transfer accounting across AUTHENTICATED planes x sizes.

The base ladders cover the anonymous planes; this grid crosses every HTTP
credential route (dav plain, davs bearer, davsg client-cert, s3 anonymous,
s3sig SigV4) with GET and PUT at three sizes, and every stream security
plane (none, gsi, token, sss) with GET and PUT at two sizes.  Each cell
asserts the unified op/byte ledgers move by exactly the payload size,
and that the payload itself lands byte-identical — proving the accounting
is credential-route independent.
"""

import os

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

HTTP_FLOWS = ["dav", "davs", "davsg", "s3", "s3sig"]
HTTP_SIZES = [7, 4096, 262144]
STREAM_PLANES = sorted(cx.STREAM_PLANES)
STREAM_SIZES = [7, 262144]


def snap(mx):
    return cx.Snap(mx.metrics)


def bearer(mx):
    if not os.path.exists(cx.TOKEN_FILE):
        pytest.skip("bearer token fixture missing")
    with open(cx.TOKEN_FILE) as f:
        return {"Authorization": f"Bearer {f.read().strip()}"}


def proto_of(flow):
    return "s3" if flow in cx.S3_PLANES else "webdav"


def http_get(mx, flow, name):
    if flow in cx.S3_PLANES:
        return mx.s3_request(flow, name)
    hdr = bearer(mx) if flow == "davs" else None
    return mx.dav_request(flow, f"/{name}", headers=hdr)


def http_put(mx, flow, name, payload):
    if flow in cx.S3_PLANES:
        return mx.s3_request(flow, name, method="PUT", data=payload)
    hdr = bearer(mx) if flow == "davs" else None
    return mx.dav_request(flow, f"/{name}", method="PUT", data=payload,
                          headers=hdr)


@pytest.mark.parametrize("size", HTTP_SIZES)
@pytest.mark.parametrize("flow", HTTP_FLOWS)
def test_http_get_bytes_exact(mx, flow, size):
    """Warm GET over `flow` at `size`: read op +1, read ledger +size,
    body byte-identical."""
    proto = proto_of(flow)
    name = cx.unique_name(f"pg{flow}{size}")
    payload = mx.seed_local(name, size)
    assert http_get(mx, flow, name)[0] == 200        # prime
    cx.settle()
    s = snap(mx)
    st, body, _ = http_get(mx, flow, name)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    assert s.delta("brix_io_ops_total",
                   {"proto": proto, "op": "read", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_bytes_read", {"proto": proto}, after) == size


@pytest.mark.parametrize("size", HTTP_SIZES)
@pytest.mark.parametrize("flow", HTTP_FLOWS)
def test_http_put_bytes_exact(mx, flow, size):
    """PUT over `flow` at `size`: write op +1, write ledger +size,
    stored object byte-identical."""
    proto = proto_of(flow)
    name = cx.unique_name(f"pp{flow}{size}")
    payload = b"G" * size
    s = snap(mx)
    st, _, _ = http_put(mx, flow, name, payload)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st in (200, 201, 204)
    assert s.delta("brix_io_ops_total",
                   {"proto": proto, "op": "write", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_bytes_written", {"proto": proto}, after) == size
    assert (mx.local_data / name).read_bytes() == payload


@pytest.mark.parametrize("size", STREAM_SIZES)
@pytest.mark.parametrize("plane", STREAM_PLANES)
def test_stream_get_bytes_exact(mx, plane, size, tmp_path):
    """Cold stream read on security plane `plane`: the unified read ledger
    is exact, payload intact."""
    name = cx.unique_name(f"sg{plane}{size}")
    payload = mx.seed_origin(name, size)
    dst = tmp_path / name
    s = snap(mx)
    r = mx.xrdcp_get(plane, f"/{name}", str(dst))
    assert r.returncode == 0, r.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert dst.read_bytes() == payload
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "read", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_bytes_read", {"proto": "stream"}, after) == size


@pytest.mark.parametrize("size", STREAM_SIZES)
@pytest.mark.parametrize("plane", STREAM_PLANES)
def test_stream_put_bytes_exact(mx, plane, size, tmp_path):
    """Stream write on security plane `plane`: the unified write ledger is
    exact, origin object intact (ops per WIRE chunk, so only counted
    exactly for single-chunk payloads)."""
    name = cx.unique_name(f"sp{plane}{size}")
    payload = b"H" * size
    src = tmp_path / name
    src.write_bytes(payload)
    s = snap(mx)
    r = mx.xrdcp_put(plane, str(src), f"/{name}")
    assert r.returncode == 0, r.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_bytes_written", {"proto": "stream"},
                   after) == size
    ops = s.delta("brix_io_ops_total",
                  {"proto": "stream", "op": "write", "status": "ok"}, after)
    if size <= 65536:
        assert ops == 1
    else:
        assert ops >= 1
    assert (mx.origin_data / name).read_bytes() == payload
