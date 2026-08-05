"""Op/byte-ledger LINEARITY across authenticated flows: N ops book N rows.

The repetition suite proves linearity on the anonymous planes; this grid
repeats it across credential routes.  For each flow (warm GETs over dav /
davs+bearer / davsg+cert / s3 / s3sig, overwrite PUTs over dav / s3, and
stream stats on the anonymous and GSI planes) and each N in {2, 4, 7},
drive the operation N times and assert ops move by exactly N and byte
ledgers by exactly N x size — catching both dropped bookings (< N) and
double-counting (> N) on every credential route.
"""

import os

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

NS = [2, 4, 7]
GET_FLOWS = ["dav", "davs", "davsg", "s3", "s3sig"]
SIZE = 1536


def snap(mx):
    return cx.Snap(mx.metrics)


def bearer(mx):
    if not os.path.exists(cx.TOKEN_FILE):
        pytest.skip("bearer token fixture missing")
    with open(cx.TOKEN_FILE) as f:
        return {"Authorization": f"Bearer {f.read().strip()}"}


def http_get(mx, flow, name):
    if flow in cx.S3_PLANES:
        return mx.s3_request(flow, name)
    hdr = bearer(mx) if flow == "davs" else None
    return mx.dav_request(flow, f"/{name}", headers=hdr)


@pytest.mark.parametrize("n", NS)
@pytest.mark.parametrize("flow", GET_FLOWS)
def test_get_linearity(mx, flow, n):
    """N warm GETs over `flow` book exactly N read ops and N x size bytes
    on the unified and wire tx ledgers."""
    proto = "s3" if flow in cx.S3_PLANES else "webdav"
    name = cx.unique_name(f"lg{flow}{n}")
    payload = mx.seed_local(name, SIZE)
    assert http_get(mx, flow, name)[0] == 200        # prime
    cx.settle()
    s = snap(mx)
    for _ in range(n):
        st, body, _ = http_get(mx, flow, name)
        assert st == 200 and body == payload
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": proto, "op": "read", "status": "ok"},
                   after) == n
    assert s.delta("brix_io_bytes_read", {"proto": proto},
                   after) == n * SIZE
    assert s.delta(f"brix_{proto}_bytes_tx_total", after=after) == n * SIZE


@pytest.mark.parametrize("n", NS)
@pytest.mark.parametrize("flow", ["dav", "s3"])
def test_put_overwrite_linearity(mx, flow, n):
    """N overwrite PUTs of one object book exactly N write ops and
    N x size rx bytes; the final object is one payload."""
    proto = "s3" if flow == "s3" else "webdav"
    name = cx.unique_name(f"lp{flow}{n}")
    payload = b"L" * SIZE
    s = snap(mx)
    for _ in range(n):
        if flow == "s3":
            st, _, _ = mx.s3_request(flow, name, method="PUT", data=payload)
            assert st == 200
        else:
            st, _, _ = mx.dav_request(flow, f"/{name}", method="PUT",
                                      data=payload)
            assert st in (200, 201, 204)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": proto, "op": "write", "status": "ok"},
                   after) == n
    assert s.delta("brix_io_bytes_written", {"proto": proto},
                   after) == n * SIZE
    assert s.delta(f"brix_{proto}_bytes_rx_total", after=after) == n * SIZE
    assert (mx.local_data / name).read_bytes() == payload


@pytest.mark.parametrize("n", NS)
@pytest.mark.parametrize("plane", ["none", "gsi"])
def test_stream_stat_linearity(mx, plane, n):
    """N kXR_stat calls book exactly N wire stat ok rows and N unified
    stat ops on plane `plane`."""
    name = cx.unique_name(f"ls{plane}{n}")
    mx.seed_origin(name, 256)
    meta = cx.STREAM_PLANES[plane]
    lbl = {"port": str(mx.port(meta["port_key"])), "auth": meta["auth"]}
    s = snap(mx)
    for _ in range(n):
        r = mx.xrdfs(plane, "stat", f"/{name}")
        assert r.returncode == 0, r.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_requests_total",
                   {**lbl, "op": "stat", "status": "ok"}, after) == n
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "stat", "status": "ok"},
                   after) == n
