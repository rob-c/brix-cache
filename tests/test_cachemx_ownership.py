"""Ledger ownership + cross-family coherence: every booking has exactly one
owner and the derived invariants between families hold.

WHAT: Cross-plane isolation (traffic on one protocol moves NO rows of the
      others), latency-count == op-count coupling per protocol, requests ==
      responses conservation for the webdav method ledger, single-booking
      pins (Bug F), auth-family coupling, and origin-instance isolation.

WHY:  The single-owner accounting rule (metrics-overview.md) says each
      unified (proto,op) row has exactly ONE booking layer.  Violations show
      up as cross-proto bleed or requests/responses imbalance long before
      any single-flow delta test goes red — these are the structural pins.
"""

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401

def _check_test_latency_count_matches_read_semantics_1(mx, name):
    assert mx.dav_request("dav", f"/{name}")[0] == 200       # prime

def _check_test_latency_count_matches_read_semantics_2(name, mx):
    assert mx.s3_request("s3", name)[0] == 200               # prime

def _check_test_latency_count_matches_read_semantics_3(mx, name):
    assert mx.dav_request("dav", f"/{name}")[0] == 200

def _check_test_latency_count_matches_read_semantics_4(name, mx):
    assert mx.s3_request("s3", name)[0] == 200

def _check_test_latency_count_matches_read_semantics_5(r):
    assert r.returncode == 0, r.stderr


pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]


def snap(mx):
    return cx.Snap(mx.metrics)


def family_sum(text, family, must_contain=""):
    """Sum every sample of `family` (optionally filtered on a label
    substring) from raw exposition text."""
    total = 0.0
    for line in text.splitlines():
        if line.startswith(family + "{") or line.startswith(family + " "):
            if must_contain and must_contain not in line:
                continue
            total += float(line.rsplit(" ", 1)[1])
    return total


# --------------------------------------------------------------------------
# Cross-plane isolation
# --------------------------------------------------------------------------

def test_dav_traffic_moves_no_stream_or_s3_rows(mx):
    """A dav GET+PUT burst leaves the stream and s3 proto ledgers, the s3
    method ledger, and the foreign cache decorators completely still."""
    name = cx.unique_name("owdav")
    mx.seed_local(name, 500)
    before = cx.mfetch(mx.metrics)
    assert mx.dav_request("dav", f"/{name}")[0] == 200
    st, _, _ = mx.dav_request("dav", f"/{cx.unique_name('owdavp')}",
                              method="PUT", data=b"x" * 300)
    assert st in (200, 201, 204)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    for fam, tag in [("brix_io_ops_total", 'proto="stream"'),
                     ("brix_io_ops_total", 'proto="s3"'),
                     ("brix_s3_requests_total", ""),
                     ("brix_cache_requests_total", 'proto="stream"'),
                     ("brix_cache_requests_total", 'proto="s3"'),
                     ("brix_requests_total", "")]:
        assert family_sum(after, fam, tag) == family_sum(before, fam, tag), \
            f"dav traffic moved {fam}{{{tag}}}"


def test_s3_traffic_moves_no_webdav_or_stream_rows(mx):
    """An s3 GET+PUT burst leaves the webdav and stream ledgers still."""
    name = cx.unique_name("ows3")
    mx.seed_local(name, 500)
    before = cx.mfetch(mx.metrics)
    assert mx.s3_request("s3", name)[0] == 200
    assert mx.s3_request("s3", cx.unique_name("ows3p"), method="PUT",
                         data=b"y" * 200)[0] == 200
    cx.settle()
    after = cx.mfetch(mx.metrics)
    for fam, tag in [("brix_io_ops_total", 'proto="webdav"'),
                     ("brix_io_ops_total", 'proto="stream"'),
                     ("brix_webdav_requests_total", ""),
                     ("brix_cache_requests_total", 'proto="webdav"'),
                     ("brix_requests_total", "")]:
        assert family_sum(after, fam, tag) == family_sum(before, fam, tag), \
            f"s3 traffic moved {fam}{{{tag}}}"


def test_stream_traffic_moves_no_webdav_or_s3_rows(mx, tmp_path):
    """A stream read leaves the webdav and s3 method + proto ledgers
    still."""
    name = cx.unique_name("owstrm")
    mx.seed_origin(name, 700)
    before = cx.mfetch(mx.metrics)
    r = mx.xrdcp_get("none", f"/{name}", str(tmp_path / name))
    assert r.returncode == 0, r.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    for fam, tag in [("brix_io_ops_total", 'proto="webdav"'),
                     ("brix_io_ops_total", 'proto="s3"'),
                     ("brix_webdav_requests_total", ""),
                     ("brix_s3_requests_total", ""),
                     ("brix_webdav_auth_total", ""),
                     ("brix_s3_auth_total", "")]:
        assert family_sum(after, fam, tag) == family_sum(before, fam, tag), \
            f"stream traffic moved {fam}{{{tag}}}"


def test_matrix_traffic_leaves_origin_instance_still(mx):
    """Matrix-local dav traffic books NOTHING on the origin instance's
    exporter — separate SHM zones, no bleed."""
    name = cx.unique_name("oworigin")
    mx.seed_local(name, 400)
    before = cx.mfetch(mx.origin_metrics)
    assert mx.dav_request("dav", f"/{name}")[0] == 200
    cx.settle()
    after = cx.mfetch(mx.origin_metrics)
    for fam in ("brix_io_ops_total", "brix_webdav_requests_total",
                "brix_io_bytes_read"):
        assert family_sum(after, fam) == family_sum(before, fam), \
            f"matrix dav GET moved origin {fam}"


# --------------------------------------------------------------------------
# Latency/op coupling — every observed op carries a real latency sample
# --------------------------------------------------------------------------

@pytest.mark.parametrize("flow", ["dav", "s3", "stream"])
def test_latency_count_matches_read_semantics(mx, flow, tmp_path):
    """One read books exactly the calibrated latency-observation count for
    its protocol: dav/s3 reads are op_done-observed (1 sample per op), while
    stream reads are wire-ledger-folded and carry NO duration (fabricating
    one would poison the quantiles)."""
    name = cx.unique_name(f"owlat{flow}")
    if flow == "stream":
        mx.seed_origin(name, 600)
    elif flow == "dav":
        mx.seed_local(name, 600)
        _check_test_latency_count_matches_read_semantics_1(mx, name)
        cx.settle()
    else:
        mx.seed_local(name, 600)
        _check_test_latency_count_matches_read_semantics_2(name, mx)
        cx.settle()
    proto = {"dav": "webdav", "s3": "s3", "stream": "stream"}[flow]
    s = snap(mx)
    if flow == "dav":
        _check_test_latency_count_matches_read_semantics_3(mx, name)
    elif flow == "s3":
        _check_test_latency_count_matches_read_semantics_4(name, mx)
    else:
        r = mx.xrdcp_get("none", f"/{name}", str(tmp_path / name))
        _check_test_latency_count_matches_read_semantics_5(r)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    ops = s.delta("brix_io_ops_total",
                  {"proto": proto, "op": "read", "status": "ok"}, after)
    lat = s.delta("brix_io_latency_seconds_count",
                  {"proto": proto, "op": "read"}, after)
    def _assert_test_latency_count_matches_read_semantics_1():
        assert ops == 1
        assert lat == (0 if flow == "stream" else 1)

    _assert_test_latency_count_matches_read_semantics_1()


# --------------------------------------------------------------------------
# Conservation: requests == responses on the webdav method ledger
# --------------------------------------------------------------------------

def test_webdav_requests_equal_responses_over_burst(mx):
    """Over a mixed burst (GET/HEAD/PUT/OPTIONS/404), the TOTAL movement of
    requests_total equals the TOTAL movement of responses_total — every
    request is answered and booked exactly once on each side."""
    name = cx.unique_name("owcons")
    mx.seed_local(name, 350)
    before = cx.mfetch(mx.metrics)
    assert mx.dav_request("dav", f"/{name}")[0] == 200
    assert mx.dav_request("dav", f"/{name}", method="HEAD")[0] == 200
    assert mx.dav_request("dav", "/", method="OPTIONS")[0] in (200, 204)
    assert mx.dav_request("dav", f"/{cx.unique_name('owghost')}")[0] == 404
    st, _, _ = mx.dav_request("dav", f"/{cx.unique_name('owput')}",
                              method="PUT", data=b"z" * 100)
    assert st in (200, 201, 204)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    req = (family_sum(after, "brix_webdav_requests_total")
           - family_sum(before, "brix_webdav_requests_total"))
    rsp = (family_sum(after, "brix_webdav_responses_total")
           - family_sum(before, "brix_webdav_responses_total"))
    assert req == 5
    assert rsp == req


def test_s3_requests_equal_responses_over_burst(mx):
    """Same conservation law on the s3 method ledger."""
    name = cx.unique_name("owcons3")
    mx.seed_local(name, 350)
    before = cx.mfetch(mx.metrics)
    assert mx.s3_request("s3", name)[0] == 200
    assert mx.s3_request("s3", name, method="HEAD")[0] == 200
    assert mx.s3_request("s3", cx.unique_name("owghost3"))[0] == 404
    cx.settle()
    after = cx.mfetch(mx.metrics)
    req = (family_sum(after, "brix_s3_requests_total")
           - family_sum(before, "brix_s3_requests_total"))
    rsp = (family_sum(after, "brix_s3_responses_total")
           - family_sum(before, "brix_s3_responses_total"))
    assert req == 3
    assert rsp == req


# --------------------------------------------------------------------------
# Single-booking pins
# --------------------------------------------------------------------------

def test_put_books_write_exactly_once(mx):
    """Bug F pin: one staged-commit PUT is ONE write op and ONE size on the
    byte ledger — the commit layer must not re-book what the fill layer
    already observed."""
    size = 4321
    name = cx.unique_name("owbugf")
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{name}", method="PUT",
                              data=b"F" * size)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st in (200, 201, 204)
    assert s.delta("brix_io_ops_total",
                   {"proto": "webdav", "op": "write", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_bytes_written", {"proto": "webdav"},
                   after) == size


def test_get_books_read_exactly_once(mx):
    """Single-owner pin for the read path: one cached GET is one read op on
    the unified ledger — no decorator/protocol double booking."""
    name = cx.unique_name("owonce")
    mx.seed_local(name, 777)
    assert mx.dav_request("dav", f"/{name}")[0] == 200      # prime
    cx.settle()
    before = cx.mfetch(mx.metrics)
    assert mx.dav_request("dav", f"/{name}")[0] == 200
    cx.settle()
    after = cx.mfetch(mx.metrics)
    moved = (family_sum(after, "brix_io_ops_total", 'proto="webdav"')
             - family_sum(before, "brix_io_ops_total", 'proto="webdav"'))
    assert moved == 1        # exactly the read row, nothing else


def test_auth_families_move_together(mx):
    """One authenticated-plane request moves the unified auth family and
    the protocol auth family by the same amount — one auth decision, two
    coupled ledgers."""
    name = cx.unique_name("owauth")
    mx.seed_local(name, 200)
    s = snap(mx)
    assert mx.dav_request("dav", f"/{name}")[0] == 200
    cx.settle()
    after = cx.mfetch(mx.metrics)
    unified = s.delta("brix_auth_total",
                      {"proto": "webdav", "method": "none", "status": "ok"},
                      after)
    protocol = s.delta("brix_webdav_auth_total", {"result": "none"}, after)
    assert unified == 1
    assert protocol == unified


def test_rename_books_no_read_write_ops(mx):
    """Ownership of MOVE: the rename row moves and the read/write rows do
    NOT — namespace ops must not masquerade as data ops."""
    name = cx.unique_name("ownsmv")
    mx.seed_local(name, 450)
    s = snap(mx)
    st, _, _ = mx.dav_request(
        "dav", f"/{name}", method="MOVE",
        headers={"Destination": mx.http_url("dav", f"/dst_{name}")})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 201
    assert s.delta("brix_io_ops_total",
                   {"proto": "webdav", "op": "rename", "status": "ok"},
                   after) == 1
    assert s.delta_or_absent("brix_io_ops_total",
                             {"proto": "webdav", "op": "read",
                              "status": "ok"}, after) == 0
    assert s.delta_or_absent("brix_io_ops_total",
                             {"proto": "webdav", "op": "write",
                              "status": "ok"}, after) == 0
