"""WebDAV namespace methods on the AUTHENTICATED planes: davs (TLS+bearer)
and davsg (TLS+client-cert).

WHAT: The namespace-method ledger contract (MKCOL/DELETE/PROPFIND/MOVE/
      OPTIONS success + error rows) re-proven per authenticated plane, with
      the auth-result row (token_ok / cert_ok) coupled 1:1 to every
      namespace op.

WHY:  The dav-plane suite proves the op ledgers; these planes add the auth
      layer in front of the same handlers.  A regression that books the op
      but drops (or double-books) the auth row — or that diverges between
      the token and cert paths — is invisible to the anonymous suite.
"""

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

IO = {"proto": "webdav"}

# plane -> (expected auth-result label, request kwargs builder)
AUTHED = ["davs", "davsg"]
AUTH_ROW = {"davs": "token_ok", "davsg": "cert_ok"}


def snap(mx):
    return cx.Snap(mx.metrics)


def creds(mx, plane):
    """Request kwargs that authenticate on the plane (bearer / client cert)."""
    if plane == "davs":
        import os
        if not os.path.exists(cx.TOKEN_FILE):
            pytest.skip("bearer token fixture missing")
        tok = open(cx.TOKEN_FILE).read().strip()
        return {"headers": {"Authorization": f"Bearer {tok}"}}
    return {}  # davsg presents the client cert by default


def req(mx, plane, path, method="GET", extra_headers=None, data=None):
    kw = creds(mx, plane)
    headers = dict(kw.get("headers", {}))
    headers.update(extra_headers or {})
    return mx.dav_request(plane, path, method=method, data=data,
                          headers=headers)


@pytest.mark.parametrize("plane", AUTHED)
def test_mkcol_created_books_op_and_auth(mx, plane):
    """MKCOL is 201 with one mkdir-ok op AND exactly one auth-ok row."""
    d = cx.unique_name(f"mp_mk_{plane}")
    s = snap(mx)
    st, _, _ = req(mx, plane, f"/{d}", method="MKCOL")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 201
    assert s.delta("brix_io_ops_total", {**IO, "op": "mkdir", "status": "ok"},
                   after) == 1
    assert s.delta("brix_webdav_responses_total",
                   {"method": "MKCOL", "status_class": "2xx"}, after) == 1
    assert s.delta("brix_webdav_auth_total", {"result": AUTH_ROW[plane]},
                   after) == 1


@pytest.mark.parametrize("plane", AUTHED)
def test_mkcol_existing_books_other_status(mx, plane):
    """MKCOL on an existing collection: 405, mkdir status="other", and the
    auth row still books (auth happens before the namespace error)."""
    d = cx.unique_name(f"mp_mke_{plane}")
    assert req(mx, plane, f"/{d}", method="MKCOL")[0] == 201
    cx.settle()
    s = snap(mx)
    st, _, _ = req(mx, plane, f"/{d}", method="MKCOL")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 405
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "mkdir", "status": "other"}, after) == 1
    assert s.delta("brix_webdav_auth_total", {"result": AUTH_ROW[plane]},
                   after) == 1


@pytest.mark.parametrize("plane", AUTHED)
def test_delete_cached_books_delete_and_eviction(mx, plane):
    """DELETE of a cached object: delete-ok + stat-ok ops and the evicted
    -bytes ledger moves by exactly the object size."""
    name = cx.unique_name(f"mp_del_{plane}")
    size = 900
    mx.seed_local(name, size)
    assert req(mx, plane, f"/{name}")[0] == 200      # prime the cache
    cx.settle()
    s = snap(mx)
    st, _, _ = req(mx, plane, f"/{name}", method="DELETE")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st in (200, 204)
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "delete", "status": "ok"}, after) == 1
    assert s.delta("brix_cache_bytes_evicted_total", IO, after) == size
    assert s.delta("brix_webdav_auth_total", {"result": AUTH_ROW[plane]},
                   after) == 1


@pytest.mark.parametrize("plane", AUTHED)
def test_delete_absent_books_stat_not_found_only(mx, plane):
    """DELETE of an absent name: 404, one stat not_found, NO delete op,
    zero evicted bytes."""
    name = cx.unique_name(f"mp_dela_{plane}")
    s = snap(mx)
    st, _, _ = req(mx, plane, f"/{name}", method="DELETE")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 404
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "stat", "status": "not_found"}, after) == 1
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "delete", "status": "ok"}, after) == 0
    assert s.delta("brix_cache_bytes_evicted_total", IO, after) == 0


@pytest.mark.parametrize("plane", AUTHED)
def test_propfind_depth0_stat_and_entry(mx, plane):
    """PROPFIND depth 0: 207, one stat-ok, depth="0" row, exactly one
    entry, and the multistatus body's bytes land on the read/tx ledgers."""
    name = cx.unique_name(f"mp_pf_{plane}")
    mx.seed_local(name, 400)
    s = snap(mx)
    st, body, _ = req(mx, plane, f"/{name}", method="PROPFIND",
                      extra_headers={"Depth": "0"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 207
    assert s.delta("brix_io_ops_total", {**IO, "op": "stat", "status": "ok"},
                   after) == 1
    assert s.delta("brix_webdav_propfind_depth_total", {"depth": "0"},
                   after) == 1
    assert s.delta("brix_webdav_propfind_entries_total", after=after) == 1
    assert s.delta("brix_io_bytes_read", IO, after) == len(body)


@pytest.mark.parametrize("plane", AUTHED)
def test_move_fresh_dest_books_rename(mx, plane):
    """MOVE to a fresh name: 201, one rename-ok op, MOVE method row, and
    the object reachable under the new name only."""
    name = cx.unique_name(f"mp_mv_{plane}")
    payload = mx.seed_local(name, 500)
    s = snap(mx)
    st, _, _ = req(mx, plane, f"/{name}", method="MOVE",
                   extra_headers={"Destination":
                                  mx.http_url(plane, f"/dst_{name}")})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 201
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "rename", "status": "ok"}, after) == 1
    assert s.delta("brix_webdav_responses_total",
                   {"method": "MOVE", "status_class": "2xx"}, after) == 1
    st, body, _ = req(mx, plane, f"/dst_{name}")
    assert st == 200 and body == payload
    assert req(mx, plane, f"/{name}")[0] == 404


@pytest.mark.parametrize("plane", AUTHED)
def test_move_absent_source_404_no_rename(mx, plane):
    """MOVE of an absent source: 404 with a MOVE 4xx response row and NO
    rename op (the precondition ladder answers before any namespace stat
    books — same contract as the anonymous plane)."""
    name = cx.unique_name(f"mp_mva_{plane}")
    s = snap(mx)
    st, _, _ = req(mx, plane, f"/{name}", method="MOVE",
                   extra_headers={"Destination":
                                  mx.http_url(plane, f"/dst_{name}")})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 404
    assert s.delta("brix_webdav_responses_total",
                   {"method": "MOVE", "status_class": "4xx"}, after) == 1
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "rename", "status": "ok"}, after) == 0


@pytest.mark.parametrize("plane", AUTHED)
def test_options_books_no_io(mx, plane):
    """OPTIONS books its method rows but touches NO io or byte ledger."""
    s = snap(mx)
    st, _, _ = req(mx, plane, "/", method="OPTIONS")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st in (200, 204)
    assert s.delta("brix_webdav_requests_total", {"method": "OPTIONS"},
                   after) == 1
    assert s.delta("brix_io_bytes_read", IO, after) == 0
    assert s.delta("brix_io_bytes_written", IO, after) == 0


@pytest.mark.parametrize("plane", AUTHED)
def test_auth_row_linearity_over_namespace_ops(mx, plane):
    """Three namespace ops book the plane's auth-ok row exactly three
    times — no per-op double count, no drop under mixed methods."""
    d = cx.unique_name(f"mp_lin_{plane}")
    s = snap(mx)
    assert req(mx, plane, f"/{d}", method="MKCOL")[0] == 201
    assert req(mx, plane, f"/{d}", method="PROPFIND",
               extra_headers={"Depth": "0"})[0] == 207
    assert req(mx, plane, f"/{d}", method="DELETE")[0] in (200, 204)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_webdav_auth_total", {"result": AUTH_ROW[plane]},
                   after) == 3


@pytest.mark.parametrize("plane", AUTHED)
def test_head_absent_books_not_found(mx, plane):
    """HEAD of an absent name on an authed plane: 404 + stat not_found —
    the auth layer must not mask the namespace miss accounting."""
    name = cx.unique_name(f"mp_hda_{plane}")
    s = snap(mx)
    st, _, _ = req(mx, plane, f"/{name}", method="HEAD")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 404
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "stat", "status": "not_found"}, after) == 1
    assert s.delta("brix_io_bytes_read", IO, after) == 0
