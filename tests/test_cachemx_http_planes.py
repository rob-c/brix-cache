"""WebDAV/HTTP metric-accuracy conformance across the three HTTP planes:
plain HTTP (dav), TLS + bearer-token (davs), TLS + client-cert (davsg).

WHAT: Exact op-count and byte assertions for GET/HEAD/PUT/DELETE/Range/
      PROPFIND/404 per plane, auth-result accounting, cache hit/miss/evict
      accuracy, and the Fix-E regression set (PROPFIND responses_total was
      never booked because its async body handler used the bare finalize).

WHY:  The HTTP planes observe ops at op_done with real request latency
      (Fix B) — a GET must be exactly one read, a HEAD exactly one stat,
      a DELETE must account the exact cached bytes it retired (Fix A).

The HTTP and S3 planes share ONE cache instance (same local-posix
root_canon), so hit/miss state is global across dav/davs/davsg/s3 planes:
every test uses a unique object name.
"""

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

PLANES = sorted(cx.LOCAL_HTTP_PLANES)   # dav davs davsg davtpc


def snap(mx):
    return cx.Snap(mx.metrics)


def bearer(mx):
    import os
    if not os.path.exists(cx.TOKEN_FILE):
        pytest.skip("bearer token fixture missing")
    tok = open(cx.TOKEN_FILE).read().strip()
    return {"Authorization": f"Bearer {tok}"}


def seed(mx, tag, size):
    name = cx.unique_name(tag)
    payload = mx.seed_local(name, size)
    return name, payload


def cached_copies(mx, name):
    return [p for p in mx.cache_root.rglob(name) if p.is_file()]


# --------------------------------------------------------------------------
# GET — the read path
# --------------------------------------------------------------------------

@pytest.mark.parametrize("plane", PLANES)
def test_get_serves_exact_and_counts_once(mx, plane):
    """A GET is exactly ONE webdav read op (no phantom stat/write — Fix B/C),
    with exact payload bytes on the read ledger, one 2xx response row, one
    full-object range classification, and one real latency observation."""
    size = 3000 + 10 * PLANES.index(plane)
    name, payload = seed(mx, f"{plane}get", size)
    s = snap(mx)
    st, body, _ = mx.dav_request(plane, f"/{name}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    def _assert_test_get_serves_exact_and_counts_once_1():
        assert st == 200
        assert body == payload

    _assert_test_get_serves_exact_and_counts_once_1()
    io = {"proto": "webdav"}
    assert s.delta("brix_io_ops_total", {**io, "op": "read", "status": "ok"},
                   after) == 1
    for op in ("stat", "write", "delete"):
        assert s.delta("brix_io_ops_total", {**io, "op": op, "status": "ok"},
                       after) == 0, f"phantom {op} on GET"
    def _assert_test_get_serves_exact_and_counts_once_2():
        assert s.delta("brix_io_bytes_read", io, after) == size

    _assert_test_get_serves_exact_and_counts_once_2()
    def _assert_test_get_serves_exact_and_counts_once_3():
        assert s.delta("brix_webdav_requests_total", {"method": "GET"},
                       after) == 1
        assert s.delta("brix_webdav_responses_total",
                       {"method": "GET", "status_class": "2xx"}, after) == 1

    _assert_test_get_serves_exact_and_counts_once_3()
    def _assert_test_get_serves_exact_and_counts_once_4():
        assert s.delta("brix_webdav_range_requests_total", {"result": "full"},
                       after) == 1
        assert s.delta("brix_io_latency_seconds_count", {**io, "op": "read"},
                       after) == 1

    _assert_test_get_serves_exact_and_counts_once_4()


@pytest.mark.parametrize("plane", PLANES)
def test_get_miss_then_hit(mx, plane):
    """First GET of a name is one webdav miss; the immediate re-GET is one
    hit, no second miss, same exact payload."""
    name, payload = seed(mx, f"{plane}mh", 2200)
    s = snap(mx)
    st, body, _ = mx.dav_request(plane, f"/{name}")
    cx.settle()
    mid = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    assert s.cache_delta("webdav", "MISS", mid) == 1
    assert s.cache_delta("webdav", "HIT", mid) == 0

    s2 = snap(mx)
    st2, body2, _ = mx.dav_request(plane, f"/{name}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st2 == 200 and body2 == payload
    assert s2.cache_delta("webdav", "HIT", after) == 1
    assert s2.cache_delta("webdav", "MISS", after) == 0


@pytest.mark.parametrize("plane", PLANES)
def test_head_is_one_stat(mx, plane):
    """HEAD: one stat op, NO read op, no payload bytes, one 2xx HEAD row."""
    name, _ = seed(mx, f"{plane}head", 8192)
    s = snap(mx)
    st, body, hdrs = mx.dav_request(plane, f"/{name}", method="HEAD")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200
    assert body == b""
    ctlen = {k.lower(): v for k, v in hdrs.items()}.get("content-length")
    assert ctlen == "8192"
    io = {"proto": "webdav"}
    assert s.delta("brix_io_ops_total", {**io, "op": "stat", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_ops_total", {**io, "op": "read", "status": "ok"},
                   after) == 0
    assert s.delta("brix_io_bytes_read", io, after) == 0
    assert s.delta("brix_webdav_responses_total",
                   {"method": "HEAD", "status_class": "2xx"}, after) == 1


@pytest.mark.parametrize("plane", PLANES)
def test_get_absent_counts_not_found(mx, plane):
    """404 GET: one read op with status=not_found and one GET 4xx response
    row — and NOT an ok-status read."""
    s = snap(mx)
    st, _, _ = mx.dav_request(plane, f"/{cx.unique_name('ghost')}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 404
    io = {"proto": "webdav"}
    assert s.delta("brix_io_ops_total",
                   {**io, "op": "read", "status": "not_found"}, after) == 1
    assert s.delta("brix_io_ops_total",
                   {**io, "op": "read", "status": "ok"}, after) == 0
    assert s.delta("brix_webdav_responses_total",
                   {"method": "GET", "status_class": "4xx"}, after) == 1


@pytest.mark.parametrize("plane", PLANES)
def test_range_get_partial_exact(mx, plane):
    """Range GET: 206 with exactly the requested bytes, a partial range
    classification, and exactly the served range on the read-byte ledger."""
    name, payload = seed(mx, f"{plane}rng", 8192)
    s = snap(mx)
    st, body, hdrs = mx.dav_request(plane, f"/{name}",
                                    headers={"Range": "bytes=0-999"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 206
    assert body == payload[:1000]
    cr = {k.lower(): v for k, v in hdrs.items()}.get("content-range")
    assert cr == "bytes 0-999/8192"
    assert s.delta("brix_webdav_range_requests_total", {"result": "partial"},
                   after) == 1
    assert s.delta("brix_webdav_range_requests_total", {"result": "full"},
                   after) == 0
    assert s.delta("brix_io_bytes_read", {"proto": "webdav"}, after) == 1000


# --------------------------------------------------------------------------
# PUT — the write path (per-plane auth routes)
# --------------------------------------------------------------------------

def _assert_put_counts(mx, s, after, size):
    io = {"proto": "webdav"}
    assert s.delta("brix_io_ops_total", {**io, "op": "write", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_bytes_written", io, after) == size
    # The body may be committed inline or via the thread pool depending on
    # size/backpressure; exactly ONE body either way.
    assert (s.delta("brix_webdav_put_bodies_total", {"mode": "memory"}, after)
            + s.delta("brix_webdav_put_bodies_total", {"mode": "threaded"},
                      after)) == 1
    assert s.delta("brix_webdav_responses_total",
                   {"method": "PUT", "status_class": "2xx"}, after) == 1
    assert s.delta("brix_io_bytes_written", {"proto": "webdav"}, after) == size
    assert s.delta("brix_io_latency_seconds_count", {**io, "op": "write"},
                   after) == 1


def test_put_dav_anonymous(mx):
    """Anonymous PUT on the plain plane: one write op, exact bytes, one
    in-memory body, one 2xx PUT row, one write-latency observation."""
    import os
    name = cx.unique_name("davput")
    payload = os.urandom(1500)
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{name}", method="PUT", data=payload)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st in (201, 204)
    assert (mx.local_data / name).read_bytes() == payload
    _assert_put_counts(mx, s, after, 1500)


def test_put_davs_bearer_token(mx):
    """Token-authenticated PUT over TLS: same exact accounting plus one
    token_ok auth result."""
    import os
    hdr = bearer(mx)
    name = cx.unique_name("toksput")
    payload = os.urandom(1500)
    s = snap(mx)
    st, _, _ = mx.dav_request("davs", f"/{name}", method="PUT", data=payload,
                              headers=hdr)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st in (201, 204)
    assert (mx.local_data / name).read_bytes() == payload
    _assert_put_counts(mx, s, after, 1500)
    assert s.delta("brix_webdav_auth_total", {"result": "token_ok"},
                   after) >= 1


def test_put_davsg_client_cert(mx):
    """Cert-authenticated PUT: exact accounting plus one cert_ok result."""
    import os
    name = cx.unique_name("certput")
    payload = os.urandom(1200)
    s = snap(mx)
    st, _, _ = mx.dav_request("davsg", f"/{name}", method="PUT", data=payload)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st in (201, 204)
    assert (mx.local_data / name).read_bytes() == payload
    _assert_put_counts(mx, s, after, 1200)
    assert s.delta("brix_webdav_auth_total", {"result": "cert_ok"},
                   after) >= 1


def test_put_file_as_parent_error_accounting(mx):
    """Error leg for the single-counted write path.  A PUT whose parent
    component is a regular FILE cannot publish (missing COLLECTIONS are
    auto-created by design — mkpath — so that is NOT an error path).  The
    failure books exactly one write op with an error status, one 4xx/5xx PUT
    response, zero ok-writes, and zero committed backend bytes."""
    parent = cx.unique_name("fileparent")
    st, _, _ = mx.dav_request("dav", f"/{parent}", method="PUT",
                              data=b"p" * 100)
    assert st in (201, 204)
    cx.settle()
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{parent}/leaf.bin", method="PUT",
                              data=b"e" * 600)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st >= 400
    assert not (mx.local_data / parent / "leaf.bin").exists()
    assert s.delta("brix_io_ops_total",
                   {"proto": "webdav", "op": "write", "status": "ok"},
                   after) == 0
    assert (s.delta("brix_io_ops_total",
                    {"proto": "webdav", "op": "write", "status": "io_error"},
                    after)
            + s.delta("brix_io_ops_total",
                      {"proto": "webdav", "op": "write", "status": "other"},
                      after)) == 1
    assert s.delta("brix_storage_io_bytes_written", {"backend": "cache"},
                   after) == 0
    assert (s.delta("brix_webdav_responses_total",
                    {"method": "PUT", "status_class": "4xx"}, after)
            + s.delta("brix_webdav_responses_total",
                      {"method": "PUT", "status_class": "5xx"}, after)) == 1


def test_put_davsg_without_cert_rejected(mx):
    """Security negative: a PUT withholding the client certificate is 401,
    writes NOTHING to disk, and moves no write op or byte counter."""
    name = cx.unique_name("nocert")
    s = snap(mx)
    st, _, _ = mx.dav_request("davsg", f"/{name}", method="PUT",
                              data=b"n" * 900, cert=False)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 401
    assert not (mx.local_data / name).exists()
    assert s.delta("brix_io_ops_total",
                   {"proto": "webdav", "op": "write", "status": "ok"},
                   after) == 0
    assert s.delta("brix_io_bytes_written", {"proto": "webdav"}, after) == 0


def test_put_davs_without_token_anonymous_accounting(mx):
    """The davs plane runs `brix_webdav_auth optional`: a PUT with no bearer
    (or an unparseable one) is served as ANONYMOUS — calibrated truth is 201,
    not 401.  The accounting must attribute it to auth result
    `anonymous_fallback` (never token_ok) with exactly one write op."""
    name = cx.unique_name("notok")
    s = snap(mx)
    st, _, _ = mx.dav_request("davs", f"/{name}", method="PUT",
                              data=b"x" * 800)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st in (201, 204)
    assert (mx.local_data / name).read_bytes() == b"x" * 800
    assert s.delta("brix_io_ops_total",
                   {"proto": "webdav", "op": "write", "status": "ok"},
                   after) == 1
    assert s.delta("brix_webdav_auth_total", {"result": "anonymous_fallback"},
                   after) >= 1
    assert s.delta("brix_webdav_auth_total", {"result": "token_ok"},
                   after) == 0


# --------------------------------------------------------------------------
# DELETE / write-over-cached — Fix A eviction accounting on the HTTP path
# --------------------------------------------------------------------------

@pytest.mark.parametrize("plane", PLANES)
def test_delete_cached_evicts_exact(mx, plane):
    """DELETE of a cached object: one delete + one stat + two xattr ops
    (sidecar retirement), the EXACT cached bytes on the webdav eviction
    counter, one 2xx DELETE row, object gone from disk and cache."""
    size = 3000 + 100 * PLANES.index(plane)
    name, _ = seed(mx, f"{plane}del", size)
    st, _, _ = mx.dav_request(plane, f"/{name}")      # prime the cache
    assert st == 200
    cx.settle()
    assert cached_copies(mx, name)
    s = snap(mx)
    st, _, _ = mx.dav_request(plane, f"/{name}", method="DELETE")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 204
    io = {"proto": "webdav"}
    assert s.delta("brix_io_ops_total", {**io, "op": "delete", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_ops_total", {**io, "op": "stat", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_ops_total", {**io, "op": "xattr", "status": "ok"},
                   after) == 2
    assert s.delta("brix_cache_bytes_evicted_total", io, after) == size
    assert s.delta("brix_webdav_responses_total",
                   {"method": "DELETE", "status_class": "2xx"}, after) == 1
    assert not (mx.local_data / name).exists()
    assert not cached_copies(mx, name)


def test_put_over_cached_evicts_exact(mx):
    """PUT over a cached name retires the cached copy and accounts its exact
    bytes (Fix A write-open-over-cached, HTTP flavor)."""
    import os
    size = 2700
    name, _ = seed(mx, "davover", size)
    st, _, _ = mx.dav_request("dav", f"/{name}")
    assert st == 200
    cx.settle()
    assert cached_copies(mx, name)
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{name}", method="PUT",
                              data=os.urandom(700))
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st in (201, 204)
    assert s.delta("brix_cache_bytes_evicted_total", {"proto": "webdav"},
                   after) == size
    assert not cached_copies(mx, name)


# --------------------------------------------------------------------------
# PROPFIND — Fix E: responses_total booked from the async body handler
# --------------------------------------------------------------------------

@pytest.mark.parametrize("plane", PLANES)
def test_propfind_207_books_response_row(mx, plane):
    """Fix E success case: PROPFIND is 207 multistatus AND books exactly one
    PROPFIND 2xx response row (the async body handler previously finalized
    without metrics, so requests_total moved while responses_total never did)
    plus one depth-0 classification."""
    name, _ = seed(mx, f"{plane}pf", 1024)
    s = snap(mx)
    st, body, _ = mx.dav_request(plane, f"/{name}", method="PROPFIND",
                                 headers={"Depth": "0"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 207
    assert b"multistatus" in body
    assert s.delta("brix_webdav_requests_total", {"method": "PROPFIND"},
                   after) == 1
    assert s.delta("brix_webdav_responses_total",
                   {"method": "PROPFIND", "status_class": "2xx"}, after) == 1
    assert s.delta("brix_webdav_propfind_depth_total", {"depth": "0"},
                   after) == 1


def test_propfind_absent_books_4xx_row(mx):
    """Fix E error case: PROPFIND of a nonexistent path books one PROPFIND
    4xx response row — not zero rows, not a 2xx."""
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{cx.unique_name('pfghost')}",
                              method="PROPFIND", headers={"Depth": "0"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 404
    assert s.delta("brix_webdav_responses_total",
                   {"method": "PROPFIND", "status_class": "4xx"}, after) == 1
    assert s.delta("brix_webdav_responses_total",
                   {"method": "PROPFIND", "status_class": "2xx"}, after) == 0


def test_propfind_unauthenticated_rejected_and_counted(mx):
    """Fix E security negative: PROPFIND withholding the client cert is 401,
    books the failure response row, and moves NO depth classification (the
    listing never ran)."""
    name, _ = seed(mx, "pfnocert", 1024)
    s = snap(mx)
    st, _, _ = mx.dav_request("davsg", f"/{name}", method="PROPFIND",
                              headers={"Depth": "0"}, cert=False)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 401
    assert s.delta("brix_webdav_responses_total",
                   {"method": "PROPFIND", "status_class": "4xx"}, after) == 1
    assert s.delta("brix_webdav_propfind_depth_total", {"depth": "0"},
                   after) == 0


# --------------------------------------------------------------------------
# Auth-result accounting granularity
# --------------------------------------------------------------------------

def test_dav_auth_none_counted_per_request(mx):
    """The plain plane books one `none` auth result PER REQUEST — three
    requests move it by exactly three."""
    name, _ = seed(mx, "authn", 512)
    s = snap(mx)
    for method in ("GET", "HEAD", "GET"):
        st, _, _ = mx.dav_request("dav", f"/{name}", method=method)
        assert st == 200
    cx.settle()
    assert s.delta("brix_webdav_auth_total", {"result": "none"}) == 3
