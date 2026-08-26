from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_srv_http_helpers")

pytestmark = pytest.mark.xdist_group("test_cvmfs_conformance_srv_http")

def test_manifest_unsatisfiable_416(srv, manifest):
    path, ref = manifest
    st, _, body = GET(srv, path, {"Range": f"bytes={len(ref)}-"})
    assert st == 416 and body == b""


def test_manifest_head_parity(srv, manifest):
    path, ref = manifest
    st, hdrs, body = HEAD(srv, path)
    assert st == 200 and body == b""
    assert int(hdrs["content-length"]) == len(ref)


def test_manifest_ims_future_304(srv, manifest):
    path, _ = manifest
    st, _, body = GET(srv, path, {"If-Modified-Since": FUTURE})
    assert st == 304 and body == b""


# ============================================================================
# Content-Length exactness + misc surface
# ============================================================================

def test_cached_200_content_length_and_identity(srv, big):
    path, ref = big
    st, hdrs, body = GET(srv, path)
    assert_200_full(ref, st, hdrs, body)


def test_accept_ranges_advertised(srv, big):
    """Apache/official Stratum-1 advertises `Accept-Ranges: bytes`; brix sets
    r->allow_ranges so nginx's range header filter stamps it on plain 200s."""
    path, _ = big
    st, hdrs, _ = GET(srv, path)
    assert st == 200
    assert hdrs.get("accept-ranges") == "bytes"


def test_range_header_on_http10(srv, big):
    """HTTP/1.0 request with a Range header still gets a correct 206 (ranges
    are defined for 1.0 clients too; Apache serves them)."""
    path, ref = big
    st, hdrs, body = request(HOST, srv.nginx_port, "GET", path,
                             {"Range": "bytes=0-3"}, version="HTTP/1.0")
    assert_206(ref, st, hdrs, body, 0, 3)
