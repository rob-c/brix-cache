from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_srv_manifest_helpers")

def test_ims_malformed_date_ignored_200(srv_long):
    s, _, body = _get(_meta_url(srv_long, ".cvmfspublished"),
                      {"If-Modified-Since": "not-a-http-date"})
    assert s == 200
    assert len(body) > 0


def test_head_with_ims_304(srv_long):
    _, hdrs, _ = _get(_meta_url(srv_long, ".cvmfswhitelist"))
    st, _, body = _head(srv_long, ".cvmfswhitelist",
                        {"If-Modified-Since": hdrs.get("Last-Modified")})
    assert st == 304
    assert body == b""


def test_304_advertises_zero_length(srv_long):
    _, hdrs, _ = _get(_meta_url(srv_long, ".cvmfspublished"))
    s, h304, _ = _get(_meta_url(srv_long, ".cvmfspublished"),
                      {"If-Modified-Since": hdrs.get("Last-Modified")})
    assert s == 304
    assert h304.get("Content-Length") == "0"


def test_etag_weak_and_stable_across_hits(srv_long):
    _, h1, _ = _get(_meta_url(srv_long, ".cvmfswhitelist"))
    _, h2, _ = _get(_meta_url(srv_long, ".cvmfswhitelist"))
    assert h1.get("ETag", "").startswith('W/"')
    assert h1.get("ETag") == h2.get("ETag")


def test_ims_on_reflog_webroot_304(web_state):
    srv, _, _ = web_state
    _, hdrs, _ = _get(_meta_url(srv, ".cvmfsreflog"))
    s, _, body = _get(_meta_url(srv, ".cvmfsreflog"),
                      {"If-Modified-Since": hdrs.get("Last-Modified")})
    assert (s, body) == (304, b"")


# ---- G. negative behavior + unknown repositories --------------------------

def test_missing_reflog_404(srv):
    s, _, _ = _get(_meta_url(srv, ".cvmfsreflog"))
    assert s == 404


def test_missing_metadata_not_absorbed_each_request_probes_origin(srv):
    # The T13 negative memo is consulted for CAS-class URLs only (gate.c):
    # a metadata miss is answered per-request off the origin's own 404 —
    # observable as one size-probe HEAD per request, and zero data GETs.
    g0, h0 = srv.count_log(".cvmfsreflog"), _heads_count(srv, ".cvmfsreflog")
    for _ in range(3):
        assert _get(_meta_url(srv, ".cvmfsreflog"))[0] == 404
    assert _heads_count(srv, ".cvmfsreflog") == h0 + 3
    assert srv.count_log(".cvmfsreflog") == g0


@pytest.mark.parametrize("name", NAMES)
def test_unknown_repo_metadata_404(srv, name):
    s, _, _ = _get(_meta_url(srv, name, repo="unknown.example.org"))
    assert s == 404


def test_unknown_repo_does_not_poison_known_repo(srv):
    assert _get(_meta_url(srv, ".cvmfspublished",
                          repo="unknown.example.org"))[0] == 404
    assert _get(_meta_url(srv, ".cvmfspublished"))[0] == 200


def test_unknown_repo_head_404(srv):
    st, _, _ = _head(srv, ".cvmfswhitelist", repo="unknown.example.org")
    assert st == 404


def test_missing_metadata_appears_at_origin_served_promptly(request, tmp_path):
    # No stale-404 for metadata: the miss is re-asked every request, so a
    # freshly published file is visible immediately (no negative window).
    web = tmp_path / "web"
    meta = web / "cvmfs" / REPO
    meta.mkdir(parents=True)
    _write_meta(meta, ".cvmfspublished", b"pub-only\n")
    with ephemeral(webroot=web, manifest_ttl=TTL) as srv:
        assert _get(_meta_url(srv, ".cvmfsreflog"))[0] == 404
        _write_meta(meta, ".cvmfsreflog", b"reflog-appears\n")
        s, _, body = _get(_meta_url(srv, ".cvmfsreflog"))
        assert (s, body) == (200, b"reflog-appears\n")
