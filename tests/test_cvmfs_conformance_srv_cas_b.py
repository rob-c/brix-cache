from split_continuation import reexport as _reexport
def _expression_1():
    return (
        [missing_path(f"slots-{i}") for i in range(8)]
    )


def _check_test_distinct_missing_uris_each_absorbed_independently_1(srv, p):
    assert GET(srv, p)[0] == 404

def _check_test_distinct_missing_uris_each_absorbed_independently_2(srv, p):
    assert GET(srv, p)[0] == 404

def _check_test_distinct_missing_uris_each_absorbed_independently_3(srv, p):
    assert count_heads(srv, p) == 1


_reexport(globals(), "_test_cvmfs_conformance_srv_cas_helpers")

def test_negative_ttl_expiry_reconsults_origin(srv):
    p = missing_path("ttl-expiry")
    srv.reset_log()
    assert GET(srv, p)[0] == 404
    assert GET(srv, p)[0] == 404          # inside TTL: absorbed
    assert count_heads(srv, p) == 1
    time.sleep(NEG_TTL + 2)   # +2: ngx_time() is event-loop cached, 1s granular
    assert GET(srv, p)[0] == 404          # after TTL: origin consulted again
    assert count_heads(srv, p) == 2


def test_absorbed_404_has_no_origin_traffic_at_all(srv):
    # Neither a data GET nor a HEAD probe may leave the cache on a memo hit.
    p = missing_path("no-traffic")
    assert GET(srv, p)[0] == 404
    srv.reset_log()
    heads_before = len(srv.get_heads())
    assert GET(srv, p)[0] == 404
    assert GET(srv, p, method="HEAD")[0] == 404
    assert srv.count_log(p) == 0
    assert len(srv.get_heads()) == heads_before


def test_distinct_missing_uris_each_absorbed_independently(srv):
    paths = _expression_1()
    srv.reset_log()
    for p in paths:                        # first pass: 8 origin 404s
        _check_test_distinct_missing_uris_each_absorbed_independently_1(srv, p)
    for p in paths:                        # second pass: all absorbed
        _check_test_distinct_missing_uris_each_absorbed_independently_2(srv, p)
    for p in paths:
        _check_test_distinct_missing_uris_each_absorbed_independently_3(srv, p)


def test_object_appearing_within_ttl_still_absorbed(web):
    # The memo answers for the full negative_ttl even once the origin HAS the
    # object — bounded staleness is the contract that makes absorption safe.
    body = body_for("appear-early")
    hx = hashlib.sha1(body).hexdigest()
    path = f"/cvmfs/{REPO}/data/{hx[:2]}/{hx[2:]}"
    web.reset_log()
    assert GET(web, path)[0] == 404       # miss memoized at origin
    put_obj(web, body)                    # object appears immediately
    assert GET(web, path)[0] == 404, "memo bypassed inside negative_ttl"
    assert count_heads(web, path) == 1
    assert web.count_log(path) == 0       # no data GET ever left the cache


def test_object_appearing_after_ttl_expiry_becomes_servable(web):
    body = body_for("appear-late")
    hx = hashlib.sha1(body).hexdigest()
    path = f"/cvmfs/{REPO}/data/{hx[:2]}/{hx[2:]}"
    web.reset_log()
    assert GET(web, path)[0] == 404
    put_obj(web, body)
    time.sleep(NEG_TTL + 2)   # +2: ngx_time() is event-loop cached, 1s granular
    status, _, got = GET(web, path)
    assert status == 200 and got == body, "published object still 404 after memo expiry"
    assert GET(web, path)[2] == body      # and it caches normally
    assert web.count_log(path) == 1       # exactly one data fill
    assert count_heads(web, path) == 2    # the 404 probe + the fill's size probe
