from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_srv_config_helpers")

@pytest.mark.parametrize("directive, needle", _INCOMPATIBLE)
def test_incompatible_directive_rejected_with_cvmfs(cc, directive, needle):
    """brix_cvmfs_reject_unsupported: EMERG at config load, never a silent no-op."""
    cc.fails(cc.base + directive.format(stage=cc.stage), needle)


@pytest.mark.parametrize("directive, needle", _INCOMPATIBLE)
def test_incompatible_directive_without_cvmfs_loads(cc, directive, needle):
    """Control rows: the same directives are legal grammar outside cvmfs."""
    cc.ok(directive.format(stage=cc.stage))


# -- structural layering contracts ------------------------------------------

def test_scvmfs_requires_cvmfs(cc):
    cc.fails("brix_scvmfs on;", "brix_scvmfs requires brix_cvmfs on")


def test_scvmfs_bearer_requires_token_issuers(cc):
    cc.fails(cc.base + "brix_scvmfs on; brix_scvmfs_authz bearer;",
             "brix_scvmfs_authz bearer requires brix_scvmfs_token_issuers")


def test_scvmfs_authz_none_needs_no_issuers(cc):
    cc.ok(cc.base + "brix_scvmfs on; brix_scvmfs_authz none;")


def test_unified_origin_requires_http_backend(cc):
    cc.fails(f"brix_cvmfs on; brix_cache_store posix:{cc.cache}; "
             "brix_cvmfs_unified_origin on;",
             "brix_cvmfs_unified_origin on requires brix_storage_backend "
             "to name an http(s) origin set")


def test_unified_origin_with_http_backend_loads(cc):
    cc.ok(cc.base + "brix_cvmfs_unified_origin on;")


def test_unified_origin_multi_endpoint_loads(cc):
    cc.ok(f"brix_cvmfs on; brix_cache_store posix:{cc.cache}; "
          'brix_storage_backend "http://127.0.0.1:9|http://127.0.0.1:8"; '  # net-literal-allow: config-load-only origin endpoints, never dialled by nginx -t
          "brix_cvmfs_unified_origin on;")


# -- duplicate rejection: full single-shot directive inventory ---------------
# Every directive from directives_core.h + directives_resilience.h except
# the two accumulators (upstream_allow, origin_coords).  A passing row proves
# both that the directive exists with this sample value AND that the second
# occurrence is refused ("is duplicate").

_SINGLE_SHOT = [
    ("brix_cvmfs", "on"),
    ("brix_scvmfs", "on"),
    ("brix_scvmfs_authz", "none"),
    ("brix_scvmfs_token_issuers", "/tmp/scitokens.cfg"),
    ("brix_cvmfs_manifest_ttl", "61"),
    ("brix_cvmfs_negative_ttl", "10"),
    ("brix_cvmfs_quarantine_dir", "/tmp/quarantine"),
    ("brix_cvmfs_upstream_max", "8"),
    ("brix_cvmfs_trace", "off"),
    ("brix_cvmfs_origin_select", "rtt"),
    ("brix_cvmfs_here", "55.9:-3.2"),
    ("brix_cvmfs_client_hold", "25"),
    ("brix_cvmfs_fill_max_life", "300"),
    ("brix_cvmfs_rtt_interval", "60"),
    ("brix_cvmfs_origin_connect_timeout", "2"),
    ("brix_cvmfs_origin_stall_timeout", "4"),
    ("brix_cvmfs_origin_stall_bytes", "1"),
    ("brix_cvmfs_origin_attempt_timeout", "0"),
    ("brix_cvmfs_shared_cache", "off"),
    ("brix_cvmfs_unified_origin", "off"),
    ("brix_cvmfs_origin_reuse_conn", "on"),
    ("brix_cvmfs_fill_retry_policy", "failover"),
    ("brix_cvmfs_geo_answer", "off"),
    ("brix_cvmfs_geo_cache_ttl", "60"),
    ("brix_cvmfs_geo_max_servers", "16"),
]


@pytest.mark.parametrize("directive, value", _SINGLE_SHOT,
                         ids=[d for d, _ in _SINGLE_SHOT])
def test_duplicate_directive_rejected(cc, directive, value):
    cc.fails(f"{directive} {value}; {directive} {value};",
             f'"{directive}" directive is duplicate')


@pytest.mark.parametrize("directives", [
    pytest.param("brix_cvmfs_upstream_allow a.example b.example; "
                 "brix_cvmfs_upstream_allow c.example;", id="upstream_allow"),
    pytest.param("brix_cvmfs_origin_coords 127.0.0.1 46.2:6.1; "  # net-literal-allow: config-load-only origin-coords host, never dialled by nginx -t
                 "brix_cvmfs_origin_coords 127.0.0.2 55.9:-3.2;", id="origin_coords"),
])
def test_accumulating_directive_repeats_load(cc, directives):
    """The two list directives deliberately accumulate across repeats."""
    cc.ok(cc.base + directives)


# -- bad values --------------------------------------------------------------

@pytest.mark.parametrize("directives, needle", [
    pytest.param("brix_cvmfs banana;", 'it must be "on" or "off"', id="flag-junk"),
    pytest.param("brix_cvmfs_manifest_ttl -1;", "invalid value", id="manifest_ttl-neg"),
    pytest.param("brix_cvmfs_negative_ttl banana;", "invalid value", id="negative_ttl-junk"),
    pytest.param("brix_cvmfs_client_hold 5wq;", "invalid value", id="client_hold-junk"),
    pytest.param("brix_cvmfs_geo_cache_ttl -3;", "invalid value", id="geo_cache_ttl-neg"),
    pytest.param("brix_cvmfs_origin_select bogus;", "invalid value", id="origin_select-enum"),
    pytest.param("brix_cvmfs_geo_answer bogus;", "invalid value", id="geo_answer-enum"),
    pytest.param("brix_cvmfs_fill_retry_policy bogus;", "invalid value",
                 id="fill_retry_policy-enum"),
    pytest.param("brix_scvmfs_authz bogus;", "invalid value", id="scvmfs_authz-enum"),
    pytest.param("brix_cvmfs_upstream_max banana;", "invalid number", id="upstream_max-junk"),
    pytest.param("brix_cvmfs_upstream_max -1;", "invalid number", id="upstream_max-neg"),
    pytest.param("brix_cvmfs_geo_max_servers banana;", "invalid number",
                 id="geo_max_servers-junk"),
    pytest.param("brix_cvmfs_origin_stall_bytes banana;", "invalid number",
                 id="stall_bytes-junk"),
    pytest.param("brix_cvmfs_trace banana;", 'it must be "on" or "off"', id="trace-junk"),
])
def test_bad_value_rejected(cc, directives, needle):
    cc.fails(directives, needle)


@pytest.mark.parametrize("args, needle", [
    pytest.param("h1 91:0", "has invalid <lat>:<lon> coordinates", id="lat-over-90"),
    pytest.param("h1 0:181", "has invalid <lat>:<lon> coordinates", id="lon-over-180"),
    pytest.param("h1 46.2", "has invalid <lat>:<lon> coordinates", id="no-colon"),
    pytest.param("h1:0 1:1", "has an invalid port", id="port-0"),
    pytest.param("h1:70000 1:1", "has an invalid port", id="port-over-65535"),
    pytest.param("h1:banana 1:1", "has an invalid port", id="port-junk"),
    pytest.param("h1", "invalid number of arguments", id="one-arg"),
])
def test_origin_coords_bad_args_rejected(cc, args, needle):
    cc.fails(f"brix_cvmfs_origin_coords {args};", needle)


# -- geo-mode structural requirements ----------------------------------------

def test_geo_select_requires_here(cc):
    cc.fails(cc.base + "brix_cvmfs_origin_select geo;",
             "brix_cvmfs_origin_select geo requires brix_cvmfs_here")


def test_geo_select_rejects_malformed_here(cc):
    """brix_cvmfs_here is a plain str slot; geo mode validates it at merge."""
    cc.fails(cc.base + "brix_cvmfs_origin_select geo; brix_cvmfs_here banana;",
             "brix_cvmfs_origin_select geo requires brix_cvmfs_here")


def test_geo_select_requires_origin_coords(cc):
    cc.fails(cc.base + "brix_cvmfs_origin_select geo; brix_cvmfs_here 55.9:-3.2;",
             "requires one brix_cvmfs_origin_coords per configured origin")


def test_geo_full_config_loads(cc):
    cc.ok(cc.base + "brix_cvmfs_origin_select geo; brix_cvmfs_here 55.9:-3.2; "
          "brix_cvmfs_origin_coords 127.0.0.1 46.2:6.1;")  # net-literal-allow: config-load-only origin-coords host, never dialled by nginx -t


def test_coords_without_geo_mode_warns_but_loads(cc):
    """Coords in non-geo mode: loads OK with the ignored-coordinates WARN."""
    out = cc.ok(cc.base + "brix_cvmfs_origin_coords 127.0.0.1 1:1;")  # net-literal-allow: config-load-only origin-coords host, never dialled by nginx -t
    assert "coordinates are ignored" in out


# -- valid corner values ------------------------------------------------------

@pytest.mark.parametrize("directives", [
    pytest.param("brix_cvmfs_manifest_ttl 0;", id="manifest_ttl-0"),
    pytest.param("brix_cvmfs_negative_ttl 0;", id="negative_ttl-0"),
    pytest.param("brix_cvmfs_upstream_max 1;", id="upstream_max-1"),
    pytest.param("brix_cvmfs_geo_max_servers 1;", id="geo_max_servers-1"),
    pytest.param("brix_cvmfs_origin_attempt_timeout 0;", id="attempt_timeout-0"),
    pytest.param("brix_cvmfs_origin_stall_bytes 0;", id="stall_bytes-0"),
    pytest.param("brix_cvmfs_origin_coords 127.0.0.1:8000 -90:180;",  # net-literal-allow: config-load-only origin-coords host:port, never dialled by nginx -t
                 id="coords-boundary-latlon-with-port"),
])
def test_corner_value_loads(cc, directives):
    cc.ok(cc.base + directives)


def test_full_inventory_single_config_loads(cc):
    """Every brix_cvmfs*/brix_scvmfs* directive once, valid values, one load."""
    every = " ".join(f"{d} {v};" for d, v in _SINGLE_SHOT
                     if d not in ("brix_cvmfs", "brix_cvmfs_origin_select",
                                  "brix_scvmfs", "brix_scvmfs_authz",
                                  "brix_scvmfs_token_issuers"))
    cc.ok(cc.base + every
          + " brix_cvmfs_origin_select geo;"
          + " brix_cvmfs_origin_coords 127.0.0.1 46.2:6.1;"  # net-literal-allow: config-load-only origin-coords host, never dialled by nginx -t
          + " brix_cvmfs_upstream_allow a.example;")


# ---------------------------------------------------------------------------
# Half B — live behavior: scvmfs authz matrix, public-by-design, read-only
# ---------------------------------------------------------------------------


@requires_tokens
@requires_openssl
def test_bearer_missing_token_401(bearer_srv):
    status, _ = _tls_fetch(bearer_srv.nginx_port, bearer_srv.objects()[0])
    assert status == 401


@requires_tokens
@requires_openssl
def test_bearer_garbage_token_401(bearer_srv):
    status, _ = _tls_fetch(bearer_srv.nginx_port, bearer_srv.objects()[0],
                           token="not.a.token")
    assert status == 401


@requires_tokens
@requires_openssl
def test_bearer_non_bearer_scheme_401(bearer_srv):
    """A non-Bearer Authorization scheme is no credential at all (NGX_DECLINED)."""
    status, _ = _tls_fetch(bearer_srv.nginx_port, bearer_srv.objects()[0],
                           headers={"Authorization": "Basic dXNlcjpwdw=="})
    assert status == 401


@requires_tokens
@requires_openssl
def test_bearer_corrupt_signature_401(bearer_srv, mint):
    forge, _ = mint
    status, _ = _tls_fetch(bearer_srv.nginx_port, bearer_srv.objects()[0],
                           token=forge.generate_bad_signature())
    assert status == 401


@requires_tokens
@requires_openssl
def test_bearer_expired_token_401(bearer_srv, mint):
    forge, _ = mint
    status, _ = _tls_fetch(bearer_srv.nginx_port, bearer_srv.objects()[0],
                           token=forge.generate_expired())
    assert status == 401


@requires_tokens
@requires_openssl
def test_bearer_unknown_issuer_401(bearer_srv, mint):
    forge, _ = mint
    status, _ = _tls_fetch(bearer_srv.nginx_port, bearer_srv.objects()[0],
                           token=forge.for_issuer("https://evil.example.com"))
    assert status == 401


@requires_tokens
@requires_openssl
def test_bearer_write_only_scope_401(bearer_srv, mint):
    """secure.c validates BRIX_TOKEN_OP_READ; a create-only scope must not read."""
    forge, _ = mint
    status, _ = _tls_fetch(bearer_srv.nginx_port, bearer_srv.objects()[0],
                           token=forge.generate(scope="storage.create:/"))
    assert status == 401


@requires_tokens
@requires_openssl
def test_bearer_valid_token_serves_exact_bytes(bearer_srv, mint):
    forge, _ = mint
    obj = bearer_srv.objects()[0]
    status, body = _tls_fetch(bearer_srv.nginx_port, obj, token=forge.generate())
    assert status == 200
    assert body == _origin_bytes(bearer_srv, obj)


@requires_tokens
@requires_openssl
def test_bearer_valid_token_head(bearer_srv, mint):
    forge, _ = mint
    status, body = _tls_fetch(bearer_srv.nginx_port, bearer_srv.objects()[1],
                              token=forge.generate(), method="HEAD")
    assert status == 200 and body == b""


@requires_tokens
@requires_openssl
def test_bearer_auth_does_not_grant_write(bearer_srv, mint):
    """Read-only is structural: a valid token cannot turn PUT into a write."""
    forge, _ = mint
    target = f"/cvmfs/{REPO}/data/ab/" + "cd" * 19
    status, _ = _tls_fetch(bearer_srv.nginx_port, target,
                           token=forge.generate(scope="storage.modify:/ storage.read:/"),
                           method="PUT")
    assert status >= 400
    status, _ = _tls_fetch(bearer_srv.nginx_port, target, token=forge.generate())
    assert status == 404, "PUT must never materialize an object"


# -- scvmfs authz none: TLS parity, auth adds nothing ------------------------

@requires_openssl
def test_scvmfs_none_serves_anonymously(none_srv):
    obj = none_srv.objects()[0]
    status, body = _tls_fetch(none_srv.nginx_port, obj)
    assert status == 200 and body == _origin_bytes(none_srv, obj)


@requires_openssl
def test_scvmfs_none_random_auth_header_changes_nothing(none_srv):
    obj = none_srv.objects()[0]
    anon = _tls_fetch(none_srv.nginx_port, obj)
    authed = _tls_fetch(none_srv.nginx_port, obj,
                        headers={"Authorization": "Bearer garbage.garbage.garbage"})
    assert anon == authed == (200, _origin_bytes(none_srv, obj))


# -- scvmfs transport gate ----------------------------------------------------

@requires_openssl
def test_plain_http_to_scvmfs_tls_port_refused(none_srv):
    """Cleartext HTTP on the ssl listener: nginx core 400s the plain request."""
    status, _, _ = request(HOST, none_srv.nginx_port, "GET",
                           none_srv.objects()[0])
    assert status == 400


def test_scvmfs_on_plain_listener_400(scvmfs_plain_srv):
    """secure.c: no r->connection->ssl -> 400 even when the listener itself is
    plain (config loads; the transport requirement is enforced per request)."""
    status, _, _ = request(HOST, scvmfs_plain_srv.nginx_port, "GET",
                           scvmfs_plain_srv.objects()[0])
    assert status == 400


# -- public-by-design (scvmfs off): auth adds nothing -------------------------

def test_public_anonymous_equals_authorized_object(plain_srv):
    obj = plain_srv.objects()[0]
    anon = request(HOST, plain_srv.nginx_port, "GET", obj)
    authed = request(HOST, plain_srv.nginx_port, "GET", obj,
                     headers={"Authorization": "Bearer whatever.some.token"})
    assert anon[0] == authed[0] == 200
    assert anon[2] == authed[2] == _origin_bytes(plain_srv, obj)


def test_public_anonymous_equals_authorized_manifest(plain_srv):
    path = f"/cvmfs/{REPO}/.cvmfspublished"
    anon = request(HOST, plain_srv.nginx_port, "GET", path)
    authed = request(HOST, plain_srv.nginx_port, "GET", path,
                     headers={"Authorization": "Basic dXNlcjpwdw=="})
    assert anon[0] == authed[0] == 200 and anon[2] == authed[2]


# -- forced read-only: mutating methods never mutate --------------------------

def test_put_never_creates_object(plain_srv):
    target = f"/cvmfs/{REPO}/data/ab/" + "ef" * 19
    status, _, _ = request(HOST, plain_srv.nginx_port, "PUT", target,
                           body=b"evil payload")
    assert status >= 400, f"PUT must be refused, got {status}"
    status, _, _ = request(HOST, plain_srv.nginx_port, "GET", target)
    assert status == 404, "PUT body must never materialize"
