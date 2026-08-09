from split_continuation import reexport as _reexport
_reexport(globals(), "_test_ipv6_admin_ratelimit_metrics_helpers")

@pytest.mark.registry_servers("ipv6-mgr", "ipv6-stream")
def test_ipv6_admin_instance_startup():
    """SMOKE: the ipv6-mgr HTTP endpoint answers over [::1] (any HTTP status is
    fine — proves the AF_INET6 listener is up)."""
    _skip_unless_mgr_http()
    status, _hdrs, _body = _http6("GET", MGR_HTTP, "/brix/api/v1/cluster")
    assert status in (200, 401, 403, 404), status


@pytest.mark.registry_servers("ipv6-mgr", "ipv6-stream")
def test_admin_no_bearer_token_admitted_from_loopback():
    """AUTH-MODEL: the ipv6-mgr config authorizes the admin API via a CIDR
    allowlist (``brix_admin_allow ::1/128``) in OR-mode and seeds NO secret
    file, so a request *from* ::1 is admitted regardless of any bearer token
    (brix_admin_check_auth: cidr_ok || secret_ok -> OK).  A register POST with
    no Authorization header therefore succeeds — it is the source IP, not a
    token, that gates this surface.

    NOTE: this is NOT a security regression.  A token-required negative (401/403
    on a missing/wrong bearer) would require a secret-file factor that this
    config deliberately does not wire; the fail-closed property here is the
    CIDR allowlist — a request from a non-allowlisted source is denied (proven
    by the malformed-host fail-closed test and the AND-mode coverage in
    test_phase23_admin_api.py)."""
    _skip_unless_admin_enabled()
    port = 41021
    status, _hdrs, body = _admin(
        "POST", "/cluster/servers", token=None,
        json_body={"host": "::1", "port": port, "paths": "/store"})  # net-literal-allow: admin-API IPv6 host registration payload under test
    assert status == 200, ("loopback admin write must be admitted by the "  # net-literal-allow: ::1/128 CIDR allowlist named in assert message
                           "::1/128 CIDR allowlist without a token", body)
    assert json.loads(body.decode())["result"] == "registered"
    _admin("DELETE", f"/cluster/servers/[::1]/{port}")  # net-literal-allow: admin-API bracket-parse URI under test


@pytest.mark.registry_servers("ipv6-mgr", "ipv6-stream")
def test_admin_wrong_bearer_token_still_admitted_from_loopback():
    """AUTH-MODEL: with the OR-mode CIDR allowlist and no secret configured, a
    *wrong* bearer secret is irrelevant — the request is still admitted because
    it originates from the allowlisted ::1 (the bearer factor is simply not
    configured, so it cannot cause a denial in OR-mode).  Asserts the actual
    auth model rather than a token-rejection that this config never enforces."""
    _skip_unless_admin_enabled()
    port = 41022
    status, _hdrs, body = _admin(
        "POST", "/cluster/servers", token="not-the-secret",
        json_body={"host": "::1", "port": port, "paths": "/store"})  # net-literal-allow: admin-API IPv6 host registration payload under test
    assert status == 200, body
    assert json.loads(body.decode())["result"] == "registered"
    _admin("DELETE", f"/cluster/servers/[::1]/{port}")  # net-literal-allow: admin-API bracket-parse URI under test


@pytest.mark.registry_servers("ipv6-mgr", "ipv6-stream")
def test_admin_api_register_ipv6_host_json_body():
    """REGRESSION: registering a bare ``::1`` host via the JSON body is accepted
    (the hostname whitelist allows ':' for IPv6 literals) and round-trips bare in
    the cluster snapshot."""
    _skip_unless_admin_enabled()
    port = 41001
    status, _hdrs, body = _admin(
        "POST", "/cluster/servers",
        json_body={"host": "::1", "port": port, "paths": "/store",  # net-literal-allow: admin-API IPv6 host registration payload under test
                   "free_mb": 1000, "util_pct": 7})
    assert status == 200, body
    assert json.loads(body.decode())["result"] == "registered"

    cstatus, servers = _cluster_servers()
    assert cstatus == 200, "dashboard cluster snapshot must be readable"
    entry = _find_server(servers, "::1", port)  # net-literal-allow: asserting registry round-trips the bare ::1 we registered
    assert entry is not None, ("registered ::1 not in cluster snapshot", servers)  # net-literal-allow: assert message names the registered ::1
    # The registry stores the address bare — never bracketed.
    assert entry["host"] == "::1"  # net-literal-allow: asserting registry stores the host bare (::1)
    assert "[" not in entry["host"] and "]" not in entry["host"]

    # cleanup so the registry does not accrete across runs
    _admin("DELETE", f"/cluster/servers/[::1]/{port}")  # net-literal-allow: admin-API bracket-parse URI under test


@pytest.mark.registry_servers("ipv6-mgr", "ipv6-stream")
def test_admin_api_register_ipv6_host_via_uri():
    """GATING (api_admin.c:395): POST /cluster/servers/[2001:db8::1]/PORT — the
    bracketed host segment in the request URI is accepted, the brackets are
    stripped, and the member round-trips *bare* (``2001:db8::1``) in the cluster
    snapshot.  PUT to a specific server path is an upsert in the dispatch."""
    _skip_unless_admin_enabled()
    host_bare = "2001:db8::1"
    host_uri = "[2001:db8::1]"
    port = 41002
    status, _hdrs, body = _admin(
        "PUT", f"/cluster/servers/{host_uri}/{port}",
        json_body={"host": host_bare, "port": port, "paths": "/store"})
    assert status == 200, body

    cstatus, servers = _cluster_servers()
    assert cstatus == 200
    entry = _find_server(servers, host_bare, port)
    assert entry is not None, (
        "bracketed-URI register did not round-trip to bare host", servers)
    assert "[" not in entry["host"] and "]" not in entry["host"], entry["host"]

    _admin("DELETE", f"/cluster/servers/{host_uri}/{port}")


@pytest.mark.registry_servers("ipv6-mgr", "ipv6-stream")
def test_admin_api_drain_ipv6_server_uri_bracket_parse():
    """GATING: register ::1, then POST /cluster/servers/[::1]/PORT/drain — the
    bracketed URI is parsed, brackets stripped, and brix_srv_blacklist matches
    the bare ``::1`` entry, which then shows ``draining: true`` in the snapshot."""
    _skip_unless_admin_enabled()
    port = 41003
    reg, _h, rb = _admin("POST", "/cluster/servers",
                         json_body={"host": "::1", "port": port,  # net-literal-allow: admin-API IPv6 host registration payload under test
                                    "paths": "/store"})
    assert reg == 200, rb

    status, _hdrs, body = _admin(
        "POST", f"/cluster/servers/[::1]/{port}/drain",  # net-literal-allow: admin-API bracket-parse URI under test
        json_body={"duration_s": 60})
    assert status == 200, body
    assert json.loads(body.decode())["result"] == "drained"

    _cstatus, servers = _cluster_servers()
    entry = _find_server(servers, "::1", port)  # net-literal-allow: asserting registry round-trips the bare ::1 we registered
    assert entry is not None, servers
    assert entry.get("draining") is True, ("drain via bracketed URI did not "
                                           "match the bare registry host", entry)

    _admin("DELETE", f"/cluster/servers/[::1]/{port}")  # net-literal-allow: admin-API bracket-parse URI under test


@pytest.mark.registry_servers("ipv6-mgr", "ipv6-stream")
def test_admin_api_undrain_ipv6_server_uri_bracket_parse():
    """GATING: a v4-mapped bracketed literal [::ffff:127.0.0.1] in the URI is
    bracket-stripped and round-trips to the bare registry host for drain then
    undrain.  undrain returns 200 only if the bracket-stripped host matched the
    drained entry (brix_srv_undrain reports true)."""
    _skip_unless_admin_enabled()
    host_bare = "::ffff:127.0.0.1"  # net-literal-allow: v4-mapped IPv6 literal under test (bracket-strip)
    host_uri = "[::ffff:127.0.0.1]"  # net-literal-allow: v4-mapped IPv6 literal under test (bracket-strip)
    port = 41004
    reg, _h, rb = _admin("POST", "/cluster/servers",
                         json_body={"host": host_bare, "port": port,
                                    "paths": "/store"})
    assert reg == 200, rb
    dr, _h, _b = _admin("POST", f"/cluster/servers/{host_uri}/{port}/drain",
                        json_body={"duration_s": 60})
    assert dr == 200

    status, _hdrs, body = _admin(
        "POST", f"/cluster/servers/{host_uri}/{port}/undrain")
    assert status == 200, body
    assert json.loads(body.decode())["result"] == "undrained"

    _cstatus, servers = _cluster_servers()
    entry = _find_server(servers, host_bare, port)
    if entry is not None:
        assert entry.get("draining") is False, entry

    _admin("DELETE", f"/cluster/servers/{host_uri}/{port}")


@pytest.mark.registry_servers("ipv6-mgr", "ipv6-stream")
def test_admin_api_remove_ipv6_server_uri():
    """GATING: DELETE /cluster/servers/[2001:db8::42]/PORT — the bracketed host is
    stripped for the canonical-host lookup and the bare entry is removed (absent
    from the subsequent cluster snapshot)."""
    _skip_unless_admin_enabled()
    host_bare = "2001:db8::42"
    host_uri = "[2001:db8::42]"
    port = 41005
    reg, _h, rb = _admin("PUT", f"/cluster/servers/{host_uri}/{port}",
                         json_body={"host": host_bare, "port": port,
                                    "paths": "/store"})
    assert reg == 200, rb
    _cstatus, servers = _cluster_servers()
    assert _find_server(servers, host_bare, port) is not None, servers

    status, _hdrs, body = _admin("DELETE", f"/cluster/servers/{host_uri}/{port}")
    assert status == 200, body
    assert json.loads(body.decode())["result"] == "removed"

    _cstatus, servers = _cluster_servers()
    assert _find_server(servers, host_bare, port) is None, (
        "removed ::-host still present in snapshot", servers)


@pytest.mark.registry_servers("ipv6-mgr", "ipv6-stream")
def test_admin_api_all_cluster_operations_ipv6_hosts():
    """GATING: full lifecycle register -> snapshot -> drain -> undrain -> remove
    using bracketed [::1] URIs end-to-end, asserting consistent bracket handling
    (every operation matches the same bare registry entry)."""
    _skip_unless_admin_enabled()
    host_uri = "[::1]"  # net-literal-allow: admin-API bracketed URI under test
    port = 41006

    assert _admin("PUT", f"/cluster/servers/{host_uri}/{port}",
                  json_body={"host": "::1", "port": port,  # net-literal-allow: admin-API IPv6 host registration payload under test
                             "paths": "/store"})[0] == 200

    _cstatus, servers = _cluster_servers()
    assert _find_server(servers, "::1", port) is not None, servers  # net-literal-allow: asserting registry round-trips the bare ::1 we registered

    assert _admin("POST", f"/cluster/servers/{host_uri}/{port}/drain",
                  json_body={"duration_s": 30})[0] == 200
    _cstatus, servers = _cluster_servers()
    assert _find_server(servers, "::1", port).get("draining") is True  # net-literal-allow: asserting registry round-trips the bare ::1 we registered

    assert _admin("POST", f"/cluster/servers/{host_uri}/{port}/undrain")[0] == 200
    assert _admin("DELETE", f"/cluster/servers/{host_uri}/{port}")[0] == 200

    _cstatus, servers = _cluster_servers()
    assert _find_server(servers, "::1", port) is None, servers  # net-literal-allow: asserting registry round-trips the bare ::1 we registered


@pytest.mark.registry_servers("ipv6-mgr", "ipv6-stream")
def test_admin_api_ipv6_host_validation_rejects_malformed():
    """SECURITY-NEG: a shell-injection-y / malformed host is rejected (400
    invalid_field) by the whitelist, never sanitised — same fail-closed behaviour
    for IPv6-adjacent inputs."""
    _skip_unless_admin_enabled()
    status, _hdrs, body = _admin(
        "POST", "/cluster/servers",
        json_body={"host": "::1;rm -rf/", "port": 1094, "paths": "/store"})  # net-literal-allow: shell-injection host payload under test
    assert status == 400, body
    assert json.loads(body.decode())["error"] == "invalid_field"


# =========================================================================== #
# Group B — rate limiting keyed by IPv6 client IP               [REGRESSION]   #
# =========================================================================== #

@pytest.mark.registry_servers("ipv6-mgr", "ipv6-stream")
def test_ratelimit_ipv6_stream_smoke_or_throttle():
    """REGRESSION: drive repeated rate-limited opcodes (kXR_open) from a single
    IPv6 client on the stream instance.  ratelimit_keys.c builds the bucket key
    from the bare ``peer_ip`` (``::1``); IPv6 already works.

    The ipv6-stream config may or may not carry a rate-limit rule (it is owned by
    the stream agent).  This is therefore tolerant: if a rule is present the burst
    is spent and we observe kXR_wait; if not, every op simply succeeds.  Either
    way the IPv6 peer is keyed without error and the session stays coherent."""
    _skip_unless_stream()
    s = _login_session6(STREAM)
    try:
        statuses = []
        for _ in range(12):
            st, _b = _open(s, "/test.txt")
            statuses.append(st)
        # No protocol-level breakage: every reply is either ok or a clean wait,
        # never a transport error / garbage status.
        assert all(st in (kXR_ok, kXR_wait) for st in statuses), statuses
        # A liveness ping still round-trips (the IPv6-keyed gate didn't wedge).
        assert _ping(s)[0] in (kXR_ok, kXR_wait)
    finally:
        s.close()


@pytest.mark.registry_servers("ipv6-mgr", "ipv6-stream")
def test_ratelimit_ipv6_stat_not_wedged():
    """REGRESSION: kXR_stat is exempt from rate limiting; many stats in a row from
    the IPv6 peer never return kXR_wait (and the IPv6 peer key never errors)."""
    _skip_unless_stream()
    s = _login_session6(STREAM)
    try:
        for _ in range(10):
            st, _b = _stat(s, "/test.txt")
            assert st != kXR_wait, ("stat must never be throttled", st)
    finally:
        s.close()


@pytest.mark.registry_servers("ipv6-mgr", "ipv6-stream")
def test_ratelimit_ipv6_no_raw_address_in_metric_labels():
    """REGRESSION / invariant #8: after driving IPv6 stream traffic, scraping
    /metrics over [::1] must not surface a raw IPv6 client address in any label —
    rate-limit/connection accounting keys the bucket internally but never emits
    the peer IP as a low-cardinality label."""
    _skip_unless_stream()
    _skip_unless_mgr_http()
    # Generate a little IPv6 stream activity first.
    s = _login_session6(STREAM)
    try:
        for _ in range(4):
            _stat(s, "/test.txt")
    finally:
        s.close()

    status, hdrs, body = _http6("GET", MGR_HTTP, "/metrics")
    if status == 404:
        pytest.skip("ipv6-mgr config does not expose /metrics")
    assert status == 200, status
    _assert_no_raw_ipv6_in_metric_labels(body.decode("utf-8", "replace"))


# =========================================================================== #
# Group C — /metrics scrapeable over [::1], bounded label cardinality          #
#                                                               [REGRESSION]   #
# =========================================================================== #


@pytest.mark.registry_servers("ipv6-mgr", "ipv6-stream")
def test_metrics_ipv6_endpoint_scrapeable():
    """REGRESSION: GET /metrics over [::1] returns 200 text/plain with Prometheus
    HELP/TYPE headers — the metrics writer serves correctly on an AF_INET6
    listener."""
    _skip_unless_mgr_http()
    status, hdrs, body = _http6("GET", MGR_HTTP, "/metrics")
    if status == 404:
        pytest.skip("ipv6-mgr config does not expose /metrics")
    assert status == 200, status
    assert "text/plain" in hdrs.get("content-type", ""), hdrs
    text = body.decode("utf-8", "replace")
    assert "# HELP " in text and "# TYPE " in text, "missing Prometheus headers"


@pytest.mark.registry_servers("ipv6-mgr", "ipv6-stream")
def test_metrics_ipv6_no_raw_address_in_labels():
    """REGRESSION / invariant #8: NO metric label value over [::1] contains a raw
    IPv6 address (neither ``::1`` nor any ``[..]`` bracketed literal)."""
    _skip_unless_mgr_http()
    status, _hdrs, body = _http6("GET", MGR_HTTP, "/metrics")
    if status == 404:
        pytest.skip("ipv6-mgr config does not expose /metrics")
    assert status == 200, status
    _assert_no_raw_ipv6_in_metric_labels(body.decode("utf-8", "replace"))
