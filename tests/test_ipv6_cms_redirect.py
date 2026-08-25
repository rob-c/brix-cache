from split_continuation import reexport as _reexport
_reexport(globals(), "_test_ipv6_cms_redirect_helpers")

# Every test registers/drains/undrains servers in the ONE ipv6-mgr registry;
# interleaved across workers, a drain from one test empties the cluster under
# another's locate (kXR_error 3011 instead of the redirect).
pytestmark = pytest.mark.xdist_group("ipv6-mgr")

class TestAdminBracketStrip:
    """dashboard/api_admin.c:admin_parse_server_uri must strip the "[...]" from
    an IPv6 host segment sent in the REST URI so it matches the registry's bare
    canonical host.  GATING: the bracketed URI must be accepted (200), not 400."""

    @pytest.mark.registry_server("ipv6-mgr")
    def test_admin_register_ipv6_host_json_body(self):
        """REGRESSION/SMOKE: bare-literal host in the JSON body registers (the
        registry stores the address canonically bare)."""
        _skip_if_http_down()
        status, data = _register_ipv6_server(DS_PORT)
        assert status == 200, data
        assert isinstance(data, dict) and data.get("result") == "registered", data

    @pytest.mark.registry_server("ipv6-mgr")
    def test_admin_drain_ipv6_host_uri_bracket_parse(self):
        """GATING: POST /cluster/servers/[::1]/PORT/drain — the bracketed host
        segment is split + stripped, so the drain targets the bare "::1" entry
        and returns 200 (bad/unstripped parse would 400 bad_uri)."""
        _skip_if_http_down()
        _register_ipv6_server(DS_PORT)
        status, data = _admin(
            "POST", f"{_ADMIN_BASE}/cluster/servers/[{IPV6_HOST}]/{DS_PORT}/drain",
            body={"duration_s": 30})
        assert status == 200, data
        assert isinstance(data, dict) and data.get("result") == "drained", data

    @pytest.mark.registry_server("ipv6-mgr")
    def test_admin_undrain_ipv6_host_uri_bracket_parse(self):
        """GATING: POST /cluster/servers/[::1]/PORT/undrain after a drain — the
        bracket-stripped host matches the drained entry (200 undrained).  A
        404 not_found would mean the strip failed and the host never matched."""
        _skip_if_http_down()
        _register_ipv6_server(DS_PORT)
        _admin("POST",
               f"{_ADMIN_BASE}/cluster/servers/[{IPV6_HOST}]/{DS_PORT}/drain",
               body={"duration_s": 30})
        status, data = _admin(
            "POST",
            f"{_ADMIN_BASE}/cluster/servers/[{IPV6_HOST}]/{DS_PORT}/undrain")
        assert status == 200, data
        assert isinstance(data, dict) and data.get("result") == "undrained", data

    @pytest.mark.registry_server("ipv6-mgr")
    def test_admin_remove_ipv6_host_uri_bracket_parse(self):
        """GATING: DELETE /cluster/servers/[::1]/PORT — canonical (bracket-
        stripped) host lookup removes the entry (200 removed)."""
        _skip_if_http_down()
        _register_ipv6_server(DS_PORT)
        status, data = _admin(
            "DELETE", f"{_ADMIN_BASE}/cluster/servers/[{IPV6_HOST}]/{DS_PORT}")
        assert status == 200, data
        assert isinstance(data, dict) and data.get("result") == "removed", data

    @pytest.mark.registry_server("ipv6-mgr")
    def test_admin_register_full_lifecycle_ipv6_uris(self):
        """GATING: end-to-end register -> drain -> undrain -> remove using
        bracketed [::1] URIs throughout; every step round-trips a consistently
        bracket-stripped host."""
        _skip_if_http_down()
        assert _register_ipv6_server(DS_PORT)[0] == 200
        base = f"{_ADMIN_BASE}/cluster/servers/[{IPV6_HOST}]/{DS_PORT}"
        assert _admin("POST", f"{base}/drain", body={"duration_s": 30})[0] == 200
        assert _admin("POST", f"{base}/undrain")[0] == 200
        assert _admin("DELETE", base)[0] == 200

    @pytest.mark.registry_server("ipv6-mgr")
    def test_admin_malformed_ipv6_uri_rejected(self):
        """SECURITY-NEG: a non-numeric port segment -> 400 bad_uri; the parser
        rejects, never half-accepts a malformed bracketed URI."""
        _skip_if_http_down()
        status, data = _admin(
            "DELETE", f"{_ADMIN_BASE}/cluster/servers/[{IPV6_HOST}]/not-a-port")
        assert status == 400, data
        assert isinstance(data, dict) and data.get("error") in (
            "bad_uri", "invalid_field"), data


# ===========================================================================
# 2. Read-only dashboard JSON round-trips the IPv6 host (GATING-adjacent)
# ===========================================================================

class TestDashboardClusterRoundTrip:
    """GET /brix/api/v1/cluster (dashboard/api.c:dashboard_fill_cluster) must
    round-trip the registered IPv6 host in the "servers" array unmangled."""

    @pytest.mark.registry_server("ipv6-mgr")
    def test_cluster_json_contains_registered_ipv6_host(self):
        """GATING: register [::1]:DS, then the cluster JSON lists a server whose
        "host" is the bare canonical "::1" at the right port — proving the host
        survived store + JSON serialization without corruption."""
        _skip_if_http_down()
        assert _register_ipv6_server(DS_PORT)[0] == 200

        cookie = _dashboard_cookie()
        if cookie is None:
            pytest.skip("dashboard login did not set a session cookie")
        status, data = _dashboard_get("/brix/api/v1/cluster", cookie)
        def _assert_test_cluster_json_contains_registered_ipv6_host_1():
            assert status == 200, data
            assert isinstance(data, dict), data

        _assert_test_cluster_json_contains_registered_ipv6_host_1()
        servers = data.get("servers", [])
        assert isinstance(servers, list), data
        match = [s for s in servers
                 if s.get("host") == IPV6_HOST and s.get("port") == DS_PORT]
        def _assert_test_cluster_json_contains_registered_ipv6_host_2():
            assert match, f"registered [{HOST6}]:{DS_PORT} not found in cluster JSON: {servers}"
            # The JSON host is stored bare (canonical); it must NOT be a bracketed
            # literal here — bracketing happens only at wire/redirect emit time.
            assert "[" not in match[0]["host"], match[0]

        _assert_test_cluster_json_contains_registered_ipv6_host_2()

    @pytest.mark.registry_server("ipv6-mgr")
    def test_cluster_json_requires_auth(self):
        """REGRESSION: the read-only cluster endpoint is auth-gated (no cookie ->
        401), so the round-trip assertion above proves an authenticated read."""
        _skip_if_http_down()
        status, _ = _dashboard_get("/brix/api/v1/cluster")
        assert status == 401


# ===========================================================================
# 3. Manager-mode kXR_locate / kXR_open -> bracketed kXR_redirect (GATING)
# ===========================================================================

class TestManagerRedirectBracketing:
    """response/control.c:brix_send_redirect must bracket an IPv6 redirect host:
    the kXR_redirect body is [port:4B][host]; the host for an IPv6 data server is
    "[::1]", never bare "::1".  Manager-mode locate/open over a raw ::1 socket
    drives brix_srv_select -> brix_send_redirect after the DS is registered."""

    def _register_and_locate(self, opfn):
        """Register [::1]:DS for "/" then run opfn(sock, path); return the
        (status, body) response from the raw manager socket."""
        if _register_ipv6_server(DS_PORT)[0] != 200:
            pytest.skip("could not register IPv6 data server via admin API")
        sock = _session6(IPV6_MGR_PORT)
        try:
            return opfn(sock, "/store/ipv6/file.dat")
        finally:
            sock.close()

    @pytest.mark.registry_server("ipv6-mgr")
    def test_cluster_locate_returns_redirect(self):
        """GATING: manager-mode kXR_locate for a registered path returns
        kXR_redirect (4004) whose port == the registered DS port."""
        _skip_if_http_down()
        _skip_if_stream_down()
        _, status, body = self._register_and_locate(_locate)
        assert status == kXR_redirect, \
            f"expected kXR_redirect (4004), got {status} err={_error_code(body)}"
        port, host = _parse_redirect(body)
        assert port == DS_PORT, f"redirect port {port} != DS port {DS_PORT}"

    @pytest.mark.registry_server("ipv6-mgr")
    def test_cluster_locate_host_is_bracketed(self):
        """GATING: the redirect host field is the bracketed literal "[::1]", not
        the unparseable bare "::1" (response/control.c:71 bracket-on-emit)."""
        _skip_if_http_down()
        _skip_if_stream_down()
        _, status, body = self._register_and_locate(_locate)
        assert status == kXR_redirect, _error_code(body)
        _, host = _parse_redirect(body)
        # The host segment (before any "?opaque") must be exactly "[::1]".
        host_only = host.split("?", 1)[0]
        assert host_only == f"[{IPV6_HOST}]", \
            f"redirect host {host_only!r} must be bracketed [::1], not bare"  # net-literal-allow: [::1] bracketing-format assertion
        assert not host_only.startswith(IPV6_HOST), \
            "bare ::1 (unbracketed) leaked into the redirect host field"  # net-literal-allow: bare-::1 redirect-leak assertion

    @pytest.mark.registry_server("ipv6-mgr")
    def test_cluster_open_returns_bracketed_redirect(self):
        """GATING: manager-mode kXR_open(read) for a registered path also
        redirects to the DS with a bracketed [::1] host and the right port."""
        _skip_if_http_down()
        _skip_if_stream_down()
        _, status, body = self._register_and_locate(_open)
        assert status == kXR_redirect, \
            f"expected kXR_redirect (4004), got {status} err={_error_code(body)}"
        port, host = _parse_redirect(body)
        assert port == DS_PORT, f"redirect port {port} != DS port {DS_PORT}"
        assert host.split("?", 1)[0] == f"[{IPV6_HOST}]", \
            f"open redirect host {host!r} must be bracketed [::1]"  # net-literal-allow: [::1] bracketing-format assertion

    @pytest.mark.registry_server("ipv6-mgr")
    def test_locate_and_open_redirect_to_same_target(self):
        """REGRESSION: locate and open select the same registered IPv6 target —
        both bracket the host identically, no per-opcode divergence."""
        _skip_if_http_down()
        _skip_if_stream_down()
        if _register_ipv6_server(DS_PORT)[0] != 200:
            pytest.skip("could not register IPv6 data server via admin API")
        sock = _session6(IPV6_MGR_PORT)
        try:
            _, ls, lb = _locate(sock, "/store/ipv6/file.dat")
            _, os_, ob = _open(sock, "/store/ipv6/file.dat")
        finally:
            sock.close()
        assert ls == kXR_redirect and os_ == kXR_redirect, (ls, os_)
        lport, lhost = _parse_redirect(lb)
        oport, ohost = _parse_redirect(ob)
        assert lport == oport == DS_PORT
        assert lhost.split("?", 1)[0] == ohost.split("?", 1)[0] == f"[{IPV6_HOST}]"

    @pytest.mark.registry_server("ipv6-mgr")
    def test_raw_redirect_body_never_contains_bare_ipv6(self):
        """GATING (negative): the raw redirect body, after the 4-byte port, never
        starts with a bare "::1" — the bracket must precede the literal so a
        client cannot mis-parse the colon-bearing address."""
        _skip_if_http_down()
        _skip_if_stream_down()
        _, status, body = self._register_and_locate(_locate)
        assert status == kXR_redirect, _error_code(body)
        host_bytes = body[4:]
        assert host_bytes.startswith(b"["), \
            f"redirect host must start with '[' (got {host_bytes[:8]!r})"
        assert not host_bytes.startswith(IPV6_HOST.encode()), \
            "bare ::1 must not be the first byte of the host field"  # net-literal-allow: bare-::1 host-field assertion


# ===========================================================================
# 4. Graceful-skip discipline (REGRESSION)
# ===========================================================================

class TestSkipDiscipline:
    """The suite must be a clean no-op when ::1 or the dedicated instance is
    absent — never a failure."""

    def test_reachable6_probe_is_boolean(self):
        """reachable6 returns a bool for a definitely-closed high port (no raise),
        so the per-file skip gate can never crash the collection."""
        # A port that is essentially never listening on ::1.
        assert reachable6(1, timeout=0.5) in (True, False)

    @pytest.mark.registry_server("ipv6-mgr")
    def test_instance_down_skips_not_fails(self):
        """If the ipv6-mgr HTTP face is down, the http-gated tests skip; this
        test documents that contract by skipping itself when it is down."""
        if not reachable6(IPV6_MGR_HTTP_PORT):
            pytest.skip("ipv6-mgr http face down — gated tests skip, never fail")
        # When up, a trivial reachability assertion holds.
        assert reachable6(IPV6_MGR_HTTP_PORT)
