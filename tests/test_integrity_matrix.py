from split_continuation import reexport as _reexport
_reexport(globals(), "_test_integrity_matrix_helpers")

@pytest.mark.parametrize("ep", ALL_FIXED, ids=_ids(ALL_FIXED))
class TestFixedTopologies:
    """Direct + every fleet mesh variant (proxy, redirector, manager, cluster,
    caches, 3-tier) for the protocols each front exposes."""

    # cluster-ds is declared explicitly: the `cluster-cms` endpoint routes writes
    # through the cluster-redir redirector, which has nowhere to send an open until
    # a data server has registered — subset-boot's closure follows `requires`
    # FORWARD only (cluster-ds requires cluster-redir, not vice-versa), so naming
    # cluster-redir alone boots a lone redirector that answers open() with EBADF.
    @pytest.mark.registry_servers("cache-only", "chaos-tier1", "cluster-redir", "cluster-ds", "manager", "proxy-nginx", "pure-nginx-proxy", "virtual-redir", "wt-sync")
    def test_write_read_scalar_byte_exact(self, ep):
        drv = _ensure(ep)
        path = _unique(f"int_{ep.topo}_{ep.proto}_scalar")
        data = BIG
        _seed(ep, drv, path, data)
        got = _guard(ep, lambda: drv.read_scalar(ep.locator, path, len(data)))
        assert got == data, \
            f"{ep.topo}/{ep.proto}: {len(got)}B read != {len(data)}B written"

    @pytest.mark.registry_servers("cache-only", "chaos-tier1", "cluster-redir", "cluster-ds", "manager", "proxy-nginx", "pure-nginx-proxy", "virtual-redir", "wt-sync")
    def test_read_vector_byte_exact(self, ep):
        drv = _ensure(ep)
        if not getattr(drv, "supports_vector", False):
            pytest.skip("protocol has no vector read")
        path = _unique(f"int_{ep.topo}_{ep.proto}_vec")
        data = BIG
        _seed(ep, drv, path, data)
        res = _guard(ep, lambda: drv.read_vector(ep.locator, path, len(data)))
        _assert_vector(res, data)

    @pytest.mark.registry_servers("cache-only", "chaos-tier1", "cluster-redir", "cluster-ds", "manager", "proxy-nginx", "pure-nginx-proxy", "virtual-redir", "wt-sync")
    def test_checksum_matches(self, ep):
        drv = _ensure(ep)
        path = _unique(f"int_{ep.topo}_{ep.proto}_cks")
        data = SMALL
        _seed(ep, drv, path, data)
        result = _guard(ep, lambda: drv.checksum(ep.locator, path, data))
        if result is None:
            pytest.skip(f"{ep.topo}/{ep.proto} exposes no verifiable checksum")
        algo, server_hex, want_hex = result
        assert server_hex == want_hex, \
            f"{ep.topo}/{ep.proto} {algo}: server={server_hex} expected={want_hex}"


# ===========================================================================
# Mirror topology (self-provisioned)
# ===========================================================================

class TestMirrorTopology:
    """A transparent stream-mirror server: client integrity must be unaffected
    by the shadow traffic, for scalar read, vector read, write, and checksum."""

    @pytest.mark.registry_servers("cache-only", "chaos-tier1", "cluster-redir", "manager", "proxy-nginx", "pure-nginx-proxy", "virtual-redir", "wt-sync")
    def test_write_read_scalar_byte_exact(self, mirror_endpoint):
        ep = mirror_endpoint
        drv = _ensure(ep)
        path = _unique("int_mirror_scalar")
        drv.write(ep.locator, path, BIG)
        assert drv.read_scalar(ep.locator, path, len(BIG)) == BIG

    @pytest.mark.registry_servers("cache-only", "chaos-tier1", "cluster-redir", "manager", "proxy-nginx", "pure-nginx-proxy", "virtual-redir", "wt-sync")
    def test_read_vector_byte_exact(self, mirror_endpoint):
        ep = mirror_endpoint
        drv = _ensure(ep)
        path = _unique("int_mirror_vec")
        drv.write(ep.locator, path, BIG)
        _assert_vector(drv.read_vector(ep.locator, path, len(BIG)), BIG)

    @pytest.mark.registry_servers("cache-only", "chaos-tier1", "cluster-redir", "manager", "proxy-nginx", "pure-nginx-proxy", "virtual-redir", "wt-sync")
    def test_checksum_matches(self, mirror_endpoint):
        ep = mirror_endpoint
        drv = _ensure(ep)
        path = _unique("int_mirror_cks")
        drv.write(ep.locator, path, SMALL)
        result = drv.checksum(ep.locator, path, SMALL)
        if result is None:
            pytest.skip("mirror front exposes no checksum query")
        algo, server_hex, want_hex = result
        assert server_hex == want_hex, \
            f"mirror {algo}: server={server_hex} expected={want_hex}"


# ===========================================================================
# Pure-nginx proxy chain (self-provisioned) — storage -> proxy -> mesh
# ===========================================================================
#
# The fleet's proxy/mesh terminate at a checksum-less reference xrootd, so their
# checksum cells skip above.  Here every hop is nginx (which DOES compute
# checksums), proving that the transparent proxy forwards byte-exact data AND
# every user query — checksum included — through one and two proxy hops.
class TestProxyChainQueries:
    """Byte-exact + checksum integrity AND full query forwarding through a
    one-hop proxy and a two-hop pure-nginx mesh."""

    def _query(self, url, code, arg):
        from XRootD import client
        fs = client.FileSystem(url)
        st, resp = fs.query(code, arg)
        return st.ok, (bytes(resp) if resp else b"")

    @pytest.fixture(autouse=True)
    def _seed(self, proxy_chain):
        self.urls = proxy_chain
        self.drv = _driver("root")
        self.path = _unique("int_proxychain")
        self.drv.write(proxy_chain["storage"], self.path, BIG)

    # --- integrity through proxy / mesh ---

    @pytest.mark.parametrize("hop", ["proxy", "mesh"])
    @pytest.mark.registry_servers("cache-only", "chaos-tier1", "cluster-redir", "manager", "proxy-nginx", "pure-nginx-proxy", "virtual-redir", "wt-sync")
    def test_scalar_byte_exact(self, hop):
        got = self.drv.read_scalar(self.urls[hop], self.path, len(BIG))
        assert got == BIG

    @pytest.mark.parametrize("hop", ["proxy", "mesh"])
    @pytest.mark.registry_servers("cache-only", "chaos-tier1", "cluster-redir", "manager", "proxy-nginx", "pure-nginx-proxy", "virtual-redir", "wt-sync")
    def test_vector_byte_exact(self, hop):
        _assert_vector(self.drv.read_vector(self.urls[hop], self.path, len(BIG)),
                       BIG)

    @pytest.mark.parametrize("hop", ["proxy", "mesh"])
    @pytest.mark.registry_servers("cache-only", "chaos-tier1", "cluster-redir", "manager", "proxy-nginx", "pure-nginx-proxy", "virtual-redir", "wt-sync")
    def test_checksum_matches(self, hop):
        result = self.drv.checksum(self.urls[hop], self.path, BIG)
        assert result is not None, f"checksum not forwarded through {hop}"
        algo, server_hex, want_hex = result
        assert server_hex == want_hex, \
            f"{hop} {algo}: server={server_hex} expected={want_hex}"

    # --- ALL user queries forward identically through proxy / mesh ---

    @pytest.mark.parametrize("hop", ["proxy", "mesh"])
    @pytest.mark.parametrize("name,code,argkind", _QUERY_CASES,
                             ids=[q[0] for q in _QUERY_CASES])
    @pytest.mark.registry_servers("cache-only", "chaos-tier1", "cluster-redir", "manager", "proxy-nginx", "pure-nginx-proxy", "virtual-redir", "wt-sync")
    def test_query_forwarded(self, hop, name, code, argkind):
        """Every query must reach the backend: the result through the proxy/mesh
        must equal the result of the same query issued directly to storage —
        proving the proxy forwards it rather than answering or rejecting locally."""
        arg = self.path.lstrip("/") if argkind == "path" else argkind
        direct_ok, direct_resp = self._query(self.urls["storage"], code, arg)
        hop_ok, hop_resp = self._query(self.urls[hop], code, arg)
        assert hop_ok == direct_ok, (
            f"{name} status differs through {hop}: "
            f"direct_ok={direct_ok} {hop}_ok={hop_ok} "
            f"(proxy rejected/handled locally instead of forwarding)")
        if direct_ok and name in ("CHECKSUM", "XATTR", "CONFIG"):
            # Deterministic responses must match byte-for-byte through the proxy.
            assert hop_resp == direct_resp, \
                f"{name} response differs through {hop}"
