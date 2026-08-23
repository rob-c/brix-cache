from split_continuation import reexport as _reexport
_reexport(globals(), "_test_manager_mode_helpers")

class TestThreeTierTopology:
    """Two-hop locate chain: client → meta → sub → leaf."""

    @pytest.mark.registry_servers("cluster-3t-leaf", "cluster-3t-meta", "cluster-3t-sub")
    def test_locate_follows_redirect_chain_to_sub(self, three_tier):
        """First locate at meta-manager must redirect to the sub-manager."""
        tt = three_tier
        sock = _cluster_handshake_login(HOST, tt["meta_port"])
        _cluster_send_locate(sock, "/test.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"meta-manager: expected kXR_redirect, got {status}"
        )
        assert len(body) >= 4
        hop1_port = struct.unpack(">I", body[:4])[0]
        assert hop1_port == tt["sub_port"], (
            f"expected redirect to sub-manager port {tt['sub_port']}, got {hop1_port}"
        )

    @pytest.mark.registry_servers("cluster-3t-leaf", "cluster-3t-meta", "cluster-3t-sub")
    def test_locate_follows_redirect_chain_to_leaf(self, three_tier):
        """Second locate at sub-manager must redirect to the leaf data server."""
        tt = three_tier
        sock = _cluster_handshake_login(HOST, tt["sub_port"])
        _cluster_send_locate(sock, "/test.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"sub-manager: expected kXR_redirect, got {status}"
        )
        assert len(body) >= 4
        leaf_port = struct.unpack(">I", body[:4])[0]
        assert leaf_port == tt["leaf_port"], (
            f"expected redirect to leaf port {tt['leaf_port']}, got {leaf_port}"
        )

    @pytest.mark.registry_servers("cluster-3t-leaf", "cluster-3t-meta", "cluster-3t-sub")
    def test_full_two_hop_chain(self, three_tier):
        """Client follows both hops and lands at the leaf port."""
        tt = three_tier

        # Hop 1: meta → sub
        sock = _cluster_handshake_login(HOST, tt["meta_port"])
        _cluster_send_locate(sock, "/test.txt")
        status, body = _cluster_read_response(sock)
        sock.close()
        assert status == kXR_redirect
        hop1_port = struct.unpack(">I", body[:4])[0]

        # Hop 2: sub → leaf
        sock2 = _cluster_handshake_login(HOST, hop1_port)
        _cluster_send_locate(sock2, "/test.txt")
        status2, body2 = _cluster_read_response(sock2)
        sock2.close()
        assert status2 == kXR_redirect
        final_port = struct.unpack(">I", body2[:4])[0]
        assert final_port == tt["leaf_port"], (
            f"two-hop chain ended at {final_port}, expected leaf {tt['leaf_port']}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 6 — kYR_select flow (CMS-assisted locate suspension + wake)
# ═══════════════════════════════════════════════════════════════════════════

# nginx at CLUSTER_SELECT_PORT has no local registry; it escalates kXR_locate
# to its parent CMS (cms_parent_stubs.py at CLUSTER_SELECT_CMS_PORT), which
# replies with kYR_select pointing at CLUSTER_SELECT_REDIRECT_PORT.
class TestCmsSelectWake:
    """nginx suspends a client kXR_locate, escalates kYR_locate to the CMS stub,
    and resumes the client with a kXR_redirect once kYR_select arrives."""

    @pytest.mark.registry_server("cluster-select")
    def test_locate_wakes_on_cms_select(self, cms_select):
        """kXR_locate must return kXR_redirect to the port advertised by kYR_select.

        Until the persistent link to the parent CMS stub is established,
        locate_try_cms_parent's send fails and locate falls through to the
        NotFound path (kXR_error) by design — so retry through the warm-up
        window rather than judging the first response.
        """
        c = cms_select

        deadline = time.monotonic() + 25.0
        status, body = None, b""
        while time.monotonic() < deadline:
            sock = _cluster_handshake_login(HOST, c["redir_port"])
            sock.settimeout(15)  # generous — allows for CMS round-trip
            _cluster_send_locate(sock, "/cms-select-test/file.dat")
            status, body = _cluster_read_response(sock)
            sock.close()
            if status == kXR_redirect:
                break
            time.sleep(0.5)

        assert status == kXR_redirect, (
            f"expected kXR_redirect after kYR_select, got {status}"
        )
        assert len(body) >= 4
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == c["redirect_port"], (
            f"redirect to port {got_port}, expected {c['redirect_port']}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 7 — Registry-full counter (brix_registry_slots + Prometheus)
# ═══════════════════════════════════════════════════════════════════════════

import urllib.request
class TestRegistryFullCounter:
    """brix_registry_full_total increments when a data server cannot register."""

    @pytest.mark.registry_servers("cluster-slots-ds1", "cluster-slots-ds2", "cluster-slots-ds3", "cluster-slots-ds4", "cluster-slots-redir")
    def test_registry_full_counter_nonzero(self, cluster_full_registry):
        """Prometheus metrics must show registry_full_total > 0 after overflow."""
        c = cluster_full_registry
        url = f"http://{url_host(HOST)}:{c['metrics_port']}/metrics"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = resp.read().decode()
        except Exception as exc:
            pytest.fail(f"Could not fetch metrics from {url}: {exc}")

        counter_value = None
        for line in body.splitlines():
            if line.startswith("brix_registry_full_total "):
                counter_value = float(line.split()[1])
                break

        def _assert_test_registry_full_counter_nonzero_1():
            assert counter_value is not None, (
                "brix_registry_full_total not present in Prometheus output"
            )
            assert counter_value > 0, (
                f"brix_registry_full_total is {counter_value}; "
                "expected > 0 after 4 servers tried to register into 3 slots"
            )

        _assert_test_registry_full_counter_nonzero_1()

    @pytest.mark.registry_servers("cluster-slots-ds1", "cluster-slots-ds2", "cluster-slots-ds3", "cluster-slots-ds4", "cluster-slots-redir")
    def test_registry_accepts_up_to_slot_limit(self, cluster_full_registry):
        """At most 3 slots filled → at least one server's locate succeeds."""
        c = cluster_full_registry
        sock = _cluster_handshake_login(HOST, c["redir_port"])
        _cluster_send_locate(sock, "/file.txt")
        status, _ = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect (at least 3 servers should have registered), got {status}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 8 — kYR_gone: path deregistration via CMS
# ═══════════════════════════════════════════════════════════════════════════


class TestKyrGone:
    """kYR_gone removes a path from the registry without disconnecting.

    A raw TCP socket registers as a data server via the CMS protocol:
      1. Connects to the redirector's CMS server port and sends LOGIN
         (which registers the path "/gone-test").
      2. Confirms locate returns kXR_redirect.
      3. Sends kYR_gone with the registered path.
      4. Confirms locate no longer redirects to that server.
    """

    @pytest.mark.registry_servers("cluster-ds", "cluster-redir")
    def test_path_unregistered_after_gone(self, cluster):
        """After kYR_gone for /gone-test, locate must stop redirecting there."""
        gone_port = CLUSTER_GONE_DS_PORT

        # Register a raw TCP socket as a CMS data server for /gone-test.
        cms_conn = _cms_connect_and_register(
            cluster["cms_port"], gone_port, "/gone-test"
        )
        time.sleep(1.5)  # let nginx process LOGIN and register the path

        # Verify the path is reachable.
        sock = _cluster_handshake_login(HOST, cluster["redir_port"])
        _cluster_send_locate(sock, "/gone-test/file.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect before kYR_gone, got {status}"
        )
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == gone_port

        # Send kYR_gone — payload is the raw path bytes (no TLV encoding).
        cms_conn.sendall(
            _cms_frame(2, CMS_RR_GONE, b"/gone-test")
        )
        time.sleep(1.5)  # let nginx process the GONE frame

        # The path must no longer redirect to gone_port.
        sock2 = _cluster_handshake_login(HOST, cluster["redir_port"])
        _cluster_send_locate(sock2, "/gone-test/file.txt")
        status2, body2 = _cluster_read_response(sock2)
        sock2.close()
        cms_conn.close()

        # After GONE the slot may either be gone entirely (no redirect) or
        # the server is still registered but the path token removed.
        # Either way the port must not be gone_port any more.
        if status2 == kXR_redirect:
            redirect_port = struct.unpack(">I", body2[:4])[0]
            assert redirect_port != gone_port, (
                f"redirector still sends to gone_port {gone_port} after kYR_gone"
            )

    @pytest.mark.registry_servers("cluster-ds", "cluster-redir")
    def test_other_paths_unaffected_by_gone(self, cluster):
        """kYR_gone for /gone-test2 must not remove /gone-other."""
        port_a = CLUSTER_GONE_DS_PORT_A
        port_b = CLUSTER_GONE_DS_PORT_B

        conn_a = _cms_connect_and_register(cluster["cms_port"], port_a, "/gone-other")
        conn_b = _cms_connect_and_register(cluster["cms_port"], port_b, "/gone-test2")
        time.sleep(1.5)

        # Send GONE only for /gone-test2.
        conn_b.sendall(_cms_frame(2, CMS_RR_GONE, b"/gone-test2"))
        time.sleep(1.5)

        # /gone-other must still redirect.
        sock = _cluster_handshake_login(HOST, cluster["redir_port"])
        _cluster_send_locate(sock, "/gone-other/x.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        conn_a.close()
        conn_b.close()

        assert status == kXR_redirect, (
            f"expected /gone-other to still redirect after GONE for /gone-test2, got {status}"
        )
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == port_a, (
            f"expected redirect to port_a {port_a}, got {got_port}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 9 — kYR_try: manager replies with ordered alternative list
# ═══════════════════════════════════════════════════════════════════════════

# kYR_try differs from kYR_select: the payload contains multiple host:port
# entries in priority order.  nginx picks the FIRST entry and wakes the
# suspended client with a redirect to that host:port.
#
# Wire format for kYR_try payload (src/net/cms/cms_internal.h CMS_RR_TRY=24):
#   entry_0: NUL-terminated hostname + 2-byte big-endian port
#   entry_1: NUL-terminated hostname + 2-byte big-endian port
#   ...

CMS_RR_TRY = 24  # kYR_try opcode
class TestCmsKyrTry:
    """kYR_try: nginx must redirect the client to the first entry in the list."""

    @pytest.mark.registry_server("cluster-try")
    def test_locate_redirects_to_first_try_entry(self, cms_try):
        """kXR_locate returns kXR_REDIRECT pointing at the FIRST kYR_try entry.

        Wire path: client → nginx XRD_ST_WAITING_CMS → CMS stub replies
        kYR_try[first_port, second_port] → nginx wakes with kXR_REDIRECT to
        first_port only.
        """
        c = cms_try
        sock = _cluster_handshake_login(HOST, c["redir_port"])
        sock.settimeout(20)
        _cluster_send_locate(sock, "/kyr-try-test/file.dat")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_REDIRECT after kYR_try wake, got {status}"
        )
        assert len(body) >= 4
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == c["first_port"], (
            f"nginx redirected to port {got_port}; expected first_port "
            f"{c['first_port']}, not second_port {c['second_port']}"
        )

    @pytest.mark.registry_server("cluster-try")
    def test_second_entry_ignored(self, cms_try):
        """The second kYR_try entry must not be used for the redirect."""
        c = cms_try
        sock = _cluster_handshake_login(HOST, c["redir_port"])
        sock.settimeout(20)
        _cluster_send_locate(sock, "/kyr-try-second-entry/file.dat")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, f"expected kXR_REDIRECT, got {status}"
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port != c["second_port"], (
            f"nginx used the second kYR_try entry (port {got_port}) "
            "instead of the first"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 10 — True CMS escalation: sub-manager asks parent on registry miss
# ═══════════════════════════════════════════════════════════════════════════
class TestCmsEscalation:
    """Registry miss -> kYR_locate to parent -> kYR_select -> kXR_redirect."""

    @pytest.mark.registry_servers("cluster-esc-leaf", "cluster-esc-sub")
    def test_three_tier_escalation_redirects_to_leaf(self, cms_escalation):
        c = cms_escalation

        sock = _cluster_handshake_login(HOST, c["sub_port"])
        sock.settimeout(15)
        _cluster_send_locate(sock, "/escalate/file.dat")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect after CMS escalation, got {status}"
        )
        assert len(body) >= 4
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == c["leaf_port"], (
            f"expected redirect to leaf port {c['leaf_port']}, got {got_port}"
        )

        leaf_sock = _cluster_handshake_login(HOST, c["leaf_port"])
        leaf_sock.settimeout(10)
        _cluster_send_open(leaf_sock, "/escalate/file.dat", kXR_open_read)
        open_status, _open_body = _cluster_read_response(leaf_sock)
        leaf_sock.close()

        assert open_status == kXR_ok, (
            f"leaf data-server did not open escalated file, got {open_status}"
        )
