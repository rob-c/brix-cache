from split_continuation import reexport as _reexport
_reexport(globals(), "_test_manager_mode_helpers")

@pytest.mark.registry_server("manager")
def test_locate_redirect_basic(manager_nginx):
    info = manager_nginx
    host = HOST
    port = info["port"]

    sock = _xrd_handshake_and_login(host, port)

    try:
        status, body = _send_locate_and_recv(sock, "/maps/somefile.bin")
        # Expect kXR_redirect (4004)
        assert status == 4004, f"expected redirect status, got {status}"

        # Body = 4-byte BE port followed by host bytes
        assert len(body) >= 4
        port_be = struct.unpack(">I", body[:4])[0]
        host_str = body[4:].decode("utf-8")

        assert port_be == info["map_a"][1]
        assert host_str == info["map_a"][0]

        # Now test longest-prefix: /maps/prefix should match map_b
        status2, body2 = _send_locate_and_recv(sock, "/maps/prefix/xyz")
        assert status2 == 4004
        pb = struct.unpack(">I", body2[:4])[0]
        hb = body2[4:].decode("utf-8")
        assert pb == info["map_b"][1]
        assert hb == info["map_b"][0]

    finally:
        sock.close()


# ═══════════════════════════════════════════════════════════════════════════
# Part 2 — Dynamic cluster mode (brix_manager_mode + brix_cms_server)
# ═══════════════════════════════════════════════════════════════════════════

# Additional wire constants for Part 2
kXR_ok        = 0
kXR_redirect  = 4004

kXR_open      = 3010
kXR_locate    = 3027

kXR_open_read = 0x0010   # open for reading
kXR_isManager = 0x00000002  # flags in kXR_protocol response body



class TestClusterProtocol:
    """kXR_protocol response advertises kXR_isManager when manager_mode is on."""

    @pytest.mark.registry_servers("cluster-ds", "cluster-redir")
    def test_protocol_flags_include_is_manager(self, cluster):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((HOST, cluster["redir_port"]))
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        sock.sendall(struct.pack(">BB H I BB 10x I",
                                 0, 1, 3006, 0x00000520, 0x02, 0x03, 0))
        _cluster_recv_exact(sock, 16)
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_ok, f"kXR_protocol failed with status {status}"
        assert len(body) >= 8, f"protocol body too short: {len(body)} bytes"
        flags = struct.unpack(">I", body[4:8])[0]
        assert flags & kXR_isManager, (
            f"kXR_isManager (0x{kXR_isManager:08x}) not set in flags {flags:#010x}"
        )


class TestClusterLocate:
    """kXR_locate on the redirector returns kXR_redirect to the registered data server."""

    @pytest.mark.registry_servers("cluster-ds", "cluster-redir")
    def test_locate_returns_redirect(self, cluster):
        sock = _cluster_handshake_login(HOST, cluster["redir_port"])
        _cluster_send_locate(sock, "/test.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect ({kXR_redirect}), got {status}"
        )
        assert len(body) >= 4, f"redirect body too short: {len(body)} bytes"
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == cluster["ds_port"], (
            f"redirect port {got_port} != data server port {cluster['ds_port']}"
        )

    @pytest.mark.registry_servers("cluster-ds", "cluster-redir")
    def test_locate_redirect_host_is_loopback(self, cluster):
        sock = _cluster_handshake_login(HOST, cluster["redir_port"])
        _cluster_send_locate(sock, "/test.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect
        host = body[4:].rstrip(b"\x00").decode(errors="replace")
        assert host == HOST, f"unexpected redirect host: {host!r}"


class TestClusterOpen:
    """kXR_open (read) on the redirector returns kXR_redirect to the data server."""

    @pytest.mark.registry_servers("cluster-ds", "cluster-redir")
    def test_open_read_returns_redirect(self, cluster):
        sock = _cluster_handshake_login(HOST, cluster["redir_port"])
        _cluster_send_open(sock, "/test.txt", kXR_open_read)
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect ({kXR_redirect}), got {status}"
        )
        assert len(body) >= 4
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == cluster["ds_port"]


kXR_mkdir = 3008
kXR_rm    = 3014



class TestClusterMutationRedirect:
    """Plane B manager orchestration: in manager mode a path-based namespace
    mutation (mkdir/rm) is redirected to the registered data node — it must NOT
    be executed against the redirector's own (empty) export."""

    @pytest.mark.registry_servers("cluster-ds", "cluster-redir")
    def test_mkdir_returns_redirect(self, cluster):
        sock = _cluster_handshake_login(HOST, cluster["redir_port"])
        try:
            _cluster_send_mkdir(sock, "/mgr_made_dir")
            status, body = _cluster_read_response(sock)
        finally:
            sock.close()
        assert status == kXR_redirect, (
            f"mkdir must be redirected in manager mode, got status {status}"
        )
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == cluster["ds_port"], (
            f"mkdir redirect port {got_port} != data server {cluster['ds_port']}"
        )

    @pytest.mark.registry_servers("cluster-ds", "cluster-redir")
    def test_rm_returns_redirect(self, cluster):
        sock = _cluster_handshake_login(HOST, cluster["redir_port"])
        try:
            _cluster_send_rm(sock, "/test.txt")
            status, body = _cluster_read_response(sock)
        finally:
            sock.close()
        assert status == kXR_redirect, (
            f"rm must be redirected in manager mode, got status {status}"
        )
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == cluster["ds_port"]


class TestClusterUnregister:
    """After the data server disconnects, the redirector stops redirecting.

    NOTE: This class stops the data server permanently — it must be last.
    """

    @pytest.mark.registry_servers("cluster-ds", "cluster-redir")
    def test_no_redirect_after_dataserver_stops(self, cluster):
        cluster["ds"]["stop"]()
        time.sleep(2.0)   # let nginx detect the dropped CMS connection

        sock = _cluster_handshake_login(HOST, cluster["redir_port"])
        _cluster_send_locate(sock, "/test.txt")
        status, _body = _cluster_read_response(sock)
        sock.close()

        assert status != kXR_redirect, (
            "redirector still returned kXR_redirect after data server disconnected"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 3 — Multi-token path list routing (srv_path_matches edge cases)
# ═══════════════════════════════════════════════════════════════════════════
class TestClusterMultiPath:
    """srv_path_matches handles colon-delimited multi-token path lists.

    Exercises the colon-split logic in registry.c: a data server that
    exports '/data:/atlas' must redirect requests under both prefixes but
    reject requests for '/physics' (not in the list).
    """

    @pytest.mark.registry_servers("cluster-mp-ds", "cluster-mp-redir")
    def test_locate_first_prefix_redirects(self, cluster_multi_path):
        """locate /data/test.txt must return kXR_redirect."""
        sock = _cluster_handshake_login(HOST, cluster_multi_path["redir_port"])
        _cluster_send_locate(sock, "/data/test.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect for /data prefix, got {status}"
        )
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == cluster_multi_path["ds_port"], (
            f"redirected to wrong port {got_port}"
        )

    @pytest.mark.registry_servers("cluster-mp-ds", "cluster-mp-redir")
    def test_locate_second_prefix_redirects(self, cluster_multi_path):
        """locate /atlas/test.txt must also return kXR_redirect."""
        sock = _cluster_handshake_login(HOST, cluster_multi_path["redir_port"])
        _cluster_send_locate(sock, "/atlas/test.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect for /atlas prefix, got {status}"
        )
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port == cluster_multi_path["ds_port"]

    @pytest.mark.registry_servers("cluster-mp-ds", "cluster-mp-redir")
    def test_locate_exact_prefix_token_redirects(self, cluster_multi_path):
        """locate /data (exactly the token without trailing slash) must redirect."""
        sock = _cluster_handshake_login(HOST, cluster_multi_path["redir_port"])
        _cluster_send_locate(sock, "/data")
        status, _ = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"exact-token locate /data expected redirect, got {status}"
        )

    @pytest.mark.registry_servers("cluster-mp-ds", "cluster-mp-redir")
    def test_locate_unregistered_path_no_redirect(self, cluster_multi_path):
        """locate /physics/test.txt must NOT redirect (path not in /data:/atlas)."""
        sock = _cluster_handshake_login(HOST, cluster_multi_path["redir_port"])
        _cluster_send_locate(sock, "/physics/test.txt")
        status, _ = _cluster_read_response(sock)
        sock.close()

        assert status != kXR_redirect, (
            "redirector incorrectly redirected /physics which is not a registered prefix"
        )

    @pytest.mark.registry_servers("cluster-mp-ds", "cluster-mp-redir")
    def test_locate_prefix_partial_match_not_redirected(self, cluster_multi_path):
        """/dataextended must NOT match the /data prefix (boundary check)."""
        sock = _cluster_handshake_login(HOST, cluster_multi_path["redir_port"])
        _cluster_send_locate(sock, "/dataextended/file.txt")
        status, _ = _cluster_read_response(sock)
        sock.close()

        assert status != kXR_redirect, (
            "/dataextended incorrectly matched the /data prefix token"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Part 4 — Multi-server registration and brix_srv_select
# ═══════════════════════════════════════════════════════════════════════════
class TestClusterMultiServer:
    """Two registered data servers — locate must return one of them."""

    @pytest.mark.registry_servers("cluster-ms-ds1", "cluster-ms-ds2", "cluster-ms-redir")
    def test_locate_returns_valid_server(self, cluster_multi_server):
        """locate /shared.txt must redirect to one of the two data servers."""
        c = cluster_multi_server
        sock = _cluster_handshake_login(HOST, c["redir_port"])
        _cluster_send_locate(sock, "/shared.txt")
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect with two registered servers, got {status}"
        )
        assert len(body) >= 4
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port in (c["ds1_port"], c["ds2_port"]), (
            f"redirected to unknown port {got_port}; "
            f"expected one of {c['ds1_port']} or {c['ds2_port']}"
        )

    @pytest.mark.registry_servers("cluster-ms-ds1", "cluster-ms-ds2", "cluster-ms-redir")
    def test_repeated_locates_stay_valid(self, cluster_multi_server):
        """Multiple locate calls must all redirect to valid servers."""
        c = cluster_multi_server
        valid_ports = {c["ds1_port"], c["ds2_port"]}

        for _ in range(5):
            sock = _cluster_handshake_login(HOST, c["redir_port"])
            _cluster_send_locate(sock, "/shared.txt")
            status, body = _cluster_read_response(sock)
            sock.close()

            assert status == kXR_redirect, f"unexpected status {status}"
            got_port = struct.unpack(">I", body[:4])[0]
            assert got_port in valid_ports, (
                f"redirected to unexpected port {got_port}"
            )

    @pytest.mark.registry_servers("cluster-ms-ds1", "cluster-ms-ds2", "cluster-ms-redir")
    def test_open_redirects_to_valid_server(self, cluster_multi_server):
        """kXR_open on the redirector with two servers must also redirect correctly."""
        c = cluster_multi_server
        sock = _cluster_handshake_login(HOST, c["redir_port"])
        _cluster_send_open(sock, "/shared.txt", kXR_open_read)
        status, body = _cluster_read_response(sock)
        sock.close()

        assert status == kXR_redirect, (
            f"expected kXR_redirect for open with two servers, got {status}"
        )
        got_port = struct.unpack(">I", body[:4])[0]
        assert got_port in (c["ds1_port"], c["ds2_port"])


# ═══════════════════════════════════════════════════════════════════════════
# Part 3 — Per-worker CMS connections
#
# Each nginx worker process must open its own independent CMS connection to
# the parent manager.  With N workers configured, the manager must receive
# exactly N connections.  This ensures that when a worker sends kYR_locate
# the kYR_select reply arrives on the same worker's event loop as the waiting
# XRootD client session — no cross-worker IPC is required.
# ═══════════════════════════════════════════════════════════════════════════
class TestPerWorkerCMS:
    """Each nginx worker must open its own independent CMS connection."""

    @pytest.mark.registry_servers("cluster-mw", "cluster-mw-mgr")
    def test_each_worker_connects_independently(self, cluster_multi_worker):
        """With worker_processes 2 and one CMS manager, expect 2 connections.

        Each worker forks from the master with cms_ctx == NULL and runs its own
        init_process hook, so both workers call ngx_brix_cms_start and open
        an independent TCP connection to the CMS manager.
        """
        count = cluster_multi_worker["connection_count"][0]
        assert count >= 2, (
            f"expected >= 2 CMS connections (one per worker), got {count}; "
            "check that ngx_brix_cms_start is not guarded to a single worker"
        )


# ═══════════════════════════════════════════════════════════════════════════
# CMS wire helpers (shared by Parts 6 and 8)
# ═══════════════════════════════════════════════════════════════════════════

#   CMS frame: 8-byte header
#     [0..3]  streamid  BE uint32
#     [4]     opcode
#     [5]     modifier
#     [6..7]  dlen      BE uint16
#   Payload of dlen bytes follows immediately.

CMS_RR_LOGIN  = 0
CMS_RR_LOCATE = 2
CMS_RR_SELECT = 10
CMS_RR_GONE   = 14
CMS_RR_PING   = 17
CMS_RR_PONG   = 18

CMS_PT_SHORT = 0x80
CMS_PT_INT   = 0xa0
