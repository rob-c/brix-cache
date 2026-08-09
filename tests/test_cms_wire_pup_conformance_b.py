from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cms_wire_pup_conformance_helpers")

class TestServerLivenessPlaneA:
    """The nginx CMS *server* (manager side) must answer node-originated
    ping/disc/update/statfs exactly like stock cmsd (do_Ping/do_Disc/do_Update/
    do_StatFS)."""

    def test_ping_gets_pong(self, cms_server):
        """An incoming kYR_ping is answered with a header-only kYR_pong."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            sock.sendall(_build_frame(0, CMS_RR_PING, 0))
            fr = _recv_code(sock, CMS_RR_PONG, timeout=5.0)
            assert fr is not None, "server did not reply kYR_pong to a ping"
            _sid, code, _mod, payload = fr
            assert code == CMS_RR_PONG
            assert payload == b"", "pong must be header-only"
        finally:
            sock.close()

    def test_update_gets_status(self, cms_server):
        """kYR_update -> the server resends its state as a kYR_status frame with
        the Resume bit set (do_Update -> sendState)."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            sock.sendall(_build_frame(0, CMS_RR_UPDATE, 0))
            fr = _recv_code(sock, CMS_RR_STATUS, timeout=5.0)
            assert fr is not None, "server did not reply kYR_status to an update"
            _sid, _code, mod, _payload = fr
            assert mod & CMS_ST_RESUME, "status reply must advertise Resume"
        finally:
            sock.close()

    def test_disc_is_echoed_and_closes(self, cms_server):
        """kYR_disc -> the manager echoes a kYR_disc and closes the link
        (do_Disc as-manager)."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            sock.sendall(_build_frame(0, CMS_RR_DISC, 0))
            fr = _recv_code(sock, CMS_RR_DISC, timeout=5.0)
            assert fr is not None, "server did not echo kYR_disc"
            # After the echo the server closes — a subsequent read sees EOF.
            sock.settimeout(5)
            assert _recv_frame(sock) is None, "server must close after disc echo"
        finally:
            sock.close()

    def test_statfs_returns_space_data(self, cms_server):
        """kYR_statfs(path) -> kYR_data with a 4-byte zero prefix and a
        'wNum wFree wUtil sNum sFree sUtil' ASCII string (do_StatFS)."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            # fwdArgC payload: ident, path (Pup strings; len incl trailing NUL).
            def pup(s):
                return struct.pack(">H", len(s) + 1) + s + b"\x00"
            payload = pup(b"tester") + pup(b"/")
            sock.sendall(_build_frame(7, CMS_RR_STATFS, 0, payload))
            fr = _recv_code(sock, CMS_RSP_DATA, timeout=5.0)
            assert fr is not None, "server did not reply kYR_data to statfs"
            sid, _code, _mod, data = fr
            assert sid == 7, "statfs reply must echo the request streamid"
            assert len(data) >= 5 and data[:4] == b"\x00\x00\x00\x00", \
                "statfs payload must start with the 4-byte zero prefix"
            fields = data[4:].rstrip(b"\x00").split(b" ")
            assert len(fields) == 6, f"expected 6 space fields, got {fields!r}"
            for f in fields:
                int(f)   # every field must be a base-10 integer
        finally:
            sock.close()

    def test_usage_gets_load_echoing_streamid(self, cms_server):
        """Phase-89 W1: kYR_usage -> kYR_load echoing the streamid, payload
        byte-exact with the node-side heartbeat: [>H 6][6 load bytes][tagged
        int dskFree] = 13 bytes; the dsk byte is a percentage (<= 100)."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            sid = 0x11223344
            sock.sendall(_build_frame(sid, CMS_RR_USAGE, 0))
            fr = _recv_code(sock, CMS_RR_LOAD, timeout=5.0)
            assert fr is not None, "server did not reply kYR_load to usage"
            rsid, _code, _mod, payload = fr
            assert rsid == sid, "load reply must echo the usage streamid"
            assert len(payload) == 13, f"load payload must be 13 bytes: {payload!r}"
            (blob_len,) = struct.unpack(">H", payload[:2])
            assert blob_len == 6, "theLoad must be a bare 6-byte blob"
            load6 = payload[2:8]
            assert load6[5] <= 100, "dsk load byte must be a percentage"
            free_mb, p = _pup_read_scalar(payload, 8)
            assert p == 13 and free_mb >= 0, "dskFree must be a tagged int"
        finally:
            sock.close()

    def test_stats_gets_size_form(self, cms_server):
        """Phase-61 W7: kYR_stats(kYR_size) -> kYR_data echoing the streamid,
        payload the raw 4-byte big-endian statsz — byte-exact with stock
        v5.9.6 (Cluster.Stats(0,0) = sizeof(statfmt1) + 8 = 48)."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            sock.sendall(_build_frame(9, CMS_RR_STATS, CMS_STATS_SIZE))
            fr = _recv_code(sock, CMS_RSP_DATA, timeout=5.0)
            assert fr is not None, "server did not reply kYR_data to stats"
            sid, _code, _mod, data = fr
            assert sid == 9, "stats reply must echo the request streamid"
            assert len(data) == 4, f"size form must be exactly 4 bytes: {data!r}"
            (need,) = struct.unpack(">I", data)
            assert need == CMS_STATS_BUFSZ, \
                f"statsz must be the stock advertisement {CMS_STATS_BUFSZ}, got {need}"
        finally:
            sock.close()

    def test_stats_full_form_returns_role_document(self, cms_server):
        """Phase-61 W7: kYR_stats without kYR_size -> kYR_data whose payload is
        [4B BE statsz][Cluster.Stats XML, snprintf length, no NUL] with this
        manager's role type ("M") in the role slot — byte-exact do_Stats."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            sock.sendall(_build_frame(10, CMS_RR_STATS, 0))
            fr = _recv_code(sock, CMS_RSP_DATA, timeout=5.0)
            assert fr is not None, "server did not reply kYR_data to stats"
            sid, _code, _mod, data = fr
            assert sid == 10, "stats reply must echo the request streamid"
            assert len(data) > 4, f"full form must carry the document: {data!r}"
            (need,) = struct.unpack(">I", data[:4])
            assert need == CMS_STATS_BUFSZ, \
                f"statsz prefix must be {CMS_STATS_BUFSZ}, got {need}"
            doc = data[4:]
            assert doc == b'<stats id="cms"><role>M</role></stats>', \
                f"unexpected Cluster.Stats document: {doc!r}"
        finally:
            sock.close()

    def test_usage_stats_pre_login_ignored(self, cms_server):
        """Security-neg: usage/stats from a connection that never logged in are
        ignored — no reply frame, and no state leaks to the unauthenticated
        peer (the connection simply stays quiet)."""
        sock = socket.create_connection((H, cms_server), timeout=8)
        try:
            sock.sendall(_build_frame(5, CMS_RR_USAGE, 0))
            sock.sendall(_build_frame(6, CMS_RR_STATS, 0))
            sock.settimeout(2)
            try:
                fr = _recv_frame(sock)
            except socket.timeout:
                fr = "silent"
            assert fr in (None, "silent"), \
                f"pre-login usage/stats must not be answered, got {fr!r}"
        finally:
            sock.close()



class TestServerStatusStateMachine:
    """Phase-89 W9: the manager side of kYR_status — reset forgets cached
    metrics, unknown modifiers are a no-op, and pre-login status frames cannot
    touch another node's registration."""

    def test_status_reset_clears_reported_space(self, cms_server):
        """kYR_status(reset) -> the manager forgets our cached load figures:
        the aggregate free space visible through statfs drops to 0 (the node
        stays registered and the connection stays open)."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            assert _statfs_wfree(sock, 21) == 5000, \
                "login-advertised fSpace must be visible before the reset"
            sock.sendall(_build_frame(0, CMS_RR_STATUS, CMS_ST_RESET))
            time.sleep(0.4)
            assert _statfs_wfree(sock, 22) == 0, \
                "reset must clear the cached free-space figure"
        finally:
            sock.close()

    def test_status_unknown_modifier_is_noop(self, cms_server):
        """A kYR_status with an unrecognised modifier bit is ignored: state is
        untouched and the connection stays live (ping still answered)."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            sock.sendall(_build_frame(0, CMS_RR_STATUS, 0x40))
            time.sleep(0.2)
            assert _statfs_wfree(sock, 23) == 5000, \
                "unknown status modifier must not touch cached metrics"
            sock.sendall(_build_frame(3, CMS_RR_PING, 0))
            fr = _recv_code(sock, CMS_RR_PONG, timeout=5.0)
            assert fr is not None, "connection must survive an unknown modifier"
        finally:
            sock.close()

    def test_status_pre_login_cannot_touch_registration(self, cms_server):
        """Security-neg: a connection that never logged in sends
        kYR_status(reset) — the frame is ignored and a logged-in node's cached
        metrics are unaffected."""
        node = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        raw = socket.create_connection((H, cms_server), timeout=8)
        try:
            time.sleep(0.4)
            raw.sendall(_build_frame(0, CMS_RR_STATUS, CMS_ST_RESET))
            time.sleep(0.4)
            assert _statfs_wfree(node, 24) == 5000, \
                "pre-login status must not reach the registry"
        finally:
            raw.close()
            node.close()

    def test_login_envcgi_vnid_accepted(self, cms_server):
        """A LOGIN whose envCGI carries '&'-separated tokens including
        vnid=<id> (stock cmsd form) still registers normally — the node
        answers queries and its metrics are visible.  (The parsed vnid is
        surfaced via the dashboard cluster listing, outside this stream-only
        fixture.)"""
        p = _minimal_login_payload(NODE_DATA_PORT)
        # Rebuild the payload tail: replace the empty envCGI (last 2 bytes,
        # a zero-length Pup string) with a populated one.
        assert p[-2:] == struct.pack(">H", 0)
        env = b"foo=1&vnid=zoneA"
        p = p[:-2] + struct.pack(">H", len(env) + 1) + env + b"\x00"
        sock = _node_login_dialog(cms_server, p)
        try:
            time.sleep(0.4)
            assert _statfs_wfree(sock, 25) == 5000, \
                "vnid-bearing login must register the node normally"
        finally:
            sock.close()


# ===========================================================================
# Class — Plane B forwarded namespace ops (manager -> data node, node side)
# ===========================================================================


class TestForwardedNamespaceOps:
    """A data node executes a manager-forwarded mkdir under kernel confinement:
    success is silent and creates the directory; a path that escapes the export
    root is refused (kYR_error) and creates nothing outside the root."""

    def test_forwarded_mkdir_creates_dir(self, node_stack):
        made = os.path.join(_DIR, "node_data", "fwd_made")
        if os.path.isdir(made):
            os.rmdir(made)
        node_stack.send_to_node(101, CMS_RR_MKDIR, 0,
                                _fwd_a_payload(b"mgr", b"755", b"/fwd_made"))
        # Success is silent; poll the filesystem for the created directory.
        deadline = time.time() + 6.0
        while time.time() < deadline and not os.path.isdir(made):
            time.sleep(0.1)
        assert os.path.isdir(made), "node did not create the forwarded directory"
        # And it must NOT have sent an error for a valid op.
        assert node_stack.collect_reply(CMS_RSP_ERROR, timeout=1.0) is None

    def test_forwarded_mkdir_traversal_is_refused(self, node_stack):
        """A '..' path that escapes the export root must be blocked by the
        kernel-confined open (openat2 RESOLVE_BENEATH) and answered kYR_error —
        and must NOT create anything outside the root."""
        escape = os.path.join(_DIR, "pwned")     # one level above node_data
        if os.path.isdir(escape):
            os.rmdir(escape)
        node_stack.send_to_node(102, CMS_RR_MKDIR, 0,
                                _fwd_a_payload(b"mgr", b"755", b"/../pwned"))
        fr = node_stack.collect_reply(CMS_RSP_ERROR, timeout=6.0)
        assert fr is not None, "node must reply kYR_error for a traversal attempt"
        # The escape target must never have been created.
        assert not os.path.exists(escape), \
            "confinement breach: directory created outside the export root"


# ===========================================================================
# Phase-61 W7 — explicit cluster roles + multi-tier state relay
# ===========================================================================


class TestRoleDirectiveNodeLeg:
    """Phase-61 W7 PR-B: ``brix_cms_role`` on the upward leg — stock Pander
    login Mode word + the role's inbound valid-ops table (manVOps)."""

    def test_manager_role_login_mode_word(self, manager_node_stack):
        """brix_cms_role manager -> LOGIN Mode is exactly kYR_manager (0x02),
        matching XrdCmsPander for a sub-manager (no kYR_server bit)."""
        fr = manager_node_stack.wait_for_code(CMS_RR_LOGIN, timeout=20.0)
        assert fr is not None, "manager-role node did not emit a LOGIN frame"
        login = _decode_login(fr[3])
        assert login["mode"] == CMS_MODE_MANAGER, \
            f"manager role must log in with Mode 0x02, got {login['mode']:#x}"

    def test_manager_role_valid_op_still_served(self, manager_node_stack):
        """kYR_state is in manVOps: a resident-path probe still draws kYR_have
        (the filter must not eat legitimate manager-leg traffic)."""
        sid = 0x61B00001
        manager_node_stack.send_to_node(sid, CMS_RR_STATE, CMS_MOD_RAW,
                                        b"/have_me.bin\x00")
        reply = manager_node_stack.collect_reply(CMS_RR_HAVE, timeout=8.0)
        assert reply is not None, \
            "manVOps must still admit kYR_state on a manager-role node"
        assert reply[0] == sid

    def test_manager_role_drops_op_outside_manvops(self, manager_node_stack):
        """Security-neg: kYR_mkdir is NOT in manVOps (stock initMANrouting) —
        a manager-role node must drop it silently: no directory created, no
        kYR_error, and the connection stays live (PING still answered)."""
        made = os.path.join(_DIR, "mgr_node_data", "mgr_no_mkdir")
        if os.path.isdir(made):
            os.rmdir(made)
        manager_node_stack.send_to_node(
            0x61B00002, CMS_RR_MKDIR, 0,
            _fwd_a_payload(b"mgr", b"755", b"/mgr_no_mkdir"))
        time.sleep(1.0)
        assert not os.path.isdir(made), \
            "manVOps filter breach: manager-role node executed kYR_mkdir"
        assert manager_node_stack.collect_reply(CMS_RSP_ERROR, timeout=1.0) \
            is None, "invalid ops are dropped, not answered with kYR_error"
        ping_sid = 0x61B00003
        manager_node_stack.send_to_node(ping_sid, CMS_RR_PING, 0)
        alive = manager_node_stack.collect_reply(CMS_RR_PONG, timeout=8.0)
        assert alive is not None and alive[0] == ping_sid, \
            "connection must survive a dropped invalid op"

    def test_server_role_login_mode_word(self, server_node_stack):
        """brix_cms_role server -> LOGIN Mode is exactly kYR_server (0x08),
        the stock Pander data-server word (no manager bit)."""
        fr = server_node_stack.wait_for_code(CMS_RR_LOGIN, timeout=20.0)
        assert fr is not None, "server-role node did not emit a LOGIN frame"
        login = _decode_login(fr[3])
        assert login["mode"] == CMS_MODE_SERVER, \
            f"server role must log in with Mode 0x08, got {login['mode']:#x}"
