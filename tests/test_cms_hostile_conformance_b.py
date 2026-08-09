from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cms_hostile_conformance_helpers")

class TestServerLegEsotericOps:

    def test_xauth_out_of_sequence_closes_offender(self, hostile_server):
        """kYR_xauth when no sss challenge is outstanding is an auth violation:
        the offending connection is closed (do_Space parity), and the server
        keeps serving everyone else."""
        bad = socket.create_connection((H, hostile_server.port), timeout=6)
        bad.settimeout(6)
        try:
            bad.sendall(_build_frame(0, CMS_RR_XAUTH, 0, b"\x00" * 8))
            assert _recv_exact(bad, 1) is None, \
                "out-of-sequence xauth did not close the connection"
            assert _server_alive(hostile_server.port), \
                "an xauth violation disturbed the server for others"
        finally:
            bad.close()

    def test_stats_pre_login_ignored(self, hostile_server):
        """kYR_stats before login is gated (no stats doc leaks pre-auth), and
        the connection survives to answer a header-only ping."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(_build_frame(0, CMS_RR_STATS, 0))
            assert _recv_code(sock, CMS_RSP_DATA, timeout=1.0) is None, \
                "server leaked a stats doc pre-login"
            sock.sendall(_build_frame(_SID | 0x20, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None
        finally:
            sock.close()

    def test_stats_full_form_returns_role_doc(self, hostile_server):
        """A logged-in kYR_stats (no kYR_size) returns [4B statsz][Cluster.Stats
        XML]: statsz is the stock advertisement and the doc carries a role."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x21, CMS_RR_STATS, 0))
            fr = _recv_code(sock, CMS_RSP_DATA, timeout=6)
            assert fr is not None, "no stats reply to a full-form kYR_stats"
            payload = fr[3]
            statsz = int.from_bytes(payload[:4], "big")
            assert statsz == CMS_STATS_BUFSZ, \
                f"statsz prefix must be {CMS_STATS_BUFSZ}, got {statsz}"
            assert b"<role>" in payload[4:], \
                "stats doc missing the role element"
        finally:
            sock.close()

    def test_stats_size_form_flood(self, hostile_server):
        """A burst of kYR_size stats queries each returns the 4-byte statsz and
        never wedges the connection."""
        sock = _login_server(hostile_server.port)
        try:
            for i in range(40):
                sock.sendall(_build_frame(_SID | i, CMS_RR_STATS,
                                          CMS_STATS_SIZE))
            got = 0
            for _ in range(40):
                fr = _recv_code(sock, CMS_RSP_DATA, timeout=4)
                if fr is None:
                    break
                assert int.from_bytes(fr[3][:4], "big") == CMS_STATS_BUFSZ
                got += 1
            assert got >= 20, f"stats size-form flood dropped replies: {got}"
        finally:
            sock.close()

    def test_gone_for_unheld_path_is_noop(self, hostile_server):
        """kYR_gone for a path the node never registered is a harmless no-op —
        the registration (and its space) is untouched."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(0, CMS_RR_GONE, 0, b"/never/held/here"))
            time.sleep(0.2)
            assert _statfs_wfree(sock, _SID | 0x22) == 5000, \
                "kYR_gone for an unheld path disturbed the registration"
        finally:
            sock.close()

    def test_gone_long_path_bounded(self, hostile_server):
        """kYR_gone with a long (but in-frame) path is bounded-copied without
        overflow; the connection stays serviceable."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(0, CMS_RR_GONE, 0, b"/" + b"a" * 3000))
            time.sleep(0.2)
            assert _statfs_wfree(sock, _SID | 0x23) == 5000, \
                "an oversized kYR_gone path disturbed the connection"
        finally:
            sock.close()

    def test_status_suspend_reset_resume_survives(self, hostile_server):
        """A node driving its own kYR_status through suspend→reset→resume must
        never crash or drop the manager connection (registry mutations are
        node-scoped); liveness is intact throughout."""
        sock = _login_server(hostile_server.port)
        try:
            for mod in (CMS_ST_SUSPEND, CMS_ST_RESET, CMS_ST_RESUME):
                sock.sendall(_build_frame(0, CMS_RR_STATUS, mod))
                time.sleep(0.1)
            sock.sendall(_build_frame(_SID | 0x24, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a suspend/reset/resume sequence killed the connection"
        finally:
            sock.close()

    def test_status_garbage_modifier_is_noop(self, hostile_server):
        """An unknown kYR_status modifier is a no-op (stock parity), not a
        crash; the connection keeps working."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(0, CMS_RR_STATUS, 0x40))
            time.sleep(0.1)
            assert _statfs_wfree(sock, _SID | 0x25) == 5000
        finally:
            sock.close()

    def test_usage_query_answered_with_load(self, hostile_server):
        """kYR_usage from a logged-in node is answered with a kYR_load vector
        echoing the streamid (do_Usage parity)."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x26, CMS_RR_USAGE, 0))
            fr = _recv_code(sock, CMS_RR_LOAD, timeout=6)
            assert fr is not None, "kYR_usage drew no kYR_load reply"
            assert fr[0] == (_SID | 0x26), "usage reply must echo the streamid"
        finally:
            sock.close()

    def test_error_frame_oversized_text_bounded(self, hostile_server):
        """A kYR_error (fan-out reply fold) with a huge peer-controlled text is
        bounded before it can reach any client reply; no overflow, conn alive."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x27, CMS_RSP_ERROR, 0,
                                      b"\x00\x00\x00\x16" + b"Z" * 2000))
            time.sleep(0.2)
            assert _statfs_wfree(sock, _SID | 0x28) == 5000, \
                "an oversized kYR_error text disturbed the connection"
        finally:
            sock.close()

    def test_error_frame_short_payload_safe(self, hostile_server):
        """A kYR_error shorter than the 4-byte ecode is handled safely (ecode
        defaults to 0, empty text), never a short read."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x29, CMS_RSP_ERROR, 0, b"\x01\x02"))
            time.sleep(0.2)
            assert _statfs_wfree(sock, _SID | 0x2A) == 5000
        finally:
            sock.close()

    def test_foreign_have_dropped(self, hostile_server):
        """Security-neg: a node exporting only /data that asserts kYR_have for a
        path OUTSIDE its exports (no relay entry in play) is dropped by the
        paths-cover gate without disturbing the connection."""
        sock = _login_server(hostile_server.port, paths=b"r /data")
        try:
            sock.sendall(_build_frame(_SID | 0x2B, CMS_RR_HAVE,
                                      CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                      b"/etc/passwd\x00"))
            time.sleep(0.2)
            sock.sendall(_build_frame(_SID | 0x2C, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a foreign kYR_have disturbed the connection"
        finally:
            sock.close()

    def test_unsolicited_pong_ignored(self, hostile_server):
        """An unsolicited kYR_pong (we never pinged the node) is logged and
        ignored, not mistaken for a request; connection stays alive."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(0, CMS_RR_PONG, 0))
            time.sleep(0.1)
            assert _statfs_wfree(sock, _SID | 0x2D) == 5000
        finally:
            sock.close()


# ===========================================================================
# Node (dial-out) leg — esoteric ops a hostile REMOTE manager can throw at the
# node, including the MITM-critical redirect-injection vector.
# ===========================================================================

class TestNodeLegEsotericManager:

    def test_unsolicited_select_injection_ignored(self, hostile_node):
        """MITM redirect-injection: a manager naming a redirect host:port for a
        streamid with NO pending locate wakes nothing — the node cannot be
        steered to an attacker-chosen server for a request it never made."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        hostile_node.send_to_node(_SID | 0x30, CMS_RR_SELECT, 0,
                                  b"evil.attacker.example\x00"
                                  + (1094).to_bytes(2, "big"))
        time.sleep(0.3)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base, \
            "an injected redirect disturbed the node connection"
        assert _node_alive(hostile_node)

    def test_unsolicited_try_injection_ignored(self, hostile_node):
        """Same defense for kYR_try (ordered redirect list)."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        hostile_node.send_to_node(_SID | 0x31, CMS_RR_TRY, 0,
                                  b"evil.attacker.example\x00"
                                  + (2094).to_bytes(2, "big"))
        time.sleep(0.3)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base
        assert _node_alive(hostile_node)

    def test_truncated_redirect_ignored(self, hostile_node):
        """A redirect payload too short to carry host+NUL+port (< 3 bytes) is
        silently ignored — no over-read."""
        hostile_node.send_to_node(_SID | 0x32, CMS_RR_SELECT, 0, b"ab")
        assert _node_alive(hostile_node)

    def test_redirect_port_overrun_ignored(self, hostile_node):
        """A redirect whose port bytes would fall past the received payload
        (host+NUL present, port missing) is rejected, not read out of bounds."""
        hostile_node.send_to_node(_SID | 0x33, CMS_RR_SELECT, 0, b"host\x00")
        assert _node_alive(hostile_node)

    def test_manager_suspend_resume_survives(self, hostile_node):
        """A manager toggling the node's login gate via kYR_status suspend then
        resume must not disturb liveness — the node keeps answering pings."""
        hostile_node.send_to_node(_SID | 0x34, CMS_RR_STATUS, CMS_ST_SUSPEND)
        assert _node_alive(hostile_node), "node died on a manager suspend"
        hostile_node.send_to_node(_SID | 0x35, CMS_RR_STATUS, CMS_ST_RESUME)
        assert _node_alive(hostile_node), "node died on a manager resume"

    def test_manager_status_garbage_modifier_noop(self, hostile_node):
        """An unknown kYR_status modifier from the manager is a no-op; node
        stays alive and connected."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        hostile_node.send_to_node(_SID | 0x36, CMS_RR_STATUS, 0x40)
        time.sleep(0.2)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base
        assert _node_alive(hostile_node)

    def test_manager_space_query_answered(self, hostile_node):
        """kYR_space is answered with a kYR_avail reply echoing the streamid."""
        hostile_node.send_to_node(_SID | 0x37, CMS_RR_SPACE, 0)
        fr = hostile_node.collect_reply(CMS_RR_AVAIL, timeout=6)
        assert fr is not None, "kYR_space drew no kYR_avail reply"
        assert fr[0] == (_SID | 0x37)

    def test_manager_stats_query_answered(self, hostile_node):
        """kYR_stats is answered with a kYR_data stats document."""
        hostile_node.send_to_node(_SID | 0x38, CMS_RR_STATS, 0)
        assert hostile_node.collect_reply(CMS_RSP_DATA, timeout=6) is not None, \
            "kYR_stats drew no kYR_data reply"

    def test_manager_update_answered_with_status(self, hostile_node):
        """kYR_update makes the node resend its state as a kYR_status frame.
        collect_reply baselines at call time, so a login-time status already
        counted does not satisfy this — only the update-driven one does."""
        hostile_node.send_to_node(_SID | 0x39, CMS_RR_UPDATE, 0)
        assert hostile_node.collect_reply(CMS_RR_STATUS, timeout=6) is not None, \
            "kYR_update drew no kYR_status reply"

    def test_malformed_forwarded_ops_dropped(self, hostile_node):
        """Every forwarded namespace opcode fed a truncated Pup payload (a
        string claiming more bytes than remain) is dropped: no crash, no
        reconnect, node still answering."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        for op in (CMS_RR_CHMOD, CMS_RR_MKDIR, CMS_RR_MKPATH, CMS_RR_MV,
                   CMS_RR_RM, CMS_RR_RMDIR, CMS_RR_TRUNC):
            hostile_node.send_to_node(_SID | op, op, 0, b"\x00\x64ab")
        time.sleep(0.4)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base, \
            "a malformed forwarded op forced a reconnect"
        assert _node_alive(hostile_node)

    def test_forwarded_dir_op_traversal_refused(self, hostile_node):
        """The dir-shaped forwarded ops (mkdir/mkpath/chmod share fwdArgA) with
        a '..' escape path are refused by the kernel-confined open and answered
        kYR_error — nothing is created outside the export root."""
        for op in (CMS_RR_MKDIR, CMS_RR_MKPATH, CMS_RR_CHMOD):
            hostile_node.send_to_node(
                _SID | 0x40 | op, op, 0,
                _fwd_a_payload(b"mgr", b"493", b"/../pwn_%d" % op))
            fr = hostile_node.collect_reply(CMS_RSP_ERROR, timeout=6)
            assert fr is not None, \
                f"forwarded op {op} traversal was not refused with kYR_error"
        assert _node_alive(hostile_node)

    def test_malformed_prepare_ops_dropped(self, hostile_node):
        """kYR_prepadd/kYR_prepdel with malformed rrdata are answered kYR_error
        (EINVAL) and never crash or reconnect the node."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        for op in (CMS_RR_PREPADD, CMS_RR_PREPDEL):
            hostile_node.send_to_node(_SID | op, op, 0, b"\x00\x64ab")
        time.sleep(0.4)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base
        assert _node_alive(hostile_node)


# ===========================================================================
# Wire-level framing hardening (both legs) — fragmentation, resync, streamid
# and modifier fuzzing, and slowloris LOGIN.
# ===========================================================================
