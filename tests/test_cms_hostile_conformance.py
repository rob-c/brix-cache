from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cms_hostile_conformance_helpers")

class TestServerLegHostileFraming:

    def test_garbage_flood_does_not_disturb_other_clients(self, hostile_server):
        """A connection spewing all-0xFF bytes (header decodes to dlen 0xFFFF,
        far over MAX_FRAME) is dropped; a *separate* fresh client is served."""
        junk = socket.create_connection((H, hostile_server.port), timeout=6)
        try:
            junk.sendall(b"\xff" * 8192)
            time.sleep(0.3)
            assert _server_alive(hostile_server.port), \
                "a garbage-flooding peer took the server down for others"
        finally:
            junk.close()

    def test_oversized_frame_closes_only_the_offender(self, hostile_server):
        """A well-formed header claiming an oversized payload (dlen 5000, so
        5008 > 4096) closes the offending connection but not the server."""
        bad = socket.create_connection((H, hostile_server.port), timeout=6)
        bad.settimeout(6)
        try:
            bad.sendall(_build_frame(0, CMS_RR_LOGIN, 0, b"\x00" * 5000))
            # The offender's own connection must be closed (recv -> EOF).
            assert _recv_exact(bad, 1) is None, \
                "server did not close the oversized-frame connection"
            assert _server_alive(hostile_server.port), \
                "oversized frame from one peer disturbed the server"
        finally:
            bad.close()

    def test_max_boundary_frame_accepted(self, hostile_server):
        """The dlen boundary: dlen 4088 (total 4096 == MAX_FRAME) is ACCEPTED
        (the reject test is dlen+8 > 4096).  An unknown opcode at exactly the
        boundary is read in full and dropped, and the connection stays open."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            frame = _build_frame(0, 0x7E, 0, b"\x00" * CMS_MAX_DLEN)
            assert len(frame) == 4096
            sock.sendall(frame)
            # Same connection must still answer liveness -> boundary accepted.
            sock.sendall(_build_frame(_SID | 1, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "server closed on a legal max-size (4088) frame"
        finally:
            sock.close()

    def test_unknown_opcode_keeps_connection(self, hostile_server):
        """An unknown opcode is dropped, not fatal — cmsd tolerates frames it
        does not act on.  The same connection stays serviceable."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(_build_frame(0, 0x7F, 0))
            sock.sendall(_build_frame(_SID | 2, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "an unknown opcode killed the connection"
        finally:
            sock.close()

    def test_half_header_then_eof_isolated(self, hostile_server):
        """A peer that sends a partial header then hangs up (EOF mid-frame) is
        cleaned up without wedging the accumulator for anyone else."""
        stub = socket.create_connection((H, hostile_server.port), timeout=6)
        stub.sendall(b"\x00\x00\x00")   # 3 of 8 header bytes, then close
        stub.close()
        time.sleep(0.2)
        assert _server_alive(hostile_server.port), \
            "a truncated-header hangup disturbed the server"

    def test_pre_login_ops_ignored_but_alive(self, hostile_server):
        """Security-neg: LOAD/AVAIL/STATFS/STATUS/USAGE before LOGIN are all
        gated (no reply, no registration side-effect), yet the connection is
        kept — proven by a header-only PING still drawing a PONG."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            for code in (CMS_RR_LOAD, CMS_RR_AVAIL, CMS_RR_STATFS,
                         CMS_RR_STATUS, CMS_RR_USAGE):
                sock.sendall(_build_frame(0, code, 0, b"\x00\x00"))
            # None of the above may have produced a reply frame ...
            assert _recv_code(sock, CMS_RR_PONG, timeout=1.0) is None
            # ... but PING (pure liveness, no login) still answers.
            sock.sendall(_build_frame(_SID | 3, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "pre-login gated ops closed the connection"
        finally:
            sock.close()

    def test_zero_dlen_state_dropped(self, hostile_server):
        """A logged-in node sending kYR_state with an empty payload hits the
        `payload_len == 0` guard and is dropped; the connection survives and
        still answers STATFS."""
        sock = _node_login_dialog(hostile_server.port,
                                  _minimal_login_payload(NODE_DATA_PORT))
        sock.settimeout(6)
        try:
            time.sleep(0.3)
            sock.sendall(_build_frame(0, CMS_RR_STATE, CMS_MOD_RAW))
            time.sleep(0.2)
            assert _statfs_wfree(sock, _SID | 4) == 5000, \
                "empty kYR_state disturbed a logged-in connection"
        finally:
            sock.close()

    def test_second_login_on_same_connection(self, hostile_server):
        """Esoteric state machine: a duplicate LOGIN on an already-registered
        connection must re-register without crashing or dropping the peer.  The
        connection stays alive and keeps answering STATFS (the aggregate free
        space reflects the live registration(s), never a hang or a zero)."""
        sock = _node_login_dialog(hostile_server.port,
                                  _minimal_login_payload(NODE_DATA_PORT))
        sock.settimeout(6)
        try:
            time.sleep(0.3)
            sock.sendall(_build_frame(0, CMS_RR_LOGIN, 0,
                                      _minimal_login_payload(NODE_DATA_PORT + 1)))
            time.sleep(0.3)
            assert _statfs_wfree(sock, _SID | 5) >= 5000, \
                "a second LOGIN wedged the connection"
        finally:
            sock.close()

    def test_ping_flood_survives_fairness_yield(self, hostile_server):
        """A logged-in node firing 200 kYR_pings in one burst crosses the
        64-frames/wakeup fairness yield several times; every frame is serviced
        (a healthy share of pongs come back) and the connection remains fully
        serviceable — STATFS still answers its unmutated 5000."""
        sock = _node_login_dialog(hostile_server.port,
                                  _minimal_login_payload(NODE_DATA_PORT))
        sock.settimeout(8)
        try:
            time.sleep(0.3)
            burst = b"".join(_build_frame(_SID | (i & 0xFF), CMS_RR_PING, 0)
                             for i in range(200))
            sock.sendall(burst)
            pongs = 0
            deadline = time.time() + 8.0
            while time.time() < deadline and pongs < 200:
                if _recv_code(sock, CMS_RR_PONG, timeout=0.5) is None:
                    break
                pongs += 1
            assert pongs >= 50, \
                f"ping flood dropped frames past the fairness yield: {pongs}"
            assert _statfs_wfree(sock, _SID | 6) == 5000, \
                "a 200-frame ping flood stalled or disturbed the connection"
        finally:
            sock.close()

    def test_connection_churn_then_serve(self, hostile_server):
        """Rapid connect/immediately-close churn (no leak, no cap wedge): after
        40 half-open churns the server still serves a fresh client."""
        for _ in range(40):
            try:
                c = socket.create_connection((H, hostile_server.port),
                                             timeout=4)
                c.close()
            except OSError:
                pass
        assert _server_alive(hostile_server.port), \
            "connection churn left the server unable to serve"


# ===========================================================================
# Node (dial-out) leg — a hostile REMOTE manager must not be able to hang the
# node; framing violations force a clean reconnect, in-frame garbage is
# tolerated.
# ===========================================================================

class TestNodeLegHostileManager:

    def test_oversized_frame_forces_clean_reconnect(self, hostile_node):
        """A manager frame with dlen 5000 (5008 > 4096) makes the node tear the
        socket down and reconnect (a fresh LOGIN), rather than mis-framing."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        hostile_node.send_to_node(0, CMS_RR_PING, 0, b"\x00" * 5000)
        assert _wait_relogin(hostile_node, base), \
            "node did not reconnect after an oversized manager frame"

    def test_manager_disc_forces_reconnect(self, hostile_node):
        """kYR_disc from the manager tears the node connection down and it
        reconnects with backoff (never sits on a dead socket)."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        hostile_node.send_to_node(0, CMS_RR_DISC, 0)
        assert _wait_relogin(hostile_node, base), \
            "node did not reconnect after a manager DISC"

    def test_in_frame_garbage_opcode_tolerated(self, hostile_node):
        """A well-sized frame with an unknown opcode is dropped WITHOUT a
        reconnect — the node tolerates junk it does not act on and stays up."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        for code in (0x7E, 0x7F, 0x5A):
            hostile_node.send_to_node(_SID, code, 0, b"garbage-payload")
        time.sleep(0.5)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base, \
            "an in-frame unknown opcode wrongly forced a reconnect"
        assert _node_alive(hostile_node), \
            "node stopped answering after in-frame garbage"

    def test_manager_ping_gets_pong(self, hostile_node):
        """Symmetric liveness: the manager can probe the node with kYR_ping and
        gets a kYR_pong (the node never black-holes a liveness check)."""
        assert _node_alive(hostile_node), "node did not answer a manager PING"

    def test_malformed_forwarded_op_dropped(self, hostile_node):
        """A forwarded kYR_mkdir whose Pup string claims more bytes than remain
        (rrdata parse -> -1) is dropped: no crash, no reconnect, node alive."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        # Pup string length 100 but only 2 bytes follow -> overrun -> -1.
        hostile_node.send_to_node(_SID, CMS_RR_MKDIR, 0,
                                  b"\x00\x64" + b"ab")
        time.sleep(0.4)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base, \
            "a malformed forwarded op forced a reconnect"
        assert _node_alive(hostile_node), \
            "node stopped answering after a malformed forwarded op"

    def test_state_traversal_yields_no_have(self, hostile_node):
        """Security-neg: a malicious manager asking kYR_state for a ".."
        escape path must draw NO kYR_have (kernel-confined existence probe) and
        must not disturb the connection."""
        base_have = hostile_node.count_frames(CMS_RR_HAVE)
        hostile_node.send_to_node(_SID, CMS_RR_STATE, CMS_MOD_RAW,
                                  b"/../../../../etc/passwd\x00")
        time.sleep(0.6)
        assert hostile_node.count_frames(CMS_RR_HAVE) == base_have, \
            "node leaked kYR_have for a traversal path"
        assert _node_alive(hostile_node), \
            "a traversal state probe disturbed the node"

    def test_ping_flood_stays_connected(self, hostile_node):
        """200 back-to-back kYR_pings cross the node's 64/wakeup fairness yield;
        the node answers a healthy share of pongs and never reconnects."""
        base_login = hostile_node.count_frames(CMS_RR_LOGIN)
        base_pong = hostile_node.count_frames(CMS_RR_PONG)
        for i in range(200):
            hostile_node.send_to_node(_SID | (i & 0xFF), CMS_RR_PING, 0)
        deadline = time.time() + 10.0
        while time.time() < deadline:
            if hostile_node.count_frames(CMS_RR_PONG) - base_pong >= 50:
                break
            time.sleep(0.1)
        assert hostile_node.count_frames(CMS_RR_PONG) - base_pong >= 50, \
            "node did not keep answering under a ping flood"
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base_login, \
            "a ping flood forced a reconnect"


# ===========================================================================
# MITM cross-leg isolation — the headline property.  Abuse on one leg must not
# stall the other; the relay fails closed rather than hanging either side.
# ===========================================================================

class TestMitmCrossLegIsolation:

    CHILD_DPORT = NODE_DATA_PORT + 20

    def _login_child(self, peer, paths=b"r /data"):
        sock = _node_login_dialog(
            peer.node_port,
            _login_payload_with_mode(self.CHILD_DPORT, CMS_MODE_SERVER,
                                     paths=paths))
        time.sleep(0.4)
        return sock

    def test_outstanding_relay_does_not_block_upward_ping(self, hostile_super):
        """A relayed probe that a (slow/hostile) child never answers leaves the
        relay entry parked — it must NOT head-of-line-block the upward leg: a
        following manager kYR_ping is answered promptly."""
        child = self._login_child(hostile_super)
        try:
            hostile_super.send_to_node(_SID | 0xA1, CMS_RR_STATE, CMS_MOD_RAW,
                                       b"/elsewhere/never-answered.bin\x00")
            # The probe reached the child (relay happened) ...
            assert _recv_code(child, CMS_RR_STATE, timeout=8) is not None, \
                "supervisor did not relay the miss to its child"
            # ... and with the entry still parked, the upward leg is responsive.
            assert _node_alive(hostile_super), \
                "an outstanding relay blocked the upward manager leg"
        finally:
            child.close()

    def test_hostile_child_cannot_wedge_upward_leg(self, hostile_super):
        """A site child that floods the downward accept leg with an oversized
        frame is dropped there; the upward manager leg stays fully responsive
        (no cross-leg contamination)."""
        child = self._login_child(hostile_super)
        try:
            child.sendall(_build_frame(0, CMS_RR_STATE, CMS_MOD_RAW,
                                       b"\x00" * 5000))
            time.sleep(0.3)
            assert _node_alive(hostile_super), \
                "a hostile child wedged the upward manager leg"
        finally:
            child.close()

    def test_relay_table_saturation_fails_closed(self, hostile_super):
        """70 distinct registry-miss probes (> RELAY_CAP 64) with no child to
        answer: the relay table saturates, add() returns 0 for the overflow and
        the leg stays silent — no crash, no hang.  The upward leg is still
        healthy afterward and no reconnect was triggered."""
        base_login = hostile_super.count_frames(CMS_RR_LOGIN)
        for i in range(70):
            path = "/miss/p{:03d}.bin\x00".format(i).encode()
            hostile_super.send_to_node(_SID | 0x300 | i, CMS_RR_STATE,
                                       CMS_MOD_RAW, path)
        time.sleep(0.5)
        assert hostile_super.count_frames(CMS_RR_LOGIN) == base_login, \
            "relay-table saturation crashed/reconnected the upward leg"
        assert _node_alive(hostile_super), \
            "relay-table saturation left the upward leg unresponsive"

    def test_child_registration_survives_relay_pressure(self, hostile_super):
        """The downward accept leg keeps admitting new site nodes even while
        the upward leg carries parked relay entries — the two planes are
        independent."""
        # Park a relay entry from the manager side.
        hostile_super.send_to_node(_SID | 0xB1, CMS_RR_STATE, CMS_MOD_RAW,
                                   b"/elsewhere/pending.bin\x00")
        # A fresh child can still log in and be served on the downward leg.
        child = self._login_child(hostile_super, paths=b"r /data")
        try:
            assert _statfs_wfree(child, _SID | 0xB2) == 5000, \
                "downward child service stalled under upward relay pressure"
        finally:
            child.close()

    @pytest.mark.slow
    def test_stale_relay_answer_after_ttl_refused(self, hostile_super):
        """A child that answers a relayed probe AFTER the 5s relay TTL has
        expired is refused — the stale entry is gone, so no upward kYR_have is
        forged, and the supervisor stays healthy."""
        child = self._login_child(hostile_super)
        try:
            path = b"/elsewhere/slow.bin"
            hostile_super.send_to_node(_SID | 0xC1, CMS_RR_STATE, CMS_MOD_RAW,
                                       path + b"\x00")
            fr = _recv_code(child, CMS_RR_STATE, timeout=8)
            assert fr is not None, "probe was not relayed to the child"
            down_sid = fr[0]
            base_have = hostile_super.count_frames(CMS_RR_HAVE)
            time.sleep(6.0)   # exceed BRIX_CMS_STATE_RELAY_TTL_MS (5000)
            child.sendall(_build_frame(down_sid, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       path + b"\x00"))
            time.sleep(1.0)
            assert hostile_super.count_frames(CMS_RR_HAVE) == base_have, \
                "a post-TTL child answer forged an upward kYR_have"
            assert _node_alive(hostile_super), \
                "the supervisor was unhealthy after a stale relay answer"
        finally:
            child.close()
