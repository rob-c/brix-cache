from split_continuation import reexport as _reexport
def _phase_test_per_ip_connection_cap_bounds_concurrency_1(s):
    try:
        s.sendall(_build_frame(_SID | 0x0F, CMS_RR_PING, 0))
        if _recv_code(s, CMS_RR_PONG, timeout=2) is not None:
            admitted += 1
    except OSError:
        pass


def _check_test_per_ip_connection_cap_bounds_concurrency_1(hardened_server):
    assert _server_alive(hardened_server.port), \
        "the server did not resume service after cap enforcement"


_reexport(globals(), "_test_cms_hostile_conformance_helpers")

class TestNodeStateProbeAndRelayDepth:

    CHILD_DPORT = NODE_DATA_PORT + 40

    def _login_child(self, peer, paths=b"r /data"):
        sock = _node_login_dialog(
            peer.node_port,
            _login_payload_with_mode(self.CHILD_DPORT, CMS_MODE_SERVER,
                                     paths=paths))
        time.sleep(0.4)
        return sock

    # -- data-node confined existence probe ---------------------------------

    def test_state_resident_file_is_locatable(self, hostile_node):
        """Baseline (positive control): a kYR_state for the genuinely resident
        export file draws a kYR_have — proving the confined probe ANSWERS, so
        the silences asserted below are confinement, not a dead probe."""
        base = hostile_node.count_frames(CMS_RR_HAVE)
        hostile_node.send_to_node(_SID | 0xD0, CMS_RR_STATE, CMS_MOD_RAW,
                                  b"/have_me.bin\x00")
        assert _wait_have_increment(hostile_node, base), \
            "node did not answer kYR_have for a genuinely resident path"

    def test_state_foreign_absolute_no_have(self, hostile_node):
        """Security-neg: a probe for a real host file OUTSIDE the export root
        (/etc/passwd) draws NO kYR_have — brix_stat_beneath resolves under the
        export rootfd with RESOLVE_BENEATH, so the escape is kernel-rejected."""
        base = hostile_node.count_frames(CMS_RR_HAVE)
        hostile_node.send_to_node(_SID | 0xD1, CMS_RR_STATE, CMS_MOD_RAW,
                                  b"/etc/passwd\x00")
        time.sleep(0.6)
        assert hostile_node.count_frames(CMS_RR_HAVE) == base, \
            "node leaked kYR_have for a path outside its export root"
        assert _node_alive(hostile_node), \
            "a foreign-path state probe disturbed the node"

    def test_state_oversized_path_bounded(self, hostile_node):
        """A ~1100-byte path (> the 1024-byte pathz buffer, still under the
        4088 frame limit) is rejected by cms_state_extract_path (pl >=
        pathz_size) with no over-read: no kYR_have, no crash, node alive."""
        base = hostile_node.count_frames(CMS_RR_HAVE)
        huge = b"/" + b"a" * 1100 + b"\x00"
        assert len(huge) < CMS_MAX_DLEN, "probe must fit inside one frame"
        hostile_node.send_to_node(_SID | 0xD2, CMS_RR_STATE, CMS_MOD_RAW, huge)
        time.sleep(0.5)
        assert hostile_node.count_frames(CMS_RR_HAVE) == base, \
            "node answered an over-length (unbounded) state path"
        assert _node_alive(hostile_node), \
            "an over-length state probe disturbed the node"

    def test_state_relative_path_no_have(self, hostile_node):
        """A non-absolute path (no leading '/') is rejected up front
        (payload[0] != '/') — no kYR_have, connection intact."""
        base = hostile_node.count_frames(CMS_RR_HAVE)
        hostile_node.send_to_node(_SID | 0xD3, CMS_RR_STATE, CMS_MOD_RAW,
                                  b"have_me.bin\x00")
        time.sleep(0.5)
        assert hostile_node.count_frames(CMS_RR_HAVE) == base, \
            "node answered a relative (non-absolute) state path"
        assert _node_alive(hostile_node), \
            "a relative-path state probe disturbed the node"

    def test_state_embedded_nul_truncates_safely(self, hostile_node):
        """A path with an embedded NUL followed by a foreign path
        (/have_me.bin\\0/etc/passwd\\0): the bounded scan stops at the FIRST
        NUL, so the probe resolves to the resident path only (kYR_have for the
        resident) and the trailing foreign bytes are never read as a path."""
        base = hostile_node.count_frames(CMS_RR_HAVE)
        hostile_node.send_to_node(_SID | 0xD4, CMS_RR_STATE, CMS_MOD_RAW,
                                  b"/have_me.bin\x00/etc/passwd\x00")
        assert _wait_have_increment(hostile_node, base), \
            "embedded-NUL probe did not truncate to the resident prefix"
        assert _node_alive(hostile_node), \
            "an embedded-NUL state probe disturbed the node"

    def test_state_empty_payload_no_have(self, hostile_node):
        """A lone NUL (zero-length path, pl == 0) is rejected — no kYR_have,
        node stays connected (distinct from the server-leg zero-dlen case)."""
        base = hostile_node.count_frames(CMS_RR_HAVE)
        hostile_node.send_to_node(_SID | 0xD5, CMS_RR_STATE, CMS_MOD_RAW,
                                  b"\x00")
        time.sleep(0.5)
        assert hostile_node.count_frames(CMS_RR_HAVE) == base, \
            "node answered an empty state path"
        assert _node_alive(hostile_node), \
            "an empty state probe disturbed the node"

    # -- relay depth: forged answers must not forge an upward kYR_have -------

    def test_relay_forged_path_answer_kept_for_honest(self, hostile_super):
        """take() consumes a parked relay entry ONLY on an exact path match: a
        child answering the right down_sid with the WRONG path is refused
        (paths-cover then drops it) AND the entry survives, so the child's later
        HONEST answer for the probed path still lands the upward kYR_have.
        Proves the forged-path branch keeps the entry (no self-inflicted DoS on
        the honest reply)."""
        child = self._login_child(hostile_super)
        try:
            hostile_super.send_to_node(_SID | 0xE1, CMS_RR_STATE, CMS_MOD_RAW,
                                       b"/relay/target.bin\x00")
            fr = _recv_code(child, CMS_RR_STATE, timeout=8)
            assert fr is not None, "supervisor did not relay the probe down"
            down_sid = fr[0]
            probed = fr[3].split(b"\x00", 1)[0]
            base_have = hostile_super.count_frames(CMS_RR_HAVE)

            # Forged path on the real down_sid: refused, entry NOT consumed.
            child.sendall(_build_frame(down_sid, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       b"/relay/FORGED.bin\x00"))
            time.sleep(0.6)
            assert hostile_super.count_frames(CMS_RR_HAVE) == base_have, \
                "a forged-path child answer forged an upward kYR_have"

            # Honest answer for the probed path still lands (entry survived).
            child.sendall(_build_frame(down_sid, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       probed + b"\x00"))
            assert _wait_have_increment(hostile_super, base_have), \
                "forged answer consumed the entry — honest reply was lost"
            assert _node_alive(hostile_super), \
                "the supervisor was unhealthy after a forged relay answer"
        finally:
            child.close()

    def test_relay_single_use_second_answer_ignored(self, hostile_super):
        """A parked relay entry is single-use: the FIRST honest child answer is
        echoed up and clears in_use; a SECOND identical answer for the same
        down_sid+path finds no live entry and is dropped by paths-cover — no
        duplicate upward kYR_have, no crash."""
        child = self._login_child(hostile_super)
        try:
            hostile_super.send_to_node(_SID | 0xE2, CMS_RR_STATE, CMS_MOD_RAW,
                                       b"/relay/once.bin\x00")
            fr = _recv_code(child, CMS_RR_STATE, timeout=8)
            assert fr is not None, "supervisor did not relay the probe down"
            down_sid = fr[0]
            probed = fr[3].split(b"\x00", 1)[0]
            base_have = hostile_super.count_frames(CMS_RR_HAVE)

            child.sendall(_build_frame(down_sid, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       probed + b"\x00"))
            assert _wait_have_increment(hostile_super, base_have), \
                "first honest relay answer was not echoed upward"
            after_first = hostile_super.count_frames(CMS_RR_HAVE)

            # Replay: the entry is already consumed.
            child.sendall(_build_frame(down_sid, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       probed + b"\x00"))
            time.sleep(0.6)
            assert hostile_super.count_frames(CMS_RR_HAVE) == after_first, \
                "a replayed child answer forged a duplicate upward kYR_have"
            assert _node_alive(hostile_super), \
                "the supervisor was unhealthy after a replayed relay answer"
        finally:
            child.close()

    def test_relay_forged_down_sid_steers_nothing(self, hostile_super):
        """A hostile child that emits an UNSOLICITED kYR_have carrying a
        down_sid the supervisor never issued matches no relay entry; the path
        (outside the child's exports) then fails paths-cover and is dropped — no
        upward kYR_have is forged and the supervisor stays healthy."""
        child = self._login_child(hostile_super)
        try:
            base_have = hostile_super.count_frames(CMS_RR_HAVE)
            child.sendall(_build_frame(0x7EADBEEF, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       b"/relay/ghost.bin\x00"))
            time.sleep(0.6)
            assert hostile_super.count_frames(CMS_RR_HAVE) == base_have, \
                "an unsolicited forged-streamid have forged an upward kYR_have"
            assert _node_alive(hostile_super), \
                "a forged-streamid child answer disturbed the supervisor"
        finally:
            child.close()


# ===========================================================================
# Accept-leg resilience limits — the deadlines + admission caps (Phase-50 WS3/
# WS4, A3) that stop a hostile site node from holding a slot forever or
# exhausting the accept leg, plus the non-blocking write path that keeps a
# slow/zero-reading or half-closed peer from wedging the single worker.  These
# are the "hostile network hang" classes stock cmsd↔cmsd is weak on.  Verified
# against src/net/cms/server_handler.c (per-IP + global caps),
# src/net/cms/server_recv.c (idle watchdog), and frame_io.c::brix_cms_send_all
# (AGAIN → drop, never block).
# ===========================================================================
class TestServerLegResilienceLimits:

    def test_idle_logged_in_peer_reaped(self, hardened_server):
        """A node that completes LOGIN then goes completely silent is closed by
        the post-login idle watchdog (3s here) — a hostile peer cannot register
        and then hold a slot forever.  The server keeps serving fresh clients."""
        victim = _login_server(hardened_server.port)
        victim.settimeout(0.5)
        try:
            closed = False
            deadline = time.time() + 9.0
            while time.time() < deadline:
                try:
                    if victim.recv(64) == b"":
                        closed = True
                        break
                    # server sent us something (e.g. a ping) — keep waiting
                except socket.timeout:
                    continue
                except OSError:
                    closed = True
                    break
            assert closed, \
                "a silent logged-in peer was not reaped by the idle watchdog"
        finally:
            victim.close()
        assert _server_alive(hardened_server.port), \
            "the server was unhealthy after reaping an idle peer"

    def test_per_ip_connection_cap_bounds_concurrency(self, hardened_server):
        """20 simultaneous connections from one source IP against a per-IP cap
        of 8: at most 8 are admitted+serviced and the overflow is refused
        (finalized FORBIDDEN at accept, before any frame handler) — one hostile
        IP cannot exhaust the accept leg.  After releasing, service resumes."""
        socks = []
        try:
            for _ in range(20):
                try:
                    s = socket.create_connection((H, hardened_server.port),
                                                 timeout=4)
                    s.settimeout(2.0)
                    socks.append(s)
                except OSError:
                    pass
            time.sleep(0.6)   # let the worker accept all + apply the cap
            admitted = 0
            for s in socks:
                _phase_test_per_ip_connection_cap_bounds_concurrency_1(s)
            def _assert_test_per_ip_connection_cap_bounds_concurrency_1():
                assert 1 <= admitted <= 8, \
                    f"per-IP cap not enforced: {admitted} conns serviced (cap 8)"
                assert len(socks) - admitted >= 1, \
                    "no connection was refused despite exceeding the per-IP cap"

            _assert_test_per_ip_connection_cap_bounds_concurrency_1()
        finally:
            for s in socks:
                s.close()
        time.sleep(0.4)   # let the finalized sessions decrement the IP count
        _check_test_per_ip_connection_cap_bounds_concurrency_1(hardened_server)

    def test_slow_reader_does_not_block_others(self, hostile_server):
        """The canonical hostile-network wedge: a peer floods kYR_ping but NEVER
        reads the kYR_pong replies, so its receive buffer (shrunk here) and the
        server's send buffer fill.  brix_cms_send_all returns AGAIN and drops
        the frame rather than blocking, so the single worker keeps serving a
        separate well-behaved peer (where a blocking-write cmsd would stall)."""
        slow = socket.create_connection((H, hostile_server.port), timeout=6)
        slow.settimeout(8)
        try:
            slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
            flood = b"".join(_build_frame(_SID | (i & 0xFF), CMS_RR_PING, 0)
                             for i in range(20000))
            try:
                slow.sendall(flood)
            except OSError:
                pass   # our own send may fail once the server stops draining us
            assert _server_alive(hostile_server.port), \
                "a slow/zero-reading peer blocked the worker for other clients"
        finally:
            slow.close()

    def test_half_closed_write_side_cleaned_up(self, hostile_server):
        """A peer that half-closes (shutdown SHUT_WR — sends FIN but keeps its
        read half open, a real asymmetric-network teardown) is seen as EOF on
        the read half and torn down cleanly; other clients keep being served."""
        peer = socket.create_connection((H, hostile_server.port), timeout=6)
        peer.settimeout(6)
        try:
            peer.sendall(_build_frame(_SID | 1, CMS_RR_PING, 0))
            assert _recv_code(peer, CMS_RR_PONG, timeout=6) is not None, \
                "server did not answer before the half-close"
            peer.shutdown(socket.SHUT_WR)
            time.sleep(0.3)
            assert _server_alive(hostile_server.port), \
                "a half-closed (SHUT_WR) peer disturbed the server"
        finally:
            peer.close()


# ===========================================================================
# Large-scale opcode / frame-size / state-path sweeps.
#
# The suites above pin *named* esoteric behaviours one at a time.  The classes
# below carpet-bomb both legs with the FULL opcode space (every rrCode a stock
# cmsd defines plus a band of raw unknowns), the full accepted/rejected frame-
# size boundary, and a broad adversarial state-path corpus — each paired with a
# garbage payload — and after EVERY single hostile frame re-prove liveness:
#   * server leg  -> a *fresh* client still gets a kYR_pong (the offender may be
#     closed; the accept leg must keep serving everyone else);
#   * node leg    -> the upward manager leg still answers kYR_ping, riding out
#     any DISC-forced reconnect.
# One long-lived instance per leg endures the whole barrage, so a slow resource
# or state leak across hundreds of hostile frames would surface as a late red.
# This is the "ROCK SOLID — neither end may hang the other" property at scale.
# ===========================================================================

# Every rrCode a stock cmsd emits (src/net/cms/cms_internal.h), minus LOGIN (0,
# its own dialog) and PING (17, the liveness op), plus a band of raw unknowns
# that MUST be read-and-dropped without disturbing the framer.
_SWEEP_OPS = [
    ("chmod", CMS_RR_CHMOD), ("mkdir", CMS_RR_MKDIR), ("mkpath", CMS_RR_MKPATH),
    ("mv", CMS_RR_MV), ("prepadd", CMS_RR_PREPADD), ("prepdel", CMS_RR_PREPDEL),
    ("rm", CMS_RR_RM), ("rmdir", CMS_RR_RMDIR), ("select", CMS_RR_SELECT),
    ("stats", CMS_RR_STATS), ("avail", CMS_RR_AVAIL), ("disc", CMS_RR_DISC),
    ("gone", CMS_RR_GONE), ("have", CMS_RR_HAVE), ("load", CMS_RR_LOAD),
    ("pong", CMS_RR_PONG), ("space", CMS_RR_SPACE), ("state", CMS_RR_STATE),
    ("statfs", CMS_RR_STATFS), ("status", CMS_RR_STATUS), ("trunc", CMS_RR_TRUNC),
    ("try", CMS_RR_TRY), ("update", CMS_RR_UPDATE), ("usage", CMS_RR_USAGE),
    ("xauth", CMS_RR_XAUTH), ("cns", CMS_RR_CNS),
    # raw unknowns spanning the low gaps and the high (>0x7F) band
    ("raw02", 0x02), ("raw1c", 0x1C), ("raw1d", 0x1D), ("raw1e", 0x1E),
    ("raw1f", 0x1F), ("raw29", 0x29), ("raw7e", 0x7E), ("raw7f", 0x7F),
    ("rawfe", 0xFE), ("rawff", 0xFF),
]
_SWEEP_IDS = [n for n, _ in _SWEEP_OPS]
_SWEEP_CODES = [c for _, c in _SWEEP_OPS]

# Structured-looking garbage: a short run that under-fills every op's expected
# payload (exercises the truncated/short-decode path of each handler).
_SWEEP_GARBAGE = bytes(range(32))



class TestServerLegOpcodeMatrix:
    """Every opcode, with a garbage payload, on the accept leg — once BEFORE
    login (pre-auth gate) and once AFTER a valid login (per-op handler live).
    The offending frame may cost the offender its connection; a fresh client
    must always still be served."""

    @pytest.mark.parametrize("code", _SWEEP_CODES, ids=_SWEEP_IDS)
    def test_pre_login_opcode_garbage_keeps_server_alive(self, sweep_server, code):
        junk = socket.create_connection((H, sweep_server.port), timeout=6)
        junk.settimeout(4)
        try:
            junk.sendall(_build_frame(_SID | code, code, 0, _SWEEP_GARBAGE))
            time.sleep(0.05)
            assert _server_alive(sweep_server.port), \
                f"pre-login opcode 0x{code:02x} took the accept leg down"
        finally:
            junk.close()

    @pytest.mark.parametrize("code", _SWEEP_CODES, ids=_SWEEP_IDS)
    def test_post_login_opcode_garbage_keeps_server_alive(self, sweep_server, code):
        victim = _login_server(sweep_server.port)
        try:
            try:
                victim.sendall(_build_frame(_SID | code, code, 0, _SWEEP_GARBAGE))
            except OSError:
                pass   # offender may already be closed by an earlier violation
            time.sleep(0.05)
            assert _server_alive(sweep_server.port), \
                f"post-login opcode 0x{code:02x} took the accept leg down"
        finally:
            victim.close()
