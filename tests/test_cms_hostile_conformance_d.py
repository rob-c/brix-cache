from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cms_hostile_conformance_helpers")

class TestRoleConfusionFrames:

    # Opcodes that only ever travel manager→node (the node/dial-out leg's
    # vocabulary); a node must NOT be able to drive these UP into the manager.
    NODE_ROLE_OPS = (
        CMS_RR_SELECT, CMS_RR_TRY, CMS_RR_STATE, CMS_RR_CHMOD, CMS_RR_MKDIR,
        CMS_RR_MKPATH, CMS_RR_MV, CMS_RR_RM, CMS_RR_RMDIR, CMS_RR_TRUNC,
        CMS_RR_PREPADD, CMS_RR_PREPDEL,
    )

    # Opcodes that only ever travel node→manager (the server/accept leg's
    # vocabulary); a manager must NOT be able to drive these DOWN into a node.
    SERVER_ROLE_OPS = (
        CMS_RR_XAUTH, CMS_RR_GONE, CMS_RR_HAVE, CMS_RR_USAGE, CMS_RR_STATFS,
        CMS_RR_LOAD, CMS_RR_AVAIL, CMS_RR_CNS,
    )

    def test_server_leg_ignores_node_role_ops(self, hostile_server):
        """A logged-in node that emits node-role opcodes (redirect/state/
        forwarded-namespace ops it should only ever RECEIVE) has each one
        dropped by the manager's route table without a mis-dispatch; the
        connection stays fully serviceable."""
        sock = _login_server(hostile_server.port)
        try:
            for op in self.NODE_ROLE_OPS:
                sock.sendall(_build_frame(_SID | op, op, 0, b"\x00\x08junk"))
            time.sleep(0.3)
            # No reply should have been produced for any of them, and the
            # connection must still answer a well-formed statfs.
            assert _statfs_wfree(sock, _SID | 0x70) == 5000, \
                "a node-role opcode confused the manager state machine"
            sock.sendall(_build_frame(_SID | 0x71, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None
        finally:
            sock.close()

    def test_node_leg_ignores_server_role_ops(self, hostile_node):
        """A hostile manager that emits server-role opcodes (statfs/gone/have/
        usage/load/avail/cns/xauth a node should only ever SEND) has each one
        dropped: no reconnect (stable LOGIN count) and the node stays alive."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        for op in self.SERVER_ROLE_OPS:
            hostile_node.send_to_node(_SID | op, op, 0, b"\x00\x08junk")
        time.sleep(0.4)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base, \
            "a server-role opcode forced the node to reconnect"
        assert _node_alive(hostile_node), \
            "a server-role opcode wedged the node"

    def test_server_disc_echoes_then_closes(self, hostile_server):
        """kYR_disc from a node is echoed back (do_Disc parity) and the manager
        then closes that link cleanly — while still serving everyone else."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x72, CMS_RR_DISC, 0))
            assert _recv_code(sock, CMS_RR_DISC, timeout=6) is not None, \
                "manager did not echo kYR_disc"
            assert _recv_exact(sock, 1) is None, \
                "manager did not close the link after a disc handshake"
        finally:
            sock.close()
        assert _server_alive(hostile_server.port), \
            "a disc handshake disturbed service for other clients"

    def test_status_stage_nostage_survives(self, hostile_server):
        """A node advertising its staging capability via kYR_status(stage) then
        retracting it (nostage) — the disk-only↔staging transition a real node
        makes — never crashes or drops the connection."""
        sock = _login_server(hostile_server.port)
        try:
            for mod in (CMS_ST_STAGE, CMS_ST_NOSTAGE,
                        CMS_ST_RESUME | CMS_ST_NOSTAGE):
                sock.sendall(_build_frame(0, CMS_RR_STATUS, mod))
                time.sleep(0.1)
            assert _statfs_wfree(sock, _SID | 0x73) == 5000, \
                "a stage/nostage transition disturbed the registration"
        finally:
            sock.close()

    def test_multi_host_try_injection_ignored(self, hostile_node):
        """MITM: a kYR_try carrying an ORDERED LIST of attacker redirect targets
        for a stream with no pending locate steers nothing — the node cannot be
        walked through an attacker's redirect chain for a request it never
        issued."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        payload = (b"evil-a.attacker.example\x00" + (1094).to_bytes(2, "big")
                   + b"evil-b.attacker.example\x00" + (2094).to_bytes(2, "big"))
        hostile_node.send_to_node(_SID | 0x74, CMS_RR_TRY, 0, payload)
        time.sleep(0.3)
        assert hostile_node.count_frames(CMS_RR_LOGIN) == base
        assert _node_alive(hostile_node)


# ===========================================================================
# Numeric payload parsers, LOGIN edge cases, zero-payload safety, and the
# 64-frame fairness-boundary reassembly — the byte-level surfaces a fuzzer
# reaches only with well-formed framing but hostile field contents.
# ===========================================================================

class TestPayloadParserAndLogin:

    # Server ops that carry a payload but must never close/reauth the link when
    # fed an empty one (DISC closes, XAUTH out-of-seq closes, LOGIN re-registers
    # — all excluded so the flood measures pure parser robustness).
    ZERO_PAYLOAD_SERVER_OPS = (
        CMS_RR_LOAD, CMS_RR_AVAIL, CMS_RR_SPACE, CMS_RR_UPDATE, CMS_RR_STATFS,
        CMS_RR_USAGE, CMS_RR_STATS, CMS_RR_STATUS, CMS_RR_GONE, CMS_RR_HAVE,
        CMS_RSP_ERROR, CMS_RR_CNS,
    )

    # Node ops that carry a payload (DISC/PING excluded — DISC forces a
    # reconnect, PING is state-neutral liveness).
    ZERO_PAYLOAD_NODE_OPS = (
        CMS_RR_SELECT, CMS_RR_TRY, CMS_RR_STATE, CMS_RR_CHMOD, CMS_RR_MKDIR,
        CMS_RR_MKPATH, CMS_RR_MV, CMS_RR_RM, CMS_RR_RMDIR, CMS_RR_TRUNC,
        CMS_RR_PREPADD, CMS_RR_PREPDEL,
    )

    def test_load_extreme_free_mb_no_overflow(self, hostile_server):
        """A kYR_load advertising the maximal 0xFFFFFFFF free-MB is decoded by
        the bounded TLV reader without overflow, the statfs encoder handles the
        extreme aggregate, and the connection stays alive."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(0, CMS_RR_LOAD, 0,
                                      _load_payload(0xFFFFFFFF, b"\xff" * 6)))
            time.sleep(0.2)
            # The statfs encoder must still produce a well-formed 6-field reply
            # (no crash / no short buffer) for the extreme advertised value.
            _statfs_wfree(sock, _SID | 0x80)
            sock.sendall(_build_frame(_SID | 0x81, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "an extreme kYR_load free-MB wedged the connection"
        finally:
            sock.close()

    def test_load_truncated_decodes_safe(self, hostile_server):
        """A kYR_load shorter than its declared TLV fields decodes missing
        fields as zero (documented parser posture) without an over-read; the
        connection recovers."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(0, CMS_RR_LOAD, 0,
                                      bytes([CMS_PT_SHORT, 0x00])))  # truncated
            time.sleep(0.2)
            sock.sendall(_build_frame(_SID | 0x82, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None
        finally:
            sock.close()

    def test_avail_malformed_then_valid_recovers(self, hostile_server):
        """A malformed kYR_avail (1 byte) decodes free/util as zero; a
        following well-formed avail restores a real figure — proving the parser
        neither crashes nor latches a bad value."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(0, CMS_RR_AVAIL, 0, b"\xa0"))  # tag only
            time.sleep(0.15)
            good = (bytes([CMS_PT_INT]) + (7000).to_bytes(4, "big")
                    + bytes([CMS_PT_INT]) + (10).to_bytes(4, "big"))
            sock.sendall(_build_frame(0, CMS_RR_AVAIL, 0, good))
            time.sleep(0.15)
            assert _statfs_wfree(sock, _SID | 0x83) == 7000, \
                "avail parser did not recover a valid figure after a bad frame"
        finally:
            sock.close()

    def test_login_empty_paths_valid_registration(self, hostile_server):
        """A LOGIN advertising no export paths is a valid, non-crashing login:
        the node registers, statfs still answers a well-formed 6-field reply
        (aggregate free space is table-wide, not path-filtered — so wFree is
        unchanged; only the path-match count would be zero), and the connection
        is healthy."""
        sock = _node_login_dialog(
            hostile_server.port, _minimal_login_payload(NODE_DATA_PORT, b""))
        sock.settimeout(6)
        try:
            time.sleep(0.3)
            _statfs_wfree(sock, _SID | 0x84)   # asserts a well-formed reply
            sock.sendall(_build_frame(_SID | 0x85, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "an empty-Paths login was not a healthy registration"
        finally:
            sock.close()

    def test_login_oversized_paths_bounded(self, hostile_server):
        """A LOGIN whose Paths list (~2.5 KB) exceeds the 1 KB ctx->paths buffer
        — but still fits within one CMS frame — is copied under the dst_end
        guard: truncated, never overflowed; the node still logs in and the
        connection answers.  (A Paths list large enough to exceed the 4 KB frame
        is a different defense — the oversized-frame close — covered elsewhere.)"""
        paths = b"\n".join(b"r /export/deep/tree/%03d" % i for i in range(100))
        assert len(paths) > BRIX_SRV_MAX_PATHS, "test must exceed the paths buf"
        sock = _node_login_dialog(
            hostile_server.port, _minimal_login_payload(NODE_DATA_PORT, paths))
        sock.settimeout(6)
        try:
            time.sleep(0.3)
            sock.sendall(_build_frame(_SID | 0x86, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "an oversized Paths login overflowed or wedged the connection"
            _statfs_wfree(sock, _SID | 0x87)   # live registration
        finally:
            sock.close()

    def test_login_invalid_mode_word_classified(self, hostile_server):
        """A LOGIN with an all-bits Mode word is classified by the Admit role
        bits without crashing (falls to supervisor/manager/server per the bit
        test) and the connection is serviceable."""
        sock = _node_login_dialog(
            hostile_server.port,
            _login_payload_with_mode(NODE_DATA_PORT, 0xFFFFFFFF,
                                     paths=b"r /data"))
        sock.settimeout(6)
        try:
            time.sleep(0.3)
            sock.sendall(_build_frame(_SID | 0x88, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None
        finally:
            sock.close()

    def test_login_traversal_in_paths_no_crash(self, hostile_server):
        """A LOGIN whose Paths advertise a '..' export is copied verbatim
        (bounded) without crashing; the actual confinement is enforced later at
        the have/statfs/forward gates, so a subsequent foreign kYR_have is still
        dropped — a hostile export declaration grants no escape."""
        sock = _node_login_dialog(
            hostile_server.port,
            _minimal_login_payload(NODE_DATA_PORT, b"r /../../etc"))
        sock.settimeout(6)
        try:
            time.sleep(0.3)
            sock.sendall(_build_frame(_SID | 0x89, CMS_RR_HAVE,
                                      CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                      b"/etc/passwd\x00"))
            time.sleep(0.15)
            sock.sendall(_build_frame(_SID | 0x8A, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a traversal export declaration crashed or wedged the link"
        finally:
            sock.close()

    def test_zero_payload_all_server_ops_safe(self, hostile_server):
        """Every payload-bearing server op fed an empty (dlen=0) body is handled
        without a short read or crash; the connection still answers a ping."""
        sock = _login_server(hostile_server.port)
        try:
            for op in self.ZERO_PAYLOAD_SERVER_OPS:
                sock.sendall(_build_frame(_SID | op, op, 0))
            time.sleep(0.3)
            sock.sendall(_build_frame(_SID | 0x8B, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a zero-payload server op wedged the connection"
        finally:
            sock.close()

    def test_zero_payload_all_node_ops_safe(self, hostile_node):
        """Every payload-bearing node op fed an empty body is dropped/error'd
        without a short read: no op forces a reconnect, node still alive.  A
        single *incidental* reconnect (an idle dial-out re-dial, or the WSL2
        backward-clock-step nudging a keepalive) is tolerated -- what must not
        happen is a per-op reconnect storm (12 ops -> ~12 fresh LOGINs), which
        would prove an empty body wedged the manager leg."""
        base = hostile_node.count_frames(CMS_RR_LOGIN)
        for op in self.ZERO_PAYLOAD_NODE_OPS:
            try:
                hostile_node.send_to_node(_SID | op, op, 0)
            except (AssertionError, OSError, AttributeError):
                pass   # incidental mid-reconnect window
        time.sleep(0.4)
        assert hostile_node.count_frames(CMS_RR_LOGIN) - base <= 1, \
            "zero-payload node ops forced a reconnect storm"
        assert _node_alive(hostile_node), \
            "the node upward leg died after a zero-payload op barrage"

    def test_64_frame_boundary_reassembles_partial(self, hostile_server):
        """Exactly 64 ping frames (one full fairness batch) followed by a 65th
        split across the wakeup boundary: all 65 pongs come back, proving no
        frame is dropped at the batch edge and the trailing partial reassembles
        on the next wakeup."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            batch = b"".join(
                _build_frame(_SID | i, CMS_RR_PING, 0) for i in range(64))
            partial = _build_frame(_SID | 0x40, CMS_RR_PING, 0)
            sock.sendall(batch + partial[:4])   # 64 whole + half a header
            time.sleep(0.3)                     # force at least one wakeup
            sock.sendall(partial[4:])           # complete the 65th
            got = 0
            for _ in range(65):
                if _recv_code(sock, CMS_RR_PONG, timeout=6) is None:
                    break
                got += 1
            assert got == 65, \
                f"expected 65 pongs across the fairness boundary, got {got}"
        finally:
            sock.close()


# ===========================================================================
# Node-leg kYR_state probe + multi-tier relay depth — the MITM *downward*
# direction.  A hostile manager probes "do you hold <path>?"; the confined
# existence check must never leak a kYR_have outside the export root, and the
# relay that parks a parent probe while re-asking children must be single-use,
# path-bound, and streamid-bound so a hostile child cannot forge an upward
# kYR_have for a path the manager never probed.  All behaviour verified against
# src/net/cms/recv_frame.c::cms_frame_state, cms_state_extract_path, and
# src/net/cms/state_relay.c (take/add) + server_recv_frame_handlers.c have
# ingest.
# ===========================================================================
