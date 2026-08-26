from split_continuation import reexport as _reexport
def _check_test_concurrent_both_leg_flood_stays_isolated_1(errors):
    assert not errors, \
        f"upward manager leg stalled under a downward flood on rounds {errors}"

def _guard_test_concurrent_both_leg_flood_stays_isolated_1(hostile_super, i, errors):
    if not _node_alive(hostile_super, timeout=6):
        errors.append(i)

def _check_test_concurrent_both_leg_flood_stays_isolated_2(child):
    assert _recv_code(child, CMS_RR_PONG, timeout=6) is not None, \
        "the accept leg would not serve a fresh child after the flood"


_reexport(globals(), "_test_cms_hostile_conformance_helpers")

class TestWireLevelHardening:

    def test_dribbled_frame_reassembled(self, hostile_server):
        """A kYR_ping delivered one byte at a time (each in its own segment) is
        reassembled across recv() calls and answered — the accumulator never
        mis-frames a fragmented header."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            frame = _build_frame(_SID | 0x50, CMS_RR_PING, 0)
            for b in frame:
                sock.sendall(bytes([b]))
                time.sleep(0.02)
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a dribbled ping frame was not reassembled"
        finally:
            sock.close()

    def test_zero_dlen_unknown_flood(self, hostile_server):
        """200 header-only unknown-opcode frames are each dropped; the
        connection stays serviceable afterward."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(b"".join(_build_frame(i, 0x7F, 0) for i in range(200)))
            sock.sendall(_build_frame(_SID | 0x51, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a zero-dlen unknown flood wedged the connection"
        finally:
            sock.close()

    def test_interleaved_valid_and_garbage_resyncs(self, hostile_server):
        """valid ping → garbage frame → valid ping: the parser drops the junk
        and stays frame-aligned, answering both pings."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(_build_frame(_SID | 0x52, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None
            sock.sendall(_build_frame(0, 0x7E, 0, b"junk-in-the-middle"))
            sock.sendall(_build_frame(_SID | 0x53, CMS_RR_PING, 0))
            # A second (header-only, streamid-0 per stock CmsPongRequest) pong
            # only arrives if the parser dropped the junk frame cleanly and
            # stayed byte-aligned on the following ping.
            fr = _recv_code(sock, CMS_RR_PONG, timeout=6)
            assert fr is not None and fr[3] == b"", \
                "parser lost frame alignment after an interleaved junk frame"
        finally:
            sock.close()

    def test_extreme_streamid_accepted(self, hostile_server):
        """A ping with streamid 0xFFFFFFFF is parsed without a signedness /
        truncation bug and answered with a header-only pong.  (Stock cmsd's
        do_Ping replies with a static streamid-0 CmsPongRequest, so the reply
        does NOT echo the ping streamid — the property under test is that the
        extreme unsigned streamid is accepted, not mis-framed.)"""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(_build_frame(0xFFFFFFFF, CMS_RR_PING, 0))
            fr = _recv_code(sock, CMS_RR_PONG, timeout=6)
            assert fr is not None and fr[0] == 0 and fr[3] == b"", \
                "extreme streamid ping was mis-framed or unanswered"
        finally:
            sock.close()

    def test_modifier_byte_fuzz_no_crash(self, hostile_server):
        """Sweeping every modifier value through the two ops that read the
        header modifier (kYR_status, kYR_stats) must never crash the server —
        a fresh client is still served afterward."""
        sock = _login_server(hostile_server.port)
        try:
            for mod in range(256):
                sock.sendall(_build_frame(0, CMS_RR_STATUS, mod))
                sock.sendall(_build_frame(_SID | 0x54, CMS_RR_STATS,
                                          mod | CMS_STATS_SIZE))
            time.sleep(0.3)
        finally:
            sock.close()
        assert _server_alive(hostile_server.port), \
            "a modifier-byte sweep took the server down"

    def test_slowloris_login_does_not_block_others(self, hostile_server):
        """A connection that dribbles a partial LOGIN and then stalls (classic
        slowloris) holds only its own slot behind the absolute login deadline —
        a well-behaved client is served immediately, not head-of-line blocked."""
        slow = socket.create_connection((H, hostile_server.port), timeout=6)
        try:
            # 4 bytes of an 8-byte header, then silence.
            slow.sendall(b"\x00\x00\x00\x00")
            assert _server_alive(hostile_server.port), \
                "a slowloris login stalled service for other clients"
        finally:
            slow.close()

    @pytest.mark.slow
    def test_slowloris_login_eventually_closed(self, hostile_server):
        """The stalled partial-login connection is reaped by the absolute
        configured 2s LOGIN handshake deadline rather than lingering forever."""
        slow = socket.create_connection((H, hostile_server.port), timeout=20)
        slow.settimeout(20)
        try:
            slow.sendall(b"\x00\x00\x00\x00")   # partial header, never completes
            time.sleep(3.0)                     # exceed the configured 2s deadline
            assert _recv_exact(slow, 1) is None, \
                "the login deadline did not reap a stalled slowloris connection"
        finally:
            slow.close()


# ===========================================================================
# Deep esoterica + teardown paths — the auth/namespace/statfs handlers a
# fuzzer reaches last, half-open teardown, and the headline MITM property under
# genuinely CONCURRENT abuse of both legs at once.
# ===========================================================================

class TestDeepEsotericAndTeardown:

    def test_malformed_login_closes_offender_only(self, hostile_server):
        """A LOGIN whose CmsLoginData fails to parse is an auth violation:
        cms_srv_fail_close tears down the offender (mirroring XrdCmsLogin::Admit
        rejecting a bad login) while a fresh client is still admitted."""
        bad = socket.create_connection((H, hostile_server.port), timeout=6)
        bad.settimeout(6)
        try:
            bad.sendall(_build_frame(0, CMS_RR_LOGIN, 0, b"\xff\xff\xffnope"))
            assert _recv_exact(bad, 1) is None, \
                "a malformed LOGIN did not close the offending connection"
            assert _server_alive(hostile_server.port), \
                "a malformed LOGIN disturbed service for other clients"
        finally:
            bad.close()

    def test_statfs_malformed_rrdata_ignored(self, hostile_server):
        """A kYR_statfs with unparseable Pup rrdata draws no kYR_data (the
        handler rejects rather than guesses) and the connection recovers to
        answer a well-formed statfs."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x60, CMS_RR_STATFS, 0,
                                      b"\x00\x40ab"))   # claims 64B, gives 2
            assert _recv_code(sock, CMS_RSP_DATA, timeout=1.0) is None, \
                "server answered a malformed statfs"
            assert _statfs_wfree(sock, _SID | 0x61) == 5000, \
                "connection did not recover after a malformed statfs"
        finally:
            sock.close()

    def test_statfs_without_path_ignored(self, hostile_server):
        """A kYR_statfs carrying only an ident field (no path) is ignored
        (d.path == NULL), never a NULL-deref; a following valid statfs works."""
        sock = _login_server(hostile_server.port)
        try:
            ident = (len(b"tester") + 1).to_bytes(2, "big") + b"tester\x00"
            sock.sendall(_build_frame(_SID | 0x62, CMS_RR_STATFS, 0, ident))
            assert _recv_code(sock, CMS_RSP_DATA, timeout=1.0) is None, \
                "server answered a path-less statfs"
            assert _statfs_wfree(sock, _SID | 0x63) == 5000
        finally:
            sock.close()

    def test_have_traversal_path_dropped(self, hostile_server):
        """Security-neg: a kYR_have whose path contains '..' is dropped by the
        same reject-not-guess shaping the state ingest uses — it can never poke
        the loc cache or wake a locate; the connection stays alive."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x64, CMS_RR_HAVE,
                                      CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                      b"/data/../../etc/passwd\x00"))
            time.sleep(0.2)
            sock.sendall(_build_frame(_SID | 0x65, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a '..' kYR_have disturbed the connection"
        finally:
            sock.close()

    def test_have_relative_path_dropped(self, hostile_server):
        """A kYR_have with a non-absolute path (payload[0] != '/') is rejected
        without disturbing the connection."""
        sock = _login_server(hostile_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x66, CMS_RR_HAVE,
                                      CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                      b"data/relative\x00"))
            time.sleep(0.2)
            assert _statfs_wfree(sock, _SID | 0x67) == 5000
        finally:
            sock.close()

    def test_cns_pre_login_ignored(self, hostile_server):
        """A kYR_cns namespace event before login (and with collect mode off)
        is ignored — no inventory mutation, no crash — and the connection still
        answers a header-only ping."""
        sock = socket.create_connection((H, hostile_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(_build_frame(0, CMS_RR_CNS, 0, b"\x01" + b"\x00" * 24))
            time.sleep(0.1)
            sock.sendall(_build_frame(_SID | 0x68, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "a pre-login CNS event disturbed the connection"
        finally:
            sock.close()

    def test_reset_mid_frame_teardown_survives(self, hostile_server):
        """A peer that announces a large dlen, sends a fraction of the body,
        then abruptly resets is a half-open teardown: the accumulator hits EOF
        with a partial frame and must clean up without wedging — a fresh client
        is served immediately."""
        rude = socket.create_connection((H, hostile_server.port), timeout=6)
        try:
            # Header claims a 4000-byte body; deliver 16 then hard-close.
            hdr = (_SID | 0x69).to_bytes(4, "big") + bytes([0x7F, 0]) \
                + (4000).to_bytes(2, "big")
            rude.sendall(hdr + b"partial-body-xxx")
            rude.close()
            assert _server_alive(hostile_server.port), \
                "a half-open partial-frame reset wedged the server"
        finally:
            try:
                rude.close()
            except OSError:
                pass

    def test_concurrent_both_leg_flood_stays_isolated(self, hostile_super):
        """THE headline MITM property under real concurrency: while a hostile
        site child saturates the supervisor's downward accept leg with garbage
        frames, the upward manager leg keeps answering pings the whole time, and
        once the flood stops the accept leg still admits a well-behaved child.
        Neither leg can be starved or wedged by sustained abuse of the other."""
        stop = threading.Event()
        errors = []

        def flood():
            try:
                fs = socket.create_connection(
                    (H, hostile_super.node_port), timeout=6)
                # Unknown opcodes pre-login are dropped-but-kept: an endless,
                # legal-to-parse torrent that never yields the socket idle.
                burst = b"".join(
                    _build_frame(i, 0x7F, 0, b"X" * 64) for i in range(64))
                while not stop.is_set():
                    fs.sendall(burst)
            except OSError:
                pass            # a mid-flood close is fine; we only measure the
                                # OTHER leg's health
            finally:
                try:
                    fs.close()
                except (OSError, UnboundLocalError):
                    pass

        t = threading.Thread(target=flood, daemon=True)
        t.start()
        try:
            for i in range(5):
                _guard_test_concurrent_both_leg_flood_stays_isolated_1(hostile_super, i, errors)
        finally:
            stop.set()
            t.join(timeout=3)
        _check_test_concurrent_both_leg_flood_stays_isolated_1(errors)

        # And the accept leg itself is still healthy for a well-behaved child.
        child = _node_login_dialog(
            hostile_super.node_port,
            _login_payload_with_mode(NODE_DATA_PORT + 40, CMS_MODE_SERVER,
                                     paths=b"r /data"))
        try:
            child.settimeout(6)
            time.sleep(0.3)
            child.sendall(_build_frame(_SID | 0x6A, CMS_RR_PING, 0))
            _check_test_concurrent_both_leg_flood_stays_isolated_2(child)
        finally:
            child.close()


# ===========================================================================
# Role confusion — a hostile peer replaying the OTHER leg's opcodes.  This is
# the classic stock cmsd↔cmsd trouble spot: a manager that speaks node-role
# frames (or vice versa) must be tolerated (dropped, connection KEPT), never
# mis-dispatched into the wrong state machine and never able to wedge the link.
# ===========================================================================
