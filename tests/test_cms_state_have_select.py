from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cms_state_have_select_helpers")

class TestStateHave:
    """The manager probes 'do you hold <path>?' (kYR_state, raw NUL-terminated
    path).  nginx must answer kYR_have (modifier RAW|Online, same streamid)
    only for an in-root file that exists, and stay silent otherwise."""

    def test_state_have_roundtrip_matching_streamid(self, client_stack):
        """A held in-root file -> kYR_have echoing the request streamid, raw
        NUL-terminated path, modifier RAW|Online."""
        conn = client_stack["conn"]
        sid = 0x00C0FFEE
        _send_frame(conn, sid, CMS_RR_STATE, payload=b"/held.bin\x00")
        got = _drain_until(conn, CMS_RR_HAVE, time.time() + 8.0,
                           allow_codes=_NOISE)
        assert got is not None, "no kYR_have for a held in-root file"
        r_sid, code, mod, payload = got
        assert code == CMS_RR_HAVE
        assert r_sid == sid, f"have streamid {r_sid} != state streamid {sid}"
        # Raw (unmarshalled) NUL-terminated path echoed back.
        assert payload.rstrip(b"\x00") == b"/held.bin"
        assert mod & CMS_MOD_RAW, "kYR_have must carry the RAW modifier"
        assert mod & CMS_HAVE_ONLINE, "kYR_have must carry the Online modifier"
        _ping_sanity(conn)

    def test_state_missing_file_silent(self, client_stack):
        """A path that does not exist under the export root -> NO kYR_have; the
        manager simply doesn't select this node.  Connection survives."""
        conn = client_stack["conn"]
        _send_frame(conn, 0x11, CMS_RR_STATE, payload=b"/does-not-exist.bin\x00")
        got = _drain_until(conn, CMS_RR_HAVE, time.time() + 3.0,
                           allow_codes=_NOISE)
        assert got is None or got[1] != CMS_RR_HAVE, \
            "must not answer kYR_have for a missing file"
        _ping_sanity(conn)

    def test_state_path_traversal_rejected_before_stat(self, client_stack):
        """A '..' in the path is rejected by the cheap pre-check BEFORE any
        stat — nginx stays silent (recv.c rejects payload containing '..')."""
        conn = client_stack["conn"]
        _send_frame(conn, 0x22, CMS_RR_STATE,
                    payload=b"/../etc/passwd\x00")
        got = _drain_until(conn, CMS_RR_HAVE, time.time() + 3.0,
                           allow_codes=_NOISE)
        assert got is None or got[1] != CMS_RR_HAVE, \
            "path traversal must not produce kYR_have"
        _ping_sanity(conn)

    def test_state_symlink_escape_not_answered_with_have(self, client_stack):
        """A symlink under the root pointing OUTSIDE it (escape -> /etc): the
        kernel-confined probe (openat2 RESOLVE_BENEATH) rejects the escape so
        nginx must NOT answer kYR_have, even though /etc/hostname exists."""
        escape = os.path.join(client_stack["data_dir"], "escape")
        if not os.path.islink(escape):
            pytest.skip("could not plant escaping symlink for the test")
        conn = client_stack["conn"]
        # /escape/hostname resolves to /etc/hostname OUTSIDE the export root.
        _send_frame(conn, 0x33, CMS_RR_STATE,
                    payload=b"/escape/hostname\x00")
        got = _drain_until(conn, CMS_RR_HAVE, time.time() + 3.0,
                           allow_codes=_NOISE)
        assert got is None or got[1] != CMS_RR_HAVE, \
            "symlink escape must not be answered with kYR_have"
        _ping_sanity(conn)

    def test_state_empty_or_missing_nul_terminator(self, client_stack):
        """An empty payload (pl==0) and a non-NUL-terminated path are both
        handled without desyncing the framer.

        recv.c's bounded scan stops at the first NUL or at plen.  An empty
        payload returns NGX_OK with no have.  For a NUL-less '/held.bin' the
        scan runs to plen and the path equals the real file, so a kYR_have is
        legitimate — we therefore only assert *survival* for that case, never a
        specific have/no-have, so this never hard-fails on a benign edge."""
        conn = client_stack["conn"]
        # Empty payload: pl==0 -> early return NGX_OK, no have.
        _send_frame(conn, 0x44, CMS_RR_STATE, payload=b"")
        got = _drain_until(conn, CMS_RR_HAVE, time.time() + 2.5,
                           allow_codes=_NOISE)
        assert got is None or got[1] != CMS_RR_HAVE
        _ping_sanity(conn)

        # No trailing NUL: survival only (a NUL-less "/held.bin" may legitimately
        # match the real file and produce a have).
        _send_frame(conn, 0x45, CMS_RR_STATE, payload=b"/held.bin")
        _drain_until(conn, CMS_RR_HAVE, time.time() + 2.5, allow_codes=_NOISE)
        _ping_sanity(conn)


# ===========================================================================
# Class 2 — kYR_select / kYR_try redirect-reply parsing (src/net/cms/recv.c)
# ===========================================================================

class TestSelectTryParsing:
    """kYR_select (single host) and kYR_try (ordered list) carry a redirect
    target the manager resolved for a waiting client.  Standalone (no suspended
    client session in the pending table) the documented behavior is a clean
    no-op (cms_wake_pending_session returns NGX_OK for an unknown streamid);
    the parser must still robustly bounds-check the host/NUL/port framing and
    leave the connection usable.  We assert that documented survival behavior
    via a ping/pong after each frame."""

    def test_select_short_payload_missing_nul_handled(self, client_stack):
        """A select payload shorter than 3 bytes (no room for host+NUL+port)
        hits the `payload_len < 3` guard -> return NGX_OK, no crash."""
        conn = client_stack["conn"]
        _send_frame(conn, 0x51, CMS_RR_SELECT, payload=b"x")   # 1 byte
        _ping_sanity(conn)
        # Host with no NUL and no port bytes: host_len+3 > payload_len guard.
        _send_frame(conn, 0x52, CMS_RR_SELECT, payload=b"host-no-nul")
        _ping_sanity(conn)

    def test_select_port_is_big_endian_2_byte(self, client_stack):
        """A well-formed select (host + NUL + BE uint16 port) parses cleanly.
        The port is read with ngx_brix_cms_get16 (big-endian, 2 bytes); we
        feed a distinctive port (0x1F90 = 8080) — the high byte first.  No
        pending session exists so this is a documented silent no-op; the
        connection must survive (proving the port bytes were consumed, not
        misread as trailing payload that desyncs the framer)."""
        conn = client_stack["conn"]
        payload = b"127.0.0.1\x00" + struct.pack(">H", 8080)  # net-literal-allow: CMS wire payload IP bytes under test
        assert payload[-2:] == b"\x1f\x90", "test built a non-BE port"
        _send_frame(conn, 0x53, CMS_RR_SELECT, payload=payload)
        _ping_sanity(conn)

    def test_select_unknown_streamid_silently_ignored(self, client_stack):
        """A select for a streamid that is NOT in the pending-locate table
        (no waiting client) is silently ignored (pending==NULL -> NGX_OK).
        The connection must not be torn down."""
        conn = client_stack["conn"]
        payload = _select_payload(HOST, 1094)
        _send_frame(conn, 0xDEADBEEF, CMS_RR_SELECT, payload=payload)
        _ping_sanity(conn)

    def test_try_multiple_entries_first_used(self, client_stack):
        """kYR_try with several (host,port) entries: recv.c uses only the FIRST
        entry (the NUL-terminated host then the following port).  With no
        pending session this is a silent no-op; survival proves the first entry
        was parsed and the trailing entries did not desync the framer."""
        conn = client_stack["conn"]
        payload = _try_payload(("first-host", 29001), ("second-host", 29002))
        _send_frame(conn, 0x61, CMS_RR_TRY, payload=payload)
        _ping_sanity(conn)

    def test_try_malformed_entry_parser_stops_cleanly(self, client_stack):
        """A malformed kYR_try (host string but truncated before the 2 port
        bytes) trips the `host_len + 3 > payload_len` guard -> return NGX_OK.
        The framer must not over-read into the next frame."""
        conn = client_stack["conn"]
        # "trunc-host" + NUL but only ONE of the two port bytes present.
        _send_frame(conn, 0x62, CMS_RR_TRY, payload=b"trunc-host\x00\x04")
        _ping_sanity(conn)
        # Also a try payload that is exactly host+NUL with zero port bytes.
        _send_frame(conn, 0x63, CMS_RR_TRY, payload=b"hostonly\x00")
        _ping_sanity(conn)


# ===========================================================================
# Class 3 — kYR_gone on the CMS server side (src/net/cms/server_recv.c)
# ===========================================================================


class TestServerGone:
    """kYR_gone on the manager side (nginx CMS-server, server_recv.c): a data
    node signals it no longer holds a path.  An empty-payload gone is a no-op;
    a gone received BEFORE login is ignored (the `if (!ctx->logged_in) break;`
    guard).  Neither must tear down the connection."""

    def _connect(self, server_stack):
        conn = socket.create_connection((H, server_stack["port"]), timeout=8)
        conn.settimeout(8)
        return conn

    def test_gone_empty_payload(self, server_stack):
        """A logged-in node sends kYR_gone with an empty payload -> the
        `payload_len > 0` guard skips the unregister; connection survives."""
        conn = self._connect(server_stack)
        try:
            assert _server_login(conn), "CMS-server did not admit the node"
            _send_frame(conn, 0, CMS_RR_GONE, payload=b"")
            _server_alive(conn)
        finally:
            conn.close()

    def test_gone_before_login_ignored(self, server_stack):
        """kYR_gone arriving BEFORE any LOGIN is ignored (not logged_in) and
        must not crash or close the connection; a subsequent LOGIN still works."""
        conn = self._connect(server_stack)
        try:
            # gone first, with a real path, while NOT logged in.
            _send_frame(conn, 0, CMS_RR_GONE, payload=b"/atlas\x00")
            # The guard `if (!ctx->logged_in) break;` means this is a no-op.
            # The connection must still accept a normal LOGIN afterwards.
            assert _server_login(conn), \
                "CMS-server did not admit the node after a pre-login gone"
            _server_alive(conn)
        finally:
            conn.close()
