from _test_a_robustness_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

class TestLockup:

    def test_partial_handshake_10_bytes(self):
        """Send 10 of 20 handshake bytes then nothing."""
        s = _connect()
        s.sendall(HANDSHAKE[:10])
        try:
            s.settimeout(3.0)
            s.recv(1024)
        except (socket.timeout, ConnectionError, OSError):
            pass
        finally:
            s.close()
        assert_healthy()

    def test_partial_handshake_19_bytes(self):
        """One byte short of a valid handshake."""
        s = _connect()
        s.sendall(HANDSHAKE[:19])
        try:
            s.settimeout(3.0)
            s.recv(1024)
        except (socket.timeout, ConnectionError, OSError):
            pass
        finally:
            s.close()
        assert_healthy()

    def test_handshake_then_silence(self):
        """Valid handshake then no kXR_protocol — other clients must not be blocked."""
        s = _connect()
        s.sendall(HANDSHAKE)
        time.sleep(1.0)
        s.close()
        assert_healthy()

    def test_huge_dlen_no_body_after_login(self):
        """
        After login, send a ping header claiming a 1 MB payload but provide
        no bytes at all.  Server must not freeze waiting for data.
        """
        s = _connect()
        _full_anon_login(s)
        # kXR_ping header with dlen=1_000_000 (no payload follows)
        bad = b'\x00\x10' + struct.pack(">H", kXR_ping) + b'\x00' * 16 + struct.pack(">i", 1_000_000)
        s.sendall(bad)
        try:
            s.settimeout(3.0)
            s.recv(1024)
        except (socket.timeout, ConnectionError, OSError):
            pass
        finally:
            s.close()
        assert_healthy()

    def test_dlen_max_uint32_after_login(self):
        """dlen = 0xFFFFFFFF — server must not wait for 4 GB of body."""
        s = _connect()
        _full_anon_login(s)
        bad = b'\x00\x11' + struct.pack(">H", kXR_stat) + b'\x00' * 16 + struct.pack(">I", 0xFFFFFFFF)
        s.sendall(bad)
        try:
            s.settimeout(3.0)
            s.recv(1024)
        except (socket.timeout, ConnectionError, OSError):
            pass
        finally:
            s.close()
        assert_healthy()

    def test_connect_and_send_nothing(self):
        """Open TCP, send nothing, leave it open for a second."""
        s = _connect()
        time.sleep(1.5)
        s.close()
        assert_healthy()

    def test_50_silent_connections_do_not_block_legitimate_traffic(self):
        """
        50 connections that stall after the handshake.
        A fresh connection must still complete successfully.
        """
        stale = []
        for _ in range(50):
            try:
                s = _connect()
                s.sendall(HANDSHAKE)
                stale.append(s)
            except OSError:
                break   # kernel queue limit; acceptable
        assert_healthy(retries=6)   # must respond while stale sockets are still open
        for s in stale:
            try:
                s.close()
            except OSError:
                pass

    def test_truncated_request_header(self):
        """Send 15 of the 24 header bytes after login, then stop."""
        s = _connect()
        _full_anon_login(s)
        s.sendall(b'\x00\x50' + struct.pack(">H", kXR_ping) + b'\x00' * 11)
        try:
            s.settimeout(3.0)
            s.recv(1024)
        except (socket.timeout, ConnectionError, OSError):
            pass
        finally:
            s.close()
        assert_healthy()


# ============================================================================
# 2. Authentication bypass
#    Operations requiring a session must always fail before login.
# ============================================================================

class TestAuthBypass:

    def _proto_only(self) -> socket.socket:
        """Connect and negotiate protocol, but do NOT login."""
        s = _connect()
        _handshake_and_protocol(s)
        return s

    def test_stat_before_login(self):
        s = self._proto_only()
        s.sendall(make_stat_req(b'/'))
        status, body = _recv_response(s)
        s.close()
        assert status == kXR_error, f"Pre-login stat must fail, got {status}"
        assert _errcode(body) == kXR_NotAuthorized, \
            f"Expected NotAuthorized(3010), got {_errcode(body)}"
        assert_healthy()

    def test_open_before_login(self):
        s = self._proto_only()
        s.sendall(make_open_req(b'/'))
        status, body = _recv_response(s)
        s.close()
        assert status == kXR_error, f"Pre-login open must fail, got {status}"
        assert _errcode(body) == kXR_NotAuthorized
        assert_healthy()

    def test_read_with_fake_handle_before_login(self):
        s = self._proto_only()
        s.sendall(make_read_req(b'\xDE\xAD\xBE\xEF', 0, 4096,
                                streamid=b'\x00\x20'))
        status, body = _recv_response(s)
        s.close()
        assert status == kXR_error, f"Pre-login read must fail, got {status}"
        assert_healthy()

    def test_dirlist_before_login(self):
        s = self._proto_only()
        s.sendall(make_request(b'\x00\x21', kXR_dirlist,
                               payload=b'/\x00'))
        status, _ = _recv_response(s)
        s.close()
        assert status == kXR_error
        assert_healthy()

    def test_mkdir_before_login(self):
        s = self._proto_only()
        s.sendall(make_request(b'\x00\x22', kXR_mkdir,
                               payload=b'/probe_mkdir\x00'))
        status, _ = _recv_response(s)
        s.close()
        assert status == kXR_error
        assert_healthy()

    def test_rm_before_login(self):
        s = self._proto_only()
        s.sendall(make_request(b'\x00\x23', kXR_rm,
                               payload=b'/probe_rm\x00'))
        status, _ = _recv_response(s)
        s.close()
        assert status == kXR_error
        assert_healthy()

    def test_write_before_login(self):
        """kXR_write with invented handle before login must fail."""
        s = self._proto_only()
        body = b'\xDE\xAD\xBE\xEF' + b'\x00' * 12   # fhandle + reserved
        s.sendall(make_request(b'\x00\x24', kXR_write, body,
                               payload=b'malicious data'))
        status, _ = _recv_response(s)
        s.close()
        assert status == kXR_error
        assert_healthy()

    def test_auth_before_login(self):
        """kXR_auth before kXR_login must not succeed."""
        s = self._proto_only()
        s.sendall(make_request(b'\x00\x25', kXR_auth,
                               payload=b'garbage_auth_data'))
        status, _ = _recv_response(s)
        s.close()
        # kXR_authmore (4002) would indicate the server is treating this as a valid
        # auth exchange — that is a bug. ok (0) is also a bug.
        assert status not in (kXR_ok, 4002), \
            f"kXR_auth before login should be rejected, got status={status}"
        assert_healthy()

    def test_double_login_does_not_crash(self):
        """A second kXR_login on an already-logged-in connection must not crash."""
        s = _connect()
        _full_anon_login(s)
        s.sendall(make_login_req(streamid=b'\x00\x30',
                                 username=b'hacker\x00\x00'))
        try:
            _recv_response(s)
        except (socket.timeout, ConnectionError):
            pass
        s.close()
        assert_healthy()


# ============================================================================
# 3. Protocol fuzzing
#    Unknown opcodes, boundary paths, extreme values, garbage bytes.
# ============================================================================

class TestProtocolFuzzing:

    def _logged_in(self) -> socket.socket:
        s = _connect()
        _full_anon_login(s)
        return s

    def test_unknown_opcode_zero(self):
        """Opcode 0 is not defined — must return error, never kXR_ok."""
        s = self._logged_in()
        s.sendall(make_request(b'\x00\x40', 0))
        try:
            status, _ = _recv_response(s)
        except (socket.timeout, ConnectionError):
            status = kXR_error
        s.close()
        assert status != kXR_ok, "Unknown opcode 0 returned kXR_ok"
        assert_healthy()

    def test_unknown_opcode_0xffff(self):
        """Opcode 0xFFFF — extreme garbage."""
        s = self._logged_in()
        s.sendall(make_request(b'\x00\x41', 0xFFFF))
        try:
            status, _ = _recv_response(s)
        except (socket.timeout, ConnectionError):
            status = kXR_error
        s.close()
        assert status != kXR_ok
        assert_healthy()

    def test_unknown_opcode_9999(self):
        """Opcode 9999 — not currently assigned."""
        s = self._logged_in()
        s.sendall(make_request(b'\x00\x42', 9999))
        try:
            status, _ = _recv_response(s)
        except (socket.timeout, ConnectionError):
            status = kXR_error
        s.close()
        assert status != kXR_ok
        assert_healthy()

    def test_path_with_embedded_null(self):
        """Path containing a null byte (/\\x00etc/passwd) must not escape or crash."""
        s = self._logged_in()
        req = make_request(b'\x00\x43', kXR_stat,
                           body=b'\x00' * 16,
                           payload=b'/\x00etc/passwd\x00')
        s.sendall(req)
        try:
            status, body = _recv_response(s)
        except (socket.timeout, ConnectionError):
            status = kXR_error
            body = b''
        s.close()
        # If the server responds ok, it must be for "/" (empty path after null),
        # never for /etc/passwd. In practice most implementations reject empty paths.
        # What we strictly forbid is any response that includes /etc/passwd content.
        if status == kXR_ok and body:
            assert b'/etc/passwd' not in body, \
                "Null-byte injection may have exposed /etc/passwd"
        assert_healthy()

    def test_path_at_maximum_length_4096(self):
        """Stat a path exactly 4096 bytes long — limit boundary."""
        s = self._logged_in()
        path = b'/' + b'a' * 4094
        req  = make_request(b'\x00\x44', kXR_stat,
                            body=b'\x00' * 16,
                            payload=path + b'\x00')
        s.sendall(req)
        try:
            _recv_response(s)   # ok or error — either is fine; no crash
        except (socket.timeout, ConnectionError):
            pass
        s.close()
        assert_healthy()

    def test_path_one_over_maximum(self):
        """Path 1 byte over the 4096-byte limit must be rejected."""
        s = self._logged_in()
        path = b'/' + b'a' * 4095
        req  = make_request(b'\x00\x45', kXR_stat,
                            body=b'\x00' * 16,
                            payload=path + b'\x00')
        s.sendall(req)
        try:
            status, _ = _recv_response(s)
        except (socket.timeout, ConnectionError):
            status = kXR_error
        s.close()
        assert status != kXR_ok, "Over-length path must be rejected"
        assert_healthy()

    def test_null_only_path(self):
        """Path that is just a null byte must not crash."""
        s = self._logged_in()
        req = make_request(b'\x00\x46', kXR_stat,
                           body=b'\x00' * 16,
                           payload=b'\x00')
        s.sendall(req)
        try:
            _recv_response(s)
        except (socket.timeout, ConnectionError):
            pass
        s.close()
        assert_healthy()

    def test_stream_id_all_ones(self):
        """Stream ID 0xFFFF is uncommon but legal."""
        s = self._logged_in()
        s.sendall(make_ping_req(streamid=b'\xFF\xFF'))
        try:
            _recv_response(s)
        except (socket.timeout, ConnectionError):
            pass
        s.close()
        assert_healthy()

    def test_all_zero_24_byte_request(self):
        """24 zero bytes after login — opcode 0, dlen 0."""
        s = self._logged_in()
        s.sendall(b'\x00' * 24)
        try:
            _recv_response(s)
        except (socket.timeout, ConnectionError):
            pass
        s.close()
        assert_healthy()

    def test_all_ff_24_byte_request(self):
        """24 0xFF bytes — extreme garbage. Server must not crash."""
        s = self._logged_in()
        s.sendall(b'\xff' * 24)
        try:
            s.settimeout(3.0)
            s.recv(1024)   # accept close or error
        except (socket.timeout, ConnectionError, OSError):
            pass
        s.close()
        assert_healthy()

    def test_bad_handshake_fourth_field(self):
        """fourth field must be 4; wrong value must be rejected cleanly."""
        try:
            s = _connect()
            s.sendall(HANDSHAKE_BAD_FOURTH)
            s.settimeout(3.0)
            s.recv(1024)
            s.close()
        except (socket.timeout, ConnectionError, OSError):
            pass
        assert_healthy()

    def test_bad_handshake_fifth_field(self):
        """fifth field must be 2012; wrong value must be rejected cleanly."""
        try:
            s = _connect()
            s.sendall(HANDSHAKE_BAD_FIFTH)
            s.settimeout(3.0)
            s.recv(1024)
            s.close()
        except (socket.timeout, ConnectionError, OSError):
            pass
        assert_healthy()

    def test_200_repeated_kxr_protocol_requests(self):
        """
        200 kXR_protocol requests on one connection.
        Server must respond to each, never exhaust per-session state.
        """
        s = _connect()
        _handshake_and_protocol(s)
        for i in range(200):
            sid = struct.pack(">H", (i % 0xFFFE) + 1)
            s.sendall(make_protocol_req(streamid=sid))
        ok_count = 0
        for _ in range(200):
            try:
                status, _ = _recv_response(s)
                if status == kXR_ok:
                    ok_count += 1
            except (socket.timeout, ConnectionError):
                break
        s.close()
        assert ok_count > 0, "No kXR_protocol responses received at all"
        assert_healthy()

    def test_wrong_login_body_zero_username(self):
        """kXR_login with an all-zero username — must not crash."""
        s = _connect()
        _handshake_and_protocol(s)
        body  = struct.pack(">I", os.getpid() & 0xFFFFFFFF)
        body += b'\x00' * 8   # all-zero username
        body += b'\x00\x00\x05\x00'
        s.sendall(make_request(b'\x00\x50', kXR_login, body))
        try:
            _recv_response(s)
        except (socket.timeout, ConnectionError):
            pass
        s.close()
        assert_healthy()


# ============================================================================
# 4. Resource exhaustion
#    Single clients must not exhaust server-side resources.
# ============================================================================

class TestResourceExhaustion:

    def test_connection_storm_50(self):
        """
        50 connections opened simultaneously.  Each performs the handshake +
        protocol negotiation, then is closed.  The server must survive and
        remain responsive; some connection resets under load are tolerated.
        """
        assert_healthy()   # ensure we start from a clean state
        sockets = []
        failures = 0
        for _ in range(50):
            try:
                s = _connect()
                hs_st, pr_st = _handshake_and_protocol(s)
                if hs_st == kXR_ok and pr_st == kXR_ok:
                    sockets.append(s)
                else:
                    s.close()
                    failures += 1
            except OSError:
                failures += 1
        # Close all before asserting health so the server can drain its backlog.
        for s in sockets:
            try:
                s.close()
            except OSError:
                pass
        # Under load some resets are expected (nginx event loop, WSL2 limits).
        # What matters is that the server recovers fully afterwards.
        assert failures <= 25, f"Too many failures ({failures}/50) in connection storm"
        assert_healthy(retries=6)

    def test_rapid_connect_disconnect_50(self):
        """50 rapid connect-then-immediately-close cycles."""
        assert_healthy(retries=6)   # wait for any prior storm to drain
        for _ in range(50):
            try:
                s = _connect()
                s.close()
            except OSError:
                pass
        assert_healthy(retries=6)

    def test_ping_flood_1000(self):
        """
        1000 pings on one authenticated connection.
        Every ping must return kXR_ok (99% success threshold).
        """
        assert_healthy(retries=6)   # wait for any prior storm to drain
        s = _connect()
        _full_anon_login(s)
        n = 1000
        for i in range(n):
            sid = struct.pack(">H", (i % 0xFFFE) + 1)
            s.sendall(make_ping_req(streamid=sid))
        ok_count = 0
        for _ in range(n):
            try:
                s.settimeout(10.0)
                status, _ = _recv_response(s)
                if status == kXR_ok:
                    ok_count += 1
            except (socket.timeout, ConnectionError):
                break
        s.close()
        assert ok_count >= int(n * 0.99), \
            f"Ping flood: only {ok_count}/{n} pings returned kXR_ok"
        assert_healthy()

    def test_open_16_handles_and_close_cleanly(self):
        """Open 16 file handles and close each one in sequence."""
        assert_healthy(retries=6)
        test_path = os.path.join(DATA_DIR, "robustness_handles.bin")
        with open(test_path, "wb") as f:
            f.write(b'x' * 1024)
        s = _connect()
        _full_anon_login(s)

        handles = []
        for i in range(16):
            sid = struct.pack(">H", 0x0100 + i)
            s.sendall(make_open_req(b'/robustness_handles.bin', streamid=sid))
            try:
                status, body = _recv_response(s)
                if status == kXR_ok and len(body) >= 4:
                    handles.append(body[:4])
            except (socket.timeout, ConnectionError):
                break

        assert len(handles) >= 8, \
            f"Expected to open at least 8 handles, got {len(handles)}"

        for i, handle in enumerate(handles):
            sid = struct.pack(">H", 0x0180 + i)
            s.sendall(make_close_req(handle, streamid=sid))
            try:
                _recv_response(s)
            except (socket.timeout, ConnectionError):
                break

        s.close()
        os.unlink(test_path)
        assert_healthy()

    def test_open_beyond_handle_limit_returns_error(self):
        """Opening more than 16 files must return an error, not crash."""
        assert_healthy(retries=6)
        test_path = os.path.join(DATA_DIR, "robustness_overlimit.bin")
        with open(test_path, "wb") as f:
            f.write(b'y' * 1024)
        s = _connect()
        _full_anon_login(s)

        open_count   = 0
        first_err_at = None
        for i in range(20):
            sid = struct.pack(">H", 0x0200 + i)
            s.sendall(make_open_req(b'/robustness_overlimit.bin', streamid=sid))
            try:
                status, _ = _recv_response(s)
                if status == kXR_ok:
                    open_count += 1
                elif first_err_at is None:
                    first_err_at = i
            except (socket.timeout, ConnectionError):
                break

        s.close()
        os.unlink(test_path)

        assert open_count <= 16, \
            f"Server allowed {open_count} simultaneous handles (limit is 16)"
        assert first_err_at is not None, \
            "Server never returned an error after exceeding handle limit"
        assert_healthy()


# ============================================================================
# 5. State machine attacks
#    Protocol must be enforced regardless of operation ordering.
# ============================================================================
