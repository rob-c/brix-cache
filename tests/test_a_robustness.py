from split_continuation import reexport as _reexport
_reexport(globals(), "_test_a_robustness_helpers")

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
