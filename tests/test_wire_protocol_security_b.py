from split_continuation import reexport as _reexport
_reexport(globals(), "_test_wire_protocol_security_helpers")

class TestPreAuthRequestRejection:
    """Opcodes not covered by test_privilege_escalation.py must also be rejected
    before kXR_login completes."""

    def _send_before_login(self, reqid, payload=b""):
        """Send opcode immediately after handshake, before login."""
        sock = _handshake()
        req = struct.pack("!2sH16sI", b"\x00\x01", reqid, b"\x00"*16, len(payload))
        sock.sendall(req + payload)
        _, status, body = _read_response(sock)
        sock.close()
        return status, body

    def _assert_rejected(self, status, body):
        assert status == kXR_error
        code = _error_code(body)
        assert code == kXR_NOT_AUTHORIZED, f"expected NOT_AUTHORIZED, got {code}"

    def test_preauth_sync_rejected(self):
        status, body = self._send_before_login(kXR_sync)
        self._assert_rejected(status, body)

    def test_preauth_fattr_rejected(self):
        path = b"/test.txt\x00"
        status, body = self._send_before_login(kXR_fattr, path)
        self._assert_rejected(status, body)

    def test_preauth_writev_rejected(self):
        status, body = self._send_before_login(kXR_writev)
        self._assert_rejected(status, body)

    def test_preauth_pgwrite_rejected(self):
        payload = b"\x00" * 20
        status, body = self._send_before_login(kXR_pgwrite, payload)
        self._assert_rejected(status, body)

    def test_preauth_locate_rejected(self):
        path = b"/test.txt\x00"
        status, body = self._send_before_login(kXR_locate, path)
        self._assert_rejected(status, body)

    def test_preauth_statx_rejected(self):
        path = b"/test.txt\x00"
        status, body = self._send_before_login(kXR_statx, path)
        self._assert_rejected(status, body)

    def test_preauth_chmod_rejected(self):
        path = b"/test.txt\x00"
        status, body = self._send_before_login(kXR_chmod, path)
        self._assert_rejected(status, body)

    def test_preauth_rm_rejected(self):
        path = b"/test.txt\x00"
        status, body = self._send_before_login(kXR_rm, path)
        self._assert_rejected(status, body)

    def test_preauth_rmdir_rejected(self):
        path = b"/test.txt\x00"
        status, body = self._send_before_login(kXR_rmdir, path)
        self._assert_rejected(status, body)

    def test_preauth_mv_rejected(self):
        path = b"/test.txt\x00/test2.txt\x00"
        status, body = self._send_before_login(kXR_mv, path)
        self._assert_rejected(status, body)


# =========================================================================
# Class 5 — Protocol Handshake Variants
# =========================================================================

class TestProtocolHandshakeVariants:
    """Edge cases in the 20-byte XRootD handshake framing."""

    def test_partial_handshake_10_bytes(self):
        sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
        sock.settimeout(2)
        sock.sendall(b"\x00" * 10)
        sock.close()  # Must not crash the server

    def test_partial_handshake_19_bytes(self):
        sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
        sock.settimeout(2)
        sock.sendall(b"\x00" * 19)
        sock.close()

    def test_handshake_first_field_nonzero(self):
        # Non-zero first byte → server closes connection immediately
        sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
        sock.settimeout(2)
        sock.sendall(b"\x01" + b"\x00" * 19)
        try:
            data = sock.recv(16)
        except Exception:
            data = b""
        sock.close()
        # Might get a response or nothing — just must not hang indefinitely

    def test_login_without_prior_protocol_frame(self):
        # kXR_login works without sending kXR_protocol first (optional frame)
        sock = _handshake()
        _, status, body = _login(sock)
        sock.close()
        assert status == kXR_ok

    def test_handshake_byte_by_byte(self):
        # 1 byte at a time — server must buffer correctly
        sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
        sock.settimeout(5)
        hs = struct.pack("!IIIII", 0, 0, 0, 4, 2012)
        for b in hs:
            sock.sendall(bytes([b]))
            time.sleep(0.001)
        _, status, body = _read_response(sock)
        sock.close()
        assert status == kXR_ok
        assert len(body) == 8

    def test_immediate_disconnect_after_handshake(self):
        # Connect, complete handshake, immediately close — no crash
        sock = _handshake()
        sock.close()

    def test_protocol_frame_sent_before_login(self):
        sock = _handshake()
        # kXR_protocol frame — optional but supported
        req = struct.pack("!2sH I BB 10s I",
                          b"\x00\x01", kXR_protocol, 39, 0x00, 0x00, b"\x00"*10, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        assert status == kXR_ok
        _, status2, body2 = _login(sock)
        assert status2 == kXR_ok
        sock.close()


# =========================================================================
# Class 6 — Fast-Path / Stress Probes
# =========================================================================

class TestFastPathAttacks:
    """Resource exhaustion probes — verify no leaks, no crashes."""

    def test_100_sequential_pings(self):
        sock = _full_session()
        for i in range(100):
            sid = struct.pack("!2s", bytes([i >> 8, i & 0xFF]))
            req = struct.pack("!2sH16sI", sid, kXR_ping, b"\x00"*16, 0)
            sock.sendall(req)
        for _ in range(100):
            _, status, body = _read_response(sock)
            assert status == kXR_ok
        sock.close()

    def test_10_opens_and_closes(self):
        sock = _full_session()
        path = "/test.txt"
        for _ in range(10):
            _, status, body = _open_file(sock, path, kXR_open_read)
            assert status == kXR_ok
            fhandle = body[:4]
            _, cs, _ = _close(sock, fhandle)
            assert cs == kXR_ok
        sock.close()

    def test_100_stat_requests(self):
        sock = _full_session()
        path = b"/test.txt\x00"
        for _ in range(100):
            req = struct.pack("!2sH16sI", b"\x00\x01", kXR_stat, b"\x00"*16, len(path))
            sock.sendall(req + path)
        for _ in range(100):
            _, status, body = _read_response(sock)
            assert status == kXR_ok
        sock.close()

    def test_50_new_connections(self):
        for _ in range(50):
            sock = _handshake()
            _, status, body = _login(sock)
            assert status == kXR_ok
            sock.close()

    def test_write_zero_bytes(self):
        path = "/wire_zero_write.txt"
        fullpath = os.path.join(DATA_DIR, path.lstrip("/"))
        with open(fullpath, "wb") as f:
            f.write(b"hello")
        sock = _full_session()
        _, open_status, open_body = _open_file(sock, path, kXR_open_updt)
        assert open_status == kXR_ok
        fhandle = open_body[:4]
        req = struct.pack("!2sH4sqiI", b"\x00\x03", kXR_write,
                          fhandle, 0, 0, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        sock.close()
        assert status in (kXR_ok, kXR_error)

    def test_read_zero_bytes(self):
        sock = _full_session()
        _, open_status, open_body = _open_file(sock, "/test.txt", kXR_open_read)
        assert open_status == kXR_ok
        fhandle = open_body[:4]
        req = struct.pack("!2sH4sqiI", b"\x00\x03", kXR_read,
                          fhandle, 0, 0, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        _close(sock, fhandle)
        sock.close()
        assert status == kXR_ok
        assert body == b""

    def test_readv_zero_segments(self):
        sock = _full_session()
        _, open_status, open_body = _open_file(sock, "/test.txt", kXR_open_read)
        assert open_status == kXR_ok
        fhandle = open_body[:4]
        req = struct.pack("!2sH16sI", b"\x00\x03", kXR_readv, b"\x00"*16, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        _close(sock, fhandle)
        sock.close()
        assert status in (kXR_ok, kXR_error)

    def test_writev_zero_segments(self):
        path = "/wire_writev_zero.txt"
        fullpath = os.path.join(DATA_DIR, path.lstrip("/"))
        with open(fullpath, "wb") as f:
            pass
        sock = _full_session()
        _, open_status, open_body = _open_file(sock, path, kXR_open_updt)
        assert open_status == kXR_ok
        fhandle = open_body[:4]
        req = struct.pack("!2sH16sI", b"\x00\x03", kXR_writev, b"\x00"*16, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        sock.close()
        assert status == kXR_error  # kXR_ArgInvalid — too few segments

    def test_two_connections_read_same_file(self):
        sock1 = _full_session()
        sock2 = _full_session()
        _, s1, b1 = _open_file(sock1, "/test.txt", kXR_open_read)
        _, s2, b2 = _open_file(sock2, "/test.txt", kXR_open_read)
        assert s1 == kXR_ok
        assert s2 == kXR_ok
        fh1, fh2 = b1[:4], b2[:4]
        # Read first 8 bytes from both
        for sock, fh in [(sock1, fh1), (sock2, fh2)]:
            req = struct.pack("!2sH4sqiI", b"\x00\x03", kXR_read, fh, 0, 8, 0)
            sock.sendall(req)
        d1 = _read_response(sock1)[2]
        d2 = _read_response(sock2)[2]
        _close(sock1, fh1)
        _close(sock2, fh2)
        sock1.close()
        sock2.close()
        assert d1 == d2

    def test_endsess_closes_gracefully(self):
        sock = _full_session()
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_endsess, b"\x00"*16, 0)
        sock.sendall(req)
        try:
            _, status, body = _read_response(sock)
            assert status in (kXR_ok, kXR_error)
        except ConnectionError:
            pass
        sock.close()

    def test_sync_invalid_handle_after_login(self):
        sock = _full_session()
        # kXR_sync with invalid handle 0xFF000000
        req = struct.pack("!2sH4s12sI",
                          b"\x00\x01", kXR_sync, b"\xff\x00\x00\x00", b"\x00"*12, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        sock.close()
        assert status == kXR_error
