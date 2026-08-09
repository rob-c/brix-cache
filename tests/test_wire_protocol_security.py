from split_continuation import reexport as _reexport
_reexport(globals(), "_test_wire_protocol_security_helpers")

class TestStreamIDEchoCorrectness:
    """Every response must echo the request's exact 2-byte streamid."""

    def _ping_with_sid(self, sid_bytes):
        sock = _full_session()
        req = struct.pack("!2sH16sI", sid_bytes, kXR_ping, b"\x00"*16, 0)
        sock.sendall(req)
        sid_back, status, body = _read_response(sock)
        sock.close()
        return sid_back, status

    def test_streamid_all_zeros(self):
        sid, status = self._ping_with_sid(b"\x00\x00")
        assert sid == b"\x00\x00"
        assert status == kXR_ok

    def test_streamid_all_ones(self):
        sid, status = self._ping_with_sid(b"\xff\xff")
        assert sid == b"\xff\xff"
        assert status == kXR_ok

    def test_streamid_alternating(self):
        sid, status = self._ping_with_sid(b"\xaa\x55")
        assert sid == b"\xaa\x55"
        assert status == kXR_ok

    def test_streamid_five_sequential(self):
        sock = _full_session()
        for i in range(1, 6):
            sid_bytes = bytes([0x00, i])
            req = struct.pack("!2sH16sI", sid_bytes, kXR_ping, b"\x00"*16, 0)
            sock.sendall(req)
            sid_back, status, body = _read_response(sock)
            assert sid_back == sid_bytes, f"sid echo mismatch at i={i}"
            assert status == kXR_ok
        sock.close()

    def test_streamid_on_error_response(self):
        sock = _full_session()
        sid_bytes = b"\x12\x34"
        path = b"/nonexistent_file_xyz.txt\x00"
        req = struct.pack("!2sH16sI", sid_bytes, kXR_stat, b"\x00"*16, len(path))
        sock.sendall(req + path)
        sid_back, status, body = _read_response(sock)
        sock.close()
        assert sid_back == sid_bytes
        assert status == kXR_error

    def test_streamid_on_login(self):
        sock = _handshake()
        sid_bytes = b"\x00\x07"
        req = struct.pack("!2sHI8sBBBBI",
                          sid_bytes, kXR_login,
                          os.getpid() & 0xFFFFFFFF,
                          b"pytest\x00\x00", 0, 0, 5, 0, 0)
        sock.sendall(req)
        sid_back, status, body = _read_response(sock)
        sock.close()
        assert sid_back == sid_bytes
        assert status == kXR_ok

    def test_streamid_on_open(self):
        sock = _full_session()
        sid_bytes = b"\xde\xad"
        path = b"/test.txt\x00"
        req = struct.pack("!2sHHH2s6s4sI",
                          sid_bytes, kXR_open,
                          0o644, kXR_open_read, b"\x00\x00", b"\x00"*6, b"\x00"*4,
                          len(path))
        sock.sendall(req + path)
        sid_back, status, body = _read_response(sock)
        if status == kXR_ok:
            fhandle = body[:4]
            _close(sock, fhandle)
        sock.close()
        assert sid_back == sid_bytes

    def test_streamid_on_stat(self):
        sock = _full_session()
        sid_bytes = b"\x01\x23"
        path = b"/test.txt\x00"
        req = struct.pack("!2sH16sI", sid_bytes, kXR_stat, b"\x00"*16, len(path))
        sock.sendall(req + path)
        sid_back, status, body = _read_response(sock)
        sock.close()
        assert sid_back == sid_bytes
        assert status == kXR_ok


# =========================================================================
# Class 2 — Malformed dlen
# =========================================================================

class TestMalformedDlen:
    """The dlen field guards in recv.c must prevent oversized allocations."""

    def test_dlen_zero_ping_ok(self):
        sock = _full_session()
        _, status, body = _ping(sock)
        sock.close()
        assert status == kXR_ok

    def test_dlen_nonzero_ping_not_crash(self):
        # ping with dlen=4 + 4 extra payload bytes — server should handle gracefully
        sock = _full_session()
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_ping, b"\x00"*16, 4)
        sock.sendall(req + b"\x00"*4)
        try:
            _, status, body = _read_response(sock)
        except ConnectionError:
            pass  # server may close connection
        sock.close()

    def test_dlen_uint32_max_rejected(self):
        # dlen = 0xFFFFFFFF must be rejected, not cause 4 GiB allocation
        sock = _full_session()
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_stat, b"\x00"*16, 0xFFFFFFFF)
        sock.sendall(req)
        try:
            _, status, body = _read_response(sock)
            assert status == kXR_error
        except ConnectionError:
            pass  # acceptable: server disconnects
        sock.close()

    def test_dlen_signed_negative_as_large_rejected(self):
        # dlen = 0x80000000 (2 GiB if treated as signed) must be rejected
        sock = _full_session()
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_stat, b"\x00"*16, 0x80000000)
        sock.sendall(req)
        try:
            _, status, body = _read_response(sock)
            assert status == kXR_error
        except ConnectionError:
            pass
        sock.close()

    def test_dlen_exactly_at_path_limit_accepted(self):
        # BRIX_MAX_PATH + 64 = 4224 for stat — at limit should be accepted
        sock = _full_session()
        payload = b"/test.txt\x00" + b"\x00" * (4224 - 10)
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_stat, b"\x00"*16, len(payload))
        sock.sendall(req + payload)
        try:
            _, status, body = _read_response(sock)
            # Either ok or error (path too long) — just must not crash
        except ConnectionError:
            pass
        sock.close()

    def test_dlen_one_over_path_limit_rejected(self):
        # BRIX_MAX_PATH + 65 — one over the limit for non-write opcodes
        sock = _full_session()
        payload = b"/" + b"a" * 4224
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_stat, b"\x00"*16, len(payload))
        sock.sendall(req)
        try:
            _, status, body = _read_response(sock)
            assert status == kXR_error
        except ConnectionError:
            pass  # acceptable: server disconnects on oversize
        sock.close()

    def test_dlen_zero_stat_handle_based(self):
        # stat with dlen=0 (handle-based variant) — must be handled
        sock = _full_session()
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_stat, b"\x00"*16, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        sock.close()
        # Either ok (root stat) or error — not a crash
        assert status in (kXR_ok, kXR_error)

    def test_valid_request_after_close_reconnect(self):
        # After sending oversized dlen and being disconnected, a new connection works
        # (Test 1: send oversized dlen)
        sock = _full_session()
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_stat, b"\x00"*16, 0xFFFFFFFF)
        sock.sendall(req)
        try:
            _read_response(sock)
        except Exception:
            pass
        sock.close()
        # (Test 2: new connection should work fine)
        sock2 = _full_session()
        _, status, body = _ping(sock2)
        sock2.close()
        assert status == kXR_ok

    def test_dlen_zero_write_opcode(self):
        # kXR_write with dlen=0 on a write-open handle
        os.makedirs(DATA_DIR, exist_ok=True)
        path = "/wire_test_dlen0_write.txt"
        fullpath = os.path.join(DATA_DIR, path.lstrip("/"))
        with open(fullpath, "wb") as f:
            f.write(b"init")
        sock = _full_session()
        _, open_status, open_body = _open_file(sock, path, kXR_open_updt)
        assert open_status == kXR_ok
        fhandle = open_body[:4]
        # Write with dlen=0 (no payload) — server accepts or errors cleanly
        req = struct.pack("!2sH4sqiI", b"\x00\x03", kXR_write,
                          fhandle, 0, 0, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        sock.close()
        assert status in (kXR_ok, kXR_error)

    def test_dlen_large_write_payload_allowed(self):
        # Write opcodes may have large payloads (up to BRIX_MAX_WRITE_PAYLOAD)
        path = "/wire_test_large_write.txt"
        fullpath = os.path.join(DATA_DIR, path.lstrip("/"))
        payload = b"A" * 65536  # 64 KiB — well within 16 MiB limit
        sock = _full_session()
        _, open_status, open_body = _open_file(sock, path,
                                                kXR_open_updt | kXR_open_new)
        if open_status != kXR_ok:
            with open(fullpath, "wb") as f:
                pass
            _, open_status, open_body = _open_file(sock, path, kXR_open_updt)
        assert open_status == kXR_ok
        fhandle = open_body[:4]
        req = struct.pack("!2sH4sqiI", b"\x00\x03", kXR_write,
                          fhandle, 0, len(payload), len(payload))
        sock.sendall(req + payload)
        _, status, body = _read_response(sock)
        sock.close()
        assert status == kXR_ok


# =========================================================================
# Class 3 — Invalid RequestID
# =========================================================================

class TestInvalidRequestID:
    """Unknown opcodes must be rejected (not crash).

    Stock xrootd replies kXR_InvalidRequest ("Invalid request code",
    XrdXrootdProtocol.cc:608) for an unrecognised request code; kXR_Unsupported
    is reserved for a *recognised* op the backend cannot perform.  We match that.
    """

    def _send_unknown(self, sock, reqid, streamid=b"\x00\x01"):
        req = struct.pack("!2sH16sI", streamid, reqid, b"\x00"*16, 0)
        sock.sendall(req)
        return _read_response(sock)

    def test_requestid_0_rejected(self):
        sock = _full_session()
        _, status, body = self._send_unknown(sock, 0)
        sock.close()
        assert status == kXR_error
        assert _error_code(body) == kXR_InvalidRequest

    def test_requestid_below_range_rejected(self):
        sock = _full_session()
        _, status, body = self._send_unknown(sock, 2999)
        sock.close()
        assert status == kXR_error
        assert _error_code(body) == kXR_InvalidRequest

    def test_requestid_above_range_rejected(self):
        sock = _full_session()
        # kXR_writev is 3031 (highest valid); 3032+ is unknown
        _, status, body = self._send_unknown(sock, 3033)
        sock.close()
        assert status == kXR_error
        assert _error_code(body) == kXR_InvalidRequest

    def test_requestid_max_uint16_rejected(self):
        sock = _full_session()
        _, status, body = self._send_unknown(sock, 0xFFFF)
        sock.close()
        assert status == kXR_error
        assert _error_code(body) == kXR_InvalidRequest

    def test_requestid_lowest_valid_is_3001(self):
        # kXR_query = 3001 is a valid opcode — must NOT return Unsupported
        sock = _full_session()
        path = b"/test.txt\x00"
        req = struct.pack("!2sHHH12sI", b"\x00\x01", kXR_query,
                          1, 0, b"\x00"*12, len(path))
        sock.sendall(req + path)
        _, status, body = _read_response(sock)
        sock.close()
        # Must not be kXR_Unsupported
        if status == kXR_error:
            assert _error_code(body) != kXR_Unsupported

    def test_requestid_highest_valid_not_unsupported(self):
        # kXR_writev = 3031 is valid — rejected for bad args, not Unsupported
        sock = _full_session()
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_writev, b"\x00"*16, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        sock.close()
        if status == kXR_error:
            assert _error_code(body) != kXR_Unsupported

    def test_multiple_unknowns_then_ping(self):
        sock = _full_session()
        for reqid in [3033, 3050, 0xABCD]:
            req = struct.pack("!2sH16sI", b"\x00\x01", reqid, b"\x00"*16, 0)
            sock.sendall(req)
            _, status, body = _read_response(sock)
            assert status == kXR_error
        _, status, body = _ping(sock)
        sock.close()
        assert status == kXR_ok

    def test_requestid_3000_auth_before_login(self):
        # kXR_auth (3000) before login — requires login first
        sock = _handshake()
        cred = b"ztn\x00" + b"fake"
        req = struct.pack("!2sH12s4sI", b"\x00\x01", kXR_auth,
                          b"\x00"*12, b"ztn\x00", len(cred))
        sock.sendall(req + cred)
        _, status, body = _read_response(sock)
        sock.close()
        assert status == kXR_error


# =========================================================================
# Class 4 — Pre-Auth Request Rejection (gaps from test_privilege_escalation.py)
# =========================================================================
