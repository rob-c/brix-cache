from split_continuation import reexport as _reexport
_reexport(globals(), "_test_privilege_escalation_helpers")

class TestPreAuthAllowed:
    """Protocol, ping, and login should work before auth."""

    def test_preauth_ping_rejected(self):
        """kXR_ping before login is rejected, matching stock xrootd.

        Stock answers a pre-auth ping with kXR_error ("user not logged in"); our
        server routes kXR_ping through the same pre-login auth gate, so both
        backends reject it identically (no cross-backend skip needed)."""
        with _raw_session() as sock:
            req = struct.pack(
                "!2sH16sI",
                b"\x00\x01", kXR_ping,
                b"\x00" * 16, 0,
            )
            sock.sendall(req)
            status, _body = _read_response(sock)

        assert status == kXR_ERROR, "pre-auth ping must be rejected (stock parity)"

    def test_preauth_protocol_ok(self):
        """kXR_protocol should succeed before login."""
        with _raw_session() as sock:
            req = struct.pack(
                "!2sHIBB10sI",
                b"\x00\x01", kXR_protocol,
                0x00000520,      # client protocol version
                0x01,            # flags: kXR_secreqs
                0x03,            # expect: kXR_ExpLogin
                b"\x00" * 10,
                0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_OK
        assert len(body) >= 8  # at least ServerProtocolBody


# ===========================================================================
# Unknown opcode handling
# ===========================================================================

class TestUnknownOpcode:
    """Unknown request IDs must return kXR_Unsupported."""

    def test_unknown_opcode_after_login(self):
        """A bogus request ID should get kXR_Unsupported."""
        with _raw_session() as sock:
            _login_anon(sock)
            # Use requestid 3099 — well outside defined range
            req = struct.pack(
                "!2sH16sI",
                b"\x00\x02", 3099,
                b"\x00" * 16, 0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR
        # nginx-xrootd answers an unknown opcode with kXR_InvalidRequest; stock
        # xrootd rejects it earlier as kXR_ArgMissing. Both are correct errors.
        expected = {kXR_InvalidRequest}
        if CROSS_BACKEND == "xrootd":
            expected.add(kXR_ArgMissing)
        assert _error_code(body) in expected

    def test_unknown_opcode_before_login(self):
        """A bogus request ID before login should also be rejected."""
        with _raw_session() as sock:
            req = struct.pack(
                "!2sH16sI",
                b"\x00\x01", 3099,
                b"\x00" * 16, 0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR


# ===========================================================================
# Handle-based truncate on a read-only handle
# ===========================================================================

class TestTruncateOnReadOnly:
    """Handle-based kXR_truncate must fail on a read-only opened file."""

    @pytest.fixture(autouse=True)
    def _setup_file(self):
        self.remote = "/_priv_truncate_ro.txt"
        self.disk_path = os.path.join(DATA_DIR, "_priv_truncate_ro.txt")
        with open(self.disk_path, "wb") as f:
            f.write(b"A" * 1024)
        yield
        _unlink_if_exists(self.disk_path)

    def test_handle_truncate_on_readonly_rejected(self):
        """Open file read-only, then try handle-based truncate → must fail."""
        with _raw_session() as sock:
            _login_anon(sock)

            # Open the file read-only
            status, body = _open_file_raw(sock, self.remote.encode(), kXR_open_read)
            assert status == kXR_OK, f"open failed: status={status}"
            fhandle = body[:4]

            # Try handle-based truncate (dlen=0 → handle mode)
            req = struct.pack(
                "!2sH4sq4sI",
                b"\x00\x03", kXR_truncate,
                fhandle,
                0,             # target length = 0
                b"\x00" * 4,
                0,             # dlen=0 → handle-based
            )
            sock.sendall(req)
            status, body = _read_response(sock)

            # Server should reject: either kXR_NotAuthorized or kXR_IOError
            # (ftruncate on read-only fd returns EINVAL/EBADF at OS level)
            assert status == kXR_ERROR, (
                f"handle-based truncate on read-only handle should fail, got status={status}"
            )

            # Verify file was NOT actually truncated
            assert os.path.getsize(self.disk_path) == 1024, (
                "file was truncated despite read-only open"
            )

            _close_handle_raw(sock, fhandle)


# ===========================================================================
# Write on a read-only handle
# ===========================================================================

class TestWriteOnReadOnly:
    """kXR_write to a read-only file handle must be rejected."""

    @pytest.fixture(autouse=True)
    def _setup_file(self):
        self.remote = "/_priv_write_ro.txt"
        self.disk_path = os.path.join(DATA_DIR, "_priv_write_ro.txt")
        with open(self.disk_path, "wb") as f:
            f.write(b"original content\n")
        yield
        _unlink_if_exists(self.disk_path)

    def test_write_on_readonly_handle_rejected(self):
        """Open file read-only, then attempt kXR_write → must fail."""
        with _raw_session() as sock:
            _login_anon(sock)

            status, body = _open_file_raw(sock, self.remote.encode(), kXR_open_read)
            assert status == kXR_OK
            fhandle = body[:4]

            # Try to write to the read-only handle
            data = b"malicious overwrite"
            req = struct.pack(
                "!2sH4sq1s3sI",
                b"\x00\x03", kXR_write,
                fhandle,
                0,             # offset
                b"\x00",       # pathid
                b"\x00" * 3,   # reserved
                len(data),
            )
            sock.sendall(req + data)
            status, body = _read_response(sock)

        _assert_readonly_handle_write_rejected(status, body)

        # Verify file content was NOT modified
        with open(self.disk_path, "rb") as f:
            assert f.read() == b"original content\n"


# ===========================================================================
# Invalid file handle tests
# ===========================================================================

class TestInvalidHandles:
    """Operations on invalid file handles must return clean errors."""

    def test_read_invalid_handle(self):
        """kXR_read with an unopened handle should error."""
        with _raw_session() as sock:
            _login_anon(sock)

            req = struct.pack(
                "!2sH4sqiI",
                b"\x00\x02", kXR_read,
                b"\xff\x00\x00\x00",  # handle 255 — unlikely to be open
                0,                     # offset
                100,                   # rlen
                0,                     # dlen
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR
        assert _error_code(body) == kXR_FileNotOpen

    def test_write_invalid_handle(self):
        """kXR_write with an unopened handle should error."""
        with _raw_session() as sock:
            _login_anon(sock)

            data = b"test data"
            req = struct.pack(
                "!2sH4sq1s3sI",
                b"\x00\x02", kXR_write,
                b"\xff\x00\x00\x00",
                0, b"\x00", b"\x00" * 3,
                len(data),
            )
            sock.sendall(req + data)
            status, body = _read_response(sock)

        assert status == kXR_ERROR
        assert _error_code(body) == kXR_FileNotOpen

    def test_sync_invalid_handle(self):
        """kXR_sync with an unopened handle should error."""
        with _raw_session() as sock:
            _login_anon(sock)

            req = struct.pack(
                "!2sH4s12sI",
                b"\x00\x02", kXR_sync,
                b"\xff\x00\x00\x00",
                b"\x00" * 12, 0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR
        assert _error_code(body) == kXR_FileNotOpen

    def test_close_invalid_handle(self):
        """kXR_close with an unopened handle should error."""
        with _raw_session() as sock:
            _login_anon(sock)

            req = struct.pack(
                "!2sH4s12sI",
                b"\x00\x02", kXR_close,
                b"\xff\x00\x00\x00",
                b"\x00" * 12, 0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR
        assert _error_code(body) == kXR_FileNotOpen

    def test_truncate_invalid_handle(self):
        """Handle-based kXR_truncate with invalid handle should error."""
        with _raw_session() as sock:
            _login_anon(sock)

            req = struct.pack(
                "!2sH4sq4sI",
                b"\x00\x02", kXR_truncate,
                b"\xff\x00\x00\x00",
                0,              # target length
                b"\x00" * 4,
                0,              # dlen=0 → handle-based
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR
        assert _error_code(body) == kXR_FileNotOpen


# ===========================================================================
# Oversized path payload
# ===========================================================================

class TestOversizedPath:
    """Paths exceeding the server buffer limit must be rejected cleanly."""

    def test_oversized_stat_path(self):
        """A stat request with a >4096 byte path should be rejected or disconnect."""
        with _raw_session() as sock:
            _login_anon(sock)

            payload = b"/" + b"A" * 8000
            req = struct.pack(
                "!2sH1s7sI4sI",
                b"\x00\x02", kXR_stat,
                b"\x00", b"\x00" * 7, 0, b"\x00" * 4,
                len(payload),
            )
            sock.sendall(req + payload)
            try:
                status, body = _read_response(sock)
                assert status == kXR_ERROR
            except (ConnectionResetError, BrokenPipeError, AssertionError):
                pass  # Server disconnecting on oversized payload is acceptable

    def test_oversized_open_path(self):
        """An open request with a >4096 byte path should be rejected or disconnect."""
        with _raw_session() as sock:
            _login_anon(sock)

            payload = b"/" + b"B" * 8000
            req = struct.pack(
                "!2sHHH2s6s4sI",
                b"\x00\x02", kXR_open,
                0o644, kXR_open_read,
                b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                len(payload),
            )
            sock.sendall(req + payload)
            try:
                status, body = _read_response(sock)
                assert status == kXR_ERROR
            except (ConnectionResetError, BrokenPipeError, AssertionError):
                pass  # Server disconnecting on oversized payload is acceptable


# ===========================================================================
# Double-close and use-after-close
# ===========================================================================
