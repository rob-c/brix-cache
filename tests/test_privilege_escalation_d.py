from split_continuation import reexport as _reexport
_reexport(globals(), "_test_privilege_escalation_helpers")

# One worker for the class: every test's autouse fixture creates and unlinks
# the SAME data-root file, so split across xdist workers one test's teardown
# unlinks the file mid-another's open (open -> 4003 on a file the setup just
# wrote).
@pytest.mark.xdist_group("shared-file-priv-use-after-close")
class TestUseAfterClose:
    """Operations on a closed handle must fail cleanly."""

    @pytest.fixture(autouse=True)
    def _setup_file(self):
        self.remote = "/_priv_use_after_close.txt"
        self.disk_path = os.path.join(DATA_DIR, "_priv_use_after_close.txt")
        with open(self.disk_path, "wb") as f:
            f.write(b"use after close test\n")
        yield
        _unlink_if_exists(self.disk_path)

    def test_read_after_close(self):
        """Reading from a closed handle must return kXR_FileNotOpen."""
        with _raw_session() as sock:
            _login_anon(sock)

            # Open
            status, body = _open_file_raw(sock, self.remote.encode(), kXR_open_read)
            assert status == kXR_OK
            fhandle = body[:4]

            # Close
            _close_handle_raw(sock, fhandle, streamid=b"\x00\x03")

            # Try to read the closed handle
            req = struct.pack(
                "!2sH4sqiI",
                b"\x00\x04", kXR_read,
                fhandle,
                0, 100, 0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR
        assert _error_code(body) == kXR_FileNotOpen

    def test_double_close(self):
        """Closing an already-closed handle must not crash."""
        with _raw_session() as sock:
            _login_anon(sock)

            status, body = _open_file_raw(sock, self.remote.encode(), kXR_open_read)
            assert status == kXR_OK
            fhandle = body[:4]

            # First close
            _close_handle_raw(sock, fhandle, streamid=b"\x00\x03")

            # Second close on same handle
            req = struct.pack(
                "!2sH4s12sI",
                b"\x00\x04", kXR_close,
                fhandle, b"\x00" * 12, 0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR
        assert _error_code(body) == kXR_FileNotOpen


# ===========================================================================
# Empty/zero payload edge cases
# ===========================================================================

class TestEmptyPayloads:
    """Operations with missing mandatory path payloads must fail."""

    def test_rm_no_path(self):
        """kXR_rm with dlen=0 (no path) should fail."""
        with _raw_session() as sock:
            _login_anon(sock)

            req = struct.pack(
                "!2sH16sI",
                b"\x00\x02", kXR_rm,
                b"\x00" * 16, 0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR

    def test_mkdir_no_path(self):
        """kXR_mkdir with dlen=0 should fail."""
        with _raw_session() as sock:
            _login_anon(sock)

            req = struct.pack(
                "!2sH1s13sHI",
                b"\x00\x02", kXR_mkdir,
                b"\x00", b"\x00" * 13, 0o755, 0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR

    def test_stat_no_path_no_handle(self):
        """kXR_stat with dlen=0 and no handle should still succeed (stat of handle 0)."""
        # This tests the edge case — stat with fhandle=0 and dlen=0 might
        # map to handle-based stat, which should fail if handle 0 is not open
        with _raw_session() as sock:
            _login_anon(sock)

            req = struct.pack(
                "!2sH1s7sI4sI",
                b"\x00\x02", kXR_stat,
                b"\x00", b"\x00" * 7, 0,
                b"\x00" * 4,    # fhandle 0
                0,              # dlen=0
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        # Either OK (if stat goes path-based with empty path → root)
        # or ERROR (if handle 0 is not open). Both are acceptable as
        # long as the server doesn't crash.
        assert status in (kXR_OK, kXR_ERROR)


# ===========================================================================
# Path traversal attempts (raw protocol — avoids XRootD client hangs)
# ===========================================================================

class TestPathTraversal:
    """Path traversal attempts must be caught and rejected."""

    def test_stat_dot_dot_traversal(self):
        """stat('/../etc/passwd') must be rejected."""
        with _raw_session() as sock:
            _login_anon(sock)

            payload = b"/../etc/passwd"
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
            except (ConnectionResetError, BrokenPipeError):
                pass  # disconnecting is also acceptable

    def test_open_dot_dot_traversal(self):
        """open('/../etc/passwd') must be rejected."""
        with _raw_session() as sock:
            _login_anon(sock)

            payload = b"/../etc/passwd"
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
            except (ConnectionResetError, BrokenPipeError):
                pass

    def test_dirlist_outside_root(self):
        """dirlist('/../') must not expose system directories."""
        with _raw_session() as sock:
            _login_anon(sock)

            payload = b"/../"
            req = struct.pack(
                "!2sH15sBi",
                b"\x00\x02", kXR_dirlist,
                b"\x00" * 15, 0,
                len(payload),
            )
            sock.sendall(req + payload)
            try:
                status, body = _read_response(sock)
                if status == kXR_OK:
                    listing = body.decode("utf-8", errors="replace")
                    # /etc, /usr, /var should NOT appear
                    assert "etc" not in listing.split("\n")
                    assert "usr" not in listing.split("\n")
                else:
                    assert status == kXR_ERROR  # outright rejection is fine
            except (ConnectionResetError, BrokenPipeError):
                pass

    def test_mv_dot_dot_destination(self):
        """mv to a path outside the root must be rejected."""
        src = os.path.join(DATA_DIR, "_priv_mv_src.txt")
        with open(src, "w") as f:
            f.write("mv traversal test\n")
        try:
            with _raw_session() as sock:
                _login_anon(sock)

                # kXR_mv payload is "oldpath \nnewpath"
                payload = b"/_priv_mv_src.txt\n/../../../tmp/_priv_mv_escaped.txt"
                req = struct.pack(
                    "!2sH16sI",
                    b"\x00\x02", kXR_mv,
                    b"\x00" * 16,
                    len(payload),
                )
                sock.sendall(req + payload)
                try:
                    status, body = _read_response(sock)
                    assert status == kXR_ERROR
                except (ConnectionResetError, BrokenPipeError):
                    pass

            assert os.path.exists(src), "source was removed despite traversal block"
            assert not os.path.exists("/tmp/_priv_mv_escaped.txt")
        finally:
            _unlink_if_exists(src)

# ===========================================================================
# kXR_set — advisory session configuration
# ===========================================================================

@pytest.mark.skipif(
    CROSS_BACKEND == "xrootd",
    reason="kXR_set leniency (advisory modifiers always accepted with kXR_ok) is nginx-xrootd-specific",
)
class TestSet:
    """kXR_set (3018) accepts all advisory modifier values after login."""

    def _send_set(self, sock, modifier: int, payload: bytes,
                  streamid: bytes = b"\x00\x02") -> tuple:
        req = struct.pack(
            "!2sHB15sI",
            streamid, kXR_set, modifier, b"\x00" * 15, len(payload),
        )
        sock.sendall(req + payload)
        return _read_response(sock)

    def test_set_appid_returns_ok(self):
        """kXR_set with modifier=0x00 (appid) returns kXR_ok after login."""
        with _raw_session() as sock:
            _login_anon(sock)
            status, body = self._send_set(sock, 0x00, b"pytest-app\n")
        assert status == kXR_OK, f"expected kXR_ok, got status={status} body={body!r}"

    def test_set_clttl_returns_ok(self):
        """kXR_set with modifier=0x01 (client TTL hint) returns kXR_ok after login."""
        with _raw_session() as sock:
            _login_anon(sock)
            status, body = self._send_set(sock, 0x01, b"3600\n")
        assert status == kXR_OK, f"expected kXR_ok, got status={status} body={body!r}"

    def test_set_unknown_modifier_returns_ok(self):
        """Unknown modifier values must also return kXR_ok (advisory; spec mandates acceptance)."""
        with _raw_session() as sock:
            _login_anon(sock)
            status, body = self._send_set(sock, 0xFF, b"anything\n")
        assert status == kXR_OK, f"expected kXR_ok for unknown modifier, got status={status}"

    def test_set_empty_payload_returns_ok(self):
        """kXR_set with zero-length payload returns kXR_ok."""
        with _raw_session() as sock:
            _login_anon(sock)
            status, body = self._send_set(sock, 0x00, b"")
        assert status == kXR_OK, f"expected kXR_ok for empty payload, got status={status}"

    def test_set_before_login_rejected(self):
        """kXR_set before kXR_login must be rejected (login guard)."""
        with _raw_session() as sock:
            status, body = self._send_set(sock, 0x00, b"early-app\n")
        assert status == kXR_ERROR, f"expected kXR_error before login, got status={status}"

    def test_set_cms_space_returns_ok(self):
        """kXR_set with cms.space space-report payload returns kXR_ok."""
        with _raw_session() as sock:
            _login_anon(sock)
            # cms.space format: "cms.space <total_bytes> <free_bytes>"
            status, body = self._send_set(sock, 0x00,
                                          b"cms.space 1073741824 536870912\n")
        assert status == kXR_OK, (
            f"expected kXR_ok for cms.space report, got status={status}")

    def test_set_cms_space_malformed_still_ok(self):
        """Malformed cms.space payload must still return kXR_ok (advisory; server must accept)."""
        with _raw_session() as sock:
            _login_anon(sock)
            status, body = self._send_set(sock, 0x00, b"cms.space notanumber\n")
        assert status == kXR_OK, (
            f"expected kXR_ok even for malformed cms.space, got status={status}")

    def test_set_cms_space_before_login_rejected(self):
        """cms.space via kXR_set before kXR_login must be rejected (login guard)."""
        with _raw_session() as sock:
            status, body = self._send_set(sock, 0x00,
                                          b"cms.space 1073741824 536870912\n")
        assert status == kXR_ERROR, (
            f"expected kXR_error for cms.space before login, got status={status}")
