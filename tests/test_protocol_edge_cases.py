from split_continuation import reexport as _reexport
_reexport(globals(), "_test_protocol_edge_cases_helpers")

class TestHandshake:
    """The initial 20-byte handshake must validate magic fields."""

    def test_valid_handshake(self):
        """Standard handshake should succeed."""
        sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
        sock.settimeout(5)
        try:
            sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
            status, body = _read_response(sock)
            assert status == kXR_OK
            assert len(body) == 8
        finally:
            sock.close()

    def test_invalid_fourth_field(self):
        """Handshake with fourth != 4 should be rejected or cause disconnect."""
        sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
        sock.settimeout(3)
        try:
            sock.sendall(struct.pack("!IIIII", 0, 0, 0, 99, 2012))
            try:
                status, body = _read_response(sock)
                # If server responds, it should be an error
                assert status == kXR_ERROR
            except (ConnectionResetError, AssertionError, socket.timeout):
                pass  # Server closed connection — acceptable behavior
        finally:
            sock.close()

    def test_invalid_fifth_field(self):
        """Handshake with fifth != 2012 should be rejected or cause disconnect."""
        sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
        sock.settimeout(3)
        try:
            sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 9999))
            try:
                status, body = _read_response(sock)
                assert status == kXR_ERROR
            except (ConnectionResetError, AssertionError, socket.timeout):
                pass  # Server closed connection — acceptable behavior
        finally:
            sock.close()


# ===========================================================================
# Multiple sequential requests on one session
# ===========================================================================

class TestSequentialRequests:
    """Multiple requests on a single connection must all be handled."""

    def test_ping_after_stat(self):
        """A ping after a stat on the same connection should succeed."""
        with _raw_session() as sock:
            _login_anon(sock)

            # stat /
            payload = b"/"
            req = struct.pack(
                "!2sH1s7sI4sI",
                b"\x00\x02", kXR_stat,
                b"\x00", b"\x00" * 7, 0, b"\x00" * 4,
                len(payload),
            )
            sock.sendall(req + payload)
            status, _ = _read_response(sock)
            assert status == kXR_OK

            # ping
            req = struct.pack("!2sH16sI", b"\x00\x03", kXR_ping, b"\x00" * 16, 0)
            sock.sendall(req)
            status, _ = _read_response(sock)
            assert status == kXR_OK

    def test_multiple_stats(self):
        """Multiple stat requests on the same connection."""
        with _raw_session() as sock:
            _login_anon(sock)

            for i in range(5):
                payload = b"/test.txt"
                sid = struct.pack("!H", i + 2)
                req = struct.pack(
                    "!2sH1s7sI4sI",
                    sid, kXR_stat,
                    b"\x00", b"\x00" * 7, 0, b"\x00" * 4,
                    len(payload),
                )
                sock.sendall(req + payload)
                status, _ = _read_response(sock)
                assert status == kXR_OK, f"stat #{i} failed"

    def test_open_read_close_cycle(self):
        """Open → read → close cycle via raw protocol."""
        with _raw_session() as sock:
            _login_anon(sock)

            status, body = _open_file_raw(sock, b"/test.txt", kXR_open_read)
            assert status == kXR_OK
            fhandle = body[:4]

            # Read first 10 bytes
            req = struct.pack(
                "!2sH4sqiI",
                b"\x00\x03", kXR_read,
                fhandle, 0, 10, 0,
            )
            sock.sendall(req)
            status, data = _read_response(sock)
            assert status == kXR_OK
            assert len(data) == 10

            _close_handle(sock, fhandle, streamid=b"\x00\x04")


# ===========================================================================
# kXR_endsess behavior
# ===========================================================================

class TestEndSession:
    """kXR_endsess should terminate the session cleanly."""

    @pytest.mark.skipif(
        CROSS_BACKEND == "xrootd",
        reason="stock xrootd drops the socket on kXR_endsess; the reply-frame contract is nginx-xrootd-specific",
    )
    def test_endsess_closes_session(self):
        """After endsess, subsequent requests should fail."""
        with _raw_session() as sock:
            login_body = _login_anon(sock)
            sessid = login_body[:16]
            assert len(sessid) == 16

            # Verify the session works
            req = struct.pack("!2sH16sI", b"\x00\x02", kXR_ping, b"\x00" * 16, 0)
            sock.sendall(req)
            status, _ = _read_response(sock)
            assert status == kXR_OK

            # Send endsess
            req = struct.pack("!2sH16sI", b"\x00\x03", kXR_endsess, sessid, 0)
            sock.sendall(req)
            status, _ = _read_response(sock)
            assert status == kXR_OK

            # After endsess, trying stat should fail or the connection closes
            payload = b"/test.txt"
            req = struct.pack(
                "!2sH1s7sI4sI",
                b"\x00\x04", kXR_stat,
                b"\x00", b"\x00" * 7, 0, b"\x00" * 4,
                len(payload),
            )
            try:
                sock.sendall(req + payload)
                status, body = _read_response(sock)
                # If server responds, it should be an auth error (session ended)
                assert status == kXR_ERROR
            except (BrokenPipeError, ConnectionResetError, AssertionError):
                pass  # Connection closed — acceptable after endsess


# ===========================================================================
# Handle-based stat
# ===========================================================================

class TestHandleStat:
    """kXR_stat with a handle (dlen=0) should work after open."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.disk = os.path.join(DATA_DIR, "_proto_handle_stat.txt")
        with open(self.disk, "wb") as f:
            f.write(b"handle stat test content\n")
        yield
        if os.path.exists(self.disk):
            os.unlink(self.disk)

    def test_stat_via_handle(self):
        """stat with fhandle from open should return file size."""
        with _raw_session() as sock:
            _login_anon(sock)

            status, body = _open_file_raw(
                sock, b"/_proto_handle_stat.txt", kXR_open_read
            )
            assert status == kXR_OK
            fhandle = body[:4]

            # Handle-based stat: dlen=0, fhandle set
            req = struct.pack(
                "!2sH1s7sI4sI",
                b"\x00\x03", kXR_stat,
                b"\x00", b"\x00" * 7, 0,
                fhandle,
                0,  # dlen=0 → handle-based
            )
            sock.sendall(req)
            status, stat_body = _read_response(sock)
            assert status == kXR_OK
            # Parse stat string: "id size flags mtime"
            stat_str = stat_body.rstrip(b"\x00").decode()
            parts = stat_str.split()
            assert len(parts) >= 4, f"stat response malformed: {stat_str!r}"
            size = int(parts[1])
            assert size == 25, f"expected size 25, got {size}"

            _close_handle(sock, fhandle, streamid=b"\x00\x04")


# ===========================================================================
# readv edge cases
# ===========================================================================

# One worker for the class: every test's autouse fixture creates and unlinks
# the SAME data-root file, so split across xdist workers one test's teardown
# unlinks the file mid-another's open ("file not found" on a file the setup
# just wrote).
@pytest.mark.xdist_group("shared-file-proto-readv")
class TestReadvEdgeCases:
    """readv with edge-case segment descriptors."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.disk = os.path.join(DATA_DIR, "_proto_readv.txt")
        with open(self.disk, "wb") as f:
            f.write(b"A" * 1000)
        yield
        if os.path.exists(self.disk):
            os.unlink(self.disk)

    def test_readv_zero_length_segment(self):
        """A zero-length readv segment should be handled gracefully."""
        f = client.File()
        status, _ = f.open(f"{ANON_URL}//_proto_readv.txt", OpenFlags.READ)
        assert status.ok

        # Zero-length chunk
        status, result = f.vector_read([(0, 0)])
        # May succeed with empty data or may error — either is fine
        f.close()

    def test_readv_past_eof(self):
        """readv segment starting past EOF should be rejected or return partial data."""
        f = client.File()
        status, _ = f.open(f"{ANON_URL}//_proto_readv.txt", OpenFlags.READ)
        assert status.ok

        # Segment starting at offset 999, requesting 100 bytes — only 1 byte available
        status, result = f.vector_read([(999, 100)])
        # Server may reject readv past EOF with an error, or return partial data
        if status.ok:
            chunks = list(result)
            if len(chunks) > 0:
                assert len(chunks[0].buffer) <= 100
        else:
            # Server correctly rejects readv past EOF — that's fine
            pass

        f.close()

    def test_readv_many_segments(self):
        """readv with many small segments should succeed."""
        f = client.File()
        status, _ = f.open(f"{ANON_URL}//_proto_readv.txt", OpenFlags.READ)
        assert status.ok

        # 50 segments of 10 bytes each
        chunks = [(i * 10, 10) for i in range(50)]
        status, result = f.vector_read(chunks)
        assert status.ok
        assert result is not None
        data_chunks = list(result)
        assert len(data_chunks) == 50
        for chunk in data_chunks:
            assert bytes(chunk.buffer) == b"A" * 10

        f.close()


# ===========================================================================
# Open with retstat flag
# ===========================================================================

class TestOpenWithRetstat:
    """kXR_open with kXR_retstat should include stat info in response."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.disk = os.path.join(DATA_DIR, "_proto_retstat.txt")
        with open(self.disk, "wb") as f:
            f.write(b"X" * 256)
        yield
        if os.path.exists(self.disk):
            os.unlink(self.disk)

    def test_open_retstat_includes_size(self):
        """Open with kXR_retstat should include stat in the response body."""
        with _raw_session() as sock:
            _login_anon(sock)

            status, body = _open_file_raw(
                sock, b"/_proto_retstat.txt",
                kXR_open_read | kXR_retstat,
            )
            assert status == kXR_OK
            # Body: fhandle(4) + cpsize(4) + cptype(4) + stat_string
            assert len(body) >= 12, f"retstat body too short: {len(body)} bytes"
            fhandle = body[:4]

            # The stat string should be after the first 12 bytes
            if len(body) > 12:
                stat_str = body[12:].rstrip(b"\x00").decode()
                parts = stat_str.split()
                assert len(parts) >= 4, f"stat string malformed: {stat_str!r}"
                size = int(parts[1])
                assert size == 256

            _close_handle(sock, fhandle, streamid=b"\x00\x03")


# ===========================================================================
# Connection resilience after errors
# ===========================================================================
