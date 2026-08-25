from split_continuation import reexport as _reexport
_reexport(globals(), "_test_proxy_mode_helpers")

# The proxy-mode tests share one proxy instance, one upstream, and fixed
# seeded data files; free scheduling interleaves another worker's handle
# lifecycle with an in-flight read (b'' at a seeded offset) — one worker.
pytestmark = pytest.mark.xdist_group("proxy-mode")

class TestProxyBootstrap:
    """Proxy lazy-connect and session-opcode behaviour."""

    def test_client_can_connect_and_login(self, proxy_env):
        """A fresh connection through the proxy completes login successfully."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        sock.close()

    def test_ping_handled_without_touching_upstream(self, proxy_env):
        """kXR_ping is a session opcode — proxy handles it before the lazy connect."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, _ = _ping(sock)
            assert status == kXR_ok, f"ping failed: status={status}"
        finally:
            sock.close()

    def test_multiple_pings_before_first_fs_op(self, proxy_env):
        """Session opcodes work many times without triggering upstream connect."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            for i in range(5):
                sid = bytes([0, i + 1])
                req = struct.pack(">2sH16sI", sid, kXR_ping, b"\x00" * 16, 0)
                sock.sendall(req)
                status, _ = _read_resp(sock)
                assert status == kXR_ok, f"ping {i} failed"
        finally:
            sock.close()

    def test_first_fs_op_triggers_lazy_connect(self, proxy_env):
        """First post-login opcode (stat) triggers upstream bootstrap; response is correct."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _stat(sock, "/hello.txt")
            assert status == kXR_ok, f"stat failed: status={status}, body={body!r}"
            flags, size, _ = _parse_stat_body(body)
            assert size == 22   # len("hello from proxy test\n")
        finally:
            sock.close()

    def test_session_opcodes_still_work_after_fs_op(self, proxy_env):
        """kXR_ping continues to work after the upstream has been bootstrapped."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            _stat(sock, "/hello.txt")
            status, _ = _ping(sock)
            assert status == kXR_ok
        finally:
            sock.close()

    def test_multiple_connections_independent_proxies(self, proxy_env):
        """Each client connection gets its own upstream proxy context."""
        socks = [_connect(HOST, proxy_env["proxy_port"]) for _ in range(4)]
        try:
            for i, sock in enumerate(socks):
                status, body = _stat(sock, "/hello.txt")
                assert status == kXR_ok, f"connection {i}: stat failed"
                _, size, _ = _parse_stat_body(body)
                assert size == 22
        finally:
            for sock in socks:
                sock.close()

    def test_endsess_terminates_cleanly(self, proxy_env):
        """kXR_endsess through the proxy is acknowledged and connection closes."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            _stat(sock, "/hello.txt")   # trigger upstream connect
            req = struct.pack(">2sH16sI", b"\x00\x02", kXR_endsess,
                              b"\x00" * 16, 0)
            sock.sendall(req)
            status, _ = _read_resp(sock)
            assert status == kXR_ok
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyStat
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyStat:
    """kXR_stat forwarding through the proxy."""

    def test_stat_existing_file(self, proxy_env):
        """Stat an existing file; size and flags come from upstream correctly."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _stat(sock, "/hello.txt")
            assert status == kXR_ok
            flags, size, mtime = _parse_stat_body(body)
            assert size == 22
            assert mtime > 0
            assert not (flags & kXR_isDir)   # not a directory
        finally:
            sock.close()

    def test_stat_directory(self, proxy_env):
        """Stat a directory returns directory flag."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _stat(sock, "/subdir")
            assert status == kXR_ok
            flags, _, _ = _parse_stat_body(body)
            assert flags & kXR_isDir, f"kXR_isDir not set for directory: flags={flags}"
        finally:
            sock.close()

    def test_stat_nonexistent_file_returns_error(self, proxy_env):
        """Stat on a nonexistent path returns kXR_error (not a crash)."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _stat(sock, "/does_not_exist_xyz.txt")
            assert status == kXR_error, f"expected error, got status={status}"
            assert len(body) >= 4   # error code present
        finally:
            sock.close()

    def test_stat_binary_file(self, proxy_env):
        """Stat binary file returns correct size."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _stat(sock, "/data256.bin")
            assert status == kXR_ok
            _, size, _ = _parse_stat_body(body)
            assert size == 1024
        finally:
            sock.close()

    def test_stat_nested_file(self, proxy_env):
        """Stat a file in a subdirectory."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _stat(sock, "/subdir/nested.txt")
            assert status == kXR_ok
            _, size, _ = _parse_stat_body(body)
            assert size == 12    # len("nested file\n")
        finally:
            sock.close()

    def test_stat_large_file(self, proxy_env):
        """Stat large file returns correct size."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _stat(sock, "/large.bin")
            assert status == kXR_ok
            _, size, _ = _parse_stat_body(body)
            assert size == 512 * 1024
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyDirlist
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyDirlist:
    """kXR_dirlist forwarding through the proxy."""

    def test_dirlist_root(self, proxy_env):
        """Listing / returns the seeded files and directories."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _dirlist(sock, "/")
            assert status == kXR_ok, f"dirlist failed: {status}"
            listing = body.decode(errors="replace")
            assert "hello.txt" in listing
            assert "data256.bin" in listing
            assert "subdir" in listing
        finally:
            sock.close()

    def test_dirlist_subdirectory(self, proxy_env):
        """Listing a subdirectory returns only files in that directory."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _dirlist(sock, "/subdir")
            assert status == kXR_ok
            listing = body.decode(errors="replace")
            assert "nested.txt" in listing
            # Root-level files must NOT appear
            assert "hello.txt" not in listing
        finally:
            sock.close()

    def test_dirlist_nonexistent_directory(self, proxy_env):
        """Listing a nonexistent directory returns kXR_error."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, _ = _dirlist(sock, "/no_such_dir_xyz")
            assert status == kXR_error
        finally:
            sock.close()

    def test_dirlist_empty_directory(self, proxy_env):
        """Listing an empty directory returns kXR_ok with empty body."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, _ = _dirlist(sock, "/subdir2")
            assert status == kXR_ok
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyOpenReadClose
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyOpenReadClose:
    """Open + read + close through the proxy: data must match upstream directly."""

    def test_read_full_small_file(self, proxy_env):
        """Read entire small file; content matches what was written to disk."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/hello.txt", kXR_open_read)
            assert status == kXR_ok, f"open failed: {status}"
            fhandle = _fh(body)

            status, data = _read(sock, fhandle, 0, 22)
            assert status == kXR_ok
            assert data == b"hello from proxy test\n"

            status, _ = _close(sock, fhandle)
            assert status == kXR_ok
        finally:
            sock.close()

    def test_read_partial_offset(self, proxy_env):
        """Read a range starting at a non-zero offset."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/data256.bin", kXR_open_read)
            assert status == kXR_ok
            fhandle = _fh(body)

            # Bytes 256-511 should be 0x00..0xFF (second repetition of the pattern)
            status, data = _read(sock, fhandle, 256, 256)
            assert status == kXR_ok
            assert len(data) == 256
            assert data == bytes(range(256))

            _close(sock, fhandle)
        finally:
            sock.close()

    def test_read_past_eof_returns_available(self, proxy_env):
        """Reading past EOF returns the bytes available, not an error."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/hello.txt", kXR_open_read)
            assert status == kXR_ok
            fhandle = _fh(body)

            # Request 1000 bytes from a 22-byte file
            status, data = _read(sock, fhandle, 0, 1000)
            assert status == kXR_ok
            assert data == b"hello from proxy test\n"

            _close(sock, fhandle)
        finally:
            sock.close()

    def test_read_exactly_at_eof(self, proxy_env):
        """Reading from exactly EOF returns empty or kXR_ok."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/hello.txt", kXR_open_read)
            assert status == kXR_ok
            fhandle = _fh(body)

            status, data = _read(sock, fhandle, 22, 10)
            assert status == kXR_ok
            assert len(data) == 0

            _close(sock, fhandle)
        finally:
            sock.close()

    def test_read_binary_data_integrity(self, proxy_env):
        """Binary file content is relayed byte-for-byte through the proxy."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/data256.bin", kXR_open_read)
            assert status == kXR_ok
            fhandle = _fh(body)

            status, data = _read(sock, fhandle, 0, 1024)
            assert status == kXR_ok
            assert len(data) == 1024
            assert data == bytes(range(256)) * 4

            _close(sock, fhandle)
        finally:
            sock.close()

    def test_multiple_reads_same_handle(self, proxy_env):
        """Multiple consecutive reads on one handle return sequential file data."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/data256.bin", kXR_open_read)
            assert status == kXR_ok
            fhandle = _fh(body)

            expected = bytes(range(256)) * 4
            for chunk_start in range(0, 1024, 128):
                status, data = _read(sock, fhandle, chunk_start, 128)
                assert status == kXR_ok
                assert data == expected[chunk_start:chunk_start + 128], \
                    f"mismatch at offset {chunk_start}"

            _close(sock, fhandle)
        finally:
            sock.close()

    def test_open_nonexistent_returns_error(self, proxy_env):
        """Opening a nonexistent file returns kXR_error from the backend."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/no_such_file.txt", kXR_open_read)
            assert status == kXR_error, f"expected kXR_error, got {status}"
            assert len(body) >= 4
        finally:
            sock.close()

    def test_open_read_nested_file(self, proxy_env):
        """Read a file in a subdirectory."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/subdir/nested.txt", kXR_open_read)
            assert status == kXR_ok
            fhandle = _fh(body)

            status, data = _read(sock, fhandle, 0, 100)
            assert status == kXR_ok
            assert data == b"nested file\n"

            _close(sock, fhandle)
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyOpenWriteClose
# ──────────────────────────────────────────────────────────────────────────────
