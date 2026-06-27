from _test_proxy_mode_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

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

class TestProxyOpenWriteClose:
    """Write round-trips through the proxy."""

    def test_write_new_file_and_read_back(self, proxy_env):
        """Create a new file via proxy write, then read it back."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            fname = f"/proxy_write_{uuid.uuid4().hex[:8]}.txt"
            payload = b"proxy write test data\n"

            status, body = _open(sock, fname,
                                 kXR_open_updt | kXR_new | kXR_mkpath)
            assert status == kXR_ok, f"write-open failed: {status}"
            fhandle = _fh(body)

            status, _ = _write(sock, fhandle, 0, payload)
            assert status == kXR_ok

            status, _ = _sync(sock, fhandle)
            assert status == kXR_ok

            status, _ = _close(sock, fhandle)
            assert status == kXR_ok

            # Re-open and verify
            status, body = _open(sock, fname, kXR_open_read)
            assert status == kXR_ok
            fhandle2 = _fh(body)

            status, data = _read(sock, fhandle2, 0, len(payload) + 10)
            assert status == kXR_ok
            assert data == payload

            _close(sock, fhandle2)
        finally:
            sock.close()

    def test_write_at_offset(self, proxy_env):
        """Write data at a non-zero offset; verify with a targeted read."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            fname = f"/proxy_offset_{uuid.uuid4().hex[:8]}.bin"

            # Create with 16 zeros
            status, body = _open(sock, fname, kXR_open_updt | kXR_new)
            assert status == kXR_ok
            fh = _fh(body)
            _write(sock, fh, 0, b"\x00" * 16)
            # Overwrite bytes 4-7 with known pattern
            _write(sock, fh, 4, b"MARK")
            _sync(sock, fh)
            _close(sock, fh)

            # Verify
            status, body = _open(sock, fname, kXR_open_read)
            assert status == kXR_ok
            fh2 = _fh(body)
            status, data = _read(sock, fh2, 0, 16)
            assert status == kXR_ok
            assert data[4:8] == b"MARK", f"expected MARK at offset 4, got {data!r}"
            _close(sock, fh2)
        finally:
            sock.close()

    def test_overwrite_existing_file(self, proxy_env):
        """Open existing file in write mode and overwrite beginning."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            fname = f"/proxy_overwrite_{uuid.uuid4().hex[:8]}.txt"

            # Create
            s, b = _open(sock, fname, kXR_open_updt | kXR_new)
            assert s == kXR_ok
            fh = _fh(b)
            _write(sock, fh, 0, b"ORIGINAL CONTENT HERE")
            _sync(sock, fh)
            _close(sock, fh)

            # Overwrite first 8 bytes
            s, b = _open(sock, fname, kXR_open_updt)
            assert s == kXR_ok
            fh = _fh(b)
            _write(sock, fh, 0, b"MODIFIED")
            _sync(sock, fh)
            _close(sock, fh)

            # Verify
            s, b = _open(sock, fname, kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)
            s, data = _read(sock, fh, 0, 8)
            assert s == kXR_ok
            assert data == b"MODIFIED"
            _close(sock, fh)
        finally:
            sock.close()

    def test_write_large_chunk(self, proxy_env):
        """Write a 256 KiB chunk through the proxy."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            fname = f"/proxy_large_write_{uuid.uuid4().hex[:8]}.bin"
            payload = bytes(i & 0xFF for i in range(256 * 1024))

            s, b = _open(sock, fname, kXR_open_updt | kXR_new)
            assert s == kXR_ok
            fh = _fh(b)
            s, _ = _write(sock, fh, 0, payload)
            assert s == kXR_ok
            _sync(sock, fh)
            _close(sock, fh)

            # Verify spot-check at several offsets
            s, b = _open(sock, fname, kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)
            for offset in (0, 1024, 65536, 131072):
                s, data = _read(sock, fh, offset, 256)
                assert s == kXR_ok
                assert data == payload[offset:offset + 256], \
                    f"mismatch at offset {offset}"
            _close(sock, fh)
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyHandleTranslation
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyHandleTranslation:
    """File handle translation: client gets local handles, proxy maps to upstream."""

    def test_two_files_open_simultaneously(self, proxy_env):
        """Two files open at once; reads from each handle return correct data."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            s1, b1 = _open(sock, "/alpha.txt", kXR_open_read, sid=b"\x00\x01")
            assert s1 == kXR_ok
            fh1 = _fh(b1)

            s2, b2 = _open(sock, "/beta.txt", kXR_open_read, sid=b"\x00\x02")
            assert s2 == kXR_ok
            fh2 = _fh(b2)

            assert fh1 != fh2, "proxy should assign different local handles"

            s, data1 = _read(sock, fh1, 0, 16, sid=b"\x00\x03")
            assert s == kXR_ok
            assert data1 == b"AAAABBBBCCCCDDDD"

            s, data2 = _read(sock, fh2, 0, 16, sid=b"\x00\x04")
            assert s == kXR_ok
            assert data2 == b"1111222233334444"

            _close(sock, fh1, sid=b"\x00\x05")
            _close(sock, fh2, sid=b"\x00\x06")
        finally:
            sock.close()

    def test_three_files_interleaved_reads(self, proxy_env):
        """Three files open; interleaved reads all return correct data."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            _, b1 = _open(sock, "/alpha.txt", kXR_open_read, sid=b"\x00\x01")
            _, b2 = _open(sock, "/beta.txt",  kXR_open_read, sid=b"\x00\x02")
            _, b3 = _open(sock, "/gamma.txt", kXR_open_read, sid=b"\x00\x03")
            fh1, fh2, fh3 = _fh(b1), _fh(b2), _fh(b3)

            expected = {
                fh1: b"AAAABBBBCCCCDDDD",
                fh2: b"1111222233334444",
                fh3: b"xyzxyzxyzxyzxyz!",
            }
            # Interleave reads
            for fh in (fh2, fh1, fh3, fh1, fh2, fh3):
                s, data = _read(sock, fh, 0, 16)
                assert s == kXR_ok
                assert data == expected[fh], \
                    f"handle {fh!r}: expected {expected[fh]!r}, got {data!r}"

            for fh in (fh1, fh2, fh3):
                _close(sock, fh)
        finally:
            sock.close()

    def test_handle_reuse_after_close(self, proxy_env):
        """After closing a handle, a new open can reuse the same local slot."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            s, b = _open(sock, "/alpha.txt", kXR_open_read, sid=b"\x00\x01")
            assert s == kXR_ok
            fh1 = _fh(b)

            _close(sock, fh1, sid=b"\x00\x02")

            # Open a different file — may reuse fh1's slot number
            s, b = _open(sock, "/beta.txt", kXR_open_read, sid=b"\x00\x03")
            assert s == kXR_ok
            fh2 = _fh(b)

            s, data = _read(sock, fh2, 0, 16)
            assert s == kXR_ok
            assert data == b"1111222233334444"

            _close(sock, fh2)
        finally:
            sock.close()

    def test_read_from_closed_handle_returns_error(self, proxy_env):
        """Reading from a handle after close returns kXR_error (invalid handle)."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            s, b = _open(sock, "/alpha.txt", kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)
            _close(sock, fh)

            # Attempting to read from the now-closed handle
            s, body = _read(sock, fh, 0, 16)
            assert s == kXR_error, f"expected error on read from closed handle, got {s}"
        finally:
            sock.close()

    def test_many_handles_open_simultaneously(self, proxy_env):
        """Open several files at once and verify each returns its own data."""
        files = ["alpha.txt", "beta.txt", "gamma.txt", "hello.txt"]
        expected = {
            "alpha.txt": b"AAAABBBBCCCCDDDD",
            "beta.txt":  b"1111222233334444",
            "gamma.txt": b"xyzxyzxyzxyzxyz!",
            "hello.txt": b"hello from proxy",  # first 16 bytes
        }
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            handles = {}
            for i, fname in enumerate(files):
                sid = bytes([0, i + 1])
                s, b = _open(sock, f"/{fname}", kXR_open_read, sid=sid)
                assert s == kXR_ok, f"open {fname} failed"
                handles[fname] = _fh(b)

            for fname, fh in handles.items():
                s, data = _read(sock, fh, 0, 16)
                assert s == kXR_ok
                assert data == expected[fname], \
                    f"{fname}: expected {expected[fname]!r}, got {data!r}"

            for fh in handles.values():
                _close(sock, fh)
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyReadV
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyReadV:
    """kXR_readv — vectored reads with per-segment fhandle translation."""

    def test_readv_single_segment(self, proxy_env):
        """Single-segment readv works and returns correct data."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            s, b = _open(sock, "/alpha.txt", kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)

            (status, body), _ = _readv(sock, [(fh, 0, 16)])
            assert status == kXR_ok, f"readv failed: {status}"
            segs = _parse_readv_body(body, 1)
            assert len(segs) == 1
            assert segs[0][2] == b"AAAABBBBCCCCDDDD"

            _close(sock, fh)
        finally:
            sock.close()

    def test_readv_two_segments_same_handle(self, proxy_env):
        """Two non-overlapping segments on one handle return correct slices."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            s, b = _open(sock, "/data256.bin", kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)

            (status, body), _ = _readv(sock, [(fh, 0, 8), (fh, 256, 8)])
            assert status == kXR_ok
            segs = _parse_readv_body(body, 2)
            assert segs[0][2] == bytes(range(8))          # bytes 0-7
            assert segs[1][2] == bytes(range(256))[:8]    # bytes 256-263

            _close(sock, fh)
        finally:
            sock.close()

    def test_readv_two_different_handles(self, proxy_env):
        """Readv with two different handles in one request translates both."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            s, b1 = _open(sock, "/alpha.txt", kXR_open_read, sid=b"\x00\x01")
            assert s == kXR_ok
            fh1 = _fh(b1)

            s, b2 = _open(sock, "/beta.txt", kXR_open_read, sid=b"\x00\x02")
            assert s == kXR_ok
            fh2 = _fh(b2)

            (status, body), _ = _readv(sock, [(fh1, 0, 4), (fh2, 0, 4)])
            assert status == kXR_ok
            segs = _parse_readv_body(body, 2)
            assert segs[0][2] == b"AAAA"
            assert segs[1][2] == b"1111"

            _close(sock, fh1)
            _close(sock, fh2)
        finally:
            sock.close()

    def test_readv_many_segments(self, proxy_env):
        """Many segments on one file all arrive and have correct total data size."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            s, b = _open(sock, "/data256.bin", kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)

            segments = [(fh, i * 16, 16) for i in range(16)]  # 16 × 16-byte segments
            (status, body), total_expected = _readv(sock, segments)
            assert status == kXR_ok, f"readv many_segments failed: {status}"
            # Total data in response = 16 * 16 (headers) + 16 * 16 (data) = 512
            assert len(body) >= total_expected, \
                f"response body too short: {len(body)} < {total_expected}"

            _close(sock, fh)
        finally:
            sock.close()

    def test_readv_after_other_operations(self, proxy_env):
        """Readv works correctly after a regular read on the same handle."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            s, b = _open(sock, "/data256.bin", kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)

            # Regular read first
            s, data = _read(sock, fh, 0, 4)
            assert s == kXR_ok
            assert data == bytes(range(4))

            # Then readv
            (status, body), _ = _readv(sock, [(fh, 8, 4)])
            assert status == kXR_ok
            segs = _parse_readv_body(body, 1)
            assert segs[0][2] == bytes(range(8, 12))

            _close(sock, fh)
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyLocate
# ──────────────────────────────────────────────────────────────────────────────
