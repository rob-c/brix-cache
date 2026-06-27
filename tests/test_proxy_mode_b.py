from _test_proxy_mode_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

class TestProxyLocate:
    """kXR_locate forwarding through the proxy."""

    def test_locate_existing_file(self, proxy_env):
        """Locate an existing file returns kXR_ok with location info."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _locate(sock, "/hello.txt")
            # The upstream may return ok or redirect; both are valid responses
            assert status in (kXR_ok, 4004), \
                f"unexpected locate status: {status}"
            assert len(body) > 0
        finally:
            sock.close()

    def test_locate_nonexistent_returns_error(self, proxy_env):
        """Locate a nonexistent file returns kXR_error."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, _ = _locate(sock, "/definitely_does_not_exist_abcde.txt")
            assert status == kXR_error
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyFsOps
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyFsOps:
    """Filesystem mutation operations forwarded through the proxy."""

    def test_mkdir_and_stat(self, proxy_env):
        """Create a directory through the proxy, then stat it."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            dname = f"/proxy_mkdir_{uuid.uuid4().hex[:8]}"
            status, _ = _mkdir(sock, dname)
            assert status == kXR_ok, f"mkdir failed: {status}"

            status, body = _stat(sock, dname)
            assert status == kXR_ok
            flags, _, _ = _parse_stat_body(body)
            assert flags & 0x10, "newly created directory should have kXR_isDir"
        finally:
            sock.close()

    def test_mkdir_nested_path(self, proxy_env):
        """mkdir with mkpath flag creates parent directories."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            dname = f"/proxy_nest_{uuid.uuid4().hex[:8]}/a/b"
            status, _ = _mkdir(sock, dname, mkpath=True)
            assert status == kXR_ok, f"mkdir nested failed: {status}"

            status, body = _stat(sock, dname)
            assert status == kXR_ok
        finally:
            sock.close()

    def test_rm_file(self, proxy_env):
        """Create a file, rm it, stat returns error."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            fname = f"/proxy_rm_{uuid.uuid4().hex[:8]}.txt"

            # Create
            s, b = _open(sock, fname, kXR_open_updt | kXR_new)
            assert s == kXR_ok
            _write(sock, _fh(b), 0, b"delete me")
            _close(sock, _fh(b))

            # Remove
            status, _ = _rm(sock, fname)
            assert status == kXR_ok, f"rm failed: {status}"

            # Stat should now fail
            status, _ = _stat(sock, fname)
            assert status == kXR_error
        finally:
            sock.close()

    def test_rmdir_empty_directory(self, proxy_env):
        """Create and remove an empty directory."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            dname = f"/proxy_rmdir_{uuid.uuid4().hex[:8]}"
            s, _ = _mkdir(sock, dname)
            assert s == kXR_ok

            s, _ = _rmdir(sock, dname)
            assert s == kXR_ok, f"rmdir failed: {s}"

            s, _ = _stat(sock, dname)
            assert s == kXR_error
        finally:
            sock.close()

    def test_mv_rename_file(self, proxy_env):
        """Rename a file through the proxy; old name disappears, new name works."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            src = f"/proxy_mv_src_{uuid.uuid4().hex[:8]}.txt"
            dst = f"/proxy_mv_dst_{uuid.uuid4().hex[:8]}.txt"

            s, b = _open(sock, src, kXR_open_updt | kXR_new)
            assert s == kXR_ok
            _write(sock, _fh(b), 0, b"rename me")
            _close(sock, _fh(b))

            s, _ = _mv(sock, src, dst)
            assert s == kXR_ok, f"mv failed: {s}"

            s, _ = _stat(sock, src)
            assert s == kXR_error, "source should no longer exist after mv"

            s, body = _stat(sock, dst)
            assert s == kXR_ok, "destination should exist after mv"
        finally:
            sock.close()

    def test_truncate_file_via_path(self, proxy_env):
        """Truncate a file to a smaller size through the proxy."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            fname = f"/proxy_trunc_{uuid.uuid4().hex[:8]}.bin"

            s, b = _open(sock, fname, kXR_open_updt | kXR_new)
            assert s == kXR_ok
            _write(sock, _fh(b), 0, b"A" * 1024)
            _close(sock, _fh(b))

            s, _ = _truncate_path(sock, fname, 16)
            assert s == kXR_ok, f"truncate failed: {s}"

            s, body = _stat(sock, fname)
            assert s == kXR_ok
            _, size, _ = _parse_stat_body(body)
            assert size == 16, f"expected size 16 after truncate, got {size}"
        finally:
            sock.close()

    def test_create_file_write_stat_rm(self, proxy_env):
        """Full lifecycle: create → write → stat → rm, all through the proxy."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            fname = f"/lifecycle_{uuid.uuid4().hex[:8]}.txt"
            content = b"lifecycle test payload 42\n"

            # create + write
            s, b = _open(sock, fname, kXR_open_updt | kXR_new)
            assert s == kXR_ok
            fh = _fh(b)
            s, _ = _write(sock, fh, 0, content)
            assert s == kXR_ok
            _sync(sock, fh)
            _close(sock, fh)

            # stat
            s, body = _stat(sock, fname)
            assert s == kXR_ok
            _, size, _ = _parse_stat_body(body)
            assert size == len(content)

            # rm
            s, _ = _rm(sock, fname)
            assert s == kXR_ok
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyErrorPropagation
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyErrorPropagation:
    """Backend errors must be relayed verbatim to the client."""

    def test_stat_missing_propagates_error(self, proxy_env):
        """kXR_error from backend on nonexistent stat reaches the client."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _stat(sock, "/this_file_does_not_exist_abc.txt")
            assert status == kXR_error
            assert len(body) >= 4   # error code present
        finally:
            sock.close()

    def test_open_missing_propagates_error(self, proxy_env):
        """kXR_error from backend on open(nonexistent) reaches the client."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/no_such.txt", kXR_open_read)
            assert status == kXR_error
            assert len(body) >= 4
        finally:
            sock.close()

    def test_error_does_not_break_connection(self, proxy_env):
        """After a backend error, the connection is still usable."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            # Trigger an error
            status, _ = _stat(sock, "/nonexistent_xyz.txt")
            assert status == kXR_error

            # Subsequent request on same connection must still work
            status, body = _stat(sock, "/hello.txt")
            assert status == kXR_ok, "connection broken after backend error"
            _, size, _ = _parse_stat_body(body)
            assert size == 22
        finally:
            sock.close()

    def test_multiple_errors_in_sequence(self, proxy_env):
        """Multiple sequential backend errors don't corrupt the connection."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            for i in range(5):
                sid = bytes([0, i + 1])
                p = f"/nonexistent_{i}.txt".encode()
                req = struct.pack(">2sHB11s4sI", sid, kXR_stat,
                                  0, b"\x00" * 11, b"\x00" * 4, len(p))
                sock.sendall(req + p)
                status, _ = _read_resp(sock)
                assert status == kXR_error, f"request {i}: expected error"

            # Connection must still be healthy
            status, _ = _ping(sock)
            assert status == kXR_ok
        finally:
            sock.close()

    def test_rm_nonexistent_error(self, proxy_env):
        """rm on a nonexistent file propagates kXR_error."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            status, _ = _rm(sock, "/ghost_file_xyz.txt")
            assert status == kXR_error
        finally:
            sock.close()

    def test_rmdir_nonempty_error(self, proxy_env):
        """rmdir on a non-empty directory propagates kXR_error."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            # /subdir has nested.txt in it
            status, _ = _rmdir(sock, "/subdir")
            assert status == kXR_error
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxySequential
# ──────────────────────────────────────────────────────────────────────────────

class TestProxySequential:
    """Many sequential requests on one connection — no state corruption."""

    def test_fifty_stats_in_sequence(self, proxy_env):
        """50 stat requests on one connection all succeed."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            for i in range(50):
                sid = bytes([i >> 8, i & 0xFF])
                p = b"/hello.txt"
                req = struct.pack(">2sHB11s4sI", sid, kXR_stat,
                                  0, b"\x00" * 11, b"\x00" * 4, len(p))
                sock.sendall(req + p)
                status, body = _read_resp(sock)
                assert status == kXR_ok, f"stat #{i} failed: {status}"
        finally:
            sock.close()

    def test_alternating_stat_and_ping(self, proxy_env):
        """Alternating stat (proxy'd) and ping (local) stay in sync."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            for i in range(20):
                # stat — goes to upstream
                s, body = _stat(sock, "/hello.txt")
                assert s == kXR_ok, f"stat #{i} failed"
                # ping — handled locally by proxy's session layer
                s, _ = _ping(sock)
                assert s == kXR_ok, f"ping #{i} failed"
        finally:
            sock.close()

    def test_open_read_close_cycle_repeated(self, proxy_env):
        """Open/read/close cycle repeated 20 times on same connection."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            for i in range(20):
                s, b = _open(sock, "/alpha.txt", kXR_open_read)
                assert s == kXR_ok, f"open #{i} failed"
                fh = _fh(b)
                s, data = _read(sock, fh, 0, 4)
                assert s == kXR_ok
                assert data == b"AAAA"
                _close(sock, fh)
        finally:
            sock.close()

    def test_write_read_delete_cycle_repeated(self, proxy_env):
        """Write/read/delete cycle 10 times — file content consistent each time."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            for i in range(10):
                fname = f"/seq_{i}_{uuid.uuid4().hex[:6]}.txt"
                content = f"iteration {i:03d}".encode()

                s, b = _open(sock, fname, kXR_open_updt | kXR_new)
                assert s == kXR_ok
                fh = _fh(b)
                _write(sock, fh, 0, content)
                _close(sock, fh)

                s, b = _open(sock, fname, kXR_open_read)
                assert s == kXR_ok
                fh = _fh(b)
                s, data = _read(sock, fh, 0, len(content) + 4)
                assert s == kXR_ok
                assert data == content, f"iter {i}: got {data!r}"
                _close(sock, fh)

                _rm(sock, fname)
        finally:
            sock.close()

    def test_mixed_opcodes_sequence(self, proxy_env):
        """A realistic mixed workload: stat, open, read, close, dirlist, mkdir, rm."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        try:
            s, _ = _stat(sock, "/hello.txt")
            assert s == kXR_ok

            s, b = _open(sock, "/alpha.txt", kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)
            s, d = _read(sock, fh, 0, 4)
            assert s == kXR_ok and d == b"AAAA"
            _close(sock, fh)

            s, _ = _dirlist(sock, "/")
            assert s == kXR_ok

            dname = f"/mixed_seq_{uuid.uuid4().hex[:6]}"
            s, _ = _mkdir(sock, dname)
            assert s == kXR_ok
            s, _ = _rmdir(sock, dname)
            assert s == kXR_ok

            s, _ = _ping(sock)
            assert s == kXR_ok
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyLargeRead
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyLargeRead:
    """Verify the proxy relays large data transfers correctly."""

    def test_read_512kb_file_in_one_request(self, proxy_env):
        """Read entire 512 KiB file in one request; content must match exactly."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        sock.settimeout(30)
        try:
            s, b = _open(sock, "/large.bin", kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)

            s, data = _read(sock, fh, 0, 512 * 1024)
            assert s == kXR_ok
            assert len(data) == 512 * 1024
            expected = bytes(i & 0xFF for i in range(512 * 1024))
            assert data == expected, "large read data mismatch"

            _close(sock, fh)
        finally:
            sock.close()

    def test_read_512kb_file_in_chunks(self, proxy_env):
        """Read a 512 KiB file in 64 KiB chunks; each chunk has expected content."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        sock.settimeout(30)
        try:
            s, b = _open(sock, "/large.bin", kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)

            chunk_size = 64 * 1024
            expected = bytes(i & 0xFF for i in range(512 * 1024))
            for offset in range(0, 512 * 1024, chunk_size):
                s, data = _read(sock, fh, offset, chunk_size)
                assert s == kXR_ok
                assert data == expected[offset:offset + chunk_size], \
                    f"chunk at offset {offset} mismatch"

            _close(sock, fh)
        finally:
            sock.close()

    def test_write_and_read_256kb(self, proxy_env):
        """Write 256 KiB through proxy, then read it back; content must match."""
        sock = _connect(HOST, proxy_env["proxy_port"])
        sock.settimeout(30)
        try:
            fname = f"/large_write_{uuid.uuid4().hex[:8]}.bin"
            payload = bytes(i & 0xFF for i in range(256 * 1024))

            s, b = _open(sock, fname, kXR_open_updt | kXR_new)
            assert s == kXR_ok
            fh = _fh(b)

            # Write in 64 KiB chunks
            chunk_size = 64 * 1024
            for offset in range(0, len(payload), chunk_size):
                s, _ = _write(sock, fh, offset, payload[offset:offset + chunk_size])
                assert s == kXR_ok
            _sync(sock, fh)
            _close(sock, fh)

            # Read back full file
            s, b = _open(sock, fname, kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)
            s, data = _read(sock, fh, 0, len(payload))
            assert s == kXR_ok
            assert data == payload
            _close(sock, fh)
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyMultiClient
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyMultiClient:
    """Multiple clients sharing the same proxy concurrently."""

    def test_two_clients_independent_file_access(self, proxy_env):
        """Two simultaneous clients read different files; each sees its own data."""
        sock1 = _connect(HOST, proxy_env["proxy_port"])
        sock2 = _connect(HOST, proxy_env["proxy_port"])
        try:
            s, b1 = _open(sock1, "/alpha.txt", kXR_open_read)
            assert s == kXR_ok
            fh1 = _fh(b1)

            s, b2 = _open(sock2, "/beta.txt", kXR_open_read)
            assert s == kXR_ok
            fh2 = _fh(b2)

            s, d1 = _read(sock1, fh1, 0, 16)
            assert s == kXR_ok
            assert d1 == b"AAAABBBBCCCCDDDD"

            s, d2 = _read(sock2, fh2, 0, 16)
            assert s == kXR_ok
            assert d2 == b"1111222233334444"

            _close(sock1, fh1)
            _close(sock2, fh2)
        finally:
            sock1.close()
            sock2.close()

    def test_four_clients_stat_same_file(self, proxy_env):
        """Four clients stat the same file; all get the same result."""
        socks = [_connect(HOST, proxy_env["proxy_port"]) for _ in range(4)]
        try:
            for i, sock in enumerate(socks):
                s, body = _stat(sock, "/data256.bin")
                assert s == kXR_ok, f"client {i}: stat failed"
                _, size, _ = _parse_stat_body(body)
                assert size == 1024, f"client {i}: wrong size {size}"
        finally:
            for sock in socks:
                sock.close()

    def test_clients_write_to_separate_files_no_interference(self, proxy_env):
        """Multiple clients write different files; content is not interleaved."""
        socks = [_connect(HOST, proxy_env["proxy_port"]) for _ in range(3)]
        fnames = [f"/mc_write_{uuid.uuid4().hex[:6]}.txt" for _ in range(3)]
        payloads = [f"client {i} content".encode() for i in range(3)]
        try:
            handles = []
            for sock, fname, payload in zip(socks, fnames, payloads):
                s, b = _open(sock, fname, kXR_open_updt | kXR_new)
                assert s == kXR_ok
                handles.append(_fh(b))

            for sock, fh, payload in zip(socks, handles, payloads):
                s, _ = _write(sock, fh, 0, payload)
                assert s == kXR_ok
                _sync(sock, fh)
                _close(sock, fh)

            # Verify each file has the right content using a fresh connection
            verify_sock = _connect(HOST, proxy_env["proxy_port"])
            try:
                for fname, payload in zip(fnames, payloads):
                    s, b = _open(verify_sock, fname, kXR_open_read)
                    assert s == kXR_ok
                    fh = _fh(b)
                    s, data = _read(verify_sock, fh, 0, len(payload) + 4)
                    assert s == kXR_ok
                    assert data == payload, f"{fname}: got {data!r}"
                    _close(verify_sock, fh)
            finally:
                verify_sock.close()
        finally:
            for sock in socks:
                sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyBackendUnavailable
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyBackendUnavailable:
    """Graceful error handling when the upstream is unreachable.

    Uses the pre-launched proxy-dead nginx at PROXY_DEAD_NGINX_PORT which
    points at PROXY_DEAD_UPSTREAM_PORT (nothing listening there).
    """

    def test_fs_op_returns_error_when_backend_down(self):
        """First post-login FS opcode returns kXR_error if backend refuses connection."""
        if not os.path.exists(NGINX_BIN):
            pytest.skip(f"nginx binary not found: {NGINX_BIN}")

        sock = _connect(HOST, PROXY_DEAD_NGINX_PORT)
        try:
            # Ping (session opcode) must succeed — it's handled before upstream connect
            status, _ = _ping(sock)
            assert status == kXR_ok, "ping should work even with dead backend"

            # First FS opcode should fail gracefully (not crash or hang)
            sock.settimeout(5)
            status, body = _stat(sock, "/any_file.txt")
            assert status == kXR_error, \
                f"expected kXR_error with dead backend, got {status}"
            assert len(body) >= 4
        finally:
            sock.close()

    def test_session_still_clean_after_backend_failure(self):
        """After a backend failure, the client gets a clean error (no hang/crash)."""
        if not os.path.exists(NGINX_BIN):
            pytest.skip(f"nginx binary not found: {NGINX_BIN}")

        for _ in range(3):
            sock = _connect(HOST, PROXY_DEAD_NGINX_PORT)
            try:
                sock.settimeout(5)
                status, _ = _stat(sock, "/any_file.txt")
                assert status == kXR_error
            finally:
                sock.close()
