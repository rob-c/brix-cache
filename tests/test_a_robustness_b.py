from _test_a_robustness_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

class TestStateMachineAttacks:

    def test_read_from_closed_handle(self):
        """
        Open a file, read from it, close it, then re-read with the same handle.
        The second read must fail.
        """
        test_path = os.path.join(DATA_DIR, "robustness_reuse.bin")
        with open(test_path, "wb") as f:
            f.write(b"REUSE TEST DATA " * 64)   # 1024 bytes

        s = _connect()
        _full_anon_login(s)

        # Open
        s.sendall(make_open_req(b'/robustness_reuse.bin', streamid=b'\x00\x70'))
        open_st, open_body = _recv_response(s)
        assert open_st == kXR_ok, "Could not open test file"
        handle = open_body[:4]

        # Read once — must succeed
        s.sendall(make_read_req(handle, 0, 256, streamid=b'\x00\x71'))
        read_st, _ = _recv_response(s)
        assert read_st == kXR_ok, f"First read failed with {read_st}"

        # Close
        s.sendall(make_close_req(handle, streamid=b'\x00\x72'))
        _recv_response(s)

        # Read again with the same handle — must fail
        s.sendall(make_read_req(handle, 0, 256, streamid=b'\x00\x73'))
        try:
            stale_st, _ = _recv_response(s)
        except (socket.timeout, ConnectionError):
            stale_st = kXR_error

        s.close()
        os.unlink(test_path)

        assert stale_st != kXR_ok, \
            f"Read from closed handle returned kXR_ok — use-after-close!"
        assert_healthy()

    def test_endsess_closes_open_file_handles(self):
        """
        After kXR_endsess, any file handles that were open must be invalidated.
        The XRootD spec says kXR_endsess releases all session resources; a read
        using a handle opened before endsess must therefore fail.

        Note: the protocol does not require the server to invalidate the TCP
        session itself — the client is expected to close the connection.  So
        path-based ops (stat, dirlist) may still work on the same socket; that
        is implementation-defined behaviour, not a bug.
        """
        test_path = os.path.join(DATA_DIR, "robustness_endsess.bin")
        with open(test_path, "wb") as f:
            f.write(b'ENDSESS DATA ' * 80)

        s = _connect()
        _, _, login_st, login_body = _full_anon_login_body(s)
        assert login_st == kXR_ok, "Could not log in before endsess test"
        sessid = login_body[:16]
        assert len(sessid) == 16, "Login did not return a session id"

        # Open a file — must succeed
        s.sendall(make_open_req(b'/robustness_endsess.bin', streamid=b'\x00\x60'))
        open_st, open_body = _recv_response(s)
        assert open_st == kXR_ok, "Could not open test file"
        handle = open_body[:4]

        # Verify it is readable
        s.sendall(make_read_req(handle, 0, 64, streamid=b'\x00\x61'))
        read_st, _ = _recv_response(s)
        assert read_st == kXR_ok, "Pre-endsess read must succeed"

        # End session
        s.sendall(make_request(b'\x00\x62', 3023, body=sessid))  # kXR_endsess
        try:
            _recv_response(s)
        except (socket.timeout, ConnectionError):
            pass

        # Read with the same handle — must fail (handle was released by endsess)
        s.sendall(make_read_req(handle, 0, 64, streamid=b'\x00\x63'))
        try:
            s.settimeout(2.0)
            post_st, _ = _recv_response(s)
        except (socket.timeout, ConnectionError, OSError):
            post_st = kXR_error  # connection closed is also correct

        s.close()
        os.unlink(test_path)

        assert post_st != kXR_ok, \
            "Read using handle from before kXR_endsess must fail after endsess"
        assert_healthy()

    def test_auth_after_anonymous_login(self):
        """Send kXR_auth after a successful anonymous login — must not crash."""
        s = _connect()
        _full_anon_login(s)
        s.sendall(make_request(b'\x00\x80', kXR_auth, payload=b'garbage'))
        try:
            _recv_response(s)
        except (socket.timeout, ConnectionError):
            pass
        s.close()
        assert_healthy()

    def test_read_without_prior_open(self):
        """kXR_read with an invented handle (no prior open) must return an error."""
        s = _connect()
        _full_anon_login(s)
        s.sendall(make_read_req(b'\xDE\xAD\xBE\xEF', 0, 4096,
                                streamid=b'\x00\x90'))
        try:
            status, body = _recv_response(s)
        except (socket.timeout, ConnectionError):
            status = kXR_error
            body = b''
        s.close()
        assert status == kXR_error, \
            f"Read with invented handle must fail, got {status}"
        assert_healthy()


# ============================================================================
# 6. Path traversal
#    Every escape attempt must be rejected cleanly.
# ============================================================================

class TestPathTraversal:

    TRAVERSAL_PATHS = [
        b"/../etc/passwd",
        b"/../../etc/shadow",
        b"/../../../root/.ssh/authorized_keys",
        b"/..",
        b"/../",
        b"/a/b/../../../../../../etc/passwd",
        b"/a/./b/./../../../../../../etc/passwd",
    ]

    def test_all_traversal_paths_rejected(self):
        """
        Every path-traversal attempt must return kXR_error, never kXR_ok.
        If the server closes the connection mid-test, we reconnect.
        """
        s = _connect()
        _full_anon_login(s)

        for path in self.TRAVERSAL_PATHS:
            req = make_request(b'\x00\xA0', kXR_stat,
                               body=b'\x00' * 16,
                               payload=path + b'\x00')
            s.sendall(req)
            try:
                status, body = _recv_response(s)
                assert status != kXR_ok, \
                    f"Traversal '{path!r}' returned kXR_ok — path escape!"
                # Extra check: body must not contain /etc content
                if body:
                    assert b'root:' not in body and b'/bin/bash' not in body, \
                        f"Traversal '{path!r}' returned /etc content!"
            except (socket.timeout, ConnectionError):
                # Connection dropped — server rejected it hard. Reconnect.
                s = _connect()
                _full_anon_login(s)

        s.close()
        assert_healthy()


# ============================================================================
# 7. Concurrency safety
#    Multiple threads must not corrupt each other's responses.
# ============================================================================

class TestConcurrencySafety:

    def _ping_worker(self, n: int, results: list, idx: int):
        ok = 0
        err = None
        try:
            s = _connect()
            _full_anon_login(s)
            for i in range(n):
                sid = struct.pack(">H", (idx * n + i) % 0xFFFE + 1)
                s.sendall(make_ping_req(streamid=sid))
                status, _ = _recv_response(s)
                if status == kXR_ok:
                    ok += 1
            s.close()
        except Exception as e:
            err = str(e)
        results.append((idx, ok, err))

    def test_16_concurrent_ping_sessions(self):
        """16 threads each send 50 pings on independent connections."""
        results = []
        threads = [
            threading.Thread(target=self._ping_worker, args=(50, results, i))
            for i in range(16)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        errors    = [r for r in results if r[2] is not None]
        total_ok  = sum(r[1] for r in results)

        assert errors == [], f"Thread errors: {errors}"
        assert total_ok == 16 * 50, \
            f"Expected {16*50} pings ok, got {total_ok}"
        assert_healthy()

    def test_concurrent_stat_and_ping(self):
        """
        8 ping threads + 8 stat threads simultaneously.
        No cross-connection response corruption should occur.
        """
        test_path = os.path.join(DATA_DIR, "robustness_concurrent.bin")
        with open(test_path, "wb") as f:
            f.write(b'z' * 512)

        errors = []

        def ping_worker():
            try:
                s = _connect()
                _full_anon_login(s)
                for i in range(20):
                    sid = struct.pack(">H", i + 1)
                    s.sendall(make_ping_req(streamid=sid))
                    st, _ = _recv_response(s)
                    assert st == kXR_ok
                s.close()
            except Exception as e:
                errors.append(f"ping: {e}")

        def stat_worker():
            try:
                s = _connect()
                _full_anon_login(s)
                for i in range(20):
                    sid = struct.pack(">H", i + 1)
                    s.sendall(make_stat_req(b'/robustness_concurrent.bin',
                                           streamid=sid))
                    st, _ = _recv_response(s)
                    assert st == kXR_ok, f"stat returned {st}"
                s.close()
            except Exception as e:
                errors.append(f"stat: {e}")

        threads = (
            [threading.Thread(target=ping_worker) for _ in range(8)]
            + [threading.Thread(target=stat_worker) for _ in range(8)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        os.unlink(test_path)
        assert errors == [], f"Concurrent errors: {errors}"
        assert_healthy()
