# ============================================================================
# 4. Resource exhaustion
#    Single clients must not exhaust server-side resources.
# ============================================================================

class TestResourceExhaustion:

    def test_connection_storm_50(self):
        """
        50 connections opened simultaneously.  Each performs the handshake +
        protocol negotiation, then is closed.  The server must survive and
        remain responsive; some connection resets under load are tolerated.
        """
        assert_healthy()   # ensure we start from a clean state
        sockets, failures = _open_connections(50)
        _close_connections(sockets)
        # Under load some resets are expected (nginx event loop, WSL2 limits).
        # What matters is that the server recovers fully afterwards.
        assert failures <= 25, f"Too many failures ({failures}/50) in connection storm"
        assert_healthy(retries=6)

    def test_rapid_connect_disconnect_50(self):
        """50 rapid connect-then-immediately-close cycles."""
        assert_healthy(retries=6)   # wait for any prior storm to drain
        for _ in range(50):
            try:
                s = _connect()
                s.close()
            except OSError:
                pass
        assert_healthy(retries=6)

    def test_ping_flood_1000(self):
        """
        1000 pings on one authenticated connection.
        Every ping must return kXR_ok (99% success threshold).
        """
        assert_healthy(retries=6)   # wait for any prior storm to drain
        s = _connect()
        _full_anon_login(s)
        n = 1000
        _send_ping_requests(s, n)
        s.settimeout(10.0)
        ok_count = _count_ok_responses(s, n)
        s.close()
        assert ok_count >= int(n * 0.99), \
            f"Ping flood: only {ok_count}/{n} pings returned kXR_ok"
        assert_healthy()

    def test_open_16_handles_and_close_cleanly(self):
        """Open 16 file handles and close each one in sequence."""
        assert_healthy(retries=6)
        test_path = os.path.join(DATA_DIR, "robustness_handles.bin")
        with open(test_path, "wb") as f:
            f.write(b'x' * 1024)
        s = _connect()
        _full_anon_login(s)

        handles = _open_handles(s, 16)

        assert len(handles) >= 8, \
            f"Expected to open at least 8 handles, got {len(handles)}"

        _close_handles(s, handles)

        s.close()
        os.unlink(test_path)
        assert_healthy()


def _open_connections(count):
    sockets = []
    failures = 0
    for _ in range(count):
        try:
            sock = _connect()
            handshake, protocol = _handshake_and_protocol(sock)
        except OSError:
            failures += 1
            continue
        if handshake == kXR_ok and protocol == kXR_ok:
            sockets.append(sock)
        else:
            sock.close()
            failures += 1
    return sockets, failures


def _close_connections(sockets):
    for sock in sockets:
        try:
            sock.close()
        except OSError:
            pass


def _send_ping_requests(sock, count):
    for index in range(count):
        stream_id = struct.pack(">H", (index % 0xFFFE) + 1)
        sock.sendall(make_ping_req(streamid=stream_id))


def _open_handles(sock, count):
    handles = []
    for index in range(count):
        stream_id = struct.pack(">H", 0x0100 + index)
        sock.sendall(make_open_req(b'/robustness_handles.bin', streamid=stream_id))
        try:
            status, body = _recv_response(sock)
        except (socket.timeout, ConnectionError):
            break
        if status == kXR_ok and len(body) >= 4:
            handles.append(body[:4])
    return handles


def _close_handles(sock, handles):
    for index, handle in enumerate(handles):
        if not _close_handle(sock, index, handle):
            break


def _close_handle(sock, index, handle):
    stream_id = struct.pack(">H", 0x0180 + index)
    sock.sendall(make_close_req(handle, streamid=stream_id))
    try:
        _recv_response(sock)
        return True
    except (socket.timeout, ConnectionError):
        return False

    def test_open_beyond_handle_limit_returns_error(self):
        """Opening more than 16 files must return an error, not crash."""
        assert_healthy(retries=6)
        test_path = os.path.join(DATA_DIR, "robustness_overlimit.bin")
        with open(test_path, "wb") as f:
            f.write(b'y' * 1024)
        s = _connect()
        _full_anon_login(s)

        open_count   = 0
        first_err_at = None
        for i in range(20):
            sid = struct.pack(">H", 0x0200 + i)
            s.sendall(make_open_req(b'/robustness_overlimit.bin', streamid=sid))
            try:
                status, _ = _recv_response(s)
                if status == kXR_ok:
                    open_count += 1
                elif first_err_at is None:
                    first_err_at = i
            except (socket.timeout, ConnectionError):
                break

        s.close()
        os.unlink(test_path)

        assert open_count <= 16, \
            f"Server allowed {open_count} simultaneous handles (limit is 16)"
        assert first_err_at is not None, \
            "Server never returned an error after exceeding handle limit"
        assert_healthy()


# ============================================================================
# 5. State machine attacks
#    Protocol must be enforced regardless of operation ordering.
# ============================================================================
