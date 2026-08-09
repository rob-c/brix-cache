from split_continuation import reexport as _reexport
_reexport(globals(), "_test_aio_helpers")

class TestAioDestroyedGuard:
    """Verify that the destroyed guard prevents stale AIO callbacks."""

    def test_disconnect_during_large_read(self):
        """Disconnecting during a large read must not cause a server crash.

        We open a file, start a large read (which should trigger AIO), then
        immediately close the connection.  The server must survive and continue
        serving other requests.
        """
        size = 10 * 1024 * 1024
        content = _pattern(size, 3, 7)
        _upload(ANON_URL, "aio-destroy.bin", content)

        # Open and start a large read on a raw socket (we control the lifecycle)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ANON_HOST, ANON_PORT))

        # Handshake (20 bytes: 5 x int32 BE)
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        _recv_exact(sock, 16)   # handshake response: 8B hdr + 8B body

        # kXR_protocol (24 bytes)
        proto_hdr = struct.pack(">BBHIBB10xI", 0, 1, 3006, 0x00000520, 0x02, 0x03, 0)
        sock.sendall(proto_hdr)
        status, _ = _read_response(sock)
        assert status == kXR_ok

        # kXR_login (24 bytes + payload) -- username must be exactly 8 bytes
        login_payload = b"anon\x00\x00\x00\x00"   # username padded to exactly 8 bytes
        login_hdr = struct.pack(">2sH", b"\x00\x01", 3007) \
              + struct.pack(">I", 0) \
              + login_payload \
              + struct.pack(">BBB", 0, 0, 5) \
              + struct.pack(">B", 0) \
              + struct.pack(">I", 0)
        sock.sendall(login_hdr)
        status, _ = _read_response(sock)
        assert status == kXR_ok

        # kXR_open for large file
        open_body = struct.pack(">H", OpenFlags.READ) + struct.pack(">HH", 0, 0) + b"\x00" * 6 + b"\x00" * 4
        path_payload = b"/aio-destroy.bin"
        status, fhandle = _send_req(sock, b"\x00\x01", kXR_open, body=open_body, payload=path_payload)
        assert status == kXR_ok

        # kXR_read -- large read that should trigger AIO
        # Body: fhandle(4) + offset(8, int64) + rlen(4, int32) = 16 bytes
        fh = fhandle[:4]
        read_body = fh + struct.pack(">qi", 0, size)
        status, data = _send_req(sock, b"\x00\x01", kXR_read, body=read_body)

        # Immediately close the socket -- the AIO callback should fire after
        # disconnect and detect ctx->destroyed = 1.
        sock.close()

        # Give the server time to process the stale callback
        time.sleep(0.5)

        # Verify the server is still alive by making a fresh request
        fresh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        fresh_sock.connect((ANON_HOST, ANON_PORT))

        # Handshake
        fresh_sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        _recv_exact(fresh_sock, 16)

        # kXR_protocol
        proto_hdr = struct.pack(">BBHIBB10xI", 0, 1, 3006, 0x00000520, 0x02, 0x03, 0)
        fresh_sock.sendall(proto_hdr)
        status, _ = _read_response(fresh_sock)
        assert status == kXR_ok

        # kXR_login
        login_payload = b"anon\x00\x00\x00\x00"
        login_hdr = struct.pack(">2sH", b"\x00\x02", 3007) \
              + struct.pack(">I", 0) \
              + login_payload \
              + struct.pack(">BBB", 0, 0, 5) \
              + struct.pack(">B", 0) \
              + struct.pack(">I", 0)
        fresh_sock.sendall(login_hdr)
        status, _ = _read_response(fresh_sock)
        assert status == kXR_ok

        # kXR_ping should still work
        ping_hdr = struct.pack(">2sH", b"\x00\x02", 3011) + b"\x00" * 16 + struct.pack(">I", 0)
        fresh_sock.sendall(ping_hdr)
        status, _ = _read_response(fresh_sock)
        assert status == kXR_ok

        fresh_sock.close()

    def test_disconnect_during_large_read_rst_midflight(self):
        """Hard RST (not an orderly FIN) mid-read: the AIO completion fires
        against an already-reset fd.  The destroyed guard must swallow the stale
        callback and the worker must keep serving.  This is the read-side analog
        of the write-mirror `close_then_immediate_disconnect` UAF driver."""
        size = 12 * 1024 * 1024
        _upload(ANON_URL, "aio-rst.bin", _pattern(size, 5, 11))
        _aio_open_read_then_drop(ANON_HOST, ANON_PORT, "/aio-rst.bin", size,
                                 rst=True)
        time.sleep(0.5)   # let the stale AIO completion land
        _aio_still_serves(ANON_HOST, ANON_PORT)

    def test_disconnect_read_churn_survives(self):
        """Alloc/free churn: many open->read->drop cycles (alternating RST and
        FIN) each allocate then tear down a per-read AIO context.  Under
        AddressSanitizer this catches any double-free / use-after-free / leak in
        the destroyed-guard teardown that a single cycle would miss; the final
        liveness probe proves the worker never fell over.  Mirrors the
        write-mirror `disconnect_churn_survives` driver."""
        size = 8 * 1024 * 1024
        _upload(ANON_URL, "aio-churn.bin", _pattern(size, 7, 3))
        for i in range(12):
            _aio_open_read_then_drop(ANON_HOST, ANON_PORT, "/aio-churn.bin",
                                     size, rst=bool(i % 2))
        _aio_still_serves(ANON_HOST, ANON_PORT)


# ---------------------------------------------------------------------------
# Wire helpers for raw socket tests
# ---------------------------------------------------------------------------
