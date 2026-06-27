from _test_io_edge_cases_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

class TestWriteEdgeCases:

    def test_write_at_offset_0(self):
        _make_file("/write_off0.txt", b"\x00" * 10)
        sock = _session()
        status, body = _open(sock,"/write_off0.txt", kXR_open_updt)
        assert status == kXR_ok
        fh = body[:4]
        status, _ = _write(sock, fh, 0, b"HELLO")
        _close(sock, fh)
        sock.close()
        assert status == kXR_ok
        assert _read_file("/write_off0.txt")[:5] == b"HELLO"

    def test_write_at_nonzero_offset(self):
        _make_file("/write_mid.txt", b"AAAAABBBBB")
        sock = _session()
        status, body = _open(sock,"/write_mid.txt", kXR_open_updt)
        assert status == kXR_ok
        fh = body[:4]
        status, _ = _write(sock, fh, 5, b"XXXXX")
        _close(sock, fh)
        sock.close()
        assert status == kXR_ok
        assert _read_file("/write_mid.txt") == b"AAAAAXXXXXB" or \
               _read_file("/write_mid.txt") == b"AAAAAXXXXX"

    def test_write_zero_bytes(self):
        _make_file("/write_zero.txt", b"original")
        sock = _session()
        status, body = _open(sock,"/write_zero.txt", kXR_open_updt)
        assert status == kXR_ok
        fh = body[:4]
        status, _ = _write(sock, fh, 0, b"")
        _close(sock, fh)
        sock.close()
        assert status in (kXR_ok, kXR_error)
        # File unchanged if write was accepted
        if status == kXR_ok:
            assert _read_file("/write_zero.txt") == b"original"

    def test_write_to_invalid_handle(self):
        sock = _session()
        # Write to handle 0xFF000000 (never opened)
        req = struct.pack("!2sH4sqiI", b"\x00\x03", kXR_write,
                          b"\xff\x00\x00\x00", 0, 5, 5)
        sock.sendall(req + b"HELLO")
        status, body = _read_response(sock)
        sock.close()
        assert status == kXR_error

    def test_write_to_readonly_handle(self):
        _make_file("/write_ro_handle.txt", b"protected")
        sock = _session()
        status, body = _open(sock,"/write_ro_handle.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        status, body2 = _write(sock, fh, 0, b"XXXXX")
        _close(sock, fh)
        sock.close()
        assert status == kXR_error

    def test_write_1kib_single_chunk(self):
        payload = b"W" * 1024
        path = "/write_1k.txt"
        _make_file(path, b"\x00" * 1024)
        sock = _session()
        status, body = _open(sock,path, kXR_open_updt)
        assert status == kXR_ok
        fh = body[:4]
        status, _ = _write(sock, fh, 0, payload)
        _close(sock, fh)
        sock.close()
        assert status == kXR_ok
        assert _read_file(path) == payload

    def test_write_beyond_eof_creates_hole(self):
        path = "/write_sparse.txt"
        _make_file(path, b"start")
        sock = _session()
        status, body = _open(sock,path, kXR_open_updt)
        assert status == kXR_ok
        fh = body[:4]
        # Write at large offset — OS creates sparse hole
        status, _ = _write(sock, fh, 100000, b"end")
        _close(sock, fh)
        sock.close()
        assert status == kXR_ok

    def test_write_offset_overflow(self):
        path = "/write_ovf.txt"
        _make_file(path, b"x")
        sock = _session()
        status, body = _open(sock,path, kXR_open_updt)
        assert status == kXR_ok
        fh = body[:4]
        # offset = 0x7FFFFFFFFFFFFFFF (max positive int64)
        req = struct.pack("!2sH4sqiI", b"\x00\x03", kXR_write,
                          fh, 0x7FFFFFFFFFFFFFFF, 3, 3)
        sock.sendall(req + b"AAA")
        status, body2 = _read_response(sock)
        sock.close()
        assert status in (kXR_ok, kXR_error)


# =========================================================================
# Class 5 — Writev Edge Cases
# =========================================================================

class TestWritevEdgeCases:

    def _writev(self, sock, segments, streamid=b"\x00\x07"):
        """Send kXR_writev with [(fhandle, offset, data)] segments.
        write_list struct: fhandle[4], wlen(int32), offset(int64)
        """
        seg_hdrs = b""
        seg_data = b""
        for fh, offset, data in segments:
            seg_hdrs += struct.pack("!4siq", fh, len(data), offset)
            seg_data += data
        payload = seg_hdrs + seg_data
        req = struct.pack("!2sH16sI", streamid, kXR_writev, b"\x00"*16, len(payload))
        sock.sendall(req + payload)
        return _read_response(sock)

    def test_writev_single_segment(self):
        path = "/writev_single.txt"
        _make_file(path, b"\x00" * 10)
        sock = _session()
        status, body = _open(sock,path, kXR_open_updt)
        assert status == kXR_ok
        fh = body[:4]
        status, _ = self._writev(sock, [(fh, 0, b"HELLO")])
        _close(sock, fh)
        sock.close()
        assert status == kXR_ok

    def test_writev_zero_segments(self):
        sock = _session()
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_writev, b"\x00"*16, 0)
        sock.sendall(req)
        status, body = _read_response(sock)
        sock.close()
        assert status == kXR_error

    def test_writev_two_non_overlapping(self):
        path = "/writev_two.txt"
        _make_file(path, b"\x00" * 20)
        sock = _session()
        status, body = _open(sock,path, kXR_open_updt)
        assert status == kXR_ok
        fh = body[:4]
        status, _ = self._writev(sock, [
            (fh, 0, b"FIRST"),
            (fh, 10, b"SECND"),
        ])
        _close(sock, fh)
        sock.close()
        assert status == kXR_ok

    def test_writev_do_sync_flag(self):
        # kXR_wv_doSync flag — bit 0x08 in the writev body flags
        path = "/writev_dosync.txt"
        _make_file(path, b"\x00" * 10)
        sock = _session()
        status, body = _open(sock,path, kXR_open_updt)
        assert status == kXR_ok
        fh = body[:4]
        # Set sync flag in body (byte 4 of fixed body = reqflags)
        seg_hdr = struct.pack("!4siq", fh, 5, 0)
        seg_data = b"SYNCD"
        payload = seg_hdr + seg_data
        # Build writev with sync flag: byte 4 of body = 0x08
        body16 = b"\x00\x00\x00\x00\x08" + b"\x00" * 11
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_writev, body16, len(payload))
        sock.sendall(req + payload)
        status, _ = _read_response(sock)
        sock.close()
        assert status == kXR_ok

    def test_writev_invalid_handle(self):
        sock = _session()
        fh = b"\xff\x00\x00\x00"
        status, body = self._writev(sock, [(fh, 0, b"FAIL")])
        sock.close()
        assert status == kXR_error

    def test_writev_readonly_handle(self):
        _make_file("/writev_ro.txt", b"x" * 10)
        sock = _session()
        status, body = _open(sock,"/writev_ro.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        status, body2 = self._writev(sock, [(fh, 0, b"WRITE")])
        _close(sock, fh)
        sock.close()
        assert status == kXR_error

    def test_writev_zero_length_segment(self):
        path = "/writev_zero_seg.txt"
        _make_file(path, b"\x00" * 10)
        sock = _session()
        status, body = _open(sock,path, kXR_open_updt)
        assert status == kXR_ok
        fh = body[:4]
        # Segment with wlen=0 — C code skips it with continue
        status, _ = self._writev(sock, [(fh, 0, b"")])
        _close(sock, fh)
        sock.close()
        # Either ok (skipped empty seg) or error (no valid segments)
        assert status in (kXR_ok, kXR_error)


# =========================================================================
# Class 6 — kXR_sync Full Coverage
# =========================================================================

class TestSyncFull:
    """kXR_sync (3016) — currently has zero wire-level tests in existing suite."""

    def test_sync_write_handle_ok(self):
        path = "/sync_write.txt"
        _make_file(path, b"\x00" * 10)
        sock = _session()
        status, body = _open(sock,path, kXR_open_updt)
        assert status == kXR_ok
        fh = body[:4]
        _write(sock, fh, 0, b"SYNCED")
        status, _ = _sync(sock, fh)
        _close(sock, fh)
        sock.close()
        assert status == kXR_ok

    def test_sync_data_durable(self):
        path = "/sync_durable.txt"
        _make_file(path, b"\x00" * 5)
        sock = _session()
        status, body = _open(sock,path, kXR_open_updt)
        assert status == kXR_ok
        fh = body[:4]
        _write(sock, fh, 0, b"DURABLE")
        status, _ = _sync(sock, fh)
        assert status == kXR_ok
        _close(sock, fh)
        sock.close()
        # Verify written data is on disk
        assert _read_file(path)[:7] == b"DURABLE"

    def test_sync_invalid_handle(self):
        sock = _session()
        req = struct.pack("!2sH4s12sI",
                          b"\x00\x01", kXR_sync, b"\xff\x00\x00\x00", b"\x00"*12, 0)
        sock.sendall(req)
        status, body = _read_response(sock)
        sock.close()
        assert status == kXR_error
        assert _error_code(body) == kXR_FileNotOpen

    def test_sync_readonly_handle_ok(self):
        # fsync() on a read-only fd succeeds on Linux (no EINVAL for regular files)
        _make_file("/sync_ro.txt", b"read only")
        sock = _session()
        status, body = _open(sock, "/sync_ro.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        status, body2 = _sync(sock, fh)
        _close(sock, fh)
        sock.close()
        assert status == kXR_ok

    def test_sync_double_same_handle(self):
        path = "/sync_double.txt"
        _make_file(path, b"\x00" * 5)
        sock = _session()
        status, body = _open(sock,path, kXR_open_updt)
        assert status == kXR_ok
        fh = body[:4]
        _write(sock, fh, 0, b"DATA")
        s1, _ = _sync(sock, fh, streamid=b"\x00\x10")
        s2, _ = _sync(sock, fh, streamid=b"\x00\x11")
        _close(sock, fh)
        sock.close()
        assert s1 == kXR_ok
        assert s2 == kXR_ok
