from split_continuation import reexport as _reexport
_reexport(globals(), "_test_new_opcodes_helpers")

class TestChkpointXeq:
    """
    Exercises ckpXeq sub-operations that were previously untested:
    pgwrite (with and without CRC corruption), truncate, writev, and
    an unknown sub-opcode that must be rejected.
    """

    # ── re-use helpers from TestChkpoint ─────────────────────────────────

    @staticmethod
    def _recvall(sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            assert chunk, "connection closed unexpectedly"
            buf += chunk
        return buf

    def _recv_response(self, sock):
        hdr    = self._recvall(sock, 8)
        status = struct.unpack(">H", hdr[2:4])[0]
        dlen   = struct.unpack(">I", hdr[4:8])[0]
        body   = self._recvall(sock, dlen) if dlen else b""
        return status, body

    def _connect(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
        hdr = self._recvall(sock, 8)
        self._recvall(sock, struct.unpack("!I", hdr[4:8])[0])
        sock.sendall(struct.pack("!2sHI8sBBBBI",
                                 b"\x00\x01", 3007, 0,
                                 b"test\x00\x00\x00\x00",
                                 0, 0, 5, 0, 0))
        self._recv_response(sock)
        return sock

    def _open(self, sock, sid, path, options=0x0020):
        path_b = path.encode()
        req = struct.pack("!2sHHH2s6s4sI",
                          bytes([0, sid]), 3010,
                          0o644, options,
                          b"\x00\x00", b"\x00"*6, b"\x00"*4,
                          len(path_b))
        sock.sendall(req + path_b)
        status, body = self._recv_response(sock)
        assert status == 0, f"open({path!r}) failed: {status}"
        return body[:4]

    def _read(self, sock, sid, fh, offset, rlen):
        req = struct.pack("!2sH4sqiI",
                          bytes([0, sid]), 3013, fh, offset, rlen, 0)
        sock.sendall(req)
        status, body = self._recv_response(sock)
        assert status == 0, f"read failed: {status}"
        return body

    def _close(self, sock, sid, fh):
        req = struct.pack("!2sH4s12sI",
                          bytes([0, sid]), 3003, fh, b"\x00"*12, 0)
        sock.sendall(req)
        self._recv_response(sock)

    def _chkpoint(self, sock, sid, fh, opcode, extra=b""):
        req = struct.pack("!2sH4s11sBI",
                          bytes([0, sid]), 3012, fh, b"\x00"*11, opcode, len(extra))
        sock.sendall(req + extra)
        return self._recv_response(sock)

    def _ckpxeq(self, sock, sid, fh, sub_hdr, sub_body=b""):
        """Send a stock-framed kXR_ckpXeq: the chkpoint dlen covers only the
        embedded 24-byte sub-header (which carries the outer streamid); the
        sub-request body streams after the frame (see chkpoint_xeq.c and
        test_chkpoint_stock_framing.py)."""
        req = struct.pack("!2sH4s11sBI",
                          bytes([0, sid]), 3012, fh, b"\x00"*11, 4,
                          len(sub_hdr))
        sock.sendall(req + sub_hdr + sub_body)
        return self._recv_response(sock)

    def _ckpxeq_pgwrite(self, sock, sid, fh, offset, data, corrupt_page=-1):
        """Send ckpXeq carrying a kXR_pgwrite sub-request."""
        payload = _pgwrite_payload(data, offset, corrupt_page)
        sub_hdr = struct.pack("!2sH4sqBBHi",
                              bytes([0, sid]), 3026,   # kXR_pgwrite
                              fh, offset, 0, 0, 0, len(payload))
        return self._ckpxeq(sock, sid, fh, sub_hdr, payload)

    def _ckpxeq_truncate(self, sock, sid, fh, length):
        """Send ckpXeq carrying a kXR_truncate sub-request (handle-based)."""
        sub_hdr = struct.pack("!2sH4sq4sI",
                              bytes([0, sid]), 3028,   # kXR_truncate
                              fh, length, b"\x00"*4, 0)
        return self._ckpxeq(sock, sid, fh, sub_hdr)

    def _ckpxeq_writev(self, sock, sid, fh, segments):
        """Send ckpXeq carrying a kXR_writev sub-request (stock framing: the
        sub-header's dlen frames only the descriptor block; the segment data
        streams after it, exactly like a standalone kXR_writev).

        segments: list of (offset, data) pairs.
        """
        seg_hdrs = b""
        seg_data = b""
        for off, data in segments:
            seg_hdrs += struct.pack("!4siq", fh, len(data), off)
            seg_data += data
        sub_hdr = struct.pack("!2sHB15sI",
                              bytes([0, sid]), 3031,   # kXR_writev
                              0, b"\x00"*15, len(seg_hdrs))
        return self._ckpxeq(sock, sid, fh, sub_hdr, seg_hdrs + seg_data)

    def _ckpxeq_write(self, sock, sid, fh, offset, data):
        """Send ckpXeq carrying a kXR_write sub-request."""
        sub_hdr = struct.pack("!2sH4sqB3sI",
                              bytes([0, sid]), 3019, fh, offset, 0,
                              b"\x00"*3, len(data))
        return self._ckpxeq(sock, sid, fh, sub_hdr, data)

    # ── tests ─────────────────────────────────────────────────────────────

    def test_ckpxeq_pgwrite_good_crc(self):
        """ckpXeq pgwrite with correct CRC32c is accepted."""
        upload(ANON_URL, "xeq_pgw_good.bin", b"original!" * 10)
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_pgw_good.bin")
            self._chkpoint(sock, 3, fh, 0)   # begin
            data = b"replaced!" * 10
            status, _ = self._ckpxeq_pgwrite(sock, 4, fh, 0, data)
            assert status in (0, 4007), (
                f"expected ok/kXR_status for good pgwrite CRC, got {status}"
            )
            actual = self._read(sock, 5, fh, 0, len(data))
            assert actual == data, "pgwrite data not written under ckpXeq"
            self._chkpoint(sock, 6, fh, 1)   # commit
            self._close(sock, 7, fh)
        finally:
            sock.close()

    def test_ckpxeq_pgwrite_bad_crc_rejected(self):
        """ckpXeq pgwrite with a corrupted CRC32c returns kXR_ChkSumErr."""
        upload(ANON_URL, "xeq_pgw_bad.bin", b"safecontent")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_pgw_bad.bin")
            self._chkpoint(sock, 3, fh, 0)   # begin
            status, body = self._ckpxeq_pgwrite(sock, 4, fh, 0,
                                                 b"corrupt!" * 5,
                                                 corrupt_page=0)
            kXR_error    = 4003
            kXR_ChkSumErr = 3019
            assert status == kXR_error, (
                f"expected kXR_error for bad CRC, got {status}"
            )
            assert len(body) >= 4
            assert struct.unpack("!I", body[:4])[0] == kXR_ChkSumErr, (
                f"expected kXR_ChkSumErr ({kXR_ChkSumErr})"
            )
            self._chkpoint(sock, 5, fh, 1)   # commit (original still intact)
            self._close(sock, 6, fh)
        finally:
            sock.close()

    def test_ckpxeq_pgwrite_then_rollback(self):
        """ckpXeq pgwrite under checkpoint rolls back cleanly."""
        original = b"keepme!!" * 4
        upload(ANON_URL, "xeq_pgw_rb.bin", original)
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_pgw_rb.bin")
            self._chkpoint(sock, 3, fh, 0)   # begin
            self._ckpxeq_pgwrite(sock, 4, fh, 0, b"changed!!" * 4)
            self._chkpoint(sock, 5, fh, 3)   # rollback
            data = self._read(sock, 6, fh, 0, len(original))
            assert data == original, f"rollback failed; got {data!r}"
            self._close(sock, 7, fh)
        finally:
            sock.close()

    def test_ckpxeq_pgwrite_multi_page(self):
        """ckpXeq pgwrite spanning two 4096-byte pages succeeds."""
        two_pages = os.urandom(4096 + 512)
        upload(ANON_URL, "xeq_pgw_mp.bin", bytes(len(two_pages)))
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_pgw_mp.bin")
            self._chkpoint(sock, 3, fh, 0)
            status, _ = self._ckpxeq_pgwrite(sock, 4, fh, 0, two_pages)
            assert status in (0, 4007), f"multi-page ckpXeq pgwrite failed: {status}"
            actual = self._read(sock, 5, fh, 0, len(two_pages))
            assert actual == two_pages, "multi-page ckpXeq pgwrite data mismatch"
            self._chkpoint(sock, 6, fh, 1)
            self._close(sock, 7, fh)
        finally:
            sock.close()

    def test_ckpxeq_truncate_reduces_file(self):
        """ckpXeq truncate shortens the file to the requested length."""
        upload(ANON_URL, "xeq_trunc.bin", b"abcdefghij")   # 10 bytes
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_trunc.bin")
            self._chkpoint(sock, 3, fh, 0)   # begin
            status, _ = self._ckpxeq_truncate(sock, 4, fh, 5)
            assert status == 0, f"ckpXeq truncate failed: {status}"
            # File should now be 5 bytes; reading 10 returns 5.
            data = self._read(sock, 5, fh, 0, 10)
            assert data == b"abcde", f"truncate produced wrong content: {data!r}"
            self._chkpoint(sock, 6, fh, 1)   # commit
            self._close(sock, 7, fh)
        finally:
            sock.close()

    def test_ckpxeq_truncate_then_rollback(self):
        """ckpXeq truncate under checkpoint is reversed by rollback."""
        original = b"abcdefghij"
        upload(ANON_URL, "xeq_trunc_rb.bin", original)
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_trunc_rb.bin")
            self._chkpoint(sock, 3, fh, 0)
            self._ckpxeq_truncate(sock, 4, fh, 3)
            self._chkpoint(sock, 5, fh, 3)   # rollback
            data = self._read(sock, 6, fh, 0, len(original))
            assert data == original, f"truncate rollback failed; got {data!r}"
            self._close(sock, 7, fh)
        finally:
            sock.close()

    def test_ckpxeq_writev_two_segments(self):
        """ckpXeq writev with two non-overlapping segments writes both correctly."""
        upload(ANON_URL, "xeq_writev.bin", b"\x00" * 20)
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_writev.bin")
            self._chkpoint(sock, 3, fh, 0)
            status, _ = self._ckpxeq_writev(sock, 4, fh,
                                              [(0, b"hello"), (10, b"world")])
            assert status == 0, f"ckpXeq writev failed: {status}"
            # Verify both segments landed at the right offsets.
            assert self._read(sock, 5, fh, 0,  5) == b"hello"
            assert self._read(sock, 6, fh, 10, 5) == b"world"
            self._chkpoint(sock, 7, fh, 1)
            self._close(sock, 8, fh)
        finally:
            sock.close()

    def test_ckpxeq_writev_then_rollback(self):
        """ckpXeq writev under checkpoint is reversed by rollback."""
        original = b"AAAAAAAAAA" * 2
        upload(ANON_URL, "xeq_writev_rb.bin", original)
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_writev_rb.bin")
            self._chkpoint(sock, 3, fh, 0)
            self._ckpxeq_writev(sock, 4, fh,
                                 [(0, b"BBBBB"), (10, b"CCCCC")])
            self._chkpoint(sock, 5, fh, 3)   # rollback
            data = self._read(sock, 6, fh, 0, len(original))
            assert data == original, f"writev rollback failed; got {data!r}"
            self._close(sock, 7, fh)
        finally:
            sock.close()

    def test_ckpxeq_unknown_subop_rejected(self):
        """ckpXeq with an unrecognised sub-opcode must return an error."""
        upload(ANON_URL, "xeq_unknown.bin", b"data")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_unknown.bin")
            self._chkpoint(sock, 3, fh, 0)   # begin
            # 24-byte sub-header with a requestid that doesn't exist (0xFFFF);
            # stock parity: error, link kept (no data was declared).
            bogus_sub = struct.pack("!2sH4s12sI",
                                    bytes([0, 4]), 0xFFFF, fh, b"\x00"*12, 0)
            status, _ = self._ckpxeq(sock, 4, fh, bogus_sub)
            assert status != 0, "expected error for unknown ckpXeq sub-opcode"
            self._chkpoint(sock, 5, fh, 1)   # commit to clean up
            self._close(sock, 6, fh)
        finally:
            sock.close()

    def test_ckpxeq_write_at_nonzero_offset(self):
        """ckpXeq write sub-op at a non-zero offset lands in the right place."""
        upload(ANON_URL, "xeq_wr_off.bin", b"\x00" * 20)
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_wr_off.bin")
            self._chkpoint(sock, 3, fh, 0)   # begin
            status, _ = self._ckpxeq_write(sock, 4, fh, 10, b"hello")
            assert status == 0, f"ckpXeq write at offset 10 failed: {status}"
            assert self._read(sock, 5, fh, 10, 5) == b"hello"
            assert self._read(sock, 6, fh,  0, 5) == b"\x00" * 5
            self._chkpoint(sock, 7, fh, 1)   # commit
            self._close(sock, 8, fh)
        finally:
            sock.close()

    def test_ckpxeq_pgwrite_at_nonzero_offset(self):
        """ckpXeq pgwrite at offset=100 (partial first page) writes to the right location."""
        upload(ANON_URL, "xeq_pgw_off.bin", b"\x00" * 200)
        data = b"mid-page data" * 3
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_pgw_off.bin")
            self._chkpoint(sock, 3, fh, 0)
            status, _ = self._ckpxeq_pgwrite(sock, 4, fh, 100, data)
            assert status in (0, 4007), f"ckpXeq pgwrite at offset 100 failed: {status}"
            assert self._read(sock, 5, fh, 100, len(data)) == data
            assert self._read(sock, 6, fh,   0,          5) == b"\x00" * 5
            self._chkpoint(sock, 7, fh, 1)
            self._close(sock, 8, fh)
        finally:
            sock.close()

    def test_ckpxeq_pgwrite_full_page(self):
        """ckpXeq pgwrite of exactly 4096 bytes (one complete page) succeeds."""
        upload(ANON_URL, "xeq_pgw_fp.bin", bytes(4096))
        data = os.urandom(4096)
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_pgw_fp.bin")
            self._chkpoint(sock, 3, fh, 0)
            status, _ = self._ckpxeq_pgwrite(sock, 4, fh, 0, data)
            assert status in (0, 4007), f"full-page ckpXeq pgwrite failed: {status}"
            assert self._read(sock, 5, fh, 0, 4096) == data
            self._chkpoint(sock, 6, fh, 1)
            self._close(sock, 7, fh)
        finally:
            sock.close()

    def test_ckpxeq_write_zero_bytes(self):
        """ckpXeq write with dlen=0 (empty payload) succeeds without modifying the file."""
        upload(ANON_URL, "xeq_wr_zero.bin", b"untouched")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_wr_zero.bin")
            self._chkpoint(sock, 3, fh, 0)
            status, _ = self._ckpxeq_write(sock, 4, fh, 0, b"")
            assert status == 0, f"ckpXeq zero-byte write failed: {status}"
            assert self._read(sock, 5, fh, 0, 9) == b"untouched"
            self._chkpoint(sock, 6, fh, 1)
            self._close(sock, 7, fh)
        finally:
            sock.close()

    def test_ckpxeq_truncate_extend_file(self):
        """ckpXeq truncate to a length larger than the current file extends it with zeros."""
        upload(ANON_URL, "xeq_trunc_ext.bin", b"short")   # 5 bytes
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_trunc_ext.bin")
            self._chkpoint(sock, 3, fh, 0)
            status, _ = self._ckpxeq_truncate(sock, 4, fh, 10)
            assert status == 0, f"ckpXeq extend-truncate failed: {status}"
            data = self._read(sock, 5, fh, 0, 10)
            assert data[:5] == b"short", "original content changed by extension"
            assert data[5:]  == b"\x00" * 5, "extended region not zeroed"
            self._chkpoint(sock, 6, fh, 1)
            self._close(sock, 7, fh)
        finally:
            sock.close()

    def test_ckpxeq_writev_single_segment(self):
        """ckpXeq writev with exactly one segment writes the data correctly."""
        upload(ANON_URL, "xeq_wv_one.bin", b"\x00" * 10)
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_wv_one.bin")
            self._chkpoint(sock, 3, fh, 0)
            status, _ = self._ckpxeq_writev(sock, 4, fh, [(3, b"hi!")])
            assert status == 0, f"ckpXeq single-segment writev failed: {status}"
            assert self._read(sock, 5, fh, 3, 3) == b"hi!"
            assert self._read(sock, 6, fh, 0, 3) == b"\x00" * 3
            self._chkpoint(sock, 7, fh, 1)
            self._close(sock, 8, fh)
        finally:
            sock.close()

    def test_ckpxeq_writev_three_segments(self):
        """ckpXeq writev with three non-overlapping segments writes all three correctly."""
        upload(ANON_URL, "xeq_wv_three.bin", b"\x00" * 30)
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_wv_three.bin")
            self._chkpoint(sock, 3, fh, 0)
            status, _ = self._ckpxeq_writev(sock, 4, fh,
                                              [(0, b"aaa"), (10, b"bbb"), (20, b"ccc")])
            assert status == 0, f"ckpXeq three-segment writev failed: {status}"
            assert self._read(sock, 5, fh,  0, 3) == b"aaa"
            assert self._read(sock, 6, fh, 10, 3) == b"bbb"
            assert self._read(sock, 7, fh, 20, 3) == b"ccc"
            assert self._read(sock, 8, fh,  3, 5) == b"\x00" * 5
            self._chkpoint(sock, 9, fh, 1)
            self._close(sock, 10, fh)
        finally:
            sock.close()

    def test_ckpxeq_writev_skips_zero_length_segment(self):
        """ckpXeq writev with a zero-length segment succeeds; only non-empty segments write."""
        upload(ANON_URL, "xeq_wv_zero_seg.bin", b"\x00" * 10)
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/xeq_wv_zero_seg.bin")
            self._chkpoint(sock, 3, fh, 0)
            # One real 5-byte segment at offset 2, plus one zero-length segment at offset 8.
            status, _ = self._ckpxeq_writev(sock, 4, fh,
                                              [(2, b"hello"), (8, b"")])
            assert status == 0, f"ckpXeq writev with zero-length segment failed: {status}"
            assert self._read(sock, 5, fh, 2, 5) == b"hello"
            assert self._read(sock, 6, fh, 8, 2) == b"\x00" * 2
            self._chkpoint(sock, 7, fh, 1)
            self._close(sock, 8, fh)
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# Extended checkpoint state invariants
# ---------------------------------------------------------------------------
