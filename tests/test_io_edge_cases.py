from _test_io_edge_cases_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

class TestReadEdgeCases:

    def test_read_at_exactly_eof(self):
        content = b"hello_eof_test"
        _make_file("/read_eof.txt", content)
        sock = _session()
        status, body = _open(sock,"/read_eof.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        # Read starting at exactly file_size → 0 bytes, kXR_ok
        status, data = _read(sock, fh, len(content), 100)
        _close(sock, fh)
        sock.close()
        assert status == kXR_ok
        assert data == b""

    def test_read_one_past_eof(self):
        content = b"short"
        _make_file("/read_past_eof.txt", content)
        sock = _session()
        status, body = _open(sock,"/read_past_eof.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        status, data = _read(sock, fh, len(content) + 1, 10)
        _close(sock, fh)
        sock.close()
        assert status == kXR_ok
        assert data == b""

    def test_read_zero_length(self):
        _make_file("/read_zero.txt", b"content")
        sock = _session()
        status, body = _open(sock,"/read_zero.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        status, data = _read(sock, fh, 0, 0)
        _close(sock, fh)
        sock.close()
        assert status == kXR_ok
        assert data == b""

    def test_read_rlen_larger_than_file(self):
        content = b"small_file_24bytes!!"
        _make_file("/read_rlen_large.txt", content)
        sock = _session()
        status, body = _open(sock,"/read_rlen_large.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        # Request 10 MB but file is tiny
        status, data = _read(sock, fh, 0, 10 * 1024 * 1024)
        _close(sock, fh)
        sock.close()
        assert status == kXR_ok
        assert data == content

    def test_read_spanning_page_boundary(self):
        content = bytes(range(256)) * 16 + b"extra_bytes_here"  # 4112 bytes
        _make_file("/read_page_boundary.txt", content)
        sock = _session()
        status, body = _open(sock,"/read_page_boundary.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        # Read 10 bytes across page boundary (4094..4103)
        status, data = _read(sock, fh, 4094, 10)
        _close(sock, fh)
        sock.close()
        assert status == kXR_ok
        assert data == content[4094:4104]

    def test_read_first_byte(self):
        content = b"\xAB" + b"\x00" * 99
        _make_file("/read_first_byte.txt", content)
        sock = _session()
        status, body = _open(sock,"/read_first_byte.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        status, data = _read(sock, fh, 0, 1)
        _close(sock, fh)
        sock.close()
        assert status == kXR_ok
        assert data == b"\xAB"

    def test_read_last_byte(self):
        content = b"\x00" * 99 + b"\xCD"
        _make_file("/read_last_byte.txt", content)
        sock = _session()
        status, body = _open(sock,"/read_last_byte.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        status, data = _read(sock, fh, 99, 1)
        _close(sock, fh)
        sock.close()
        assert status == kXR_ok
        assert data == b"\xCD"

    def test_read_exact_file_size(self):
        content = b"exact_content_here"
        _make_file("/read_exact_size.txt", content)
        sock = _session()
        status, body = _open(sock,"/read_exact_size.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        status, data = _read(sock, fh, 0, len(content))
        _close(sock, fh)
        sock.close()
        assert status == kXR_ok
        assert data == content

    def test_read_two_non_overlapping(self):
        content = b"AAAABBBB"
        _make_file("/read_two_parts.txt", content)
        sock = _session()
        status, body = _open(sock,"/read_two_parts.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        s1, d1 = _read(sock, fh, 0, 4, streamid=b"\x00\x10")
        s2, d2 = _read(sock, fh, 4, 4, streamid=b"\x00\x11")
        _close(sock, fh)
        sock.close()
        assert s1 == kXR_ok and d1 == b"AAAA"
        assert s2 == kXR_ok and d2 == b"BBBB"

    def test_read_same_offset_twice(self):
        content = b"REPEAT_ME"
        _make_file("/read_same_twice.txt", content)
        sock = _session()
        status, body = _open(sock,"/read_same_twice.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        s1, d1 = _read(sock, fh, 0, 9, streamid=b"\x00\x10")
        s2, d2 = _read(sock, fh, 0, 9, streamid=b"\x00\x11")
        _close(sock, fh)
        sock.close()
        assert d1 == d2 == content

    def test_read_negative_offset_as_unsigned(self):
        _make_file("/read_neg_offset.txt", b"x" * 100)
        sock = _session()
        status, body = _open(sock,"/read_neg_offset.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        # offset = 0xFFFFFFFFFFFFFFFF (max int64 unsigned = -1 signed)
        req = struct.pack("!2sH4sqiI", b"\x00\x03", kXR_read,
                          fh, -1, 10, 0)
        sock.sendall(req)
        status, body = _read_response(sock)
        _close(sock, fh)
        sock.close()
        # Must not crash — error or empty data are both fine
        assert status in (kXR_ok, kXR_error)

    def test_read_far_beyond_eof(self):
        _make_file("/read_far_eof.txt", b"short")
        sock = _session()
        status, body = _open(sock,"/read_far_eof.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        status, data = _read(sock, fh, 0x3FFFFFFFFFFFFFFF, 10)
        _close(sock, fh)
        sock.close()
        assert status in (kXR_ok, kXR_error)
        if status == kXR_ok:
            assert data == b""


# =========================================================================
# Class 2 — pgread Edge Cases
# =========================================================================

class TestPgreadEdgeCases:
    """Verify CRC32c per-page response encoding in pgread."""

    def _pgread_session(self, path):
        sock = _session()
        status, body = _open(sock,path, kXR_open_read)
        assert status == kXR_ok
        return sock, body[:4]

    def test_pgread_single_page_crc_correct(self):
        # kXR_status response body: 16B ServerResponseBody_Status + 8B pgRead
        # header (=24 bytes), then per-page [CRC32c(4)][page_data] pairs.
        # CRC comes BEFORE the page data (XRootD wire format).
        data = b"A" * 4096
        _make_file("/pgread_single.bin", data)
        sock, fh = self._pgread_session("/pgread_single.bin")
        status, body = _send_pgread(sock, fh, 0, 4096)
        _close(sock, fh)
        sock.close()
        assert status == kXR_status
        # 24 header + 4 CRC + 4096 data = 4124
        assert len(body) >= 24 + 4 + 4096
        resp_crc = struct.unpack("!I", body[24:28])[0]
        page_data = body[28:28 + 4096]
        assert resp_crc == _crc32c(page_data)

    def test_pgread_empty_file(self):
        _make_file("/pgread_empty.bin", b"")
        sock, fh = self._pgread_session("/pgread_empty.bin")
        status, body = _send_pgread(sock, fh, 0, 4096)
        _close(sock, fh)
        sock.close()
        # 0-byte file → 0 bytes read, kXR_ok or kXR_status with empty body
        assert status in (kXR_ok, kXR_status, kXR_error)

    def test_pgread_single_byte_file(self):
        _make_file("/pgread_1byte.bin", b"\x42")
        sock, fh = self._pgread_session("/pgread_1byte.bin")
        status, body = _send_pgread(sock, fh, 0, 1)
        _close(sock, fh)
        sock.close()
        assert status in (kXR_ok, kXR_status)
        # Per-page layout: [CRC32c(4)][data]. For 1 byte: body[24:28]=CRC, body[28]=data.
        if status == kXR_status and len(body) >= 24 + 4 + 1:
            resp_crc = struct.unpack("!I", body[24:28])[0]
            page_byte = body[28:29]
            assert resp_crc == _crc32c(page_byte)

    def test_pgread_exactly_two_pages(self):
        data = b"B" * 8192
        _make_file("/pgread_two_pages.bin", data)
        sock, fh = self._pgread_session("/pgread_two_pages.bin")
        status, body = _send_pgread(sock, fh, 0, 8192)
        _close(sock, fh)
        sock.close()
        assert status in (kXR_ok, kXR_status)
        # Per-page layout: [CRC32c(4)][data]. First page: body[24:28]=CRC, body[28:4124]=data.
        if len(body) >= 24 + 4 + 4096:
            crc1 = struct.unpack("!I", body[24:28])[0]
            page1 = body[28:28 + 4096]
            assert crc1 == _crc32c(page1)

    def test_pgread_partial_last_page(self):
        # File not a multiple of 4096 → last CRC covers actual bytes only
        data = b"C" * 5000  # 4096 + 904 bytes
        _make_file("/pgread_partial_last.bin", data)
        sock, fh = self._pgread_session("/pgread_partial_last.bin")
        status, body = _send_pgread(sock, fh, 0, 5000)
        _close(sock, fh)
        sock.close()
        assert status in (kXR_ok, kXR_status)

    def test_pgread_at_page_boundary_offset(self):
        data = b"D" * 8192
        _make_file("/pgread_boundary_off.bin", data)
        sock, fh = self._pgread_session("/pgread_boundary_off.bin")
        # pgread starting at offset=4096 (second page exactly)
        status, body = _send_pgread(sock, fh, 4096, 4096)
        _close(sock, fh)
        sock.close()
        assert status in (kXR_ok, kXR_status)
        if status == kXR_status and len(body) >= 24 + 4 + 4096:
            crc = struct.unpack("!I", body[24:28])[0]
            page = body[28:28 + 4096]
            assert crc == _crc32c(page)

    def test_pgread_sequential_calls_same_handle(self):
        data = b"E" * 8192
        _make_file("/pgread_seq.bin", data)
        sock, fh = self._pgread_session("/pgread_seq.bin")
        # Two consecutive pgread calls on same handle
        s1, b1 = _send_pgread(sock, fh, 0, 4096, streamid=b"\x00\x10")
        s2, b2 = _send_pgread(sock, fh, 4096, 4096, streamid=b"\x00\x11")
        _close(sock, fh)
        sock.close()
        assert s1 in (kXR_ok, kXR_status)
        assert s2 in (kXR_ok, kXR_status)

    def test_pgread_all_page_crcs_correct(self):
        # Two pages — verify CRC for each page individually
        # Per-page layout: [CRC32c(4)][data]. Two pages:
        # body[24:28]=CRC1, body[28:4124]=page1(4096B),
        # body[4124:4128]=CRC2, body[4128:4640]=page2(512B)
        page1 = b"F" * 4096
        page2 = b"G" * 512
        data = page1 + page2
        _make_file("/pgread_crc_all.bin", data)
        sock, fh = self._pgread_session("/pgread_crc_all.bin")
        status, body = _send_pgread(sock, fh, 0, len(data))
        _close(sock, fh)
        sock.close()
        assert status in (kXR_ok, kXR_status)
        hdr = 24
        if status == kXR_status and len(body) >= hdr + 4 + 4096 + 4 + 512:
            # Page 1: CRC[hdr:hdr+4], data[hdr+4:hdr+4100]
            p1_crc = struct.unpack("!I", body[hdr:hdr + 4])[0]
            p1_data = body[hdr + 4:hdr + 4100]
            assert p1_crc == _crc32c(p1_data)
            # Page 2: CRC[hdr+4100:hdr+4104], data[hdr+4104:hdr+4104+512]
            p2_crc = struct.unpack("!I", body[hdr + 4100:hdr + 4104])[0]
            p2_data = body[hdr + 4104:hdr + 4104 + 512]
            assert p2_crc == _crc32c(p2_data)


# =========================================================================
# Class 3 — Readv Edge Cases
# =========================================================================

class TestReadvEdgeCases:

    def _readv_request(self, sock, fhandle, segments, streamid=b"\x00\x07"):
        """Send kXR_readv with given [(offset, length)] segments."""
        seg_data = b""
        for offset, length in segments:
            seg_data += struct.pack("!4sIq", fhandle, length, offset)
        req = struct.pack("!2sH16sI", streamid, kXR_readv, b"\x00"*16, len(seg_data))
        sock.sendall(req + seg_data)
        return _read_response(sock)

    def test_readv_single_segment(self):
        content = b"abcdefghij"
        _make_file("/readv_single.txt", content)
        sock = _session()
        status, body = _open(sock,"/readv_single.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        status, resp = self._readv_request(sock, fh, [(0, 5)])
        _close(sock, fh)
        sock.close()
        assert status in (kXR_ok, kXR_status)

    def test_readv_single_zero_length_segment(self):
        _make_file("/readv_zero_seg.txt", b"data")
        sock = _session()
        status, body = _open(sock,"/readv_zero_seg.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        # 1 segment with length=0
        status, resp = self._readv_request(sock, fh, [(0, 0)])
        _close(sock, fh)
        sock.close()
        assert status in (kXR_ok, kXR_status, kXR_error)

    def test_readv_two_segments(self):
        content = b"AAAABBBB"
        _make_file("/readv_two.txt", content)
        sock = _session()
        status, body = _open(sock,"/readv_two.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        status, resp = self._readv_request(sock, fh, [(0, 4), (4, 4)])
        _close(sock, fh)
        sock.close()
        assert status in (kXR_ok, kXR_status)

    def test_readv_segment_at_eof(self):
        content = b"x" * 10
        _make_file("/readv_at_eof.txt", content)
        sock = _session()
        status, body = _open(sock,"/readv_at_eof.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        # Segment starting exactly at EOF
        status, resp = self._readv_request(sock, fh, [(10, 5)])
        _close(sock, fh)
        sock.close()
        assert status in (kXR_ok, kXR_status, kXR_error)

    def test_readv_segment_wraps_eof(self):
        content = b"y" * 10
        _make_file("/readv_wrap_eof.txt", content)
        sock = _session()
        status, body = _open(sock,"/readv_wrap_eof.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        # Starts before EOF, extends past → returns available bytes
        status, resp = self._readv_request(sock, fh, [(8, 10)])
        _close(sock, fh)
        sock.close()
        assert status in (kXR_ok, kXR_status, kXR_error)

    def test_readv_one_byte_segments(self):
        content = b"ABCDEF"
        _make_file("/readv_one_byte.txt", content)
        sock = _session()
        status, body = _open(sock,"/readv_one_byte.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        segs = [(i, 1) for i in range(6)]
        status, resp = self._readv_request(sock, fh, segs)
        _close(sock, fh)
        sock.close()
        assert status in (kXR_ok, kXR_status)

    def test_readv_overlapping_segments(self):
        content = b"OVERLAPPING_DATA"
        _make_file("/readv_overlap.txt", content)
        sock = _session()
        status, body = _open(sock,"/readv_overlap.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        # Two overlapping segments
        status, resp = self._readv_request(sock, fh, [(0, 8), (4, 8)])
        _close(sock, fh)
        sock.close()
        assert status in (kXR_ok, kXR_status, kXR_error)

    def test_readv_descending_offsets(self):
        content = b"REVERSE_ORDER_TEST"
        _make_file("/readv_descend.txt", content)
        sock = _session()
        status, body = _open(sock,"/readv_descend.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        # Segments in reverse order
        n = len(content)
        segs = [(n-2, 2), (n-4, 2), (n-6, 2)]
        status, resp = self._readv_request(sock, fh, segs)
        _close(sock, fh)
        sock.close()
        assert status in (kXR_ok, kXR_status)

    def test_readv_many_small_segments(self):
        content = bytes(range(100))
        _make_file("/readv_many.txt", content)
        sock = _session()
        status, body = _open(sock,"/readv_many.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        segs = [(i, 1) for i in range(100)]
        status, resp = self._readv_request(sock, fh, segs)
        _close(sock, fh)
        sock.close()
        assert status in (kXR_ok, kXR_status)

    def test_readv_response_returned_after_request(self):
        content = b"RESPONSE_ORDER_CHECK"
        _make_file("/readv_resp_order.txt", content)
        sock = _session()
        status, body = _open(sock,"/readv_resp_order.txt", kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        segs = [(0, 5), (5, 5), (10, 5)]
        status, resp = self._readv_request(sock, fh, segs)
        _close(sock, fh)
        sock.close()
        # Just verify we got a response (not a timeout)
        assert status in (kXR_ok, kXR_status)


# =========================================================================
# Class 4 — Write Edge Cases
# =========================================================================
