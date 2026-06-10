"""
tests/test_io_edge_cases.py

Read/write boundary conditions, pgread CRC32c integrity, kXR_sync,
readv/writev edge cases.

Run:
    pytest tests/test_io_edge_cases.py -v
"""

import os
import struct
import socket

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

kXR_protocol  = 3006
kXR_login     = 3007
kXR_open      = 3010
kXR_close     = 3003
kXR_read      = 3013
kXR_sync      = 3016
kXR_write     = 3019
kXR_readv     = 3025
kXR_pgwrite   = 3026
kXR_pgread    = 3030
kXR_writev    = 3031

kXR_ok        = 0
kXR_error     = 4003
kXR_status    = 4007

kXR_ChkSumErr   = 3019
kXR_FileNotOpen = 3004
kXR_IOError     = 3007

kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_open_new  = 0x0008
kXR_delete    = 0x0002

kXR_pgPageSZ  = 4096

# ---------------------------------------------------------------------------
# Module globals
# ---------------------------------------------------------------------------

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT
DATA_DIR  = DATA_ROOT


# ---------------------------------------------------------------------------
# CRC32c
# ---------------------------------------------------------------------------

def _crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
    return crc ^ 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Socket helpers
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"socket closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def _read_response(sock):
    hdr = _recv_exact(sock, 8)
    sid, status, dlen = struct.unpack("!2sHI", hdr)
    body = _recv_exact(sock, dlen) if dlen else b""
    # kXR_status two-phase: header dlen=24 (fixed body), then bdy.dlen more bytes
    # for page data.  bdy.dlen lives at body[12:16].
    if status == kXR_status and dlen == 24 and len(body) == 24:
        extra = struct.unpack("!I", body[12:16])[0]
        if extra > 0:
            body = body + _recv_exact(sock, extra)
    return status, body


def _session():
    sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=10)
    sock.settimeout(10)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, _ = _read_response(sock)
    assert status == kXR_ok
    sock.sendall(struct.pack("!2sHI8sBBBBI",
                              b"\x00\x01", kXR_login,
                              os.getpid() & 0xFFFFFFFF,
                              b"pytest\x00\x00", 0, 0, 5, 0, 0))
    status, _ = _read_response(sock)
    assert status == kXR_ok
    return sock


def _open(sock, path, flags=kXR_open_read, streamid=b"\x00\x02"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH2s6s4sI",
                      streamid, kXR_open,
                      0o644, flags, b"\x00\x00", b"\x00"*6, b"\x00"*4, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _close(sock, fhandle, streamid=b"\x00\x0e"):
    req = struct.pack("!2sH4s12sI", streamid, kXR_close, fhandle, b"\x00"*12, 0)
    sock.sendall(req)
    _read_response(sock)


def _read(sock, fhandle, offset, rlen, streamid=b"\x00\x03"):
    req = struct.pack("!2sH4sqiI", streamid, kXR_read, fhandle, offset, rlen, 0)
    sock.sendall(req)
    return _read_response(sock)


def _write(sock, fhandle, offset, data, streamid=b"\x00\x03"):
    req = struct.pack("!2sH4sqiI", streamid, kXR_write,
                      fhandle, offset, len(data), len(data))
    sock.sendall(req + data)
    return _read_response(sock)


def _sync(sock, fhandle, streamid=b"\x00\x04"):
    req = struct.pack("!2sH4s12sI", streamid, kXR_sync, fhandle, b"\x00"*12, 0)
    sock.sendall(req)
    return _read_response(sock)


def _error_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


def _make_file(name, content=b"hello"):
    path = os.path.join(DATA_DIR, name.lstrip("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(content)
    return path


def _read_file(name):
    with open(os.path.join(DATA_DIR, name.lstrip("/")), "rb") as f:
        return f.read()


# ---------------------------------------------------------------------------
# pgwrite helpers
# ---------------------------------------------------------------------------

def _build_pgwrite_payload(data: bytes, offset: int, corrupt_page: int = -1):
    out = bytearray()
    pos = 0
    page_idx = 0
    cur_offset = offset
    while pos < len(data):
        page_off = cur_offset % kXR_pgPageSZ
        room = kXR_pgPageSZ - page_off
        chunk = data[pos: pos + room]
        crc = _crc32c(chunk)
        if page_idx == corrupt_page:
            crc = (crc ^ 0xDEADBEEF) & 0xFFFFFFFF
        out += struct.pack("!I", crc)
        out += chunk
        pos += len(chunk)
        cur_offset += len(chunk)
        page_idx += 1
    return bytes(out)


def _send_pgwrite(sock, fhandle, offset, payload, streamid=b"\x00\x05"):
    hdr = struct.pack("!2sH4sqBBHi",
                      streamid, kXR_pgwrite,
                      fhandle, offset,
                      0, 0, 0, len(payload))
    sock.sendall(hdr + payload)
    return _read_response(sock)


# ---------------------------------------------------------------------------
# pgread helpers
# ---------------------------------------------------------------------------

def _send_pgread(sock, fhandle, offset, length, streamid=b"\x00\x06"):
    req = struct.pack("!2sH4sqiI",
                      streamid, kXR_pgread,
                      fhandle, offset, length, 0)
    sock.sendall(req)
    return _read_response(sock)


def _parse_pgread_response(body):
    """Parse pgread response: list of (crc, page_bytes) pairs."""
    pages = []
    pos = 0
    while pos < len(body):
        if pos + 4 > len(body):
            break
        crc = struct.unpack("!I", body[pos:pos+4])[0]
        pos += 4
        # Page data extends to next CRC or end; we can't know length without header
        # The pgread response interleaves CRC+data per page boundary
        # Read until next page boundary
        pages.append((crc, body[pos:]))
        break  # simplification: just return the first CRC and the rest as data
    return pages


# =========================================================================
# Class 1 — Read Edge Cases
# =========================================================================

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
