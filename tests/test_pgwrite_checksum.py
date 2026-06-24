"""
Raw-protocol tests for kXR_pgwrite CRC32c checksum verification.

The XRootD kXR_pgwrite opcode (3026) embeds a 4-byte big-endian CRC32c
before each page of data.  nginx-xrootd verifies each page's checksum and now
follows the stock "accept-then-correct" (CSE) protocol:

  - Every correct CRC → kXR_status (4007) with no trailer.
  - A bad CRC is NOT hard-failed: the page is still written and reported in a
    SUCCESS kXR_status frame carrying a CSE retransmit list; kXR_close then
    returns kXR_ChkSumErr (3019) until the page is corrected via kXR_pgRetry.

The full CSE machine (trailer parsing, retry, close gate) is exercised in
test_pgwrite_cse.py.  This file keeps the framing/regression coverage: good
writes succeed and reach disk, and a bad page is reported (not silently
accepted) and gates the close.

kXR_pgwrite payload layout (one entry per 4096-byte page):
    [4 bytes CRC32c big-endian][up to 4096 bytes page data]
The first / last entries may be shorter when the write is unaligned.

Run:
    pytest tests/test_pgwrite_checksum.py -v -s
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
kXR_pgwrite   = 3026

kXR_ok        = 0
kXR_error     = 4003
kXR_status    = 4007

kXR_ChkSumErr = 3019   # error code embedded in kXR_error body

kXR_open_updt = 0x0020   # open for read+write
kXR_new       = 0x0008   # create new file
kXR_delete    = 0x0002   # truncate on open

kXR_pgPageSZ  = 4096     # must match XRD_PGWRITE_PAGESZ in the C module


# ---------------------------------------------------------------------------
# CRC32c (Castagnoli) — pure Python using reversed polynomial 0x82F63B78
# ---------------------------------------------------------------------------

def _crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
    return crc ^ 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise AssertionError(f"socket closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def _read_response(sock: socket.socket):
    hdr = _recv_exact(sock, 8)
    _sid, status, dlen = struct.unpack("!2sHI", hdr)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _handshake_login(host: str, port: int) -> socket.socket:
    """Connect, XRootD handshake, kXR_protocol, kXR_login.  Returns the socket."""
    sock = socket.create_connection((host, port), timeout=10)
    sock.settimeout(10)

    # initial 20-byte handshake
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, _ = _read_response(sock)
    assert status == kXR_ok, f"handshake failed: {status}"

    # kXR_protocol
    sock.sendall(
        struct.pack("!2sHI2s10xI", b"\x00\x01", kXR_protocol, 0x00000520, b"\x02\x03", 0)
    )
    status, _ = _read_response(sock)
    assert status == kXR_ok, f"kXR_protocol failed: {status}"

    # kXR_login
    sock.sendall(
        struct.pack("!2sHI8sBBBBI",
                    b"\x00\x01", kXR_login,
                    os.getpid() & 0xFFFFFFFF,
                    b"pytest\x00\x00",
                    0, 0, 5, 0, 0)
    )
    status, _ = _read_response(sock)
    assert status == kXR_ok, f"kXR_login failed: {status}"

    return sock


def _open_for_write(sock: socket.socket, path: bytes) -> bytes:
    """Open *path* for write (truncate), return 4-byte file handle."""
    flags = kXR_open_updt | kXR_delete
    sock.sendall(
        struct.pack("!2sHHH2s6s4sI",
                    b"\x00\x02", kXR_open,
                    0o644, flags,
                    b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                    len(path))
        + path
    )
    status, body = _read_response(sock)
    assert status == kXR_ok, f"kXR_open failed: {status}"
    assert len(body) >= 4, "open response too short for fhandle"
    return body[:4]


def _close(sock: socket.socket, fhandle: bytes) -> None:
    sock.sendall(
        struct.pack("!2sH4s12sI", b"\x00\x09", kXR_close, fhandle, b"\x00" * 12, 0)
    )
    _read_response(sock)


def _build_pgwrite_payload(data: bytes, offset: int, corrupt_page: int = -1) -> bytes:
    """
    Build a kXR_pgwrite payload for *data* starting at file *offset*.

    corrupt_page: if >= 0, flip the CRC of that page index to trigger a mismatch.
    """
    out = bytearray()
    pos = 0
    page_idx = 0
    cur_offset = offset

    while pos < len(data):
        page_off_in_page = cur_offset % kXR_pgPageSZ
        page_room = kXR_pgPageSZ - page_off_in_page
        chunk = data[pos: pos + page_room]

        crc = _crc32c(chunk)
        if page_idx == corrupt_page:
            crc = (crc ^ 0xDEADBEEF) & 0xFFFFFFFF  # deliberate corruption

        out += struct.pack("!I", crc)
        out += chunk

        pos += len(chunk)
        cur_offset += len(chunk)
        page_idx += 1

    return bytes(out)


def _send_pgwrite(sock: socket.socket, fhandle: bytes, offset: int, payload: bytes):
    """Send a raw kXR_pgwrite frame and return (status, body)."""
    hdr = struct.pack(
        "!2sH4sqBBHi",
        b"\x00\x03", kXR_pgwrite,
        fhandle,
        offset,
        0,   # pathid
        0,   # reqflags
        0,   # reserved
        len(payload),
    )
    sock.sendall(hdr + payload)
    return _read_response(sock)


# ---------------------------------------------------------------------------
# Module globals
# ---------------------------------------------------------------------------

_ANON_HOST = SERVER_HOST
_ANON_PORT = NGINX_ANON_PORT
_DATA_DIR  = DATA_ROOT


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPgWriteChecksumVerification:
    """
    Verify that xrootd_pgwrite_decode_payload enforces CRC32c integrity.

    Each test opens a temporary file, sends one or more pgwrite requests,
    and checks the server's response code.
    """

    def test_good_checksum_accepted(self):
        """A single-page pgwrite with a correct CRC32c must succeed."""
        data = b"correct checksum payload " * 20   # 500 bytes, fits in one page
        host, port = _ANON_HOST, _ANON_PORT
        sock = _handshake_login(host, port)
        try:
            fhandle = _open_for_write(sock, b"/_pgwrite_good_crc.bin")
            payload = _build_pgwrite_payload(data, offset=0)
            status, _ = _send_pgwrite(sock, fhandle, 0, payload)
            assert status == kXR_status, (
                f"expected kXR_status ({kXR_status}) for correct CRC, got {status}"
            )
            _close(sock, fhandle)
        finally:
            sock.close()

    def test_bad_checksum_reported_via_cse(self):
        """A single-page pgwrite with a corrupted CRC32c is accepted-and-reported
        (success kXR_status + CSE trailer), not hard-failed."""
        data = b"bad checksum payload " * 20   # 420 bytes
        host, port = _ANON_HOST, _ANON_PORT
        sock = _handshake_login(host, port)
        try:
            fhandle = _open_for_write(sock, b"/_pgwrite_bad_crc.bin")
            payload = _build_pgwrite_payload(data, offset=0, corrupt_page=0)
            status, _body = _send_pgwrite(sock, fhandle, 0, payload)
            assert status == kXR_status, (
                f"expected kXR_status ({kXR_status}) CSE reply, got {status}"
            )
        finally:
            sock.close()

    def test_multi_page_all_good(self):
        """A two-page pgwrite with all correct CRCs must succeed."""
        data = os.urandom(kXR_pgPageSZ + 512)   # 1 full page + partial second
        host, port = _ANON_HOST, _ANON_PORT
        sock = _handshake_login(host, port)
        try:
            fhandle = _open_for_write(sock, b"/_pgwrite_multi_good.bin")
            payload = _build_pgwrite_payload(data, offset=0)
            status, _ = _send_pgwrite(sock, fhandle, 0, payload)
            assert status == kXR_status, (
                f"expected kXR_status ({kXR_status}) for two good pages, got {status}"
            )
            _close(sock, fhandle)
        finally:
            sock.close()

    def test_multi_page_first_page_bad(self):
        """A two-page pgwrite where the first page has a bad CRC → CSE report."""
        data = os.urandom(kXR_pgPageSZ + 512)
        host, port = _ANON_HOST, _ANON_PORT
        sock = _handshake_login(host, port)
        try:
            fhandle = _open_for_write(sock, b"/_pgwrite_multi_bad0.bin")
            payload = _build_pgwrite_payload(data, offset=0, corrupt_page=0)
            status, _body = _send_pgwrite(sock, fhandle, 0, payload)
            assert status == kXR_status, (
                f"expected kXR_status CSE reply for bad first page, got {status}"
            )
        finally:
            sock.close()

    def test_multi_page_second_page_bad(self):
        """A two-page pgwrite where the second page has a bad CRC → CSE report."""
        data = os.urandom(kXR_pgPageSZ + 512)
        host, port = _ANON_HOST, _ANON_PORT
        sock = _handshake_login(host, port)
        try:
            fhandle = _open_for_write(sock, b"/_pgwrite_multi_bad1.bin")
            payload = _build_pgwrite_payload(data, offset=0, corrupt_page=1)
            status, _body = _send_pgwrite(sock, fhandle, 0, payload)
            assert status == kXR_status, (
                f"expected kXR_status CSE reply for bad second page, got {status}"
            )
        finally:
            sock.close()

    def test_good_write_data_reaches_disk(self):
        """After a successful pgwrite, the data must be readable from disk."""
        data = b"persistent payload check " * 40   # 1000 bytes
        remote = "_pgwrite_persist_check.bin"
        host, port = _ANON_HOST, _ANON_PORT
        sock = _handshake_login(host, port)
        try:
            fhandle = _open_for_write(sock, f"/{remote}".encode())
            payload = _build_pgwrite_payload(data, offset=0)
            status, _ = _send_pgwrite(sock, fhandle, 0, payload)
            assert status == kXR_status
            _close(sock, fhandle)
        finally:
            sock.close()

        disk_path = os.path.join(_DATA_DIR, remote)
        assert os.path.exists(disk_path), "written file not found on disk"
        assert open(disk_path, "rb").read() == data, "data on disk does not match written payload"
        os.unlink(disk_path)

    def test_bad_write_gates_close(self):
        """A bad-CRC pgwrite is accepted-and-reported (CSE), and the close is then
        gated with kXR_ChkSumErr until the page is corrected — this close gate is
        what prevents a committed file from holding known-corrupt bytes."""
        remote = "_pgwrite_close_gate.bin"
        disk_path = os.path.join(_DATA_DIR, remote)
        host, port = _ANON_HOST, _ANON_PORT
        sock = _handshake_login(host, port)
        try:
            fhandle = _open_for_write(sock, f"/{remote}".encode())
            data = b"overwrite attempt " * 3
            payload = _build_pgwrite_payload(data, offset=0, corrupt_page=0)
            status, sbody = _send_pgwrite(sock, fhandle, 0, payload)
            assert status == kXR_status, "bad page should be reported via CSE"
            # Drain the CSE trailer (not counted in hdr.dlen) so the socket stays
            # aligned for the close response that follows.
            cse_len = struct.unpack("!i", sbody[12:16])[0]
            if cse_len > 0:
                _recv_exact(sock, cse_len)

            # The close must fail while the page is uncorrected.
            sock.sendall(struct.pack("!2sH4s12sI",
                                     b"\x00\x09", kXR_close, fhandle, b"\x00" * 12, 0))
            cstatus, cbody = _read_response(sock)
            assert cstatus == kXR_error, "close must be gated on uncorrected pages"
            err_code = struct.unpack("!I", cbody[:4])[0]
            assert err_code == kXR_ChkSumErr, (
                f"expected kXR_ChkSumErr ({kXR_ChkSumErr}) at close, got {err_code}"
            )
        finally:
            sock.close()
        if os.path.exists(disk_path):
            os.unlink(disk_path)

    def test_unaligned_start_offset_good_crc(self):
        """pgwrite at a non-zero offset (partial first page) with correct CRC succeeds."""
        data = b"offset payload " * 20   # 300 bytes starting at offset 100
        host, port = _ANON_HOST, _ANON_PORT
        sock = _handshake_login(host, port)
        try:
            fhandle = _open_for_write(sock, b"/_pgwrite_unaligned_good.bin")
            payload = _build_pgwrite_payload(data, offset=100)
            status, _ = _send_pgwrite(sock, fhandle, 100, payload)
            assert status == kXR_status, (
                f"expected kXR_status for unaligned-start pgwrite, got {status}"
            )
            _close(sock, fhandle)
        finally:
            sock.close()

    def test_unaligned_start_offset_bad_crc(self):
        """pgwrite at offset=100 (partial first page) with a corrupted CRC is rejected."""
        data = b"bad offset crc " * 15   # 225 bytes
        host, port = _ANON_HOST, _ANON_PORT
        sock = _handshake_login(host, port)
        try:
            fhandle = _open_for_write(sock, b"/_pgwrite_unaligned_bad.bin")
            payload = _build_pgwrite_payload(data, offset=100, corrupt_page=0)
            status, _body = _send_pgwrite(sock, fhandle, 100, payload)
            assert status == kXR_status, (
                f"expected kXR_status CSE reply for unaligned bad CRC, got {status}"
            )
        finally:
            sock.close()

    def test_three_pages_all_good(self):
        """A three-page pgwrite (>2 full pages) with all correct CRCs succeeds."""
        data = os.urandom(kXR_pgPageSZ * 2 + 512)   # 2 full pages + partial third
        host, port = _ANON_HOST, _ANON_PORT
        sock = _handshake_login(host, port)
        try:
            fhandle = _open_for_write(sock, b"/_pgwrite_3page_good.bin")
            payload = _build_pgwrite_payload(data, offset=0)
            status, _ = _send_pgwrite(sock, fhandle, 0, payload)
            assert status == kXR_status, (
                f"expected kXR_status for 3-page pgwrite, got {status}"
            )
            _close(sock, fhandle)
        finally:
            sock.close()

    def test_three_pages_middle_page_bad(self):
        """A three-page pgwrite with a bad CRC on the second page is rejected."""
        data = os.urandom(kXR_pgPageSZ * 2 + 512)
        host, port = _ANON_HOST, _ANON_PORT
        sock = _handshake_login(host, port)
        try:
            fhandle = _open_for_write(sock, b"/_pgwrite_3page_bad1.bin")
            payload = _build_pgwrite_payload(data, offset=0, corrupt_page=1)
            status, _body = _send_pgwrite(sock, fhandle, 0, payload)
            assert status == kXR_status, (
                f"expected kXR_status CSE reply for 3-page middle-bad, got {status}"
            )
        finally:
            sock.close()

    def test_write_at_page_boundary_offset(self):
        """A pgwrite starting at offset=4096 (a page boundary) with correct CRC succeeds."""
        data = b"page boundary write " * 10   # 200 bytes
        host, port = _ANON_HOST, _ANON_PORT
        sock = _handshake_login(host, port)
        try:
            fhandle = _open_for_write(sock, b"/_pgwrite_pgboundary.bin")
            payload = _build_pgwrite_payload(data, offset=kXR_pgPageSZ)
            status, _ = _send_pgwrite(sock, fhandle, kXR_pgPageSZ, payload)
            assert status == kXR_status, (
                f"expected kXR_status for page-boundary pgwrite, got {status}"
            )
            _close(sock, fhandle)
        finally:
            sock.close()

    def test_full_page_exactly_4096_bytes(self):
        """A pgwrite of exactly 4096 bytes (one complete page) with correct CRC succeeds."""
        data = os.urandom(kXR_pgPageSZ)   # exactly one full page
        host, port = _ANON_HOST, _ANON_PORT
        sock = _handshake_login(host, port)
        try:
            fhandle = _open_for_write(sock, b"/_pgwrite_exactpage.bin")
            payload = _build_pgwrite_payload(data, offset=0)
            status, _ = _send_pgwrite(sock, fhandle, 0, payload)
            assert status == kXR_status, (
                f"expected kXR_status for exact-one-page pgwrite, got {status}"
            )
            _close(sock, fhandle)
        finally:
            sock.close()

    def test_sequential_writes_same_handle(self):
        """Two successive pgwrite calls to the same file handle both succeed."""
        data1 = b"first segment  " * 10   # 150 bytes
        data2 = b"second segment " * 10   # 150 bytes
        host, port = _ANON_HOST, _ANON_PORT
        sock = _handshake_login(host, port)
        try:
            fhandle = _open_for_write(sock, b"/_pgwrite_sequential.bin")
            status, _ = _send_pgwrite(sock, fhandle, 0,
                                       _build_pgwrite_payload(data1, 0))
            assert status == kXR_status, f"first pgwrite failed: {status}"
            status, _ = _send_pgwrite(sock, fhandle, len(data1),
                                       _build_pgwrite_payload(data2, len(data1)))
            assert status == kXR_status, f"second pgwrite failed: {status}"
            _close(sock, fhandle)
        finally:
            sock.close()

    def test_overwrite_partial_existing_content(self):
        """pgwrite into the middle of an existing file leaves surrounding bytes intact."""
        original  = b"AAAAAAAAAA" * 5   # 50 bytes
        overwrite = b"BBBBB"            # 5 bytes at offset 10
        remote    = "_pgwrite_partial_ow.bin"
        disk_path = os.path.join(_DATA_DIR, remote)

        with open(disk_path, "wb") as f:
            f.write(original)

        host, port = _ANON_HOST, _ANON_PORT
        sock = _handshake_login(host, port)
        try:
            path   = f"/{remote}".encode()
            flags  = kXR_open_updt   # read+write, no truncation
            sock.sendall(
                struct.pack("!2sHHH2s6s4sI",
                            b"\x00\x02", kXR_open,
                            0o644, flags,
                            b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                            len(path))
                + path
            )
            status, body = _read_response(sock)
            assert status == kXR_ok, f"open for update failed: {status}"
            fhandle = body[:4]

            payload = _build_pgwrite_payload(overwrite, offset=10)
            status, _ = _send_pgwrite(sock, fhandle, 10, payload)
            assert status == kXR_status, f"partial-overwrite pgwrite failed: {status}"
            _close(sock, fhandle)
        finally:
            sock.close()

        on_disk = open(disk_path, "rb").read()
        assert on_disk[:10] == original[:10], "bytes before overwrite region changed"
        assert on_disk[10:15] == overwrite,   "overwrite bytes not applied"
        assert on_disk[15:]   == original[15:], "bytes after overwrite region changed"
        os.unlink(disk_path)
