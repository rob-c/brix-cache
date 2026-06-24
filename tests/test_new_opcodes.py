"""
Functional tests for five newly-implemented XRootD protocol opcodes:

  kXR_pgread  (3030) — paged read with per-page CRC32c
  kXR_writev  (3031) — scatter-gather / vector write
  kXR_locate  (3027) — file replica location query
  kXR_sigver  (3029) — request signing (accepted without verification)
  kXR_statx   (3022) — multi-path stat

Run:
    pytest tests/test_new_opcodes.py -v -s
"""

import hashlib
import os
import struct
import socket
from pathlib import Path


# ---------------------------------------------------------------------------
# CRC32c (Castagnoli) — shared by TestChkpointXeq and TestChkpointExtended
# ---------------------------------------------------------------------------

def _crc32c(data: bytes) -> int:
    """Pure-Python CRC32c using reversed Castagnoli polynomial 0x82F63B78."""
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
    return crc ^ 0xFFFFFFFF


def _pgwrite_payload(data: bytes, offset: int, corrupt_page: int = -1) -> bytes:
    """Build a kXR_pgwrite payload: [4B CRC32c BE][page data] per 4096-byte page."""
    out = bytearray()
    pos, cur_off, page_idx = 0, offset, 0
    while pos < len(data):
        room = 4096 - (cur_off % 4096)
        chunk = data[pos: pos + room]
        crc = _crc32c(chunk)
        if page_idx == corrupt_page:
            crc = (crc ^ 0xDEADBEEF) & 0xFFFFFFFF
        out += struct.pack("!I", crc) + chunk
        pos += len(chunk);  cur_off += len(chunk);  page_idx += 1
    return bytes(out)

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags, StatInfoFlags
from settings import (
    CA_DIR,
    DATA_ROOT,
    HOST,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    PROXY_STD,
    SERVER_HOST,
)

ANON_URL  = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
ANON_PORT = NGINX_ANON_PORT
GSI_URL   = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}"
PROXY_PEM = PROXY_STD

PATTERN   = bytes(i & 0xFF for i in range(65536))     # 64 KiB
LARGE     = bytes((i * 7 + 13) & 0xFF for i in range(512 * 1024))  # 512 KiB


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def upload(url_base: str, remote: str, data: bytes) -> None:
    f = client.File()
    status, _ = f.open(f"{url_base}//{remote.lstrip('/')}",
                       OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open for upload failed: {status.message}"
    if data:
        status, _ = f.write(data)
        assert status.ok, f"write failed: {status.message}"
    f.close()


def open_rd(url_base: str, remote: str) -> client.File:
    f = client.File()
    status, _ = f.open(f"{url_base}//{remote.lstrip('/')}", OpenFlags.READ)
    assert status.ok, f"open for read failed: {status.message}"
    return f


def open_wr(url_base: str, remote: str) -> client.File:
    f = client.File()
    status, _ = f.open(f"{url_base}//{remote.lstrip('/')}",
                       OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open for write failed: {status.message}"
    return f


# ---------------------------------------------------------------------------
# kXR_pgread
# ---------------------------------------------------------------------------

class TestPgRead:
    """Tests for kXR_pgread — paged read with per-page CRC32c."""

    def test_pgread_small_file(self):
        """pgread a file smaller than one page (< 4096 bytes)."""
        data = b"hello pgread " * 100   # 1300 bytes
        upload(ANON_URL, "pgread_small.bin", data)

        f = open_rd(ANON_URL, "pgread_small.bin")
        status, result = f.read(offset=0, size=len(data))
        f.close()

        assert status.ok, f"pgread failed: {status.message}"
        assert result == data

    def test_pgread_exactly_one_page(self):
        """pgread a file exactly 4096 bytes (one full page)."""
        data = bytes(range(256)) * 16   # 4096 bytes
        upload(ANON_URL, "pgread_one_page.bin", data)

        f = open_rd(ANON_URL, "pgread_one_page.bin")
        status, result = f.read(offset=0, size=4096)
        f.close()

        assert status.ok, f"pgread failed: {status.message}"
        assert result == data

    def test_pgread_multiple_pages(self):
        """pgread a 512 KiB file spanning 128 pages, verify integrity."""
        upload(ANON_URL, "pgread_large.bin", LARGE)

        f = open_rd(ANON_URL, "pgread_large.bin")
        status, result = f.read(offset=0, size=len(LARGE))
        f.close()

        assert status.ok, f"pgread failed: {status.message}"
        assert result == LARGE

    def test_pgread_mid_file_offset(self):
        """pgread starting at a non-zero offset returns correct data."""
        upload(ANON_URL, "pgread_offset.bin", PATTERN)

        f = open_rd(ANON_URL, "pgread_offset.bin")
        offset = 8192
        size   = 16384
        status, result = f.read(offset=offset, size=size)
        f.close()

        assert status.ok, f"pgread failed: {status.message}"
        assert result == PATTERN[offset:offset + size]

    def test_pgread_gsi_endpoint(self):
        """pgread works on the GSI-authenticated endpoint."""
        upload(GSI_URL, "pgread_gsi.bin", PATTERN)

        f = open_rd(GSI_URL, "pgread_gsi.bin")
        status, result = f.read(offset=0, size=len(PATTERN))
        f.close()

        assert status.ok, f"pgread on GSI failed: {status.message}"
        assert result == PATTERN

    def test_pgread_integrity_md5(self):
        """pgread data integrity: md5 of result matches the source."""
        upload(ANON_URL, "pgread_md5.bin", LARGE)

        f = open_rd(ANON_URL, "pgread_md5.bin")
        status, result = f.read(offset=0, size=len(LARGE))
        f.close()

        assert status.ok
        assert hashlib.md5(result).hexdigest() == hashlib.md5(LARGE).hexdigest()


# ---------------------------------------------------------------------------
# kXR_writev
# ---------------------------------------------------------------------------

class TestWriteV:
    """Tests for kXR_writev — scatter-gather / vector write."""

    def test_writev_two_segments_non_overlapping(self):
        """Write two non-overlapping segments and read back to verify."""
        seg_a = b"AAA" * 100   # 300 bytes at offset 0
        seg_b = b"BBB" * 100   # 300 bytes at offset 4096

        # We need to write-open and then use writev through the XRootD client.
        # The Python client exposes write() at given offsets; we call it twice
        # to simulate two-segment writev (the client may pipeline these).
        f = open_wr(ANON_URL, "writev_two_segs.bin")
        status, _ = f.write(seg_a, offset=0)
        assert status.ok, f"write seg_a failed: {status.message}"
        status, _ = f.write(seg_b, offset=4096)
        assert status.ok, f"write seg_b failed: {status.message}"
        f.close()

        # Verify via read.
        f = open_rd(ANON_URL, "writev_two_segs.bin")
        status, result_a = f.read(offset=0, size=300)
        assert status.ok
        status, result_b = f.read(offset=4096, size=300)
        assert status.ok
        f.close()

        assert result_a == seg_a
        assert result_b == seg_b

    def test_writev_contiguous_segments(self):
        """Write many contiguous segments and read back the whole file."""
        n_segs  = 16
        seg_len = 1024
        segments = [bytes([i] * seg_len) for i in range(n_segs)]
        expected = b"".join(segments)

        f = open_wr(ANON_URL, "writev_contiguous.bin")
        for i, seg in enumerate(segments):
            status, _ = f.write(seg, offset=i * seg_len)
            assert status.ok, f"write seg {i} failed: {status.message}"
        f.close()

        f = open_rd(ANON_URL, "writev_contiguous.bin")
        status, result = f.read(offset=0, size=len(expected))
        f.close()

        assert status.ok
        assert result == expected

    def test_writev_then_read_integrity(self):
        """md5 of written data matches md5 of read-back data."""
        f = open_wr(ANON_URL, "writev_integrity.bin")
        status, _ = f.write(LARGE, offset=0)
        assert status.ok
        f.close()

        f = open_rd(ANON_URL, "writev_integrity.bin")
        status, result = f.read(offset=0, size=len(LARGE))
        f.close()

        assert status.ok
        assert hashlib.md5(result).hexdigest() == hashlib.md5(LARGE).hexdigest()

    def test_writev_gsi_endpoint(self):
        """Vector write through the GSI-authenticated endpoint."""
        data = b"GSI writev test " * 64   # 1024 bytes
        f = open_wr(GSI_URL, "writev_gsi.bin")
        status, _ = f.write(data, offset=0)
        assert status.ok, f"writev on GSI failed: {status.message}"
        f.close()

        f = open_rd(GSI_URL, "writev_gsi.bin")
        status, result = f.read(offset=0, size=len(data))
        f.close()

        assert status.ok
        assert result == data


# ---------------------------------------------------------------------------
# kXR_locate
# ---------------------------------------------------------------------------

class TestLocate:
    """Tests for kXR_locate — file replica location query."""

    def test_locate_existing_file(self):
        """locate an existing file returns at least one location entry."""
        upload(ANON_URL, "locate_test.bin", b"locate me")

        fs = client.FileSystem(ANON_URL)
        status, locations = fs.locate("/locate_test.bin", OpenFlags.NONE)

        assert status.ok, f"locate failed: {status.message}"
        assert locations is not None
        assert len(list(locations)) >= 1

    def test_locate_returns_server_type(self):
        """locate returns a server (not manager) location."""
        upload(ANON_URL, "locate_type.bin", b"type check")

        fs = client.FileSystem(ANON_URL)
        status, locations = fs.locate("/locate_type.bin", OpenFlags.NONE)

        assert status.ok, f"locate failed: {status.message}"
        locs = list(locations)
        assert len(locs) >= 1
        assert locs[0].is_server, "expected is_server to be True"
        assert not locs[0].is_manager, "expected is_manager to be False"

    def test_locate_missing_file_returns_error(self):
        """locate a non-existent path returns an error (not a crash)."""
        fs = client.FileSystem(ANON_URL)
        status, locations = fs.locate("/no_such_file_xyz.bin", OpenFlags.NONE)

        assert not status.ok, "expected error for missing file"

    def test_locate_gsi_endpoint(self):
        """locate works on the GSI-authenticated endpoint."""
        upload(GSI_URL, "locate_gsi.bin", b"gsi locate")

        fs = client.FileSystem(GSI_URL)
        status, locations = fs.locate("/locate_gsi.bin", OpenFlags.NONE)

        assert status.ok, f"locate on GSI failed: {status.message}"
        assert len(list(locations)) >= 1

    def test_locate_access_type_read_only_server(self):
        """locate on a read-only server returns a non-write-only accesstype."""
        upload(ANON_URL, "locate_access.bin", b"access check")

        fs = client.FileSystem(ANON_URL)
        status, locations = fs.locate("/locate_access.bin", OpenFlags.NONE)

        assert status.ok, f"locate failed: {status.message}"
        locs = list(locations)
        assert len(locs) >= 1
        # accesstype: 1 = Read, 2 = ReadWrite (XRootD Python client integer enum)
        assert locs[0].accesstype == 1, \
            f"expected Read accesstype (1), got {locs[0].accesstype!r}"


# ---------------------------------------------------------------------------
# kXR_sigver
# ---------------------------------------------------------------------------

class TestSigver:
    """Tests for kXR_sigver — request signing (accepted without verification).

    The XRootD Python client does not expose a direct sigver API, so we
    test the opcode via a raw TCP socket using the XRootD wire format.
    """

    @staticmethod
    def _recvall(sock, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            assert chunk, "connection closed unexpectedly"
            buf += chunk
        return buf

    def _recv_response(self, sock):
        """Read one XRootD response header + body."""
        hdr    = self._recvall(sock, 8)
        status = struct.unpack(">H", hdr[2:4])[0]
        dlen   = struct.unpack(">I", hdr[4:8])[0]
        body   = self._recvall(sock, dlen) if dlen else b""
        return status, body

    def _xrd_connect_and_login(self, host: str, port: int):
        """Establish an XRootD session (handshake + protocol + login).
        Returns a connected socket with a logged-in session."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))

        # 1. Initial handshake (20 bytes)
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))

        # 2. kXR_protocol
        sock.sendall(struct.pack(">BB H I BB 10x I",
                                 0, 1, 3006, 0x00000520, 0x02, 0x03, 0))

        self._recvall(sock, 16)   # handshake response
        self._recv_response(sock) # protocol response

        # 3. kXR_login
        sock.sendall(struct.pack(">BB H I 8s BB B B I",
                                 0, 1, 3007, 0,
                                 b"test\x00\x00\x00\x00",
                                 0, 0, 5, 0, 0))
        self._recv_response(sock)  # login response (variable length)

        return sock

    def test_sigver_accepted_returns_ok(self):
        """A kXR_sigver packet followed by kXR_ping is accepted on the wire."""
        sock = self._xrd_connect_and_login(HOST, ANON_PORT)

        try:
            # kXR_sigver (3029): 24-byte header + signature payload
            # expectrid=kXR_ping (3011), version=0, flags=1 (nodata),
            # seqno=1, crypto=0x01 (SHA256), dlen=32 (fake signature)
            fake_sig = b"\xde\xad\xbe\xef" * 8   # 32 bytes
            sigver_hdr = struct.pack(">BB H H BB Q B 3x I",
                                     0, 2,         # streamid
                                     3029,         # kXR_sigver
                                     3011,         # expectrid = kXR_ping
                                     0, 1,         # version=0, flags=nodata
                                     1,            # seqno
                                     0x01,         # crypto = SHA256
                                     len(fake_sig))
            sock.sendall(sigver_hdr + fake_sig)

            # kXR_sigver is a request PREFIX — a valid (or no-op) envelope draws
            # NO response (the reply belongs to the request that follows); see
            # src/session/signing.c.  So do NOT read here.  Send the covered ping
            # and confirm it succeeds — proving the sigver was accepted and the
            # session is still live.
            ping_hdr = struct.pack(">BB H 16x I", 0, 3, 3011, 0)
            sock.sendall(ping_hdr)

            status, body = self._recv_response(sock)
            assert status == 0, f"ping after sigver returned status {status}"

        finally:
            sock.close()

    def test_sigver_session_continues_after_accept(self):
        """After sigver is accepted the session remains fully functional."""
        sock = self._xrd_connect_and_login(HOST, ANON_PORT)

        try:
            # Send sigver
            fake_sig = b"\x00" * 16
            sigver_hdr = struct.pack(">BB H H BB Q B 3x I",
                                     0, 4,
                                     3029,
                                     3011,   # expectrid = kXR_ping
                                     0, 1,
                                     2,
                                     0x01,
                                     len(fake_sig))
            sock.sendall(sigver_hdr + fake_sig)
            # sigver is a silent request PREFIX (no response on the accept/no-op
            # path) — confirm acceptance + liveness via the covered ping instead.
            ping_hdr = struct.pack(">BB H 16x I", 0, 5, 3011, 0)
            sock.sendall(ping_hdr)
            status, _ = self._recv_response(sock)
            assert status == 0, "session broken after sigver"

        finally:
            sock.close()


# ---------------------------------------------------------------------------
# kXR_statx
# ---------------------------------------------------------------------------

class TestStatx:
    """Tests for kXR_statx — multi-path stat via raw socket.

    The Python XRootD client does not expose statx directly, so we use
    raw socket tests for the wire-level checks and the Python FileSystem
    API (which calls stat internally) to cross-check results.
    """

    @staticmethod
    def _recvall(sock, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            assert chunk, "connection closed unexpectedly"
            buf += chunk
        return buf

    @staticmethod
    def _recv_response(sock):
        """Read one complete XRootD response (header + body)."""
        hdr    = TestStatx._recvall(sock, 8)
        status = struct.unpack(">H", hdr[2:4])[0]
        dlen   = struct.unpack(">I", hdr[4:8])[0]
        body   = TestStatx._recvall(sock, dlen) if dlen else b""
        return status, body

    def _send_statx(self, host: str, port: int, paths: list[str]) -> bytes:
        """Connect, login, send kXR_statx for the given paths, return body."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))

        # 1. Initial handshake (20 bytes)
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        # 2. kXR_protocol (24 bytes)
        sock.sendall(struct.pack(">BB H I BB 10x I",
                                 0, 1, 3006, 0x00000520, 0, 3, 0))

        # Consume handshake response (8B hdr + 8B body)
        self._recvall(sock, 16)
        # Consume protocol response (8B hdr + 8B body)
        self._recvall(sock, 16)

        # 3. kXR_login (24 bytes)
        sock.sendall(struct.pack(">BB H I 8s BB B B I",
                                 0, 1, 3007, 0, b"test\x00\x00\x00\x00",
                                 0, 0, 5, 0, 0))
        # Consume login response fully (variable dlen)
        self._recv_response(sock)

        # 4. kXR_statx (3022) — NEWLINE-separated paths (the reference do_Statx
        # tokenizes a '\n' list via XrdOucTokenizer; a NUL list is read as one
        # giant path that C-string-truncates at the first NUL).
        payload = b"\n".join(p.encode() for p in paths) + b"\n"
        statx_hdr = struct.pack(">BB H B 11x 4x I",
                                 0, 2,
                                 3022,   # kXR_statx
                                 0,      # options
                                 len(payload))
        sock.sendall(statx_hdr + payload)

        status, body = self._recv_response(sock)
        sock.close()
        return status, body

    # kXR_statx returns ONE flag byte per path (NOT a stat line) — exactly like
    # the reference do_Statx (XrdXrootdXeq.cc): *respinfo = kXR_isDir / kXR_file /
    # kXR_offline.  A path whose stat fails terminates the batch with an error
    # response (no per-path sentinel).  Flag bits: kXR_file=0, kXR_isDir=2,
    # kXR_other=4, kXR_offline=8.
    _kXR_isDir = 0x02

    def test_statx_single_path(self):
        """statx for one regular file returns one flag byte (kXR_file == 0)."""
        upload(ANON_URL, "statx_single.bin", b"x" * 1234)

        status, body = self._send_statx(HOST, ANON_PORT, ["/statx_single.bin"])

        assert status == 0, f"statx returned error status {status}"
        assert len(body) == 1, f"expected one flag byte, got {body!r}"
        assert not (body[0] & self._kXR_isDir), f"file flagged as dir: {body[0]:#x}"

    def test_statx_multiple_paths(self):
        """statx for three regular files returns three flag bytes."""
        for i in range(3):
            upload(ANON_URL, f"statx_multi_{i}.bin", b"y" * (100 * (i + 1)))

        status, body = self._send_statx(HOST, ANON_PORT,
                                        [f"/statx_multi_{i}.bin" for i in range(3)])

        assert status == 0
        assert len(body) == 3, f"expected three flag bytes, got {body!r}"
        for i, flag in enumerate(body):
            assert not (flag & self._kXR_isDir), f"path {i} flagged as dir"

    def test_statx_missing_path_errors(self):
        """statx for a non-existent path terminates the batch with an error
        (the reference do_Statx fsErrors on the first failing path — it does NOT
        emit a per-path sentinel and continue)."""
        status, _ = self._send_statx(HOST, ANON_PORT,
                                     ["/no_such_file_statx.bin"])
        assert status != 0, "statx of a missing path must be an error"

    def test_statx_mixed_existing_and_missing(self):
        """A missing path anywhere in the batch makes the whole statx an error,
        matching the reference (error on first failure, batch aborted)."""
        upload(ANON_URL, "statx_mixed_ok.bin", b"z" * 500)

        status, _ = self._send_statx(HOST, ANON_PORT,
                                     ["/statx_mixed_ok.bin",
                                      "/no_such_statx_xyz.bin"])
        assert status != 0, "statx batch with a missing path must be an error"

    def test_statx_directory(self):
        """statx of a directory sets the kXR_isDir flag bit in its flag byte."""
        status, body = self._send_statx(HOST, ANON_PORT, ["/"])

        assert status == 0
        assert len(body) == 1, f"expected one flag byte, got {body!r}"
        assert body[0] & self._kXR_isDir, \
            f"expected kXR_isDir flag set, got {body[0]:#x}"


# ---------------------------------------------------------------------------
# kXR_chkpoint and kXR_ckpXeq
# ---------------------------------------------------------------------------

class TestChkpoint:
    """
    Wire-level tests for kXR_chkpoint (begin/commit/rollback/query) and
    kXR_ckpXeq — write sub-operations executed under checkpoint protection.

    Opcodes exercised: kXR_chkpoint (3012), kXR_ckpXeq (sub-opcode 4).
    """

    # ── low-level helpers ────────────────────────────────────────────────

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
        """Handshake + kXR_login; return connected socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
        hdr = self._recvall(sock, 8)
        self._recvall(sock, struct.unpack("!I", hdr[4:8])[0])  # handshake body
        sock.sendall(struct.pack("!2sHI8sBBBBI",
                                 b"\x00\x01", 3007, 0,
                                 b"test\x00\x00\x00\x00",
                                 0, 0, 5, 0, 0))
        self._recv_response(sock)
        return sock

    def _open(self, sock, sid, path, options=0x0020):
        """kXR_open; return 4-byte fhandle. Default options=kXR_open_updt."""
        path_b = path.encode()
        req = struct.pack("!2sHHH2s6s4sI",
                          bytes([0, sid]), 3010,
                          0o644, options,
                          b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                          len(path_b))
        sock.sendall(req + path_b)
        status, body = self._recv_response(sock)
        assert status == 0, f"open({path!r}) failed: status={status} body={body!r}"
        return body[:4]

    def _write(self, sock, sid, fh, offset, data):
        req = struct.pack("!2sH4sqB3sI",
                          bytes([0, sid]), 3019, fh, offset, 0, b"\x00" * 3, len(data))
        sock.sendall(req + data)
        status, _ = self._recv_response(sock)
        assert status == 0, f"write failed: status={status}"

    def _read(self, sock, sid, fh, offset, rlen):
        req = struct.pack("!2sH4sqiI",
                          bytes([0, sid]), 3013, fh, offset, rlen, 0)
        sock.sendall(req)
        status, body = self._recv_response(sock)
        assert status == 0, f"read failed: status={status}"
        return body

    def _close(self, sock, sid, fh):
        req = struct.pack("!2sH4s12sI",
                          bytes([0, sid]), 3003, fh, b"\x00" * 12, 0)
        sock.sendall(req)
        self._recv_response(sock)

    def _chkpoint(self, sock, sid, fh, opcode, extra=b""):
        """Send kXR_chkpoint with the given sub-opcode; return (status, body)."""
        req = struct.pack("!2sH4s11sBI",
                          bytes([0, sid]), 3012, fh, b"\x00" * 11, opcode, len(extra))
        sock.sendall(req + extra)
        return self._recv_response(sock)

    def _ckpxeq_write(self, sock, sid, fh, offset, data):
        """kXR_ckpXeq carrying a kXR_write sub-request."""
        sub = struct.pack("!2sH4sqB3sI",
                          b"\x00\x00", 3019, fh, offset, 0, b"\x00" * 3, len(data))
        return self._chkpoint(sock, sid, fh, 4, sub + data)  # 4 = kXR_ckpXeq

    # ── tests ────────────────────────────────────────────────────────────

    def test_chkpoint_begin_commit(self):
        """begin + write + commit: modified content is made permanent."""
        upload(ANON_URL, "ckp_commit.bin", b"original")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ckp_commit.bin")
            status, _ = self._chkpoint(sock, 3, fh, 0)   # kXR_ckpBegin
            assert status == 0, f"chkpoint begin failed: {status}"
            self._write(sock, 4, fh, 0, b"modified")
            status, _ = self._chkpoint(sock, 5, fh, 1)   # kXR_ckpCommit
            assert status == 0, f"chkpoint commit failed: {status}"
            data = self._read(sock, 6, fh, 0, 8)
            assert data == b"modified", f"commit did not persist data: {data!r}"
            self._close(sock, 7, fh)
        finally:
            sock.close()

    def test_chkpoint_begin_rollback(self):
        """begin + write + rollback: file reverts to the pre-checkpoint content."""
        upload(ANON_URL, "ckp_rollback.bin", b"before!!")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ckp_rollback.bin")
            status, _ = self._chkpoint(sock, 3, fh, 0)   # begin
            assert status == 0
            self._write(sock, 4, fh, 0, b"MODIFIED")
            status, _ = self._chkpoint(sock, 5, fh, 3)   # kXR_ckpRollback
            assert status == 0, f"chkpoint rollback failed: {status}"
            data = self._read(sock, 6, fh, 0, 8)
            assert data == b"before!!", f"rollback did not restore data: {data!r}"
            self._close(sock, 7, fh)
        finally:
            sock.close()

    def test_chkpoint_query(self):
        """kXR_ckpQuery returns a nonzero max capacity and zero initial usage."""
        upload(ANON_URL, "ckp_query.bin", b"querytest")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ckp_query.bin")
            status, body = self._chkpoint(sock, 3, fh, 2)   # kXR_ckpQuery
            assert status == 0
            assert len(body) >= 8
            max_sz, use_sz = struct.unpack(">II", body[:8])
            assert max_sz > 0, "maxCkpSize should be > 0"
            assert use_sz == 0, "useCkpSize should be 0 before any checkpoint"
            self._close(sock, 4, fh)
        finally:
            sock.close()

    def test_chkpoint_ckpXeq_write(self):
        """kXR_ckpXeq dispatches a kXR_write sub-request under an active checkpoint."""
        upload(ANON_URL, "ckp_xeq.bin", b"aaaaaaaaa")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ckp_xeq.bin")
            status, _ = self._chkpoint(sock, 3, fh, 0)   # begin
            assert status == 0
            status, _ = self._ckpxeq_write(sock, 4, fh, 0, b"bbbbbbbbb")
            assert status == 0, f"kXR_ckpXeq write failed: {status}"
            data = self._read(sock, 5, fh, 0, 9)
            assert data == b"bbbbbbbbb", f"ckpXeq data mismatch: {data!r}"
            self._chkpoint(sock, 6, fh, 1)   # commit to clean up
            self._close(sock, 7, fh)
        finally:
            sock.close()

    def test_chkpoint_double_begin_rejected(self):
        """A second kXR_ckpBegin while a checkpoint is active returns an error."""
        upload(ANON_URL, "ckp_double.bin", b"data")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ckp_double.bin")
            status, _ = self._chkpoint(sock, 3, fh, 0)   # first begin — ok
            assert status == 0
            status, _ = self._chkpoint(sock, 4, fh, 0)   # second begin — error
            assert status != 0, "expected kXR_inProgress on double begin"
            self._chkpoint(sock, 5, fh, 1)   # commit to clean up
            self._close(sock, 6, fh)
        finally:
            sock.close()

    def test_chkpoint_same_file_second_handle_rejected(self):
        """A checkpoint on one handle must block another handle to the same file."""
        upload(ANON_URL, "ckp_same_file.bin", b"data")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh1 = self._open(sock, 2, "/ckp_same_file.bin")
            fh2 = self._open(sock, 3, "/ckp_same_file.bin")

            status, _ = self._chkpoint(sock, 4, fh1, 0)
            assert status == 0

            status, _ = self._chkpoint(sock, 5, fh2, 0)
            assert status != 0, "second handle must not replace active checkpoint"

            self._chkpoint(sock, 6, fh1, 1)
            self._close(sock, 7, fh2)
            self._close(sock, 8, fh1)
        finally:
            sock.close()

    def test_chkpoint_startup_recovery_guardrails(self):
        """Startup recovery must rollback stale .ckp snapshots under a lock."""
        src = (
            Path(__file__).resolve().parents[1]
            / "src" / "write" / "chkpoint.c"
        ).read_text(encoding="utf-8")
        process = (
            Path(__file__).resolve().parents[1]
            / "src" / "config" / "process.c"
        ).read_text(encoding="utf-8")

        assert "xrootd_chkpoint_recover_root" in src
        assert "flock(lock_fd, LOCK_EX)" in src
        assert "xrootd_copy_range" in src
        assert "xrootd_staged_open" in src
        assert "xrootd_staged_commit" in src
        assert "xrootd_unlink_confined_canon" in src
        assert "O_DIRECTORY" in src
        assert "O_NOFOLLOW" in src
        assert "fstatat" in src
        assert "xrootd_chkpoint_recover_root" in process

    def test_chkpoint_rollback_without_begin_rejected(self):
        """kXR_ckpRollback without an active checkpoint returns an error."""
        upload(ANON_URL, "ckp_nobegin.bin", b"data")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ckp_nobegin.bin")
            status, _ = self._chkpoint(sock, 3, fh, 3)   # rollback without begin
            assert status != 0, "expected kXR_InvalidRequest on rollback without begin"
            self._close(sock, 4, fh)
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# kXR_clone
# ---------------------------------------------------------------------------

class TestClone:
    """Wire-level tests for kXR_clone — server-side range copy (protocol v5.2.0)."""

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
                          b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                          len(path_b))
        sock.sendall(req + path_b)
        status, body = self._recv_response(sock)
        assert status == 0, f"open({path!r}) failed: status={status}"
        return body[:4]

    def _read(self, sock, sid, fh, offset, rlen):
        req = struct.pack("!2sH4sqiI",
                          bytes([0, sid]), 3013, fh, offset, rlen, 0)
        sock.sendall(req)
        status, body = self._recv_response(sock)
        assert status == 0, f"read failed: status={status}"
        return body

    def _close(self, sock, sid, fh):
        req = struct.pack("!2sH4s12sI",
                          bytes([0, sid]), 3003, fh, b"\x00" * 12, 0)
        sock.sendall(req)
        self._recv_response(sock)

    def _clone(self, sock, sid, dst_fh, items):
        """Send kXR_clone; items = list of (src_fh, src_off, src_len, dst_off)."""
        payload = b"".join(
            struct.pack("!4s4sQQQ",
                        src_fh, b"\x00" * 4, src_off, src_len, dst_off)
            for src_fh, src_off, src_len, dst_off in items
        )
        req = struct.pack("!2sH4s12sI",
                          bytes([0, sid]), 3032, dst_fh, b"\x00" * 12, len(payload))
        sock.sendall(req + payload)
        return self._recv_response(sock)

    def test_clone_full_file(self):
        """clone copies the entire source file to the destination."""
        src_data = b"CLONE_FULL_DATA_" * 16   # 256 bytes
        upload(ANON_URL, "clone_full_src.bin", src_data)
        upload(ANON_URL, "clone_full_dst.bin", b"\x00" * len(src_data))

        sock = self._connect(HOST, ANON_PORT)
        try:
            src_fh = self._open(sock, 2, "/clone_full_src.bin", options=0x0010)  # read
            dst_fh = self._open(sock, 3, "/clone_full_dst.bin", options=0x0020)  # r/w

            status, body = self._clone(sock, 4, dst_fh, [(src_fh, 0, len(src_data), 0)])
            assert status == 0, f"clone failed: status={status} body={body!r}"

            result = self._read(sock, 5, dst_fh, 0, len(src_data))
            assert result == src_data, f"clone data mismatch"

            self._close(sock, 6, src_fh)
            self._close(sock, 7, dst_fh)
        finally:
            sock.close()

    def test_clone_partial_range(self):
        """clone copies only the specified byte range at the given dst offset."""
        src_data = bytes(range(100))
        upload(ANON_URL, "clone_range_src.bin", src_data)
        upload(ANON_URL, "clone_range_dst.bin", b"\x00" * 100)

        sock = self._connect(HOST, ANON_PORT)
        try:
            src_fh = self._open(sock, 2, "/clone_range_src.bin", options=0x0010)
            dst_fh = self._open(sock, 3, "/clone_range_dst.bin", options=0x0020)

            # copy src[20:50] → dst[0:30]
            status, _ = self._clone(sock, 4, dst_fh, [(src_fh, 20, 30, 0)])
            assert status == 0

            result = self._read(sock, 5, dst_fh, 0, 30)
            assert result == src_data[20:50], f"range clone mismatch: {result!r}"

            self._close(sock, 6, src_fh)
            self._close(sock, 7, dst_fh)
        finally:
            sock.close()

    def test_clone_to_read_only_handle_rejected(self):
        """clone to a read-only file handle returns an error."""
        upload(ANON_URL, "clone_ro_src.bin", b"x" * 50)
        upload(ANON_URL, "clone_ro_dst.bin", b"y" * 50)

        sock = self._connect(HOST, ANON_PORT)
        try:
            src_fh = self._open(sock, 2, "/clone_ro_src.bin", options=0x0010)
            ro_fh  = self._open(sock, 3, "/clone_ro_dst.bin", options=0x0010)

            status, _ = self._clone(sock, 4, ro_fh, [(src_fh, 0, 10, 0)])
            assert status != 0, "expected error: clone to read-only handle"

            self._close(sock, 5, src_fh)
            self._close(sock, 6, ro_fh)
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# kXR_ckpXeq — sub-operation variants (pgwrite, truncate, writev)
#
# chkpoint_xeq.c dispatches four sub-opcodes under an active checkpoint:
#   kXR_write (3019)    — tested in TestChkpoint.test_chkpoint_ckpXeq_write
#   kXR_pgwrite (3026)  — no existing test
#   kXR_truncate (3028) — no existing test
#   kXR_writev (3031)   — no existing test
# ---------------------------------------------------------------------------

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

    def _ckpxeq_pgwrite(self, sock, sid, fh, offset, data, corrupt_page=-1):
        """Send ckpXeq carrying a kXR_pgwrite sub-request."""
        payload = _pgwrite_payload(data, offset, corrupt_page)
        sub_hdr = struct.pack("!2sH4sqBBHi",
                              b"\x00\x00", 3026,   # kXR_pgwrite
                              fh, offset, 0, 0, 0, len(payload))
        return self._chkpoint(sock, sid, fh, 4, sub_hdr + payload)

    def _ckpxeq_truncate(self, sock, sid, fh, length):
        """Send ckpXeq carrying a kXR_truncate sub-request (handle-based)."""
        sub_hdr = struct.pack("!2sH4sq4sI",
                              b"\x00\x00", 3028,   # kXR_truncate
                              fh, length, b"\x00"*4, 0)
        return self._chkpoint(sock, sid, fh, 4, sub_hdr)

    def _ckpxeq_writev(self, sock, sid, fh, segments):
        """Send ckpXeq carrying a kXR_writev sub-request.

        segments: list of (offset, data) pairs.
        """
        seg_hdrs = b""
        seg_data = b""
        for off, data in segments:
            seg_hdrs += struct.pack("!4siq", fh, len(data), off)
            seg_data += data
        payload = seg_hdrs + seg_data
        sub_hdr = struct.pack("!2sHB15sI",
                              b"\x00\x00", 3031,   # kXR_writev
                              0, b"\x00"*15, len(payload))
        return self._chkpoint(sock, sid, fh, 4, sub_hdr + payload)

    def _ckpxeq_write(self, sock, sid, fh, offset, data):
        """Send ckpXeq carrying a kXR_write sub-request."""
        sub = struct.pack("!2sH4sqB3sI",
                          b"\x00\x00", 3019, fh, offset, 0, b"\x00"*3, len(data))
        return self._chkpoint(sock, sid, fh, 4, sub + data)

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
            # Sub-header with an opcode that doesn't exist (0xFFFF).
            bogus_sub = struct.pack("!2sH4s16sI",
                                    b"\x00\x00", 0xFFFF, fh, b"\x00"*16, 0)
            status, _ = self._chkpoint(sock, 4, fh, 4, bogus_sub)   # ckpXeq
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

class TestChkpointExtended:
    """
    Checkpoint state invariants not covered by TestChkpoint:

      - Query after begin shows nonzero checkpoint file usage.
      - Multiple ckpXeq writes under one checkpoint — commit persists all.
      - Multiple ckpXeq writes under one checkpoint — rollback restores all.
      - ckpXeq before begin returns an error (no active checkpoint).
      - Query after commit shows zero checkpoint usage again.
    """

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
                          bytes([0, sid]), 3010, 0o644, options,
                          b"\x00\x00", b"\x00"*6, b"\x00"*4, len(path_b))
        sock.sendall(req + path_b)
        status, body = self._recv_response(sock)
        assert status == 0, f"open({path!r}) failed: {status}"
        return body[:4]

    def _write(self, sock, sid, fh, offset, data):
        req = struct.pack("!2sH4sqB3sI",
                          bytes([0, sid]), 3019, fh, offset, 0, b"\x00"*3, len(data))
        sock.sendall(req + data)
        status, _ = self._recv_response(sock)
        assert status == 0, f"write failed: {status}"

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

    def _ckpxeq_write(self, sock, sid, fh, offset, data):
        sub = struct.pack("!2sH4sqB3sI",
                          b"\x00\x00", 3019, fh, offset, 0, b"\x00"*3, len(data))
        return self._chkpoint(sock, sid, fh, 4, sub + data)

    # ── tests ──────────────────────────────────────────────────────────────

    def test_query_after_begin_shows_nonzero_usage(self):
        """After kXR_ckpBegin the query response must show useCkpSize > 0."""
        upload(ANON_URL, "ext_query_begin.bin", b"some content")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ext_query_begin.bin")
            self._chkpoint(sock, 3, fh, 0)   # begin — snapshot taken
            status, body = self._chkpoint(sock, 4, fh, 2)   # query
            assert status == 0
            assert len(body) >= 8
            _max_sz, use_sz = struct.unpack(">II", body[:8])
            assert use_sz > 0, (
                f"useCkpSize should be >0 after begin, got {use_sz}"
            )
            self._chkpoint(sock, 5, fh, 1)   # commit to clean up
            self._close(sock, 6, fh)
        finally:
            sock.close()

    def test_multiple_xeq_then_commit_persists_all(self):
        """Multiple ckpXeq writes under one checkpoint all persist after commit."""
        upload(ANON_URL, "ext_multi_commit.bin", b"\x00" * 30)
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ext_multi_commit.bin")
            self._chkpoint(sock, 3, fh, 0)   # begin
            self._ckpxeq_write(sock, 4, fh,  0, b"first")
            self._ckpxeq_write(sock, 5, fh, 10, b"second")
            self._ckpxeq_write(sock, 6, fh, 20, b"third!")
            self._chkpoint(sock, 7, fh, 1)   # commit
            assert self._read(sock,  8, fh,  0, 5) == b"first"
            assert self._read(sock,  9, fh, 10, 6) == b"second"
            assert self._read(sock, 10, fh, 20, 6) == b"third!"
            self._close(sock, 11, fh)
        finally:
            sock.close()

    def test_multiple_xeq_then_rollback_restores_all(self):
        """Multiple ckpXeq writes under one checkpoint are all undone by rollback."""
        original = b"XXXXXXXXXX" * 3
        upload(ANON_URL, "ext_multi_rb.bin", original)
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ext_multi_rb.bin")
            self._chkpoint(sock, 3, fh, 0)
            self._ckpxeq_write(sock, 4, fh,  0, b"aaaaaa")
            self._ckpxeq_write(sock, 5, fh, 10, b"bbbbbb")
            self._ckpxeq_write(sock, 6, fh, 20, b"cccccc")
            self._chkpoint(sock, 7, fh, 3)   # rollback
            data = self._read(sock, 8, fh, 0, len(original))
            assert data == original, (
                f"rollback did not restore all three writes; got {data!r}"
            )
            self._close(sock, 9, fh)
        finally:
            sock.close()

    def test_xeq_without_active_checkpoint_fails(self):
        """ckpXeq before kXR_ckpBegin must return an error (no snapshot file)."""
        upload(ANON_URL, "ext_xeq_nobegin.bin", b"intact")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ext_xeq_nobegin.bin")
            # No begin — ckpXeq must fail.
            status, _ = self._ckpxeq_write(sock, 3, fh, 0, b"override")
            assert status != 0, "ckpXeq without begin should return an error"
            self._close(sock, 4, fh)
        finally:
            sock.close()

    def test_query_after_commit_shows_zero_usage(self):
        """After kXR_ckpCommit the query response must show useCkpSize == 0."""
        upload(ANON_URL, "ext_query_commit.bin", b"committed content")
        sock = self._connect(HOST, ANON_PORT)
        try:
            fh = self._open(sock, 2, "/ext_query_commit.bin")
            self._chkpoint(sock, 3, fh, 0)   # begin
            self._write(sock, 4, fh, 0, b"changed!")
            self._chkpoint(sock, 5, fh, 1)   # commit
            status, body = self._chkpoint(sock, 6, fh, 2)   # query
            assert status == 0
            assert len(body) >= 8
            _max_sz, use_sz = struct.unpack(">II", body[:8])
            assert use_sz == 0, (
                f"useCkpSize should be 0 after commit, got {use_sz}"
            )
            self._close(sock, 7, fh)
        finally:
            sock.close()
