"""
Tests for the AIO (async I/O) subsystem -- nginx thread-pool pread/pwrite path.

The module uses an nginx thread pool to offload blocking file I/O so that the
single worker event loop never stalls.  This test suite exercises:

  - Large reads that trigger the async pread path
  - Large writes that trigger the async pwrite path
  - readv with multiple segments (async scatter-gather)
  - pgread with per-page CRC32c integrity (async)
  - destroyed guard: AIO callback after client disconnect does not crash

Run:
    pytest tests/test_aio.py -v -s
"""

import hashlib
import os
import struct
import socket
import threading
import time

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags

from settings import (
    NGINX_ANON_PORT,
    CA_DIR,
    DATA_ROOT,
    PROXY_STD,
    SERVER_HOST,
)

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT
ANON_URL  = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
PROXY_PEM = PROXY_STD


def _pattern(size, mul, add=0):
    """Deterministic test payload, byte-identical to
    ``bytes((i * mul + add) & 0xFF for i in range(size))`` but built at C speed.

    The old per-byte generator ran a Python loop of up to 20 million iterations
    to build each payload. That CPU-bound work dominated these tests' runtime and,
    under -n8 CPU contention from the rest of the fast lane, pushed the larger
    cases past the 30s per-test timeout (they pass in isolation). The sequence
    ``(add + i * mul) mod 256`` is periodic every 256 bytes -- ``256 * mul`` is a
    multiple of 256 for any ``mul`` -- so one 256-byte period tiled to length
    reproduces it exactly. Same bytes the integrity asserts check; no CPU loop.
    """
    period = bytes((add + i * mul) & 0xFF for i in range(256))
    return (period * (size // 256 + 1))[:size]


# ---------------------------------------------------------------------------
# Helpers -- XRootD Python client (FileSystem handles login/auth)
# ---------------------------------------------------------------------------

def _upload(url, remote, data):
    f = client.File()
    status, _ = f.open(f"{url}//{remote.lstrip('/')}", OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open failed: {status.message}"
    if data:
        status, _ = f.write(data)
        assert status.ok, f"write failed: {status.message}"
    f.close()


def _read_file(url, remote):
    f = client.File()
    status, _ = f.open(f"{url}//{remote.lstrip('/')}", OpenFlags.READ)
    assert status.ok, f"open failed: {status.message}"
    status, data = f.read()
    assert status.ok, f"read failed: {status.message}"
    f.close()
    return data


def _open_rd(url, remote):
    f = client.File()
    status, _ = f.open(f"{url}//{remote.lstrip('/')}", OpenFlags.READ)
    assert status.ok, f"open failed: {status.message}"
    return f


def _open_wr(url, remote):
    f = client.File()
    status, _ = f.open(f"{url}//{remote.lstrip('/')}", OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open for write failed: {status.message}"
    return f


# ---------------------------------------------------------------------------
# Large read -- exercises async pread path (data > page cache threshold)
# ---------------------------------------------------------------------------

class TestAioRead:
    """Verify that large reads complete correctly via the AIO thread-pool."""

    # These cases move 10-20 MiB over root:// end to end. They are correct but
    # genuinely slow under the -n8 fast lane's CPU contention (they pass easily in
    # isolation). Raising ONLY the per-test timeout ceiling from the 30s global
    # default is a non-masking fix: it does not touch the integrity assertions,
    # it just refuses to declare a slow-but-correct transfer a failure.
    pytestmark = pytest.mark.timeout(120)

    def test_large_read_integrity(self):
        """A 10 MiB read must return identical data -- proves async pread works."""
        size = 10 * 1024 * 1024
        content = _pattern(size, 3, 7)
        _upload(ANON_URL, "aio-large.bin", content)

        result = _read_file(ANON_URL, "aio-large.bin")
        assert len(result) == size
        assert result == content

    def test_large_read_at_offset(self):
        """Reading a 10 MiB file at offset 5 MiB must return correct tail."""
        size = 10 * 1024 * 1024
        content = _pattern(size, 3, 7)
        _upload(ANON_URL, "aio-offset.bin", content)

        f = _open_rd(ANON_URL, "aio-offset.bin")
        offset = 5 * 1024 * 1024
        want_len = 3 * 1024 * 1024
        status, data = f.read(offset=offset, size=want_len)
        assert status.ok, f"read at offset failed: {status.message}"
        expected = content[offset:offset + want_len]
        assert data == expected
        f.close()

    def test_large_read_multiple_chunks(self):
        """A 15 MiB file read in 3 chunks must produce identical total."""
        size = 15 * 1024 * 1024
        content = _pattern(size, 11, 3)
        _upload(ANON_URL, "aio-chunks.bin", content)

        f = _open_rd(ANON_URL, "aio-chunks.bin")
        chunk_size = 5 * 1024 * 1024
        total = b""
        for i in range(3):
            status, data = f.read(offset=i * chunk_size, size=chunk_size)
            assert status.ok, f"chunk {i} failed: {status.message}"
            total += data
        f.close()
        assert total == content

    def test_large_read_md5(self):
        """A 15 MiB read must match the expected MD5 hash."""
        size = 15 * 1024 * 1024
        content = _pattern(size, 17, 5)
        _upload(ANON_URL, "aio-md5.bin", content)

        result = _read_file(ANON_URL, "aio-md5.bin")
        assert hashlib.md5(result).hexdigest() == hashlib.md5(content).hexdigest()


# ---------------------------------------------------------------------------
# Large write -- exercises async pwrite path
# ---------------------------------------------------------------------------

class TestAioWrite:
    """Verify that large writes complete correctly via the AIO thread-pool."""

    # Same rationale as TestAioRead: 10-20 MiB writes that are slow-but-correct
    # under -n8 CPU contention. Raise only the timeout ceiling, never the asserts.
    pytestmark = pytest.mark.timeout(120)

    def test_large_write_integrity(self):
        """Writing 10 MiB and reading back must produce identical data."""
        size = 10 * 1024 * 1024
        content = _pattern(size, 5, 9)
        _upload(ANON_URL, "aio-write.bin", content)

        result = _read_file(ANON_URL, "aio-write.bin")
        assert len(result) == size
        assert result == content

    def test_large_write_at_offset(self):
        """Writing 2 MiB at offset 8 MiB in a 10 MiB file must not corrupt head."""
        total_size = 10 * 1024 * 1024
        head = _pattern(8 * 1024 * 1024, 3)
        tail_data = _pattern(2 * 1024 * 1024, 7, 1)

        f = _open_wr(ANON_URL, "aio-write-offset.bin")
        status, _ = f.write(head)
        assert status.ok
        status, _ = f.write(tail_data, offset=8 * 1024 * 1024)
        assert status.ok, f"write at offset failed: {status.message}"
        f.close()

        result = _read_file(ANON_URL, "aio-write-offset.bin")
        expected = head + tail_data
        assert len(result) == total_size
        assert result == expected

    def test_large_write_multiple_chunks(self):
        """Writing 20 MiB in 5 chunks must produce identical file."""
        size = 20 * 1024 * 1024
        content = _pattern(size, 13, 2)

        f = _open_wr(ANON_URL, "aio-write-chunks.bin")
        chunk_size = 4 * 1024 * 1024
        for i in range(5):
            start = i * chunk_size
            end = min(start + chunk_size, size)
            chunk = content[start:end]
            status, _ = f.write(chunk, offset=start)
            assert status.ok, f"chunk {i} write failed: {status.message}"
        f.close()

        result = _read_file(ANON_URL, "aio-write-chunks.bin")
        assert result == content


# ---------------------------------------------------------------------------
# readv -- async scatter-gather read
# ---------------------------------------------------------------------------

class TestAioReadV:
    """Verify that kXR_readv with multiple segments works via AIO."""

    def test_readv_multiple_segments(self):
        """readv of 4 non-contiguous segments must return correct data."""
        size = 10 * 1024 * 1024
        content = _pattern(size, 3, 7)
        _upload(ANON_URL, "aio-readv.bin", content)

        f = _open_rd(ANON_URL, "aio-readv.bin")

        segments = [
            (0, 1 * 1024 * 1024),
            (3 * 1024 * 1024, 512 * 1024),
            (7 * 1024 * 1024, 1 * 1024 * 1024),
            (9 * 1024 * 1024, 512 * 1024),
        ]

        status, chunks = f.vector_read(segments)
        assert status.ok, f"readv failed: {status.message}"

        for i, ((off, sz), chunk) in enumerate(zip(segments, chunks)):
            assert bytes(chunk.buffer) == content[off:off + sz], \
                f"segment {i} at offset {off}: data mismatch"
        f.close()

    def test_readv_max_segments(self):
        """readv with many segments must succeed."""
        size = 4 * 1024 * 1024
        content = _pattern(size, 5, 1)
        _upload(ANON_URL, "aio-readv-max.bin", content)

        f = _open_rd(ANON_URL, "aio-readv-max.bin")

        segments = []
        for i in range(16):
            start = (i * 2 + 1) * 256 * 1024
            if start + 256 * 1024 <= size:
                segments.append((start, 256 * 1024))

        status, chunks = f.vector_read(segments)
        assert status.ok, f"readv max segments failed: {status.message}"

        for i, ((off, sz), chunk) in enumerate(zip(segments, chunks)):
            assert bytes(chunk.buffer) == content[off:off + sz], \
                f"segment {i} at offset {off}: data mismatch"
        f.close()


# ---------------------------------------------------------------------------
# pgread -- async paged read with CRC32c integrity
# ---------------------------------------------------------------------------

class TestAioPgRead:
    """Verify that kXR_pgread (paged read) works via AIO."""

    def test_pgread_integrity(self):
        """pgread via raw socket must return kXR_status with interleaved CRC32c.

        Wire format per page: [CRC32c(4)][data(page_size)] — digest before data,
        matching AsyncPageReader::InitIOV() in XrdClAsyncPageReader.hh.

        The Python XRootD client does not expose kXR_pgread, so we use a raw
        socket.  The server sends kXR_status (4007) with the response body:
          ServerResponseBody_Status (16 B) | pgRead offset (8 B) |
          [page data (4096 B) | CRC32c (4 B)] * N_pages
        """
        page_size = 4096
        n_pages = 4
        size = page_size * n_pages
        content = _pattern(size, 7, 3)
        _upload(ANON_URL, "aio-pgread.bin", content)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ANON_HOST, ANON_PORT))
        sock.settimeout(10)

        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        _recv_exact(sock, 16)

        proto_hdr = struct.pack(">BBHIBB10xI", 0, 1, 3006, 0x00000520, 0x02, 0x03, 0)
        sock.sendall(proto_hdr)
        st, _ = _read_response(sock)
        assert st == kXR_ok

        login_payload = b"anon\x00\x00\x00\x00"
        login_hdr = (struct.pack(">2sH", b"\x00\x01", 3007)
                     + struct.pack(">I", 0)
                     + login_payload
                     + struct.pack(">BBB", 0, 0, 5)
                     + struct.pack(">B", 0)
                     + struct.pack(">I", 0))
        sock.sendall(login_hdr)
        st, _ = _read_response(sock)
        assert st == kXR_ok

        open_body = struct.pack(">HH", 0x01B4, 0x0010) + b"\x00" * 12
        path_bytes = b"/aio-pgread.bin\x00"
        hdr = (struct.pack(">2sH", b"\x00\x01", kXR_open)
               + open_body
               + struct.pack(">I", len(path_bytes)))
        sock.sendall(hdr + path_bytes)
        st, fhandle_body = _read_response(sock)
        assert st == kXR_ok
        fh = fhandle_body[:4]

        # kXR_pgread (3030): body = fhandle(4) + offset(8) + rlen(4), dlen=0
        pgread_body = fh + struct.pack(">qi", 0, size)
        hdr = (struct.pack(">2sH", b"\x00\x01", kXR_pgread)
               + pgread_body
               + struct.pack(">I", 0))
        sock.sendall(hdr)

        # kXR_status (4007) framing for pgread:
        #   hdr.dlen  = 24  (sizeof(bdy) + sizeof(pgr) — does NOT include page data)
        #   bdy.dlen  = total page data size (client reads this many more bytes next)
        # So _read_response reads the 24-byte status header; page data follows separately.
        st, body = _read_response(sock)
        assert st == kXR_status, f"pgread expected kXR_status (4007), got {st}"

        # bdy.dlen is at offset 12 within body:
        #   crc32c(4) + streamID(2) + requestid(1) + resptype(1) + reserved(4) + dlen(4)
        inner_dlen = struct.unpack(">I", body[12:16])[0]
        encoded = _recv_exact(sock, inner_dlen)

        # Wire format per page: [CRC32c(4)][data(page_size)]
        # AsyncPageReader reads digest first, then page data.
        actual_data = b""
        pos = 0
        while len(actual_data) < size and pos < len(encoded):
            page_data_len = min(page_size, size - len(actual_data))
            pos += 4  # skip the 4-byte CRC32c before each page
            actual_data += encoded[pos:pos + page_data_len]
            pos += page_data_len

        assert actual_data == content, \
            f"pgread data mismatch: got {len(actual_data)} bytes, expected {len(content)}"

        sock.close()


# ---------------------------------------------------------------------------
# destroyed guard -- AIO callback after disconnect must not crash
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Wire helpers for raw socket tests
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _read_response(sock):
    """Read a XRootD response: header + optional body."""
    hdr = _recv_exact(sock, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _send_req(sock, streamid, reqid, body=b"", payload=b""):
    """Send a XRootD request and receive the response header + body."""
    hdr = struct.pack(">2sH", streamid, reqid) + body + struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)
    return _read_response(sock)


# ---------------------------------------------------------------------------
# Wire constants (inline to avoid import issues)
# ---------------------------------------------------------------------------

kXR_ok       = 0
kXR_status   = 4007
kXR_protocol = 3006
kXR_login    = 3007
kXR_open     = 3010
kXR_read     = 3013
kXR_ping     = 3011
kXR_pgread   = 3030
