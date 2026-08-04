"""
Streaming large plain kXR_write (write_stream.c) — end-to-end wire tests.

A single kXR_write whose dlen exceeds BRIX_WRITE_STREAM_CHUNK (8 MiB) is delivered
to the file in bounded chunks with a SINGLE final ack, instead of being buffered
whole.  Before this path existed a >16 MiB write was rejected outright
("payload too large") because BriX buffered the entire payload; go-hep's 64 MiB
inline WriteAtContext tripped exactly that.  These raw-socket tests pin the new
behaviour against the plain anonymous data server (auth=none):

  * success        — one 20 MiB inline write is acked kXR_ok and reads back byte
                     -exact (crosses two full chunks + a partial tail)
  * boundary       — a write exactly one byte over the chunk size streams and
                     reads back exact (guards the first-chunk/last-chunk seam)
  * security-neg   — a large write to a NON-writable (read-only) handle is
                     refused with a single error AFTER the payload is drained, so
                     the connection stays framed (a follow-up ping still answers)

The <= chunk-size path is unchanged (buffered + AIO) and already covered by
test_write.py / test_large_offset_wire.py; here we only exercise the streaming
threshold and above.
"""

import os
import socket
import struct

import pytest

from settings import NGINX_ANON_PORT, SERVER_HOST

# Allow pointing the test at a dedicated streaming BriX instance (a plain
# local-fs, direct-write server) via env, defaulting to the anon fleet port.
STREAM_PORT = int(os.environ.get("BRIX_STREAM_TEST_PORT", NGINX_ANON_PORT))

kXR_close    = 3003
kXR_login    = 3007
kXR_open     = 3010
kXR_ping     = 3011
kXR_read     = 3013
kXR_write    = 3019

kXR_ok       = 0
kXR_oksofar  = 4000   # partial read response; more frames follow on same sid
kXR_error    = 4003

kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_open_new  = 0x0008
kXR_delete    = 0x0004
kXR_mkpath    = 0x0100

# Must match BRIX_WRITE_STREAM_CHUNK in src/core/types/tunables.h.
STREAM_CHUNK = 8 * 1024 * 1024


def _recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(f"socket closed, {n - len(data)} left")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    header = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return streamid, status, body


def _session():
    sock = socket.create_connection((SERVER_HOST, STREAM_PORT), timeout=30)
    sock.settimeout(30)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _, status, _ = _read_response(sock)
    assert status == kXR_ok, "handshake rejected"
    req = struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                      os.getpid() & 0xFFFFFFFF, b"pytest\x00\x00", 0, 0, 5, 0, 0)
    sock.sendall(req)
    _, status, _ = _read_response(sock)
    assert status == kXR_ok, "login rejected"
    return sock


def _open(sock, path, options, streamid=b"\x00\x02"):
    p = path.encode() + b"\x00"
    req = struct.pack("!2sHHH2s6s4sI", streamid, kXR_open,
                      0o644, options, b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                      len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _write(sock, fhandle, offset, payload, streamid=b"\x00\x09"):
    req = struct.pack("!2sH4sqB3sI", streamid, kXR_write, fhandle,
                      offset, 0, b"\x00\x00\x00", len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _read(sock, fhandle, offset, rlen, streamid=b"\x00\x06"):
    """Issue one kXR_read and drain the full response, which may arrive as a
    kXR_oksofar sequence (several partial frames on the same streamid ending in a
    final kXR_ok).  Returns (final_status, concatenated_body)."""
    req = struct.pack("!2sH4sqiI", streamid, kXR_read, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    out = bytearray()
    while True:
        sid, status, body = _read_response(sock)
        out.extend(body)
        if status != kXR_oksofar:
            return status, bytes(out)


def _close(sock, fhandle, streamid=b"\x00\x0e"):
    req = struct.pack("!2sH4s12sI", streamid, kXR_close, fhandle,
                      b"\x00" * 12, 0)
    sock.sendall(req)
    return _read_response(sock)


def _ping(sock, streamid=b"\x00\x0f"):
    req = struct.pack("!2sH16sI", streamid, kXR_ping, b"\x00" * 16, 0)
    sock.sendall(req)
    return _read_response(sock)


def _read_all(sock, fhandle, total):
    """Read `total` bytes back in <=4 MiB requests.  A large read may come back
    as a kXR_oksofar sequence (several partial frames on the same streamid ending
    in a final kXR_ok), so drain those per request."""
    out = bytearray()
    off = 0
    while off < total:
        want = min(4 * 1024 * 1024, total - off)
        status, body = _read(sock, fhandle, off, want)
        assert status == kXR_ok, f"read at {off} failed status={status}"
        if not body:
            break
        out.extend(body)
        off += len(body)
    return bytes(out)


def _pattern(n):
    """Deterministic non-trivial payload (position-dependent, not all-equal)."""
    base = bytes((i * 37 + 11) & 0xFF for i in range(4096))
    reps = (n + 4095) // 4096
    return (base * reps)[:n]


@pytest.mark.requires_local_server
class TestStreamingWrite:

    def _writeback_check(self, size):
        name = f"/stream_wr_{size}_{os.getpid()}.bin"
        payload = _pattern(size)

        sock = _session()
        try:
            _, st, body = _open(sock, name,
                                kXR_open_updt | kXR_open_new | kXR_delete
                                | kXR_mkpath)
            assert st == kXR_ok, f"open-for-write failed status={st}"
            fhandle = body[:4]

            _, st, _ = _write(sock, fhandle, 0, payload)
            assert st == kXR_ok, (
                f"streaming write of {size} bytes must be acked kXR_ok, "
                f"got status={st}")

            _, st, _ = _close(sock, fhandle)
            assert st == kXR_ok
        finally:
            sock.close()

        # Reopen and verify the bytes landed exactly.
        sock = _session()
        try:
            _, st, body = _open(sock, name, kXR_open_read)
            assert st == kXR_ok, f"reopen-for-read failed status={st}"
            fhandle = body[:4]
            got = _read_all(sock, fhandle, size)
            assert len(got) == size, f"read back {len(got)} != {size}"
            assert got == payload, "streamed bytes differ from what was written"
            _close(sock, fhandle)
        finally:
            sock.close()

    def test_streaming_write_multichunk_roundtrip(self):
        """success: 20 MiB inline write (2 full chunks + tail) round-trips."""
        self._writeback_check(20 * 1024 * 1024)

    def test_streaming_write_one_over_chunk(self):
        """boundary: chunk_size + 1 byte streams and reads back exact."""
        self._writeback_check(STREAM_CHUNK + 1)

    def test_large_write_to_readonly_handle_refused_and_stays_framed(self):
        """security-neg: a large write to a read-only handle errors once, then
        the connection is still correctly framed (a following ping answers)."""
        name = f"/stream_ro_{os.getpid()}.bin"

        # Create a small file first so it exists for a read-only open.
        sock = _session()
        try:
            _, st, body = _open(sock, name,
                                kXR_open_updt | kXR_open_new | kXR_delete
                                | kXR_mkpath)
            assert st == kXR_ok
            fhandle = body[:4]
            _write(sock, fhandle, 0, b"seed")
            _close(sock, fhandle)
        finally:
            sock.close()

        sock = _session()
        try:
            # Open READ-ONLY, then attempt a >chunk streaming write to it.
            _, st, body = _open(sock, name, kXR_open_read)
            assert st == kXR_ok, f"reopen-for-read failed status={st}"
            fhandle = body[:4]

            _, st, _ = _write(sock, fhandle, 0, _pattern(STREAM_CHUNK + 4096))
            assert st == kXR_error, (
                "a large write to a read-only handle must be refused, "
                f"got status={st}")

            # The whole payload was drained before the error, so framing is
            # intact — a subsequent request must be answered normally.
            _, st, _ = _ping(sock)
            assert st == kXR_ok, (
                "connection desynced after refused streaming write "
                f"(ping status={st})")
        finally:
            sock.close()
