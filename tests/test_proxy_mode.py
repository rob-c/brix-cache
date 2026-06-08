"""
Tests for XRootD transparent proxy mode (xrootd_proxy on + xrootd_proxy_upstream).

Topology:   test client ──► nginx (xrootd_proxy on) ──► xrootd reference daemon

The proxy authenticates clients independently (anonymous in Phase 1), lazily
connects to the upstream on the first post-login opcode, translates
client-assigned file handles to upstream-assigned handles, and relays all
responses verbatim back to the client with the original client streamid.

Test categories
───────────────
  Class TestProxyBootstrap         – lazy connect, session opcodes, endsess
  Class TestProxyStat              – path-based stat, nonexistent paths
  Class TestProxyDirlist           – directory listing, nested dirs
  Class TestProxyOpenReadClose     – open + read + close round-trips
  Class TestProxyOpenWriteClose    – open + write + sync + close + verify
  Class TestProxyHandleTranslation – multi-handle open/read/close, handle reuse
  Class TestProxyReadV             – kXR_readv fhandle translation + data integrity
  Class TestProxyLocate            – kXR_locate forwarding
  Class TestProxyFsOps             – mkdir / rmdir / rm / mv / truncate
  Class TestProxyErrorPropagation  – backend errors relay to client correctly
  Class TestProxySequential        – many sequential requests on one connection
  Class TestProxyLargeRead         – large data relay (> 64 KiB)
  Class TestProxyMultiClient       – concurrent clients through same proxy
  Class TestProxyBackendUnavailable – graceful error when backend is unreachable
"""

import os
import socket
import struct
import time
import uuid
from pathlib import Path

import pytest

from settings import (
    NGINX_BIN,
    PROXY_DATA_ROOT,
    PROXY_DEAD_NGINX_PORT,
    PROXY_NGINX_PORT,
    PROXY_UPSTREAM_PORT,
)

# ──────────────────────────────────────────────────────────────────────────────
# XRootD protocol constants (from XProtocol.hh)
# ──────────────────────────────────────────────────────────────────────────────

kXR_auth      = 3000
kXR_query     = 3001
kXR_chmod     = 3002
kXR_close     = 3003
kXR_dirlist   = 3004
kXR_protocol  = 3006
kXR_login     = 3007
kXR_mkdir     = 3008
kXR_mv        = 3009
kXR_open      = 3010
kXR_ping      = 3011
kXR_read      = 3013
kXR_rm        = 3014
kXR_rmdir     = 3015
kXR_sync      = 3016
kXR_stat      = 3017
kXR_write     = 3019
kXR_endsess   = 3023
kXR_readv     = 3025
kXR_locate    = 3027
kXR_truncate  = 3028

kXR_ok        = 0
kXR_oksofar   = 4000
kXR_error     = 4003

kXR_open_read  = 0x0010
kXR_open_updt  = 0x0020
kXR_new        = 0x0008
kXR_delete     = 0x0002
kXR_mkpath     = 0x0100

# kXR_stat flags (XProtocol.hh StatFlags enum)
kXR_isDir   = 2
kXR_other   = 4
kXR_readable = 16
kXR_writable = 32

# ──────────────────────────────────────────────────────────────────────────────
# nginx proxy config template
# ──────────────────────────────────────────────────────────────────────────────

_PROXY_CONF = """\
worker_processes 1;
error_log {LOG_DIR}/error.log debug;
pid       {LOG_DIR}/nginx.pid;

events {{ worker_connections 256; }}

stream {{
    server {{
        listen 127.0.0.1:{PORT};
        xrootd on;
        xrootd_auth none;
        xrootd_proxy on;
        xrootd_proxy_upstream 127.0.0.1:{UPSTREAM_PORT};
    }}
}}
"""

# ──────────────────────────────────────────────────────────────────────────────
# Module fixture: one xrootd backend + one nginx proxy in front of it
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def proxy_env():
    """Use the pre-launched nginx proxy (PROXY_NGINX_PORT) and xrootd upstream.

    Seeds test data into PROXY_DATA_ROOT (the upstream's data directory) and
    waits for the proxy to accept connections.
    """
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    data_dir = Path(PROXY_DATA_ROOT)
    data_dir.mkdir(parents=True, exist_ok=True)

    (data_dir / "hello.txt").write_bytes(b"hello from proxy test\n")
    (data_dir / "data256.bin").write_bytes(bytes(range(256)) * 4)
    (data_dir / "large.bin").write_bytes(bytes(i & 0xFF for i in range(512 * 1024)))
    (data_dir / "alpha.txt").write_bytes(b"AAAABBBBCCCCDDDD")
    (data_dir / "beta.txt").write_bytes(b"1111222233334444")
    (data_dir / "gamma.txt").write_bytes(b"xyzxyzxyzxyzxyz!")
    (data_dir / "subdir").mkdir(exist_ok=True)
    (data_dir / "subdir" / "nested.txt").write_bytes(b"nested file\n")
    (data_dir / "subdir2").mkdir(exist_ok=True)

    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", PROXY_NGINX_PORT), timeout=1):
                break
        except OSError:
            time.sleep(0.25)
    else:
        pytest.skip(f"proxy-nginx not ready on port {PROXY_NGINX_PORT}")

    yield {
        "proxy_port":    PROXY_NGINX_PORT,
        "upstream_port": PROXY_UPSTREAM_PORT,
        "data_dir":      data_dir,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Wire protocol helpers
# ──────────────────────────────────────────────────────────────────────────────

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(f"connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def _read_resp(sock):
    """Read one XRootD response frame → (status: int, body: bytes)."""
    hdr = _recv_exact(sock, 8)
    _, status, dlen = struct.unpack(">2sHI", hdr)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _read_resp_all(sock):
    """Accumulate kXR_oksofar frames into a single (status, body) pair."""
    data = b""
    while True:
        status, body = _read_resp(sock)
        data += body
        if status != kXR_oksofar:
            return status, data


def _connect(host, port):
    """Return a connected, fully-logged-in socket (ready for post-login opcodes)."""
    sock = socket.create_connection((host, port), timeout=10)
    sock.settimeout(10)
    # Initial handshake (20 bytes)
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    # kXR_protocol
    sock.sendall(struct.pack(">2sHIBB10sI",
                             b"\x00\x01", kXR_protocol,
                             0x00000520, 0x02, 0x03, b"\x00" * 10, 0))
    _recv_exact(sock, 16)   # server hello: 8-byte header + 8-byte body
    _read_resp(sock)        # kXR_protocol response
    # kXR_login
    sock.sendall(struct.pack(">2sHI8sBBBBI",
                             b"\x00\x01", kXR_login,
                             os.getpid() & 0xFFFFFFFF,
                             b"pytest\x00\x00",
                             0, 0, 5, 0, 0))
    _read_resp(sock)
    return sock


# ── per-request helpers ────────────────────────────────────────────────────

def _stat(sock, path, sid=b"\x00\x10"):
    p = path.encode() if isinstance(path, str) else path
    req = struct.pack(">2sHB11s4sI", sid, kXR_stat,
                      0, b"\x00" * 11, b"\x00" * 4, len(p))
    sock.sendall(req + p)
    return _read_resp(sock)


def _open(sock, path, options, mode=0o644, sid=b"\x00\x20"):
    p = path.encode() if isinstance(path, str) else path
    req = struct.pack(">2sHHH12sI", sid, kXR_open,
                      mode, options, b"\x00" * 12, len(p))
    sock.sendall(req + p)
    return _read_resp(sock)


def _fh(open_body):
    """Extract the 4-byte file handle from an open response body."""
    assert len(open_body) >= 4, f"open body too short: {len(open_body)}"
    return open_body[:4]


def _read(sock, fhandle, offset, rlen, sid=b"\x00\x30"):
    req = struct.pack(">2sH4sQiI", sid, kXR_read, fhandle, offset, rlen, 0)
    sock.sendall(req)
    return _read_resp_all(sock)


def _write(sock, fhandle, offset, data, sid=b"\x00\x40"):
    req = struct.pack(">2sH4sQ4sI", sid, kXR_write,
                      fhandle, offset, b"\x00" * 4, len(data))
    sock.sendall(req + data)
    return _read_resp(sock)


def _sync(sock, fhandle, sid=b"\x00\x50"):
    req = struct.pack(">2sH4s12sI", sid, kXR_sync, fhandle, b"\x00" * 12, 0)
    sock.sendall(req)
    return _read_resp(sock)


def _close(sock, fhandle, sid=b"\x00\x60"):
    req = struct.pack(">2sH4s12sI", sid, kXR_close, fhandle, b"\x00" * 12, 0)
    sock.sendall(req)
    return _read_resp(sock)


def _dirlist(sock, path, sid=b"\x00\x70"):
    p = path.encode() if isinstance(path, str) else path
    req = struct.pack(">2sH15sBI", sid, kXR_dirlist,
                      b"\x00" * 15, 0, len(p))
    sock.sendall(req + p)
    return _read_resp_all(sock)


def _locate(sock, path, options=0, sid=b"\x00\x80"):
    p = path.encode() if isinstance(path, str) else path
    req = struct.pack(">2sHH14sI", sid, kXR_locate,
                      options, b"\x00" * 14, len(p))
    sock.sendall(req + p)
    return _read_resp(sock)


def _mkdir(sock, path, mode=0o755, mkpath=True, sid=b"\x00\x90"):
    p = path.encode() if isinstance(path, str) else path
    options = 0x01 if mkpath else 0x00
    req = struct.pack(">2sHB13sHI", sid, kXR_mkdir,
                      options, b"\x00" * 13, mode, len(p))
    sock.sendall(req + p)
    return _read_resp(sock)


def _rm(sock, path, sid=b"\x00\xa0"):
    p = path.encode() if isinstance(path, str) else path
    req = struct.pack(">2sH16sI", sid, kXR_rm, b"\x00" * 16, len(p))
    sock.sendall(req + p)
    return _read_resp(sock)


def _rmdir(sock, path, sid=b"\x00\xb0"):
    p = path.encode() if isinstance(path, str) else path
    req = struct.pack(">2sH16sI", sid, kXR_rmdir, b"\x00" * 16, len(p))
    sock.sendall(req + p)
    return _read_resp(sock)


def _mv(sock, old_path, new_path, sid=b"\x00\xc0"):
    old_p = old_path.encode() if isinstance(old_path, str) else old_path
    new_p = new_path.encode() if isinstance(new_path, str) else new_path
    # kXR_mv wire format: payload = old_path + ' ' + new_path (space separator)
    # arg1len = len(old_path); xrootd skips the space and reads the rest as new_path
    payload = old_p + b" " + new_p
    req = struct.pack(">2sH14sHI", sid, kXR_mv,
                      b"\x00" * 14, len(old_p), len(payload))
    sock.sendall(req + payload)
    return _read_resp(sock)


def _ping(sock, sid=b"\x00\xd0"):
    req = struct.pack(">2sH16sI", sid, kXR_ping, b"\x00" * 16, 0)
    sock.sendall(req)
    return _read_resp(sock)


def _truncate_path(sock, path, offset, sid=b"\x00\xe0"):
    p = path.encode() if isinstance(path, str) else path
    req = struct.pack(">2sH4sQ4sI", sid, kXR_truncate,
                      b"\x00" * 4, offset, b"\x00" * 4, len(p))
    sock.sendall(req + p)
    return _read_resp(sock)


def _readv(sock, segments, sid=b"\x00\xf0"):
    """kXR_readv — segments is [(fhandle_bytes, offset, rlen), ...]."""
    payload = b""
    total_expected = 0
    for fh, offset, rlen in segments:
        payload += struct.pack(">4siQ", fh, rlen, offset)
        total_expected += rlen
    req = struct.pack(">2sH15sBI", sid, kXR_readv,
                      b"\x00" * 15, 0, len(payload))
    sock.sendall(req + payload)
    return _read_resp_all(sock), total_expected


def _parse_readv_body(body, n_segments):
    """Parse readv response body into [(fhandle, rlen, data), ...].

    The wire format is, for each segment:
      readahead_list header: fhandle[4] + rlen[4] + offset[8]  (16 bytes)
      data[rlen]
    """
    results = []
    pos = 0
    for _ in range(n_segments):
        if pos + 16 > len(body):
            break
        fhandle = body[pos:pos + 4]
        rlen = struct.unpack(">i", body[pos + 4:pos + 8])[0]
        pos += 16
        data = body[pos:pos + max(0, rlen)] if rlen > 0 else b""
        pos += max(0, rlen)
        results.append((fhandle, rlen, data))
    return results


def _parse_stat_body(body):
    """Parse stat response text → (flags, size, modtime).

    xrootd 5.x extended format: id size flags mtime [atime ctime mode owner group]
    Classic xrootd format was:  id flags size modtime
    The 5.x server returns size at index 1 and flags at index 2.
    """
    text = body.rstrip(b"\x00").decode(errors="replace")
    parts = text.split()
    assert len(parts) >= 4, f"unexpected stat body: {body!r}"
    return int(parts[2]), int(parts[1]), int(parts[3])   # flags, size, mtime


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyBootstrap
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyBootstrap:
    """Proxy lazy-connect and session-opcode behaviour."""

    def test_client_can_connect_and_login(self, proxy_env):
        """A fresh connection through the proxy completes login successfully."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        sock.close()

    def test_ping_handled_without_touching_upstream(self, proxy_env):
        """kXR_ping is a session opcode — proxy handles it before the lazy connect."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, _ = _ping(sock)
            assert status == kXR_ok, f"ping failed: status={status}"
        finally:
            sock.close()

    def test_multiple_pings_before_first_fs_op(self, proxy_env):
        """Session opcodes work many times without triggering upstream connect."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            for i in range(5):
                sid = bytes([0, i + 1])
                req = struct.pack(">2sH16sI", sid, kXR_ping, b"\x00" * 16, 0)
                sock.sendall(req)
                status, _ = _read_resp(sock)
                assert status == kXR_ok, f"ping {i} failed"
        finally:
            sock.close()

    def test_first_fs_op_triggers_lazy_connect(self, proxy_env):
        """First post-login opcode (stat) triggers upstream bootstrap; response is correct."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _stat(sock, "/hello.txt")
            assert status == kXR_ok, f"stat failed: status={status}, body={body!r}"
            flags, size, _ = _parse_stat_body(body)
            assert size == 22   # len("hello from proxy test\n")
        finally:
            sock.close()

    def test_session_opcodes_still_work_after_fs_op(self, proxy_env):
        """kXR_ping continues to work after the upstream has been bootstrapped."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            _stat(sock, "/hello.txt")
            status, _ = _ping(sock)
            assert status == kXR_ok
        finally:
            sock.close()

    def test_multiple_connections_independent_proxies(self, proxy_env):
        """Each client connection gets its own upstream proxy context."""
        socks = [_connect("127.0.0.1", proxy_env["proxy_port"]) for _ in range(4)]
        try:
            for i, sock in enumerate(socks):
                status, body = _stat(sock, "/hello.txt")
                assert status == kXR_ok, f"connection {i}: stat failed"
                _, size, _ = _parse_stat_body(body)
                assert size == 22
        finally:
            for sock in socks:
                sock.close()

    def test_endsess_terminates_cleanly(self, proxy_env):
        """kXR_endsess through the proxy is acknowledged and connection closes."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            _stat(sock, "/hello.txt")   # trigger upstream connect
            req = struct.pack(">2sH16sI", b"\x00\x02", kXR_endsess,
                              b"\x00" * 16, 0)
            sock.sendall(req)
            status, _ = _read_resp(sock)
            assert status == kXR_ok
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyStat
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyStat:
    """kXR_stat forwarding through the proxy."""

    def test_stat_existing_file(self, proxy_env):
        """Stat an existing file; size and flags come from upstream correctly."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _stat(sock, "/hello.txt")
            assert status == kXR_ok
            flags, size, mtime = _parse_stat_body(body)
            assert size == 22
            assert mtime > 0
            assert not (flags & kXR_isDir)   # not a directory
        finally:
            sock.close()

    def test_stat_directory(self, proxy_env):
        """Stat a directory returns directory flag."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _stat(sock, "/subdir")
            assert status == kXR_ok
            flags, _, _ = _parse_stat_body(body)
            assert flags & kXR_isDir, f"kXR_isDir not set for directory: flags={flags}"
        finally:
            sock.close()

    def test_stat_nonexistent_file_returns_error(self, proxy_env):
        """Stat on a nonexistent path returns kXR_error (not a crash)."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _stat(sock, "/does_not_exist_xyz.txt")
            assert status == kXR_error, f"expected error, got status={status}"
            assert len(body) >= 4   # error code present
        finally:
            sock.close()

    def test_stat_binary_file(self, proxy_env):
        """Stat binary file returns correct size."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _stat(sock, "/data256.bin")
            assert status == kXR_ok
            _, size, _ = _parse_stat_body(body)
            assert size == 1024
        finally:
            sock.close()

    def test_stat_nested_file(self, proxy_env):
        """Stat a file in a subdirectory."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _stat(sock, "/subdir/nested.txt")
            assert status == kXR_ok
            _, size, _ = _parse_stat_body(body)
            assert size == 12    # len("nested file\n")
        finally:
            sock.close()

    def test_stat_large_file(self, proxy_env):
        """Stat large file returns correct size."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _stat(sock, "/large.bin")
            assert status == kXR_ok
            _, size, _ = _parse_stat_body(body)
            assert size == 512 * 1024
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyDirlist
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyDirlist:
    """kXR_dirlist forwarding through the proxy."""

    def test_dirlist_root(self, proxy_env):
        """Listing / returns the seeded files and directories."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _dirlist(sock, "/")
            assert status == kXR_ok, f"dirlist failed: {status}"
            listing = body.decode(errors="replace")
            assert "hello.txt" in listing
            assert "data256.bin" in listing
            assert "subdir" in listing
        finally:
            sock.close()

    def test_dirlist_subdirectory(self, proxy_env):
        """Listing a subdirectory returns only files in that directory."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _dirlist(sock, "/subdir")
            assert status == kXR_ok
            listing = body.decode(errors="replace")
            assert "nested.txt" in listing
            # Root-level files must NOT appear
            assert "hello.txt" not in listing
        finally:
            sock.close()

    def test_dirlist_nonexistent_directory(self, proxy_env):
        """Listing a nonexistent directory returns kXR_error."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, _ = _dirlist(sock, "/no_such_dir_xyz")
            assert status == kXR_error
        finally:
            sock.close()

    def test_dirlist_empty_directory(self, proxy_env):
        """Listing an empty directory returns kXR_ok with empty body."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, _ = _dirlist(sock, "/subdir2")
            assert status == kXR_ok
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyOpenReadClose
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyOpenReadClose:
    """Open + read + close through the proxy: data must match upstream directly."""

    def test_read_full_small_file(self, proxy_env):
        """Read entire small file; content matches what was written to disk."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/hello.txt", kXR_open_read)
            assert status == kXR_ok, f"open failed: {status}"
            fhandle = _fh(body)

            status, data = _read(sock, fhandle, 0, 22)
            assert status == kXR_ok
            assert data == b"hello from proxy test\n"

            status, _ = _close(sock, fhandle)
            assert status == kXR_ok
        finally:
            sock.close()

    def test_read_partial_offset(self, proxy_env):
        """Read a range starting at a non-zero offset."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/data256.bin", kXR_open_read)
            assert status == kXR_ok
            fhandle = _fh(body)

            # Bytes 256-511 should be 0x00..0xFF (second repetition of the pattern)
            status, data = _read(sock, fhandle, 256, 256)
            assert status == kXR_ok
            assert len(data) == 256
            assert data == bytes(range(256))

            _close(sock, fhandle)
        finally:
            sock.close()

    def test_read_past_eof_returns_available(self, proxy_env):
        """Reading past EOF returns the bytes available, not an error."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/hello.txt", kXR_open_read)
            assert status == kXR_ok
            fhandle = _fh(body)

            # Request 1000 bytes from a 22-byte file
            status, data = _read(sock, fhandle, 0, 1000)
            assert status == kXR_ok
            assert data == b"hello from proxy test\n"

            _close(sock, fhandle)
        finally:
            sock.close()

    def test_read_exactly_at_eof(self, proxy_env):
        """Reading from exactly EOF returns empty or kXR_ok."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/hello.txt", kXR_open_read)
            assert status == kXR_ok
            fhandle = _fh(body)

            status, data = _read(sock, fhandle, 22, 10)
            assert status == kXR_ok
            assert len(data) == 0

            _close(sock, fhandle)
        finally:
            sock.close()

    def test_read_binary_data_integrity(self, proxy_env):
        """Binary file content is relayed byte-for-byte through the proxy."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/data256.bin", kXR_open_read)
            assert status == kXR_ok
            fhandle = _fh(body)

            status, data = _read(sock, fhandle, 0, 1024)
            assert status == kXR_ok
            assert len(data) == 1024
            assert data == bytes(range(256)) * 4

            _close(sock, fhandle)
        finally:
            sock.close()

    def test_multiple_reads_same_handle(self, proxy_env):
        """Multiple consecutive reads on one handle return sequential file data."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/data256.bin", kXR_open_read)
            assert status == kXR_ok
            fhandle = _fh(body)

            expected = bytes(range(256)) * 4
            for chunk_start in range(0, 1024, 128):
                status, data = _read(sock, fhandle, chunk_start, 128)
                assert status == kXR_ok
                assert data == expected[chunk_start:chunk_start + 128], \
                    f"mismatch at offset {chunk_start}"

            _close(sock, fhandle)
        finally:
            sock.close()

    def test_open_nonexistent_returns_error(self, proxy_env):
        """Opening a nonexistent file returns kXR_error from the backend."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/no_such_file.txt", kXR_open_read)
            assert status == kXR_error, f"expected kXR_error, got {status}"
            assert len(body) >= 4
        finally:
            sock.close()

    def test_open_read_nested_file(self, proxy_env):
        """Read a file in a subdirectory."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/subdir/nested.txt", kXR_open_read)
            assert status == kXR_ok
            fhandle = _fh(body)

            status, data = _read(sock, fhandle, 0, 100)
            assert status == kXR_ok
            assert data == b"nested file\n"

            _close(sock, fhandle)
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyOpenWriteClose
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyOpenWriteClose:
    """Write round-trips through the proxy."""

    def test_write_new_file_and_read_back(self, proxy_env):
        """Create a new file via proxy write, then read it back."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            fname = f"/proxy_write_{uuid.uuid4().hex[:8]}.txt"
            payload = b"proxy write test data\n"

            status, body = _open(sock, fname,
                                 kXR_open_updt | kXR_new | kXR_mkpath)
            assert status == kXR_ok, f"write-open failed: {status}"
            fhandle = _fh(body)

            status, _ = _write(sock, fhandle, 0, payload)
            assert status == kXR_ok

            status, _ = _sync(sock, fhandle)
            assert status == kXR_ok

            status, _ = _close(sock, fhandle)
            assert status == kXR_ok

            # Re-open and verify
            status, body = _open(sock, fname, kXR_open_read)
            assert status == kXR_ok
            fhandle2 = _fh(body)

            status, data = _read(sock, fhandle2, 0, len(payload) + 10)
            assert status == kXR_ok
            assert data == payload

            _close(sock, fhandle2)
        finally:
            sock.close()

    def test_write_at_offset(self, proxy_env):
        """Write data at a non-zero offset; verify with a targeted read."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            fname = f"/proxy_offset_{uuid.uuid4().hex[:8]}.bin"

            # Create with 16 zeros
            status, body = _open(sock, fname, kXR_open_updt | kXR_new)
            assert status == kXR_ok
            fh = _fh(body)
            _write(sock, fh, 0, b"\x00" * 16)
            # Overwrite bytes 4-7 with known pattern
            _write(sock, fh, 4, b"MARK")
            _sync(sock, fh)
            _close(sock, fh)

            # Verify
            status, body = _open(sock, fname, kXR_open_read)
            assert status == kXR_ok
            fh2 = _fh(body)
            status, data = _read(sock, fh2, 0, 16)
            assert status == kXR_ok
            assert data[4:8] == b"MARK", f"expected MARK at offset 4, got {data!r}"
            _close(sock, fh2)
        finally:
            sock.close()

    def test_overwrite_existing_file(self, proxy_env):
        """Open existing file in write mode and overwrite beginning."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            fname = f"/proxy_overwrite_{uuid.uuid4().hex[:8]}.txt"

            # Create
            s, b = _open(sock, fname, kXR_open_updt | kXR_new)
            assert s == kXR_ok
            fh = _fh(b)
            _write(sock, fh, 0, b"ORIGINAL CONTENT HERE")
            _sync(sock, fh)
            _close(sock, fh)

            # Overwrite first 8 bytes
            s, b = _open(sock, fname, kXR_open_updt)
            assert s == kXR_ok
            fh = _fh(b)
            _write(sock, fh, 0, b"MODIFIED")
            _sync(sock, fh)
            _close(sock, fh)

            # Verify
            s, b = _open(sock, fname, kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)
            s, data = _read(sock, fh, 0, 8)
            assert s == kXR_ok
            assert data == b"MODIFIED"
            _close(sock, fh)
        finally:
            sock.close()

    def test_write_large_chunk(self, proxy_env):
        """Write a 256 KiB chunk through the proxy."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            fname = f"/proxy_large_write_{uuid.uuid4().hex[:8]}.bin"
            payload = bytes(i & 0xFF for i in range(256 * 1024))

            s, b = _open(sock, fname, kXR_open_updt | kXR_new)
            assert s == kXR_ok
            fh = _fh(b)
            s, _ = _write(sock, fh, 0, payload)
            assert s == kXR_ok
            _sync(sock, fh)
            _close(sock, fh)

            # Verify spot-check at several offsets
            s, b = _open(sock, fname, kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)
            for offset in (0, 1024, 65536, 131072):
                s, data = _read(sock, fh, offset, 256)
                assert s == kXR_ok
                assert data == payload[offset:offset + 256], \
                    f"mismatch at offset {offset}"
            _close(sock, fh)
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyHandleTranslation
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyHandleTranslation:
    """File handle translation: client gets local handles, proxy maps to upstream."""

    def test_two_files_open_simultaneously(self, proxy_env):
        """Two files open at once; reads from each handle return correct data."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            s1, b1 = _open(sock, "/alpha.txt", kXR_open_read, sid=b"\x00\x01")
            assert s1 == kXR_ok
            fh1 = _fh(b1)

            s2, b2 = _open(sock, "/beta.txt", kXR_open_read, sid=b"\x00\x02")
            assert s2 == kXR_ok
            fh2 = _fh(b2)

            assert fh1 != fh2, "proxy should assign different local handles"

            s, data1 = _read(sock, fh1, 0, 16, sid=b"\x00\x03")
            assert s == kXR_ok
            assert data1 == b"AAAABBBBCCCCDDDD"

            s, data2 = _read(sock, fh2, 0, 16, sid=b"\x00\x04")
            assert s == kXR_ok
            assert data2 == b"1111222233334444"

            _close(sock, fh1, sid=b"\x00\x05")
            _close(sock, fh2, sid=b"\x00\x06")
        finally:
            sock.close()

    def test_three_files_interleaved_reads(self, proxy_env):
        """Three files open; interleaved reads all return correct data."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            _, b1 = _open(sock, "/alpha.txt", kXR_open_read, sid=b"\x00\x01")
            _, b2 = _open(sock, "/beta.txt",  kXR_open_read, sid=b"\x00\x02")
            _, b3 = _open(sock, "/gamma.txt", kXR_open_read, sid=b"\x00\x03")
            fh1, fh2, fh3 = _fh(b1), _fh(b2), _fh(b3)

            expected = {
                fh1: b"AAAABBBBCCCCDDDD",
                fh2: b"1111222233334444",
                fh3: b"xyzxyzxyzxyzxyz!",
            }
            # Interleave reads
            for fh in (fh2, fh1, fh3, fh1, fh2, fh3):
                s, data = _read(sock, fh, 0, 16)
                assert s == kXR_ok
                assert data == expected[fh], \
                    f"handle {fh!r}: expected {expected[fh]!r}, got {data!r}"

            for fh in (fh1, fh2, fh3):
                _close(sock, fh)
        finally:
            sock.close()

    def test_handle_reuse_after_close(self, proxy_env):
        """After closing a handle, a new open can reuse the same local slot."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            s, b = _open(sock, "/alpha.txt", kXR_open_read, sid=b"\x00\x01")
            assert s == kXR_ok
            fh1 = _fh(b)

            _close(sock, fh1, sid=b"\x00\x02")

            # Open a different file — may reuse fh1's slot number
            s, b = _open(sock, "/beta.txt", kXR_open_read, sid=b"\x00\x03")
            assert s == kXR_ok
            fh2 = _fh(b)

            s, data = _read(sock, fh2, 0, 16)
            assert s == kXR_ok
            assert data == b"1111222233334444"

            _close(sock, fh2)
        finally:
            sock.close()

    def test_read_from_closed_handle_returns_error(self, proxy_env):
        """Reading from a handle after close returns kXR_error (invalid handle)."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            s, b = _open(sock, "/alpha.txt", kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)
            _close(sock, fh)

            # Attempting to read from the now-closed handle
            s, body = _read(sock, fh, 0, 16)
            assert s == kXR_error, f"expected error on read from closed handle, got {s}"
        finally:
            sock.close()

    def test_many_handles_open_simultaneously(self, proxy_env):
        """Open several files at once and verify each returns its own data."""
        files = ["alpha.txt", "beta.txt", "gamma.txt", "hello.txt"]
        expected = {
            "alpha.txt": b"AAAABBBBCCCCDDDD",
            "beta.txt":  b"1111222233334444",
            "gamma.txt": b"xyzxyzxyzxyzxyz!",
            "hello.txt": b"hello from proxy",  # first 16 bytes
        }
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            handles = {}
            for i, fname in enumerate(files):
                sid = bytes([0, i + 1])
                s, b = _open(sock, f"/{fname}", kXR_open_read, sid=sid)
                assert s == kXR_ok, f"open {fname} failed"
                handles[fname] = _fh(b)

            for fname, fh in handles.items():
                s, data = _read(sock, fh, 0, 16)
                assert s == kXR_ok
                assert data == expected[fname], \
                    f"{fname}: expected {expected[fname]!r}, got {data!r}"

            for fh in handles.values():
                _close(sock, fh)
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyReadV
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyReadV:
    """kXR_readv — vectored reads with per-segment fhandle translation."""

    def test_readv_single_segment(self, proxy_env):
        """Single-segment readv works and returns correct data."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            s, b = _open(sock, "/alpha.txt", kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)

            (status, body), _ = _readv(sock, [(fh, 0, 16)])
            assert status == kXR_ok, f"readv failed: {status}"
            segs = _parse_readv_body(body, 1)
            assert len(segs) == 1
            assert segs[0][2] == b"AAAABBBBCCCCDDDD"

            _close(sock, fh)
        finally:
            sock.close()

    def test_readv_two_segments_same_handle(self, proxy_env):
        """Two non-overlapping segments on one handle return correct slices."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            s, b = _open(sock, "/data256.bin", kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)

            (status, body), _ = _readv(sock, [(fh, 0, 8), (fh, 256, 8)])
            assert status == kXR_ok
            segs = _parse_readv_body(body, 2)
            assert segs[0][2] == bytes(range(8))          # bytes 0-7
            assert segs[1][2] == bytes(range(256))[:8]    # bytes 256-263

            _close(sock, fh)
        finally:
            sock.close()

    def test_readv_two_different_handles(self, proxy_env):
        """Readv with two different handles in one request translates both."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            s, b1 = _open(sock, "/alpha.txt", kXR_open_read, sid=b"\x00\x01")
            assert s == kXR_ok
            fh1 = _fh(b1)

            s, b2 = _open(sock, "/beta.txt", kXR_open_read, sid=b"\x00\x02")
            assert s == kXR_ok
            fh2 = _fh(b2)

            (status, body), _ = _readv(sock, [(fh1, 0, 4), (fh2, 0, 4)])
            assert status == kXR_ok
            segs = _parse_readv_body(body, 2)
            assert segs[0][2] == b"AAAA"
            assert segs[1][2] == b"1111"

            _close(sock, fh1)
            _close(sock, fh2)
        finally:
            sock.close()

    def test_readv_many_segments(self, proxy_env):
        """Many segments on one file all arrive and have correct total data size."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            s, b = _open(sock, "/data256.bin", kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)

            segments = [(fh, i * 16, 16) for i in range(16)]  # 16 × 16-byte segments
            (status, body), total_expected = _readv(sock, segments)
            assert status == kXR_ok, f"readv many_segments failed: {status}"
            # Total data in response = 16 * 16 (headers) + 16 * 16 (data) = 512
            assert len(body) >= total_expected, \
                f"response body too short: {len(body)} < {total_expected}"

            _close(sock, fh)
        finally:
            sock.close()

    def test_readv_after_other_operations(self, proxy_env):
        """Readv works correctly after a regular read on the same handle."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            s, b = _open(sock, "/data256.bin", kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)

            # Regular read first
            s, data = _read(sock, fh, 0, 4)
            assert s == kXR_ok
            assert data == bytes(range(4))

            # Then readv
            (status, body), _ = _readv(sock, [(fh, 8, 4)])
            assert status == kXR_ok
            segs = _parse_readv_body(body, 1)
            assert segs[0][2] == bytes(range(8, 12))

            _close(sock, fh)
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyLocate
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyLocate:
    """kXR_locate forwarding through the proxy."""

    def test_locate_existing_file(self, proxy_env):
        """Locate an existing file returns kXR_ok with location info."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _locate(sock, "/hello.txt")
            # The upstream may return ok or redirect; both are valid responses
            assert status in (kXR_ok, 4004), \
                f"unexpected locate status: {status}"
            assert len(body) > 0
        finally:
            sock.close()

    def test_locate_nonexistent_returns_error(self, proxy_env):
        """Locate a nonexistent file returns kXR_error."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, _ = _locate(sock, "/definitely_does_not_exist_abcde.txt")
            assert status == kXR_error
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyFsOps
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyFsOps:
    """Filesystem mutation operations forwarded through the proxy."""

    def test_mkdir_and_stat(self, proxy_env):
        """Create a directory through the proxy, then stat it."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            dname = f"/proxy_mkdir_{uuid.uuid4().hex[:8]}"
            status, _ = _mkdir(sock, dname)
            assert status == kXR_ok, f"mkdir failed: {status}"

            status, body = _stat(sock, dname)
            assert status == kXR_ok
            flags, _, _ = _parse_stat_body(body)
            assert flags & 0x10, "newly created directory should have kXR_isDir"
        finally:
            sock.close()

    def test_mkdir_nested_path(self, proxy_env):
        """mkdir with mkpath flag creates parent directories."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            dname = f"/proxy_nest_{uuid.uuid4().hex[:8]}/a/b"
            status, _ = _mkdir(sock, dname, mkpath=True)
            assert status == kXR_ok, f"mkdir nested failed: {status}"

            status, body = _stat(sock, dname)
            assert status == kXR_ok
        finally:
            sock.close()

    def test_rm_file(self, proxy_env):
        """Create a file, rm it, stat returns error."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            fname = f"/proxy_rm_{uuid.uuid4().hex[:8]}.txt"

            # Create
            s, b = _open(sock, fname, kXR_open_updt | kXR_new)
            assert s == kXR_ok
            _write(sock, _fh(b), 0, b"delete me")
            _close(sock, _fh(b))

            # Remove
            status, _ = _rm(sock, fname)
            assert status == kXR_ok, f"rm failed: {status}"

            # Stat should now fail
            status, _ = _stat(sock, fname)
            assert status == kXR_error
        finally:
            sock.close()

    def test_rmdir_empty_directory(self, proxy_env):
        """Create and remove an empty directory."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            dname = f"/proxy_rmdir_{uuid.uuid4().hex[:8]}"
            s, _ = _mkdir(sock, dname)
            assert s == kXR_ok

            s, _ = _rmdir(sock, dname)
            assert s == kXR_ok, f"rmdir failed: {s}"

            s, _ = _stat(sock, dname)
            assert s == kXR_error
        finally:
            sock.close()

    def test_mv_rename_file(self, proxy_env):
        """Rename a file through the proxy; old name disappears, new name works."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            src = f"/proxy_mv_src_{uuid.uuid4().hex[:8]}.txt"
            dst = f"/proxy_mv_dst_{uuid.uuid4().hex[:8]}.txt"

            s, b = _open(sock, src, kXR_open_updt | kXR_new)
            assert s == kXR_ok
            _write(sock, _fh(b), 0, b"rename me")
            _close(sock, _fh(b))

            s, _ = _mv(sock, src, dst)
            assert s == kXR_ok, f"mv failed: {s}"

            s, _ = _stat(sock, src)
            assert s == kXR_error, "source should no longer exist after mv"

            s, body = _stat(sock, dst)
            assert s == kXR_ok, "destination should exist after mv"
        finally:
            sock.close()

    def test_truncate_file_via_path(self, proxy_env):
        """Truncate a file to a smaller size through the proxy."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            fname = f"/proxy_trunc_{uuid.uuid4().hex[:8]}.bin"

            s, b = _open(sock, fname, kXR_open_updt | kXR_new)
            assert s == kXR_ok
            _write(sock, _fh(b), 0, b"A" * 1024)
            _close(sock, _fh(b))

            s, _ = _truncate_path(sock, fname, 16)
            assert s == kXR_ok, f"truncate failed: {s}"

            s, body = _stat(sock, fname)
            assert s == kXR_ok
            _, size, _ = _parse_stat_body(body)
            assert size == 16, f"expected size 16 after truncate, got {size}"
        finally:
            sock.close()

    def test_create_file_write_stat_rm(self, proxy_env):
        """Full lifecycle: create → write → stat → rm, all through the proxy."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            fname = f"/lifecycle_{uuid.uuid4().hex[:8]}.txt"
            content = b"lifecycle test payload 42\n"

            # create + write
            s, b = _open(sock, fname, kXR_open_updt | kXR_new)
            assert s == kXR_ok
            fh = _fh(b)
            s, _ = _write(sock, fh, 0, content)
            assert s == kXR_ok
            _sync(sock, fh)
            _close(sock, fh)

            # stat
            s, body = _stat(sock, fname)
            assert s == kXR_ok
            _, size, _ = _parse_stat_body(body)
            assert size == len(content)

            # rm
            s, _ = _rm(sock, fname)
            assert s == kXR_ok
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyErrorPropagation
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyErrorPropagation:
    """Backend errors must be relayed verbatim to the client."""

    def test_stat_missing_propagates_error(self, proxy_env):
        """kXR_error from backend on nonexistent stat reaches the client."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _stat(sock, "/this_file_does_not_exist_abc.txt")
            assert status == kXR_error
            assert len(body) >= 4   # error code present
        finally:
            sock.close()

    def test_open_missing_propagates_error(self, proxy_env):
        """kXR_error from backend on open(nonexistent) reaches the client."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, body = _open(sock, "/no_such.txt", kXR_open_read)
            assert status == kXR_error
            assert len(body) >= 4
        finally:
            sock.close()

    def test_error_does_not_break_connection(self, proxy_env):
        """After a backend error, the connection is still usable."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            # Trigger an error
            status, _ = _stat(sock, "/nonexistent_xyz.txt")
            assert status == kXR_error

            # Subsequent request on same connection must still work
            status, body = _stat(sock, "/hello.txt")
            assert status == kXR_ok, "connection broken after backend error"
            _, size, _ = _parse_stat_body(body)
            assert size == 22
        finally:
            sock.close()

    def test_multiple_errors_in_sequence(self, proxy_env):
        """Multiple sequential backend errors don't corrupt the connection."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            for i in range(5):
                sid = bytes([0, i + 1])
                p = f"/nonexistent_{i}.txt".encode()
                req = struct.pack(">2sHB11s4sI", sid, kXR_stat,
                                  0, b"\x00" * 11, b"\x00" * 4, len(p))
                sock.sendall(req + p)
                status, _ = _read_resp(sock)
                assert status == kXR_error, f"request {i}: expected error"

            # Connection must still be healthy
            status, _ = _ping(sock)
            assert status == kXR_ok
        finally:
            sock.close()

    def test_rm_nonexistent_error(self, proxy_env):
        """rm on a nonexistent file propagates kXR_error."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            status, _ = _rm(sock, "/ghost_file_xyz.txt")
            assert status == kXR_error
        finally:
            sock.close()

    def test_rmdir_nonempty_error(self, proxy_env):
        """rmdir on a non-empty directory propagates kXR_error."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            # /subdir has nested.txt in it
            status, _ = _rmdir(sock, "/subdir")
            assert status == kXR_error
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxySequential
# ──────────────────────────────────────────────────────────────────────────────

class TestProxySequential:
    """Many sequential requests on one connection — no state corruption."""

    def test_fifty_stats_in_sequence(self, proxy_env):
        """50 stat requests on one connection all succeed."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            for i in range(50):
                sid = bytes([i >> 8, i & 0xFF])
                p = b"/hello.txt"
                req = struct.pack(">2sHB11s4sI", sid, kXR_stat,
                                  0, b"\x00" * 11, b"\x00" * 4, len(p))
                sock.sendall(req + p)
                status, body = _read_resp(sock)
                assert status == kXR_ok, f"stat #{i} failed: {status}"
        finally:
            sock.close()

    def test_alternating_stat_and_ping(self, proxy_env):
        """Alternating stat (proxy'd) and ping (local) stay in sync."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            for i in range(20):
                # stat — goes to upstream
                s, body = _stat(sock, "/hello.txt")
                assert s == kXR_ok, f"stat #{i} failed"
                # ping — handled locally by proxy's session layer
                s, _ = _ping(sock)
                assert s == kXR_ok, f"ping #{i} failed"
        finally:
            sock.close()

    def test_open_read_close_cycle_repeated(self, proxy_env):
        """Open/read/close cycle repeated 20 times on same connection."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            for i in range(20):
                s, b = _open(sock, "/alpha.txt", kXR_open_read)
                assert s == kXR_ok, f"open #{i} failed"
                fh = _fh(b)
                s, data = _read(sock, fh, 0, 4)
                assert s == kXR_ok
                assert data == b"AAAA"
                _close(sock, fh)
        finally:
            sock.close()

    def test_write_read_delete_cycle_repeated(self, proxy_env):
        """Write/read/delete cycle 10 times — file content consistent each time."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            for i in range(10):
                fname = f"/seq_{i}_{uuid.uuid4().hex[:6]}.txt"
                content = f"iteration {i:03d}".encode()

                s, b = _open(sock, fname, kXR_open_updt | kXR_new)
                assert s == kXR_ok
                fh = _fh(b)
                _write(sock, fh, 0, content)
                _close(sock, fh)

                s, b = _open(sock, fname, kXR_open_read)
                assert s == kXR_ok
                fh = _fh(b)
                s, data = _read(sock, fh, 0, len(content) + 4)
                assert s == kXR_ok
                assert data == content, f"iter {i}: got {data!r}"
                _close(sock, fh)

                _rm(sock, fname)
        finally:
            sock.close()

    def test_mixed_opcodes_sequence(self, proxy_env):
        """A realistic mixed workload: stat, open, read, close, dirlist, mkdir, rm."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            s, _ = _stat(sock, "/hello.txt")
            assert s == kXR_ok

            s, b = _open(sock, "/alpha.txt", kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)
            s, d = _read(sock, fh, 0, 4)
            assert s == kXR_ok and d == b"AAAA"
            _close(sock, fh)

            s, _ = _dirlist(sock, "/")
            assert s == kXR_ok

            dname = f"/mixed_seq_{uuid.uuid4().hex[:6]}"
            s, _ = _mkdir(sock, dname)
            assert s == kXR_ok
            s, _ = _rmdir(sock, dname)
            assert s == kXR_ok

            s, _ = _ping(sock)
            assert s == kXR_ok
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyLargeRead
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyLargeRead:
    """Verify the proxy relays large data transfers correctly."""

    def test_read_512kb_file_in_one_request(self, proxy_env):
        """Read entire 512 KiB file in one request; content must match exactly."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        sock.settimeout(30)
        try:
            s, b = _open(sock, "/large.bin", kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)

            s, data = _read(sock, fh, 0, 512 * 1024)
            assert s == kXR_ok
            assert len(data) == 512 * 1024
            expected = bytes(i & 0xFF for i in range(512 * 1024))
            assert data == expected, "large read data mismatch"

            _close(sock, fh)
        finally:
            sock.close()

    def test_read_512kb_file_in_chunks(self, proxy_env):
        """Read a 512 KiB file in 64 KiB chunks; each chunk has expected content."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        sock.settimeout(30)
        try:
            s, b = _open(sock, "/large.bin", kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)

            chunk_size = 64 * 1024
            expected = bytes(i & 0xFF for i in range(512 * 1024))
            for offset in range(0, 512 * 1024, chunk_size):
                s, data = _read(sock, fh, offset, chunk_size)
                assert s == kXR_ok
                assert data == expected[offset:offset + chunk_size], \
                    f"chunk at offset {offset} mismatch"

            _close(sock, fh)
        finally:
            sock.close()

    def test_write_and_read_256kb(self, proxy_env):
        """Write 256 KiB through proxy, then read it back; content must match."""
        sock = _connect("127.0.0.1", proxy_env["proxy_port"])
        sock.settimeout(30)
        try:
            fname = f"/large_write_{uuid.uuid4().hex[:8]}.bin"
            payload = bytes(i & 0xFF for i in range(256 * 1024))

            s, b = _open(sock, fname, kXR_open_updt | kXR_new)
            assert s == kXR_ok
            fh = _fh(b)

            # Write in 64 KiB chunks
            chunk_size = 64 * 1024
            for offset in range(0, len(payload), chunk_size):
                s, _ = _write(sock, fh, offset, payload[offset:offset + chunk_size])
                assert s == kXR_ok
            _sync(sock, fh)
            _close(sock, fh)

            # Read back full file
            s, b = _open(sock, fname, kXR_open_read)
            assert s == kXR_ok
            fh = _fh(b)
            s, data = _read(sock, fh, 0, len(payload))
            assert s == kXR_ok
            assert data == payload
            _close(sock, fh)
        finally:
            sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyMultiClient
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyMultiClient:
    """Multiple clients sharing the same proxy concurrently."""

    def test_two_clients_independent_file_access(self, proxy_env):
        """Two simultaneous clients read different files; each sees its own data."""
        sock1 = _connect("127.0.0.1", proxy_env["proxy_port"])
        sock2 = _connect("127.0.0.1", proxy_env["proxy_port"])
        try:
            s, b1 = _open(sock1, "/alpha.txt", kXR_open_read)
            assert s == kXR_ok
            fh1 = _fh(b1)

            s, b2 = _open(sock2, "/beta.txt", kXR_open_read)
            assert s == kXR_ok
            fh2 = _fh(b2)

            s, d1 = _read(sock1, fh1, 0, 16)
            assert s == kXR_ok
            assert d1 == b"AAAABBBBCCCCDDDD"

            s, d2 = _read(sock2, fh2, 0, 16)
            assert s == kXR_ok
            assert d2 == b"1111222233334444"

            _close(sock1, fh1)
            _close(sock2, fh2)
        finally:
            sock1.close()
            sock2.close()

    def test_four_clients_stat_same_file(self, proxy_env):
        """Four clients stat the same file; all get the same result."""
        socks = [_connect("127.0.0.1", proxy_env["proxy_port"]) for _ in range(4)]
        try:
            for i, sock in enumerate(socks):
                s, body = _stat(sock, "/data256.bin")
                assert s == kXR_ok, f"client {i}: stat failed"
                _, size, _ = _parse_stat_body(body)
                assert size == 1024, f"client {i}: wrong size {size}"
        finally:
            for sock in socks:
                sock.close()

    def test_clients_write_to_separate_files_no_interference(self, proxy_env):
        """Multiple clients write different files; content is not interleaved."""
        socks = [_connect("127.0.0.1", proxy_env["proxy_port"]) for _ in range(3)]
        fnames = [f"/mc_write_{uuid.uuid4().hex[:6]}.txt" for _ in range(3)]
        payloads = [f"client {i} content".encode() for i in range(3)]
        try:
            handles = []
            for sock, fname, payload in zip(socks, fnames, payloads):
                s, b = _open(sock, fname, kXR_open_updt | kXR_new)
                assert s == kXR_ok
                handles.append(_fh(b))

            for sock, fh, payload in zip(socks, handles, payloads):
                s, _ = _write(sock, fh, 0, payload)
                assert s == kXR_ok
                _sync(sock, fh)
                _close(sock, fh)

            # Verify each file has the right content using a fresh connection
            verify_sock = _connect("127.0.0.1", proxy_env["proxy_port"])
            try:
                for fname, payload in zip(fnames, payloads):
                    s, b = _open(verify_sock, fname, kXR_open_read)
                    assert s == kXR_ok
                    fh = _fh(b)
                    s, data = _read(verify_sock, fh, 0, len(payload) + 4)
                    assert s == kXR_ok
                    assert data == payload, f"{fname}: got {data!r}"
                    _close(verify_sock, fh)
            finally:
                verify_sock.close()
        finally:
            for sock in socks:
                sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# TestProxyBackendUnavailable
# ──────────────────────────────────────────────────────────────────────────────

class TestProxyBackendUnavailable:
    """Graceful error handling when the upstream is unreachable.

    Uses the pre-launched proxy-dead nginx at PROXY_DEAD_NGINX_PORT which
    points at PROXY_DEAD_UPSTREAM_PORT (nothing listening there).
    """

    def test_fs_op_returns_error_when_backend_down(self):
        """First post-login FS opcode returns kXR_error if backend refuses connection."""
        if not os.path.exists(NGINX_BIN):
            pytest.skip(f"nginx binary not found: {NGINX_BIN}")

        sock = _connect("127.0.0.1", PROXY_DEAD_NGINX_PORT)
        try:
            # Ping (session opcode) must succeed — it's handled before upstream connect
            status, _ = _ping(sock)
            assert status == kXR_ok, "ping should work even with dead backend"

            # First FS opcode should fail gracefully (not crash or hang)
            sock.settimeout(5)
            status, body = _stat(sock, "/any_file.txt")
            assert status == kXR_error, \
                f"expected kXR_error with dead backend, got {status}"
            assert len(body) >= 4
        finally:
            sock.close()

    def test_session_still_clean_after_backend_failure(self):
        """After a backend failure, the client gets a clean error (no hang/crash)."""
        if not os.path.exists(NGINX_BIN):
            pytest.skip(f"nginx binary not found: {NGINX_BIN}")

        for _ in range(3):
            sock = _connect("127.0.0.1", PROXY_DEAD_NGINX_PORT)
            try:
                sock.settimeout(5)
                status, _ = _stat(sock, "/any_file.txt")
                assert status == kXR_error
            finally:
                sock.close()
