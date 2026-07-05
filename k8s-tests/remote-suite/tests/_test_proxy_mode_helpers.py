# _test_proxy_mode_helpers.py - shared header/helpers/fixtures for the Phase-38 split of
# test_proxy_mode.py.  `from _test_proxy_mode_helpers import *` re-exports EVERYTHING (incl imported
# names and `_`-prefixed helpers) via the __all__ below, so every split
# sibling shares the exact module-level environment of the original.
"""
Tests for XRootD transparent proxy mode (brix_tap_proxy on + brix_tap_proxy_upstream).

Topology:   test client ──► nginx (brix_tap_proxy on) ──► xrootd reference daemon

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
    BIND_HOST,
    HOST,
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

_PROXY_CONF = (
    """\
worker_processes 1;
error_log {LOG_DIR}/error.log debug;
pid       {LOG_DIR}/nginx.pid;

events {{ worker_connections 256; }}

stream {{
    server {{
        listen """
    + BIND_HOST
    + """:{PORT};
        xrootd on;
        brix_auth none;
        brix_tap_proxy on;
        brix_tap_proxy_upstream """
    + HOST
    + """:{UPSTREAM_PORT};
        brix_tap_proxy_auth anonymous;
    }}
}}
"""
)

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
            with socket.create_connection((HOST, PROXY_NGINX_PORT), timeout=1):
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


__all__ = [n for n in dir() if not n.startswith('__')]
