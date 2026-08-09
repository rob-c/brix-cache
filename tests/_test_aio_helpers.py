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


# ---------------------------------------------------------------------------
# Raw-wire session + disconnect-mid-read drivers (destroyed-guard stressors).
#
# `test_disconnect_during_large_read` above exercises ONE clean-close cycle.
# These add the two stressors the write-mirror ASan drivers have but the read
# side lacked: a HARD RST mid-flight (so the AIO completion fires against an
# already-reset fd, not an orderly FIN), and a churn loop that allocates then
# tears down the per-read AIO context many times so a double-free / UAF / leak
# in the destroyed-guard path is caught by AddressSanitizer.  Both run in the
# default (`not slow and not serial`) fleet, so they ride ASAN_TEST_CMD.
# ---------------------------------------------------------------------------

def _aio_login(sock, streamid):
    """Handshake + kXR_protocol + kXR_login as the anon user; asserts each OK."""
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    _recv_exact(sock, 16)
    sock.sendall(struct.pack(">BBHIBB10xI", 0, 1, kXR_protocol,
                             0x00000520, 0x02, 0x03, 0))
    status, _ = _read_response(sock)
    assert status == kXR_ok, "kXR_protocol failed"
    login_hdr = (struct.pack(">2sH", streamid, kXR_login) + struct.pack(">I", 0)
                 + b"anon\x00\x00\x00\x00" + struct.pack(">BBB", 0, 0, 5)
                 + struct.pack(">B", 0) + struct.pack(">I", 0))
    sock.sendall(login_hdr)
    status, _ = _read_response(sock)
    assert status == kXR_ok, "kXR_login failed"


def _aio_open_read_then_drop(host, port, path, size, rst, streamid=b"\x00\x01"):
    """Log in, open `path` for read, fire a large kXR_read that forces the AIO
    path, then drop the connection WITHOUT draining the reply — so the async
    completion lands after the client is gone.  `rst=True` sends a RST (SO_LINGER
    0) instead of an orderly close.  Returns nothing; the point is the drop."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    try:
        _aio_login(sock, streamid)
        open_body = (struct.pack(">H", OpenFlags.READ) + struct.pack(">HH", 0, 0)
                     + b"\x00" * 6 + b"\x00" * 4)
        status, fhandle = _send_req(sock, streamid, kXR_open, body=open_body,
                                    payload=path.encode())
        assert status == kXR_ok, "kXR_open failed"
        read_body = fhandle[:4] + struct.pack(">qi", 0, size)
        read_hdr = (struct.pack(">2sH", streamid, kXR_read) + read_body
                    + struct.pack(">I", 0))
        sock.sendall(read_hdr)        # do NOT read the response — drop mid-flight
        if rst:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            struct.pack("ii", 1, 0))   # close() -> RST, no FIN
    finally:
        sock.close()


def _aio_still_serves(host, port):
    """A fresh login+ping must still round-trip — proves the worker survived the
    stale AIO completion (no crash / UAF took it down)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    try:
        _aio_login(sock, b"\x00\x09")
        ping_hdr = (struct.pack(">2sH", b"\x00\x09", kXR_ping) + b"\x00" * 16
                    + struct.pack(">I", 0))
        sock.sendall(ping_hdr)
        status, _ = _read_response(sock)
        assert status == kXR_ok, "worker stopped serving after a mid-read drop"
    finally:
        sock.close()
