"""
tests/test_query_extended.py

Query infotypes with zero coverage: Qconfig keys, Qvisa, Qopaque,
dirlist edge cases, cross-query consistency checks.

Run:
    pytest tests/test_query_extended.py -v
"""

import os
import socket
import struct
import zlib

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

kXR_query    = 3001
kXR_login    = 3007
kXR_open     = 3010
kXR_close    = 3003
kXR_dirlist  = 3004
kXR_ping     = 3011

# Query infotypes
kXR_QStats   = 1
kXR_QPrep    = 2
kXR_Qcksum   = 3
kXR_Qckscan  = 6
kXR_Qspace   = 5
kXR_Qconfig  = 7
kXR_Qvisa    = 8
kXR_QFSinfo  = 10
kXR_Qopaque  = 16

# Response codes
kXR_ok       = 0
kXR_oksofar  = 4000
kXR_error    = 4003
kXR_ArgInvalid = 3000
kXR_NotFound = 3011
kXR_Unsupported = 3013

# Open flags
kXR_open_read = 0x0010

# Dirlist flags
kXR_dstat = 0x02

# ---------------------------------------------------------------------------
# Module globals
# ---------------------------------------------------------------------------

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT
DATA_DIR  = DATA_ROOT


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


def _query(sock, infotype, payload=b"", streamid=b"\x00\x02"):
    """Send kXR_query with infotype and optional payload."""
    req = struct.pack("!2sHHH4s8sI",
                      streamid, kXR_query,
                      infotype,
                      0,             # reserved1
                      b"\x00"*4,    # fhandle (unused)
                      b"\x00"*8,    # reserved2
                      len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _dirlist(sock, path, flags=0, streamid=b"\x00\x02"):
    path_bytes = path.encode() + b"\x00" if isinstance(path, str) else path
    # kXR_dirlist body: 15 bytes reserved + 1 byte options + 4-byte dlen
    body16 = b"\x00" * 15 + bytes([flags])
    req = struct.pack("!2sH16sI", streamid, kXR_dirlist, body16, len(path_bytes))
    sock.sendall(req + path_bytes)
    # Drain kXR_oksofar (4000) chunks until final kXR_ok (0)
    all_body = bytearray()
    while True:
        status, body = _read_response(sock)
        all_body.extend(body)
        if status != kXR_oksofar:
            return status, bytes(all_body)


def _error_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


def _make_file(name, content=b"x"):
    path = os.path.join(DATA_DIR, name.lstrip("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(content)


def _make_dir(name):
    os.makedirs(os.path.join(DATA_DIR, name.lstrip("/")), exist_ok=True)


def _adler_hex(data):
    return f"{zlib.adler32(data) & 0xFFFFFFFF:08x}"


# =========================================================================
# Class 1 — Qconfig Known Keys
# =========================================================================
