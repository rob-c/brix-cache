"""
tests/test_wire_protocol_security.py

Wire protocol security: stream ID echo, malformed dlen, unknown opcodes,
pre-auth rejection gaps, handshake edge cases, resource exhaustion probes.

All tests use raw TCP sockets to NGINX_ANON_PORT (11094).

Run:
    pytest tests/test_wire_protocol_security.py -v
"""

import os
import socket
import struct
import time

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

# ---------------------------------------------------------------------------
# Module globals
# ---------------------------------------------------------------------------

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT
DATA_DIR  = DATA_ROOT

# XRootD opcodes
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
kXR_set       = 3018
kXR_write     = 3019
kXR_fattr     = 3020
kXR_statx     = 3022
kXR_endsess   = 3023
kXR_readv     = 3025
kXR_pgwrite   = 3026
kXR_locate    = 3027
kXR_truncate  = 3028
kXR_writev    = 3031
kXR_pgread    = 3026 + 1  # not a real opcode; intentionally invalid

# kXR_pgread is actually 3026+1=3027 which is locate; use an actual value
kXR_pgread    = 3029  # just beyond range, for invalid opcode tests

# Response codes
kXR_ok           = 0
kXR_error        = 4003
kXR_NOT_AUTHORIZED = 3010
kXR_Unsupported    = 3013
kXR_InvalidRequest = 3006   # "Invalid request code" — stock's reply for an unknown opcode

# Open flags
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_open_new  = 0x0008


# ---------------------------------------------------------------------------
# Raw socket helpers
# ---------------------------------------------------------------------------

def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError(f"socket closed, {nbytes - len(data)} bytes remaining")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    header = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return streamid, status, body


def _handshake(host=None, port=None):
    h = host or ANON_HOST
    p = port or ANON_PORT
    sock = socket.create_connection((h, p), timeout=5)
    sock.settimeout(5)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    sid, status, body = _read_response(sock)
    assert status == kXR_ok
    return sock


def _login(sock, streamid=b"\x00\x01"):
    req = struct.pack("!2sHI8sBBBBI",
                      streamid, kXR_login,
                      os.getpid() & 0xFFFFFFFF,
                      b"pytest\x00\x00", 0, 0, 5, 0, 0)
    sock.sendall(req)
    return _read_response(sock)


def _ping(sock, streamid=b"\x00\x0f"):
    req = struct.pack("!2sH16sI", streamid, kXR_ping, b"\x00"*16, 0)
    sock.sendall(req)
    return _read_response(sock)


def _open_file(sock, path, options=kXR_open_read, streamid=b"\x00\x02"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH2s6s4sI",
                      streamid, kXR_open,
                      0o644, options, b"\x00\x00", b"\x00"*6, b"\x00"*4, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _close(sock, fhandle, streamid=b"\x00\x0e"):
    req = struct.pack("!2sH4s12sI", streamid, kXR_close, fhandle, b"\x00"*12, 0)
    sock.sendall(req)
    return _read_response(sock)


def _full_session():
    """Handshake + login; return open socket."""
    sock = _handshake()
    sid, status, body = _login(sock)
    assert status == kXR_ok
    return sock


def _error_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


def _send_raw(sock, streamid, reqid, body16, payload=b""):
    """Send a raw XRootD request with 16-byte fixed body."""
    req = struct.pack("!2sH16sI",
                      streamid, reqid, body16, len(payload))
    sock.sendall(req + payload)


# =========================================================================
# Class 1 — StreamID Echo Correctness
# =========================================================================
