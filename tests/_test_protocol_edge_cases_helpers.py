"""
Protocol conformance edge cases for nginx-xrootd.

Tests wire-level protocol behavior that is not covered by the higher-level
XRootD Python client API tests:

  - Handshake validation (bad magic fields)
  - Multiple sequential requests on one connection
  - kXR_endsess behavior
  - readv with invalid segment descriptors
  - Stat on a handle (handle-based stat)
  - Open with conflicting flags
  - Connection resilience (server stays up after bad requests)

Run:
    pytest tests/test_protocol_edge_cases.py -v -s
"""

import os
import socket
import struct
import time

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags, QueryCode
from backend_matrix import root_endpoint_parts, selected_backend_name
from settings import (
    DATA_ROOT,
    HOST,
    NGINX_ANON_PORT,
    REF_BRIX_PORT,
    SERVER_HOST,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CROSS_BACKEND = selected_backend_name()

if CROSS_BACKEND == "xrootd":
    ANON_URL = f"root://{HOST}:{REF_BRIX_PORT}"
else:
    ANON_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"

ANON_HOST, ANON_PORT = root_endpoint_parts(ANON_URL)
DATA_DIR  = DATA_ROOT


# Request opcodes
kXR_query     = 3001
kXR_close     = 3003
kXR_dirlist   = 3004
kXR_protocol  = 3006
kXR_login     = 3007
kXR_open      = 3010
kXR_ping      = 3011
kXR_read      = 3013
kXR_stat      = 3017
kXR_readv     = 3025
kXR_endsess   = 3023

# Response/error codes
kXR_OK          = 0
kXR_ERROR       = 4003
kXR_FileNotOpen = 3004
kXR_ArgInvalid  = 3000

# Open flags
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_new       = 0x0008
kXR_delete    = 0x0002
kXR_retstat   = 0x0400

# Query infotypes
kXR_Qcksum  = 8
kXR_QSpace  = 6
kXR_QCONFIG = 7


# ---------------------------------------------------------------------------
# Raw protocol helpers
# ---------------------------------------------------------------------------

def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise AssertionError("socket closed early")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    header = _recv_exact(sock, 8)
    _sid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _raw_session():
    sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
    sock.settimeout(5)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, body = _read_response(sock)
    assert status == kXR_OK
    assert len(body) == 8
    return sock


def _login_anon(sock, streamid=b"\x00\x01"):
    username = b"pytest\x00\x00"
    req = struct.pack(
        "!2sHI8sBBBBI",
        streamid, kXR_login,
        os.getpid() & 0xFFFFFFFF,
        username, 0, 0, 5, 0, 0,
    )
    sock.sendall(req)
    status, body = _read_response(sock)
    assert status == kXR_OK
    return body


def _open_file_raw(sock, path, options, streamid=b"\x00\x02"):
    req = struct.pack(
        "!2sHHH2s6s4sI",
        streamid, kXR_open,
        0o644, options,
        b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
        len(path),
    )
    sock.sendall(req + path)
    return _read_response(sock)


def _close_handle(sock, fhandle, streamid=b"\x00\x09"):
    req = struct.pack("!2sH4s12sI", streamid, kXR_close, fhandle, b"\x00" * 12, 0)
    sock.sendall(req)
    _read_response(sock)


def _error_code(body):
    assert len(body) >= 4
    return struct.unpack("!I", body[:4])[0]


# ===========================================================================
# Handshake validation
# ===========================================================================
