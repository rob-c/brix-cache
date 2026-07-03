# _test_a_robustness_helpers.py - shared header/helpers/fixtures for the Phase-38 split of
# test_a_robustness.py.  `from _test_a_robustness_helpers import *` re-exports EVERYTHING (incl imported
# names and `_`-prefixed helpers) via the __all__ below, so every split
# sibling shares the exact module-level environment of the original.
"""
tests/test_server_robustness.py

Adversarial / robustness tests against a running XRootD server.

Uses raw TCP sockets with hand-crafted XRootD protocol messages to probe for:

  • Lockups   — server stops answering legitimate clients after malformed input
  • Crashes   — server process disappears
  • Auth-bypass — operations succeed without authentication
  • DoS vectors — a single client can exhaust connections or file descriptors
  • Protocol fuzzing — garbage opcodes, wrong dlen, bad magic, embedded nulls

The target is the nginx-xrootd anonymous endpoint on ANON_PORT.  Every
attack ends with a health check confirming the server still responds to
legitimate traffic.

Run with:
    pytest tests/test_server_robustness.py -v

Prerequisites:
    • nginx-xrootd running with anonymous auth on ANON_PORT  (default 1094)
    • A file at /tmp/xrd-test/data/ for read tests

Protocol wire layout (from brix_protocol.h + XProtocol.hh):

  ClientInitHandShake (20 bytes):
    first[4]=0  second[4]=0  third[4]=0  fourth[4]=htonl(4)  fifth[4]=htonl(2012)

  ClientRequestHdr (24 bytes):
    streamid[2]  requestid[2]  body[16]  dlen[4]
    ↑ All fields big-endian.  dlen = bytes of payload that follow.

  ClientOpenRequest body[16]:
    mode[2]  options[2]  optiont[2]  reserved[6]  fhtemplt[4]

  ClientReadRequest body[16]:
    fhandle[4]  offset[8]  rlen[4]
    ↑ No separate payload; dlen = 0.

  ClientCloseRequest body[16]:
    fhandle[4]  reserved[12]
    ↑ No payload; dlen = 0.

  ServerResponseHdr (8 bytes):
    streamid[2]  status[2]  dlen[4]
"""

import os
import socket
import struct
import threading
import time

import pytest
from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT
DATA_DIR  = DATA_ROOT

# ---------------------------------------------------------------------------
# XRootD protocol constants
# ---------------------------------------------------------------------------

# Request opcodes
kXR_auth     = 3000
kXR_close    = 3003
kXR_dirlist  = 3004
kXR_protocol = 3006
kXR_login    = 3007
kXR_mkdir    = 3008
kXR_open     = 3010
kXR_ping     = 3011
kXR_read     = 3013
kXR_rm       = 3014
kXR_stat     = 3017
kXR_write    = 3019
kXR_pgwrite  = 3026

# Response status codes
kXR_ok        = 0
kXR_error     = 4003

# Error codes (first 4 bytes of kXR_error body)
kXR_NotAuthorized = 3010
kXR_Unsupported   = 3013
kXR_FileNotOpen   = 3004

# Protocol version 5.2.0
PROTOVER = 0x00000520

# Handshake magic values
ROOTD_PQ = 2012

# ---------------------------------------------------------------------------
# Protocol builders
# All integers big-endian; all body arguments must be exactly 16 bytes.
# ---------------------------------------------------------------------------

HANDSHAKE              = struct.pack(">iiiii", 0, 0, 0, 4, ROOTD_PQ)
HANDSHAKE_BAD_FOURTH   = struct.pack(">iiiii", 0, 0, 0, 0, ROOTD_PQ)  # fourth must be 4
HANDSHAKE_BAD_FIFTH    = struct.pack(">iiiii", 0, 0, 0, 4, 9999)       # fifth must be 2012


def _body16(data: bytes) -> bytes:
    """Pad or truncate data to exactly 16 bytes."""
    return data[:16].ljust(16, b'\x00')


def make_request(streamid: bytes, reqid: int,
                 body: bytes = b'\x00' * 16,
                 payload: bytes = b'') -> bytes:
    """
    Build one complete XRootD request:
      ClientRequestHdr (24 bytes) + optional payload.
    streamid must be 2 bytes; body must be 16 bytes.
    """
    return (streamid
            + struct.pack(">H", reqid)
            + _body16(body)
            + struct.pack(">i", len(payload))
            + payload)


def make_protocol_req(streamid: bytes = b'\x00\x01',
                      flags: int = 0x01) -> bytes:
    """kXR_protocol — capability negotiation."""
    body = struct.pack(">I", PROTOVER)  # clientpv (4 bytes)
    body += bytes([flags])              # flags: 0x01 = kXR_secreqs
    body += b'\x00' * 11               # reserved
    return make_request(streamid, kXR_protocol, body)


def make_login_req(streamid: bytes = b'\x00\x02',
                   username: bytes = b'test\x00\x00\x00\x00') -> bytes:
    """kXR_login — anonymous login.
    ClientLoginRequest body[16]: pid[4] username[8] ability2[1] ability[1] capver[1] reserved[1]
    """
    body  = struct.pack(">I", os.getpid() & 0xFFFFFFFF)  # pid
    body += username[:8].ljust(8, b'\x00')                # username
    body += b'\x00'                                         # ability2
    body += b'\x00'                                         # ability
    body += b'\x05'                                         # capver (v5)
    body += b'\x00'                                         # reserved
    return make_request(streamid, kXR_login, body)


def make_ping_req(streamid: bytes = b'\x00\x03') -> bytes:
    """kXR_ping — liveness check (no body, no payload)."""
    return make_request(streamid, kXR_ping)


def make_stat_req(path: bytes, streamid: bytes = b'\x00\x04') -> bytes:
    """kXR_stat — stat a path.
    ClientStatRequest body[16]: options[1] reserved[7] wants[4] fhandle[4]
    Path (null-terminated) is the payload.
    """
    return make_request(streamid, kXR_stat,
                        body=b'\x00' * 16,
                        payload=path + b'\x00')


def make_open_req(path: bytes, options: int = 0x0010,
                  streamid: bytes = b'\x00\x05') -> bytes:
    """kXR_open — open a file.
    ClientOpenRequest body[16]: mode[2] options[2] optiont[2] reserved[6] fhtemplt[4]
    Path (null-terminated) is the payload.
    """
    body  = struct.pack(">H", 0)        # mode (POSIX bits; 0 = default)
    body += struct.pack(">H", options)  # options: 0x0010 = kXR_open_read
    body += b'\x00' * 12               # optiont + reserved + fhtemplt
    return make_request(streamid, kXR_open, body, path + b'\x00')


def make_read_req(handle: bytes, offset: int, rlen: int,
                  streamid: bytes = b'\x00\x06') -> bytes:
    """kXR_read — read from an open file.
    ClientReadRequest body[16]: fhandle[4] offset[8] rlen[4]
    No payload; dlen = 0.
    """
    body = handle[:4] + struct.pack(">qi", offset, rlen)
    return make_request(streamid, kXR_read, body)


def make_close_req(handle: bytes,
                   streamid: bytes = b'\x00\x07') -> bytes:
    """kXR_close — close an open file handle.
    ClientCloseRequest body[16]: fhandle[4] reserved[12]
    """
    body = handle[:4] + b'\x00' * 12
    return make_request(streamid, kXR_close, body)


# ---------------------------------------------------------------------------
# Low-level socket helpers
# ---------------------------------------------------------------------------

RECV_TIMEOUT = 5.0
CONN_TIMEOUT = 3.0


def _connect(host: str = None, port: int = None) -> socket.socket:
    if host is None:
        host = ANON_HOST
    if port is None:
        port = ANON_PORT
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(CONN_TIMEOUT)
    s.connect((host, port))
    s.settimeout(RECV_TIMEOUT)
    return s


def _recvall(s: socket.socket, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Server closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def _recv_response(s: socket.socket) -> tuple[int, bytes]:
    """Read one complete ServerResponseHdr + body. Returns (status, body)."""
    hdr    = _recvall(s, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen   = struct.unpack(">i", hdr[4:8])[0]
    body   = _recvall(s, dlen) if dlen > 0 else b''
    return status, body


def _handshake_and_protocol(s: socket.socket) -> tuple[int, int]:
    """Send handshake + kXR_protocol; return (hs_status, proto_status)."""
    s.sendall(HANDSHAKE + make_protocol_req())
    hs_st, _  = _recv_response(s)
    pr_st, _  = _recv_response(s)
    return hs_st, pr_st


def _full_anon_login(s: socket.socket) -> tuple[int, int, int]:
    """Handshake + protocol + anonymous login. Returns (hs, proto, login) statuses."""
    hs_st, pr_st, lg_st, _ = _full_anon_login_body(s)
    return hs_st, pr_st, lg_st


def _full_anon_login_body(s: socket.socket) -> tuple[int, int, int, bytes]:
    """Handshake + protocol + anonymous login. Includes the login response body."""
    hs_st, pr_st = _handshake_and_protocol(s)
    s.sendall(make_login_req())
    lg_st, body = _recv_response(s)
    return hs_st, pr_st, lg_st, body


def _errcode(body: bytes) -> int:
    """Extract the 4-byte error code from a kXR_error response body."""
    return struct.unpack(">I", body[:4])[0] if len(body) >= 4 else 0


# ---------------------------------------------------------------------------
# Health check — confirm server still serves legitimate requests
# ---------------------------------------------------------------------------

def server_healthy(host: str = None, port: int = None) -> bool:
    if host is None:
        host = ANON_HOST
    if port is None:
        port = ANON_PORT
    """
    Connect, complete handshake + login + ping.
    Returns True if every step returns kXR_ok within short timeouts.
    """
    try:
        s = _connect(host, port)
        s.settimeout(4.0)
        hs_st, pr_st = _handshake_and_protocol(s)
        if hs_st != kXR_ok or pr_st != kXR_ok:
            s.close()
            return False
        s.sendall(make_login_req())
        lg_st, _ = _recv_response(s)
        if lg_st != kXR_ok:
            s.close()
            return False
        s.sendall(make_ping_req())
        ping_st, _ = _recv_response(s)
        s.close()
        return ping_st == kXR_ok
    except Exception:
        return False


def assert_healthy(host: str = None, port: int = None, retries: int = 3):
    """Verify the server is healthy, retrying briefly to allow recovery."""
    if host is None:
        host = ANON_HOST
    if port is None:
        port = ANON_PORT
    for _ in range(retries):
        if server_healthy(host, port):
            return
        time.sleep(0.5)
    pytest.fail(
        f"Server at {host}:{port} failed health check after {retries} attempts — "
        "it may have crashed or locked up."
    )


# ---------------------------------------------------------------------------
# Module fixture — skip if server is not reachable
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def require_server(test_env):
    time.sleep(5.0)
    for _ in range(10):
        if server_healthy():
            return
        time.sleep(0.5)
    pytest.skip(
        f"No XRootD server reachable at {ANON_HOST}:{ANON_PORT}."
    )


# ============================================================================
# 1. Lockup probes
#    Malformed or truncated input must never cause the server to hang.
# ============================================================================


__all__ = [n for n in dir() if not n.startswith('__')]
