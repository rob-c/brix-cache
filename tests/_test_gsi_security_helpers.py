"""
tests/test_gsi_security.py

GSI authentication security tests for nginx-xrootd.

Covers:
  - Wire-level pre-auth opcode rejection on the GSI port (plain TCP, no TLS)
  - Protocol edge cases: bad credtype, empty/truncated kXR_auth body
  - XRootD Python client GSI functional tests (stat, read, write, dirlist)
  - VOMS proxy variant handling
  - GSI + in-protocol TLS port (port 11096) — same functional coverage

All raw-socket tests target port 11095 (plain GSI, no TLS).
XRootD client tests use gsi_url (port 11095) and gsi_tls_url (port 11096).

Run:
    python3 -m pytest tests/test_gsi_security.py -v
"""

import hashlib
import os
import socket
import struct

import pytest

from XRootD import client as xrd_client
from XRootD.client.flags import OpenFlags, QueryCode

from settings import (
    CA_DIR,
    DATA_ROOT,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    NGINX_GSI_TLS_PORT,
    PROXY_STD,
    SERVER_HOST,
    USER_CERT,
)

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

GSI_HOST    = SERVER_HOST
GSI_PORT    = NGINX_GSI_PORT      # plain GSI, port 11095
GSI_URL     = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}"
GSI_TLS_URL = f"roots://{SERVER_HOST}:{NGINX_GSI_TLS_PORT}"
ANON_URL    = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
PROXY_PEM   = PROXY_STD


def _ensure_random_bin():
    os.makedirs(DATA_ROOT, exist_ok=True)
    path = os.path.join(DATA_ROOT, "random.bin")
    if os.path.exists(path) and os.path.getsize(path) == 5242880:
        return
    with open(path, "wb") as handle:
        handle.write(bytes((i * 37 + 17) & 0xff for i in range(5242880)))

# ---------------------------------------------------------------------------
# XRootD opcodes (same as wire_protocol_security.py)
# ---------------------------------------------------------------------------

kXR_auth       = 3000
kXR_query      = 3001
kXR_chmod      = 3002
kXR_close      = 3003
kXR_dirlist    = 3004
kXR_mkdir      = 3008
kXR_login      = 3007
kXR_open       = 3010
kXR_ping       = 3011
kXR_read       = 3013
kXR_rm         = 3014
kXR_rmdir      = 3015
kXR_sync       = 3016
kXR_stat       = 3017
kXR_write      = 3019
kXR_writev     = 3031
kXR_readv      = 3025
kXR_pgwrite    = 3026
kXR_truncate   = 3028

kXR_ok              = 0
kXR_error           = 4003
kXR_NOT_AUTHORIZED  = 3010
kXR_Unsupported     = 3013


# ---------------------------------------------------------------------------
# Low-level helpers (raw TCP against plain-GSI port 11095)
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


def _handshake(sock):
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, _ = _read_response(sock)
    assert status == kXR_ok


def _login(sock, user=b"testuser"):
    padded = (user + b"\x00" * 8)[:8]
    req = struct.pack("!2sHI8sBBBBI",
                      b"\x00\x01", kXR_login,
                      os.getpid() & 0xFFFFFFFF,
                      padded, 0, 0, 5, 0, 0)
    sock.sendall(req)
    status, body = _read_response(sock)
    return status, body


def _raw_conn():
    sock = socket.create_connection((GSI_HOST, GSI_PORT), timeout=5)
    sock.settimeout(5)
    return sock


def _make_file(rel, content=b"x"):
    full = os.path.join(DATA_ROOT, rel.lstrip("/"))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        f.write(content)


def _gsi_fs():
    return xrd_client.FileSystem(GSI_URL)


def _gsi_tls_fs():
    return xrd_client.FileSystem(GSI_TLS_URL)


def _anon_fs():
    return xrd_client.FileSystem(ANON_URL)


def _xrd_read_all(url):
    f = xrd_client.File()
    status, _ = f.open(url)
    if not status.ok:
        return None
    status, st = f.stat()
    if not status.ok or st.size == 0:
        f.close()
        return b""
    status, data = f.read(size=st.size)
    f.close()
    return data if status.ok else None


# ---------------------------------------------------------------------------
# TestGSIPreAuthRejection
# (pre-login opcode rejection on plain GSI port 11095)
# ---------------------------------------------------------------------------
