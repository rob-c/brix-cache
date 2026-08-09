"""
tests/test_fattr_query.py

Functional tests for:
  - kXR_fattr  (3020): file extended attributes (get/set/del/list)
  - kXR_QStats  (1): server statistics XML response
  - kXR_Qxattr  (4): extended-attribute query by path
  - kXR_QFinfo  (9): file information (compression type)
  - kXR_QFSinfo (10): filesystem information

Most tests use the anonymous XRootD endpoint (root://localhost:11094/),
with selected tests also covering the GSI endpoint (root://localhost:11095/).

kXR_fattr uses the XRootD Python-client FileProperty / FileSystem.{set,get,
del,list}_xattr API.  The query subtypes are exercised via raw socket tests
(the Python client does not expose all QueryCode variants) or via
FileSystem.query() where the enum value is available.
"""

import os
import socket
import struct
import tempfile
import time
import pytest
from settings import (
    CA_DIR,
    DATA_ROOT,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    PROXY_STD,
    SERVER_HOST,
)

# ── XRootD Python client imports ─────────────────────────────────────────────

try:
    from XRootD import client as xrd_client
    from XRootD.client.flags import OpenFlags, QueryCode
    HAS_XROOTD = True
except ImportError:
    HAS_XROOTD = False

pytestmark = pytest.mark.skipif(not HAS_XROOTD,
                                reason="XRootD Python client not installed")

# ── Endpoints ─────────────────────────────────────────────────────────────────

ANON_URL  = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}/"
GSI_URL   = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}/"
ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT
DATA_DIR  = DATA_ROOT
PROXY_PEM = PROXY_STD


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_file(name: str, content: bytes = b"hello fattr\n") -> str:
    """Create a test file under DATA_DIR and return the XRootD path."""
    os.makedirs(DATA_DIR, exist_ok=True)
    fpath = os.path.join(DATA_DIR, name)
    with open(fpath, "wb") as f:
        f.write(content)
    return "/" + name


def rm_file(name: str) -> None:
    path = os.path.join(DATA_DIR, name)
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


# ── Raw-socket helpers (for query subtypes the Python client doesn't expose) ──

_SESSION_ID_LEN = 16
_HDR_LEN = 24
_RSP_HDR_LEN = 8

_kXR_protocol = 3006
_kXR_login    = 3007
_kXR_query    = 3001
_kXR_ok       = 0

_kXR_QStats  = 1
_kXR_Qxattr  = 4
_kXR_QFinfo  = 9
_kXR_QFSinfo = 10


def _recvall(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        assert chunk, "connection closed unexpectedly"
        buf += chunk
    return buf


def _recv_response(sock: socket.socket) -> tuple[int, bytes]:
    """Read one XRootD response and return (status, body)."""
    hdr = _recvall(sock, _RSP_HDR_LEN)
    _sid0, _sid1, status, dlen = struct.unpack(">BBHI", hdr)
    body = _recvall(sock, dlen) if dlen else b""
    return status, body


def _raw_session(host: str, port: int) -> socket.socket:
    """Open a raw TCP socket, perform handshake + anonymous login."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))

    # Handshake: 5 × int32 = 20 bytes
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))

    # kXR_protocol (24 bytes): streamid[2] requestid[2] clientpv[4]
    #   flags[1] expect[1] reserved[10] dlen[4]
    sock.sendall(struct.pack(">BB H I BB 10x I",
                             0, 1, _kXR_protocol, 0x00000520, 0x02, 0x03, 0))

    _recvall(sock, 16)    # handshake reply (standard 8-byte hdr + 8-byte body)
    _recv_response(sock)  # protocol reply

    # kXR_login (24 bytes): streamid[2] requestid[2] pid[4] username[8]
    #   ability2[1] ability[1] capver[1] reserved[1] dlen[4]
    sock.sendall(struct.pack(">BB H I 8s BB B B I",
                             0, 1, _kXR_login, 0,
                             b"nobody\x00\x00",
                             0, 0, 5, 0, 0))
    status, body = _recv_response(sock)
    assert status == _kXR_ok, f"login failed: status={status}"
    return sock


def _send_query(sock: socket.socket, infotype: int, payload: bytes) -> bytes:
    """Send kXR_query with the given infotype and payload, return response body.

    ClientQueryRequest (24 bytes):
      streamid[2] requestid[2] infotype[2] reserved1[2]
      fhandle[4] reserved2[8] dlen[4]
    """
    dlen = len(payload)
    # 2+2+2+2+4+8 = 20 bytes before dlen, then dlen[4] = 24 total
    hdr = struct.pack(">BB H H 2x 4x 8x I",
                      0, 1, _kXR_query, infotype, dlen)
    sock.sendall(hdr + payload)
    status, body = _recv_response(sock)
    assert status == _kXR_ok, f"query infotype={infotype} failed: status={status}"
    return body


# ═══════════════════════════════════════════════════════════════════════════════
# TestFattr — kXR_fattr via Python client
# ═══════════════════════════════════════════════════════════════════════════════
