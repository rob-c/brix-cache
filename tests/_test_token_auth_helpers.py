"""
tests/test_token_auth.py

JWT/WLCG bearer-token authentication tests for nginx-xrootd.

Tests both the XRootD stream protocol (port 11097, "ztn" credential type)
and HTTPS/WebDAV (port 8443, Authorization: Bearer header).

Token generation uses the local signing authority created by
utils/make_token.py.  The JWKS is loaded at nginx startup from
/tmp/xrd-test/tokens/jwks.json.

Test categories:
  1. Token generation — valid, expired, bad signature, wrong issuer etc.
  2. XRootD protocol — raw-socket auth with ztn, then file operations
  3. WebDAV/HTTPS    — Bearer token for GET/PUT/HEAD/PROPFIND
  4. Scope enforcement — path-based read/write authorization
  5. Negative cases  — expired, wrong issuer, wrong audience, bad sig

Run:
    pytest tests/test_token_auth.py -v
"""

import os
import re
import socket
import struct
import tempfile

import urllib3
import pytest
import requests
from settings import (
    CA_CERT,
    DATA_ROOT,
    NGINX_TOKEN_PORT,
    NGINX_WEBDAV_PORT,
    SERVER_HOST,
    TOKENS_DIR,
)

# Suppress InsecureRequestWarning for verify=False in WebDAV tests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Adjust import path for the token issuer utility
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.make_token import TokenIssuer


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOKEN_DIR   = TOKENS_DIR
TOKEN_URL   = f"root://{SERVER_HOST}:{NGINX_TOKEN_PORT}"
TOKEN_HOST  = SERVER_HOST
TOKEN_PORT  = NGINX_TOKEN_PORT
WEBDAV_BASE = f"https://{SERVER_HOST}:{NGINX_WEBDAV_PORT}"
CA_PEM      = CA_CERT

# XRootD request IDs (host byte order)
kXR_auth     = 3000
kXR_login    = 3007
kXR_protocol = 3006
kXR_stat     = 3017
kXR_open     = 3010
kXR_read     = 3013
kXR_close    = 3003
kXR_dirlist  = 3004
kXR_write    = 3019
kXR_ping     = 3011

# XRootD response status codes
kXR_ok        = 0
kXR_oksofar   = 4000
kXR_error     = 4003
kXR_authmore  = 4002

# kXR_open flags
kXR_open_read  = 0x0000
kXR_open_new   = 0x0008
kXR_open_mkpath = 0x0100
kXR_open_force  = 0x0004  # kXR_delete

# ---------------------------------------------------------------------------
# Token issuer fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def issuer():
    """Load the test signing authority (keys already created)."""
    ti = TokenIssuer(TOKEN_DIR)
    # Keys should exist from the init step; re-create if missing
    if not os.path.exists(ti.key_path):
        ti.init_keys()
    return ti


# ---------------------------------------------------------------------------
# Raw XRootD protocol helpers
# ---------------------------------------------------------------------------

def _recv_exact(sock, nbytes):
    """Read exactly nbytes from a socket."""
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError(f"socket closed with {nbytes - len(data)} bytes remaining")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    """Read one XRootD response: 8-byte header + body."""
    header = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _raw_handshake(host=None, port=None):
    """Open a raw socket and complete the 20-byte XRootD handshake."""
    if host is None:
        host = TOKEN_HOST
    if port is None:
        port = TOKEN_PORT
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(5)
    # Client hello: 20 bytes of handshake
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, body = _read_response(sock)
    assert status == kXR_ok, f"handshake failed: status={status}"
    assert len(body) == 8, f"unexpected handshake body length: {len(body)}"
    return sock


def _send_protocol(sock, streamid=b"\x00\x01"):
    """Send kXR_protocol with kXR_secreqs flag and return security info."""
    req = struct.pack(
        "!2sH I BB 10s I",
        streamid,
        kXR_protocol,
        39,           # clientpv = 0x27 = protocol version 39
        0x01,         # flags: kXR_secreqs
        0x03,         # expect: kXR_ExpLogin
        b"\x00" * 10, # reserved
        0,            # dlen
    )
    sock.sendall(req)
    status, body = _read_response(sock)
    return status, body


def _send_login(sock, streamid=b"\x00\x02"):
    """Send kXR_login and return the session ID + parameter block."""
    username = b"pytest\x00\x00"
    req = struct.pack(
        "!2sH I 8s B B B B I",
        streamid,
        kXR_login,
        os.getpid() & 0xFFFFFFFF,
        username,
        0,    # ability2
        0,    # ability
        5,    # capver
        0,    # reserved
        0,    # dlen
    )
    sock.sendall(req)
    status, body = _read_response(sock)
    return status, body


def _send_auth_ztn(sock, token, streamid=b"\x00\x03"):
    """Send kXR_auth with credential type 'ztn' and raw JWT payload."""
    token_bytes = token.encode("ascii") if isinstance(token, str) else token
    # Credential type goes in cur_body[0..3]; token in payload after "ztn\0"
    cred_payload = b"ztn\x00" + token_bytes

    # Build the 24-byte request header
    credtype = b"ztn\x00"
    reserved = b"\x00" * 12
    req = struct.pack("!2sH", streamid, kXR_auth)
    req += reserved
    req += credtype
    req += struct.pack("!I", len(cred_payload))
    req += cred_payload

    sock.sendall(req)
    return _read_response(sock)


def _send_stat(sock, path, streamid=b"\x00\x04"):
    """Send kXR_stat for a path."""
    path_bytes = path.encode() + b"\x00"
    # kXR_stat body: 16 bytes reserved, then path in payload
    req = struct.pack("!2sH", streamid, kXR_stat)
    req += b"\x00" * 16  # reserved body bytes
    req += struct.pack("!I", len(path_bytes))
    req += path_bytes
    sock.sendall(req)
    return _read_response(sock)


def _send_dirlist(sock, path, streamid=b"\x00\x05"):
    """Send kXR_dirlist and drain all kXR_oksofar chunks."""
    path_bytes = path.encode() + b"\x00"
    req = struct.pack("!2sH", streamid, kXR_dirlist)
    req += b"\x00" * 16
    req += struct.pack("!I", len(path_bytes))
    req += path_bytes
    sock.sendall(req)
    all_body = bytearray()
    while True:
        status, body = _read_response(sock)
        all_body.extend(body)
        if status != kXR_oksofar:
            return status, bytes(all_body)


def _send_ping(sock, streamid=b"\x00\x06"):
    """Send kXR_ping."""
    req = struct.pack("!2sH", streamid, kXR_ping)
    req += b"\x00" * 16
    req += struct.pack("!I", 0)
    sock.sendall(req)
    return _read_response(sock)


def _token_session(token, host=None, port=None):
    """Open a raw XRootD session with token auth and return the socket."""
    sock = _raw_handshake(host, port)
    status, body = _send_protocol(sock)
    assert status == kXR_ok

    status, body = _send_login(sock)
    assert status == kXR_ok
    assert len(body) >= 16

    status, body = _send_auth_ztn(sock, token)
    return sock, status, body


# =========================================================================
# 1. TOKEN GENERATION TESTS
# =========================================================================
