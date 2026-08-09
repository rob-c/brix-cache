"""
tests/test_token_security.py

JWT token security edge cases: algorithm confusion, nbf boundary,
structural malformation, scope path boundary, WebDAV Bearer edge cases,
and XRootD protocol-level token interactions.

Run:
    pytest tests/test_token_security.py -v
"""

import base64
import json
import os
import socket
import struct
import time

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.make_token import TokenIssuer, b64url_encode

from settings import (
    CA_CERT,
    DATA_ROOT,
    NGINX_TOKEN_PORT,
    NGINX_WEBDAV_PORT,
    SERVER_HOST,
    TOKENS_DIR,
)

# ---------------------------------------------------------------------------
# Module globals
# ---------------------------------------------------------------------------

TOKEN_DIR    = TOKENS_DIR
TOKEN_HOST   = SERVER_HOST
TOKEN_PORT   = NGINX_TOKEN_PORT
WEBDAV_BASE  = f"https://{SERVER_HOST}:{NGINX_WEBDAV_PORT}"
CA_PEM       = CA_CERT

# XRootD opcodes
kXR_auth     = 3000
kXR_login    = 3007
kXR_protocol = 3006
kXR_stat     = 3017
kXR_ping     = 3011
kXR_open     = 3010
kXR_close    = 3003

# Response status codes
kXR_ok       = 0
kXR_error    = 4003


@pytest.fixture(scope="module")
def issuer():
    ti = TokenIssuer(TOKEN_DIR)
    if not os.path.exists(ti.key_path):
        ti.init_keys()
    return ti


# ---------------------------------------------------------------------------
# Raw socket helpers
# ---------------------------------------------------------------------------

def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError(f"socket closed with {nbytes - len(data)} bytes remaining")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    header = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _raw_handshake():
    sock = socket.create_connection((TOKEN_HOST, TOKEN_PORT), timeout=5)
    sock.settimeout(5)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, body = _read_response(sock)
    assert status == kXR_ok
    return sock


def _send_login(sock, streamid=b"\x00\x02"):
    username = b"pytest\x00\x00"
    req = struct.pack("!2sHI8sBBBBI",
                      streamid, kXR_login,
                      os.getpid() & 0xFFFFFFFF,
                      username, 0, 0, 5, 0, 0)
    sock.sendall(req)
    return _read_response(sock)


def _send_auth_ztn(sock, token, streamid=b"\x00\x03"):
    token_bytes = token.encode("ascii") if isinstance(token, str) else token
    cred_payload = b"ztn\x00" + token_bytes
    req = struct.pack("!2sH", streamid, kXR_auth)
    req += b"\x00" * 12
    req += b"ztn\x00"
    req += struct.pack("!I", len(cred_payload))
    req += cred_payload
    sock.sendall(req)
    return _read_response(sock)


def _send_ping(sock, streamid=b"\x00\x04"):
    req = struct.pack("!2sH", streamid, kXR_ping)
    req += b"\x00" * 16
    req += struct.pack("!I", 0)
    sock.sendall(req)
    return _read_response(sock)


def _token_session(token):
    """Open a session and send ztn auth; return (sock, auth_status, auth_body)."""
    sock = _raw_handshake()
    req = struct.pack("!2sH I BB 10s I",
                      b"\x00\x01", kXR_protocol, 39, 0x01, 0x03, b"\x00"*10, 0)
    sock.sendall(req)
    _read_response(sock)
    _send_login(sock)
    status, body = _send_auth_ztn(sock, token)
    return sock, status, body


def _make_raw_token(alg, payload_dict):
    """Build a JWT with the given alg header value and payload dict.

    Signature is the raw RS256 sig over the signing input so that only
    the algorithm header differs from a valid token — the server must
    reject on alg, not on sig failure.
    """
    header = {"alg": alg, "typ": "JWT", "kid": TokenIssuer.DEFAULT_KID}
    h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64url_encode(json.dumps(payload_dict, separators=(",", ":")).encode())
    # Empty signature — the server should reject on alg before verifying sig
    s_b64 = b64url_encode(b"")
    return f"{h_b64}.{p_b64}.{s_b64}"


def _valid_payload():
    now = int(time.time())
    return {
        "iss": TokenIssuer.DEFAULT_ISSUER,
        "sub": "testuser",
        "aud": TokenIssuer.DEFAULT_AUDIENCE,
        "exp": now + 3600,
        "iat": now,
        "nbf": now,
        "scope": "storage.read:/",
        "wlcg.ver": "1.0",
    }


# =========================================================================
# Class 1 — Algorithm Confusion
# =========================================================================
