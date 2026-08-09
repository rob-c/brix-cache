"""
Tests for kXR_bind — secondary data channel attachment to an existing session.

Secondary connections are used by xrdcp for parallel data transfer.  The client
establishes a primary connection (handshake + login + auth), then opens
additional TCP connections that skip login and send kXR_bind with the primary
session's sessid.  The server assigns a pathid (1–253) to the secondary.

This test suite exercises:

  - Bind request with valid primary session ID → pathid assignment
  - Secondary connection inherits auth state (logged_in + auth_done = 1)
  - Secondary can read file handles opened and published by the primary
  - Secondary cannot independently open, close, or mutate files
  - Pathid cycling — multiple binds cycle through 1–253
  - Invalid sessid → kXR_error

Run:
    pytest tests/test_session_bind.py -v -s
"""

import os
import socket
import struct
import threading
import time

import pytest

from settings import CA_DIR, DATA_ROOT, SERVER_HOST

ANON_HOST = SERVER_HOST
ANON_PORT = 0


# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------

kXR_ok        = 0
kXR_oksofar   = 4000
kXR_error     = 4003
kXR_protocol  = 3006
kXR_login     = 3007
kXR_open      = 3010
kXR_read      = 3013
kXR_write     = 3017
kXR_close     = 3003
kXR_bind      = 3024
kXR_open_read = 0x0010  # open flags: read-only
kXR_new       = 0x0008  # open flags: create new
kXR_delete    = 0x0002  # open flags: delete/overwrite


# ---------------------------------------------------------------------------
# Helpers — raw socket XRootD client
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _send_req(sock, streamid, reqid, body=b"", payload=b""):
    hdr = bytes(streamid[:2]) + struct.pack(">H", reqid)
    hdr += body.ljust(16, b"\x00")
    hdr += struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)
    rsp_hdr = _recv_exact(sock, 8)
    assert rsp_hdr is not None, "no response received"
    status = struct.unpack(">H", rsp_hdr[2:4])[0]
    dlen = struct.unpack(">I", rsp_hdr[4:8])[0]
    body_data = b""
    if dlen > 0:
        body_data = _recv_exact(sock, dlen)
    return status, body_data


def _establish_primary(url_port):
    """Establish a primary connection: handshake + protocol + login.

    Returns (sock, sessid, streamid).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ANON_HOST, url_port))

    # Handshake
    handshake = struct.pack(">IIIII", 0, 0, 0, 4, 2012)
    sock.sendall(handshake)
    rsp = _recv_exact(sock, 16)  # handshake response is 16 bytes (8B hdr + 8B body)
    assert rsp is not None

    # kXR_protocol
    status, body = _send_req(sock, b"\x00\x01", kXR_protocol)
    assert status == kXR_ok

    # kXR_login — anonymous
    login_payload = b"anonymous\x00"
    status, sessid_body = _send_req(sock, b"\x00\x01", kXR_login, payload=login_payload)
    assert status == kXR_ok
    assert len(sessid_body) >= 16

    sessid = sessid_body[:16]
    return sock, sessid, b"\x00\x01"


def _write_data_file(name, content):
    os.makedirs(DATA_ROOT, exist_ok=True)
    with open(os.path.join(DATA_ROOT, name), "wb") as f:
        f.write(content)


def _open_read(sock, streamid, path):
    open_body = struct.pack(">HH", 0o644, kXR_open_read) + b"\x00" * 12
    status, body = _send_req(sock, streamid, kXR_open, body=open_body,
                             payload=path.encode() + b"\x00")
    assert status == kXR_ok, f"open failed: status={status}"
    assert len(body) >= 4, "open response did not include fhandle"
    return body[:4]


def _read_handle(sock, streamid, fhandle, length, offset=0):
    read_body = fhandle + struct.pack(">q", offset) + struct.pack(">i", length)
    return _send_req(sock, streamid, kXR_read, body=read_body)


# ---------------------------------------------------------------------------
# Fixture — anonymous nginx port for bind tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def bind_nginx(test_env):
    """Use the shared anonymous nginx endpoint for bind tests."""
    global ANON_HOST, ANON_PORT
    ANON_HOST = test_env["server_host"]
    ANON_PORT = test_env["anon_port"]
    yield ANON_PORT


# ---------------------------------------------------------------------------
# Bind with valid sessid — pathid assignment
# ---------------------------------------------------------------------------

def _bind_secondary(port, sessid, streamid):
    """Open a secondary TCP connection, handshake, and bind to sessid."""
    sec_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sec_sock.connect((ANON_HOST, port))
    handshake = struct.pack(">IIIII", 0, 0, 0, 4, 2012)
    sec_sock.sendall(handshake)
    _recv_exact(sec_sock, 16)
    status, _ = _send_req(sec_sock, streamid, kXR_bind, body=sessid)
    assert status == kXR_ok, f"bind failed: status={status}"
    return sec_sock


# ---------------------------------------------------------------------------
# Phase 33 C2 — bound-secondary handle slot cache
#
# A bound secondary re-validates its primary-published handle under the handle
# mutex on EVERY read.  Phase 33 caches the matched SHM slot index on the ctx
# (brix_file_t.shared_handle_slot_hint) so reads 2..N skip the table scan.  The
# cache must remain correct: repeated reads stay byte-exact, and a primary close
# (which clears the slot's in_use flag) must still revoke the secondary on its
# next read rather than serving a stale handle.
# ---------------------------------------------------------------------------
