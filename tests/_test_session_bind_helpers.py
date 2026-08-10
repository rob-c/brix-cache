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
kXR_ArgInvalid = 3000    # §1.1 read pathid validation: unbound path ID
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


def _read_pathid(sock, streamid, fhandle, length, pathid, offset=0):
    """A kXR_read carrying a read_args payload (§1.1): pathid at byte 0, then
    seven reserved bytes — the offload channel selector the server validates
    against the session's live kXR_bind paths."""
    read_body = fhandle + struct.pack(">q", offset) + struct.pack(">i", length)
    payload = bytes([pathid & 0xFF]) + b"\x00" * 7
    return _send_req(sock, streamid, kXR_read, body=read_body, payload=payload)


def _send_read_only(sock, streamid, fhandle, length, pathid=0, offset=0):
    """Send a kXR_read (optionally carrying a read_args pathid) WITHOUT reading
    the response — used by the §1.1 offload test, where a pathid-tagged read's
    response is expected on a DIFFERENT (secondary) socket."""
    body = fhandle + struct.pack(">q", offset) + struct.pack(">i", length)
    payload = bytes([pathid & 0xFF]) + b"\x00" * 7 if pathid else b""
    hdr = bytes(streamid[:2]) + struct.pack(">H", kXR_read)
    hdr += body.ljust(16, b"\x00")
    hdr += struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)


def _recv_response(sock):
    """Read one XRootD response frame from `sock`: returns (streamid, status,
    data) or (None, None, None) on a closed socket."""
    rsp_hdr = _recv_exact(sock, 8)
    if rsp_hdr is None:
        return None, None, None
    streamid = rsp_hdr[0:2]
    status = struct.unpack(">H", rsp_hdr[2:4])[0]
    dlen = struct.unpack(">I", rsp_hdr[4:8])[0]
    data = _recv_exact(sock, dlen) if dlen > 0 else b""
    return streamid, status, data


def _bind_on(port, sessid, streamid=b"\x00\x05"):
    """Open + connect a fresh secondary socket, handshake, and kXR_bind it to
    `sessid`; returns (sock, pathid) with pathid the assigned channel (1-253)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ANON_HOST, port))
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    _recv_exact(sock, 16)
    status, pathid_body = _send_req(sock, streamid, kXR_bind, body=sessid)
    assert status == kXR_ok, f"bind failed: status={status}"
    return sock, pathid_body[0]


kXR_readv = 3025
READV_SEGSIZE = 16   # readahead_list element: fhandle[4] + rlen[4] + offset[8]


def _readv_seg(fhandle, rlen, offset):
    """One readahead_list element: fhandle[4] + rlen(int32 BE) + offset(int64 BE)."""
    return struct.pack("!4siq", fhandle, rlen, offset)


def _send_readv_only(sock, streamid, segments, pathid=0):
    """Send a kXR_readv WITHOUT reading the response. The §1.1 offload pathid
    rides the request HEADER body at byte 15 (the read_list is the payload)."""
    payload = b"".join(segments)
    body = b"\x00" * 15 + bytes([pathid & 0xFF])   # 16-byte body; pathid at [15]
    hdr = bytes(streamid[:2]) + struct.pack(">H", kXR_readv) + body
    hdr += struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)


def _readv_payload_bytes(body, nsegs):
    """Strip the readahead_list headers from a readv response body, returning the
    concatenated payload bytes. Each segment is [fhandle4][rlen4][offset8] then
    rlen payload bytes."""
    out = []
    pos = 0
    for _ in range(nsegs):
        if pos + READV_SEGSIZE > len(body):
            break
        rlen = struct.unpack("!i", body[pos + 4:pos + 8])[0]
        pos += READV_SEGSIZE
        out.append(body[pos:pos + rlen])
        pos += rlen
    return b"".join(out)


kXR_pgread = 3030
kXR_status = 4007
PG_PAGE_SZ = 4096


def _send_pgread_only(sock, streamid, fhandle, length, pathid=0, offset=0):
    """Send a kXR_pgread WITHOUT reading the response (read_args pathid at payload
    byte 0, reqflags at byte 1) — used by the §1.1 offload test where the reply
    is expected on the secondary."""
    body = fhandle + struct.pack(">q", offset) + struct.pack(">i", length)
    payload = bytes([pathid & 0xFF, 0]) if pathid else b""
    hdr = bytes(streamid[:2]) + struct.pack(">H", kXR_pgread)
    hdr += body.ljust(16, b"\x00")
    hdr += struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)


def _pg_strip_crcs(raw):
    """Strip the leading 4-byte CRC32c from each page unit ([CRC32c][<=4096 data])
    of a pgread page-data blob, returning the concatenated data bytes."""
    out = []
    pos = 0
    while pos + 4 <= len(raw):
        pos += 4   # skip the page's CRC32c
        take = min(PG_PAGE_SZ, len(raw) - pos)
        out.append(raw[pos:pos + take])
        pos += take
    return b"".join(out)


def _recv_pgread_response(sock):
    """Read a kXR_pgread response: 8B header + status body, then the separately
    framed CRC-interleaved page data (bdy.dlen at status-body [12:16]). Returns
    (streamid, status, stripped_data)."""
    hdr = _recv_exact(sock, 8)
    if hdr is None:
        return None, None, None
    streamid = hdr[0:2]
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    body = _recv_exact(sock, dlen) if dlen > 0 else b""
    data = b""
    if status == kXR_status and len(body) >= 16:
        bdy_dlen = struct.unpack(">i", body[12:16])[0]
        if bdy_dlen > 0:
            data = _pg_strip_crcs(_recv_exact(sock, bdy_dlen))
    return streamid, status, data


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
