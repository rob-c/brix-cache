"""
Privilege escalation and authorization boundary tests for nginx-xrootd.

Tests that verify the server correctly enforces:
  - Pre-auth rejection of ALL data opcodes (not just rm/mv/chmod)
  - Read-only server config rejects every mutating opcode
  - Read-side path resolution rejects symlinks escaping the export root
  - Handle-based truncate respects read-only open mode
  - Write operations on read-only opened handles are rejected
  - Unknown opcodes return kXR_Unsupported
  - Invalid/out-of-range file handles are rejected
  - Negative or overflow offsets in read/write
  - Oversized path payloads

These complement test_security_hardening.py (which covers symlink escapes,
embedded NULs, and log sanitization) with protocol-level privilege checks.

Run:
    pytest tests/test_privilege_escalation.py -v -s
"""

import os
import socket
import struct
import tempfile

import pytest

from backend_matrix import root_endpoint_parts, selected_backend_name
from settings import (
    DATA_ROOT,
    HOST,
    NGINX_ANON_PORT,
    READONLY_DATA_ROOT,
    READONLY_PORT as FIXED_READONLY_PORT,
    REF_BRIX_PORT,
    SERVER_HOST,
    url_host,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CROSS_BACKEND = selected_backend_name()

if CROSS_BACKEND == "xrootd":
    ANON_HOST, ANON_PORT = root_endpoint_parts(
        f"root://{url_host(HOST)}:{REF_BRIX_PORT}")
else:
    ANON_HOST = SERVER_HOST
    ANON_PORT = NGINX_ANON_PORT

DATA_DIR      = DATA_ROOT
READONLY_HOST = SERVER_HOST
READONLY_PORT = FIXED_READONLY_PORT

# XRootD request opcodes
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
kXR_writev    = 3031
kXR_endsess   = 3023
kXR_readv     = 3025
kXR_pgwrite   = 3026
kXR_truncate  = 3028

# XRootD response/error codes
kXR_OK             = 0
kXR_ERROR          = 4003
kXR_ArgInvalid     = 3000
kXR_ArgMissing     = 3001
kXR_FileNotOpen    = 3004
kXR_InvalidRequest = 3006
kXR_NOT_AUTHORIZED = 3010
kXR_Unsupported    = 3013
kXR_fsReadOnly     = 3025

# Open flags for raw protocol
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_open_wrto = 0x8000
kXR_new       = 0x0008
kXR_delete    = 0x0002


# ---------------------------------------------------------------------------
# Raw protocol helpers  (same pattern as test_security_hardening.py)
# ---------------------------------------------------------------------------

def _recv_exact(sock: socket.socket, nbytes: int) -> bytes:
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise AssertionError("socket closed before full response arrived")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock: socket.socket) -> tuple[int, bytes]:
    header = _recv_exact(sock, 8)
    _streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _raw_session(host: str = None, port: int = None) -> socket.socket:
    if host is None:
        host = ANON_HOST
    if port is None:
        port = ANON_PORT
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(5)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, body = _read_response(sock)
    assert status == kXR_OK, f"handshake failed: status={status}"
    assert len(body) == 8
    return sock


def _login_anon(sock: socket.socket, streamid: bytes = b"\x00\x01") -> None:
    username = b"pytest\x00\x00"
    req = struct.pack(
        "!2sHI8sBBBBI",
        streamid, kXR_login,
        os.getpid() & 0xFFFFFFFF,
        username, 0, 0, 5, 0, 0,
    )
    sock.sendall(req)
    status, body = _read_response(sock)
    assert status == kXR_OK, f"login failed: status={status} body={body!r}"


def _error_code(body: bytes) -> int:
    assert len(body) >= 4, f"error response too short: {body!r}"
    return struct.unpack("!I", body[:4])[0]


def _open_file_raw(sock: socket.socket, path: bytes, options: int,
                   streamid: bytes = b"\x00\x02") -> tuple[int, bytes]:
    """Send kXR_open and return (status, body). Body contains fhandle on success."""
    req = struct.pack(
        "!2sHHH2s6s4sI",
        streamid, kXR_open,
        0o644,           # mode
        options,         # kXR_open_read, kXR_open_updt, etc.
        b"\x00\x00",    # optiont
        b"\x00" * 6,    # reserved
        b"\x00" * 4,    # fhtemplt
        len(path),
    )
    sock.sendall(req + path)
    return _read_response(sock)


def _close_handle_raw(sock: socket.socket, fhandle: bytes,
                      streamid: bytes = b"\x00\x09") -> None:
    req = struct.pack(
        "!2sH4s12sI",
        streamid, kXR_close, fhandle, b"\x00" * 12, 0,
    )
    sock.sendall(req)
    _read_response(sock)  # discard


def _stat_path_raw(sock: socket.socket, path: bytes,
                   streamid: bytes = b"\x00\x02") -> tuple[int, bytes]:
    req = struct.pack(
        "!2sH1s7sI4sI",
        streamid, kXR_stat,
        b"\x00",
        b"\x00" * 7,
        0,
        b"\x00" * 4,
        len(path),
    )
    sock.sendall(req + path)
    return _read_response(sock)


def _dirlist_raw(sock: socket.socket, path: bytes,
                 streamid: bytes = b"\x00\x02") -> tuple[int, bytes]:
    req = struct.pack(
        "!2sH15sBi",
        streamid, kXR_dirlist,
        b"\x00" * 15,
        0,
        len(path),
    )
    sock.sendall(req + path)
    return _read_response(sock)


def _read_raw(sock: socket.socket, fhandle: bytes, offset: int, length: int,
              streamid: bytes = b"\x00\x02") -> tuple[int, bytes]:
    req = struct.pack(
        "!2sH4sqiI",
        streamid, kXR_read,
        fhandle,
        offset,
        length,
        0,
    )
    sock.sendall(req)
    return _read_response(sock)


def _readv_raw(sock: socket.socket, fhandle: bytes, offset: int, length: int,
               streamid: bytes = b"\x00\x02") -> tuple[int, bytes]:
    segment = struct.pack("!4sIq", fhandle, length, offset)
    req = struct.pack(
        "!2sH16sI",
        streamid, kXR_readv,
        b"\x00" * 16,
        len(segment),
    )
    sock.sendall(req + segment)
    return _read_response(sock)


def _assert_readonly_response(status: int, body: bytes) -> None:
    assert status == kXR_ERROR
    assert _error_code(body) == kXR_fsReadOnly


def _assert_preauth_rejected(status: int, body: bytes) -> None:
    """Portable pre-auth rejection: nginx and xrootd use different codes."""
    assert status == kXR_ERROR
    code = _error_code(body)
    if CROSS_BACKEND == "xrootd":
        assert code in (kXR_NOT_AUTHORIZED, kXR_InvalidRequest)
    else:
        assert code == kXR_NOT_AUTHORIZED


def _assert_readonly_handle_write_rejected(status: int, body: bytes) -> None:
    """Portable read-only-handle write rejection across nginx and xrootd."""
    assert status == kXR_ERROR
    code = _error_code(body)
    if CROSS_BACKEND == "xrootd":
        assert code in (kXR_NOT_AUTHORIZED, kXR_FileNotOpen)
    else:
        assert code == kXR_NOT_AUTHORIZED


def _unlink_if_exists(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _rmdir_if_exists(path: str) -> None:
    try:
        os.rmdir(path)
    except FileNotFoundError:
        pass


@pytest.fixture(scope="session")
def readonly_nginx():
    """Verify the dedicated read-only server is reachable."""
    try:
        with socket.create_connection((READONLY_HOST, READONLY_PORT), timeout=5):
            pass
    except OSError:
        pytest.skip(f"read-only server not reachable at {READONLY_HOST}:{READONLY_PORT}")
    yield


# ===========================================================================
# Read-only server authorization boundary
# ===========================================================================
