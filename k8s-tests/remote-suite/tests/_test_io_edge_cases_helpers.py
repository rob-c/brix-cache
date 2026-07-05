# _test_io_edge_cases_helpers.py - shared header/helpers/fixtures for the Phase-38 split of
# test_io_edge_cases.py.  `from _test_io_edge_cases_helpers import *` re-exports EVERYTHING (incl imported
# names and `_`-prefixed helpers) via the __all__ below, so every split
# sibling shares the exact module-level environment of the original.
"""
tests/test_io_edge_cases.py

Read/write boundary conditions, pgread CRC32c integrity, kXR_sync,
readv/writev edge cases.

Run:
    pytest tests/test_io_edge_cases.py -v
"""

import os
import struct
import socket

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

kXR_protocol  = 3006
kXR_login     = 3007
kXR_open      = 3010
kXR_close     = 3003
kXR_read      = 3013
kXR_sync      = 3016
kXR_write     = 3019
kXR_readv     = 3025
kXR_pgwrite   = 3026
kXR_pgread    = 3030
kXR_writev    = 3031

kXR_ok        = 0
kXR_error     = 4003
kXR_status    = 4007

kXR_ChkSumErr   = 3019
kXR_FileNotOpen = 3004
kXR_IOError     = 3007

kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_open_new  = 0x0008
kXR_delete    = 0x0002

kXR_pgPageSZ  = 4096

# ---------------------------------------------------------------------------
# Module globals
# ---------------------------------------------------------------------------

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT
DATA_DIR  = DATA_ROOT


# ---------------------------------------------------------------------------
# CRC32c
# ---------------------------------------------------------------------------

def _crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
    return crc ^ 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Socket helpers
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
    # kXR_status two-phase: header dlen=24 (fixed body), then bdy.dlen more bytes
    # for page data.  bdy.dlen lives at body[12:16].
    if status == kXR_status and dlen == 24 and len(body) == 24:
        extra = struct.unpack("!I", body[12:16])[0]
        if extra > 0:
            body = body + _recv_exact(sock, extra)
    return status, body


def _session():
    sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=10)
    sock.settimeout(10)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, _ = _read_response(sock)
    assert status == kXR_ok
    sock.sendall(struct.pack("!2sHI8sBBBBI",
                              b"\x00\x01", kXR_login,
                              os.getpid() & 0xFFFFFFFF,
                              b"pytest\x00\x00", 0, 0, 5, 0, 0))
    status, _ = _read_response(sock)
    assert status == kXR_ok
    return sock


def _open(sock, path, flags=kXR_open_read, streamid=b"\x00\x02"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH2s6s4sI",
                      streamid, kXR_open,
                      0o644, flags, b"\x00\x00", b"\x00"*6, b"\x00"*4, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _close(sock, fhandle, streamid=b"\x00\x0e"):
    req = struct.pack("!2sH4s12sI", streamid, kXR_close, fhandle, b"\x00"*12, 0)
    sock.sendall(req)
    _read_response(sock)


def _read(sock, fhandle, offset, rlen, streamid=b"\x00\x03"):
    req = struct.pack("!2sH4sqiI", streamid, kXR_read, fhandle, offset, rlen, 0)
    sock.sendall(req)
    return _read_response(sock)


def _write(sock, fhandle, offset, data, streamid=b"\x00\x03"):
    req = struct.pack("!2sH4sqiI", streamid, kXR_write,
                      fhandle, offset, len(data), len(data))
    sock.sendall(req + data)
    return _read_response(sock)


def _sync(sock, fhandle, streamid=b"\x00\x04"):
    req = struct.pack("!2sH4s12sI", streamid, kXR_sync, fhandle, b"\x00"*12, 0)
    sock.sendall(req)
    return _read_response(sock)


def _error_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


def _make_file(name, content=b"hello"):
    path = os.path.join(DATA_DIR, name.lstrip("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(content)
    return path


def _read_file(name):
    with open(os.path.join(DATA_DIR, name.lstrip("/")), "rb") as f:
        return f.read()


# ---------------------------------------------------------------------------
# pgwrite helpers
# ---------------------------------------------------------------------------

def _build_pgwrite_payload(data: bytes, offset: int, corrupt_page: int = -1):
    out = bytearray()
    pos = 0
    page_idx = 0
    cur_offset = offset
    while pos < len(data):
        page_off = cur_offset % kXR_pgPageSZ
        room = kXR_pgPageSZ - page_off
        chunk = data[pos: pos + room]
        crc = _crc32c(chunk)
        if page_idx == corrupt_page:
            crc = (crc ^ 0xDEADBEEF) & 0xFFFFFFFF
        out += struct.pack("!I", crc)
        out += chunk
        pos += len(chunk)
        cur_offset += len(chunk)
        page_idx += 1
    return bytes(out)


def _send_pgwrite(sock, fhandle, offset, payload, streamid=b"\x00\x05"):
    hdr = struct.pack("!2sH4sqBBHi",
                      streamid, kXR_pgwrite,
                      fhandle, offset,
                      0, 0, 0, len(payload))
    sock.sendall(hdr + payload)
    return _read_response(sock)


# ---------------------------------------------------------------------------
# pgread helpers
# ---------------------------------------------------------------------------

def _send_pgread(sock, fhandle, offset, length, streamid=b"\x00\x06"):
    req = struct.pack("!2sH4sqiI",
                      streamid, kXR_pgread,
                      fhandle, offset, length, 0)
    sock.sendall(req)
    return _read_response(sock)


def _parse_pgread_response(body):
    """Parse pgread response: list of (crc, page_bytes) pairs."""
    pages = []
    pos = 0
    while pos < len(body):
        if pos + 4 > len(body):
            break
        crc = struct.unpack("!I", body[pos:pos+4])[0]
        pos += 4
        # Page data extends to next CRC or end; we can't know length without header
        # The pgread response interleaves CRC+data per page boundary
        # Read until next page boundary
        pages.append((crc, body[pos:]))
        break  # simplification: just return the first CRC and the rest as data
    return pages


# =========================================================================
# Class 1 — Read Edge Cases
# =========================================================================


__all__ = [n for n in dir() if not n.startswith('__')]
