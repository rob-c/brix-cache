"""
tests/test_interop_io.py

Conformance tests for I/O operations comparing nginx-xrootd against the
reference xrootd server.

Covered opcodes: kXR_readv, kXR_pgread, kXR_pgwrite, kXR_writev, kXR_sync,
                 kXR_locate, kXR_clone

The reference server shares the same filesystem.  For read operations we seed
a known file and compare both servers' output.  For write operations we write
through nginx-xrootd and verify the result via the reference server.

Run:
    pytest tests/test_interop_io.py -v
"""

import hashlib
import os
import socket
import struct
import zlib

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags, StatInfoFlags
from settings import (
    DATA_ROOT,
    HOST,
    NGINX_ANON_PORT,
    REF_BRIX_PORT,
    SERVER_HOST,
    url_host,
)

# ---------------------------------------------------------------------------
# Module globals
# ---------------------------------------------------------------------------

NGINX_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
REF_URL   = f"root://{url_host(HOST)}:{REF_BRIX_PORT}"
DATA_DIR  = DATA_ROOT
ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fs(url):
    return client.FileSystem(url)


def _url(url, path):
    return f"{url.rstrip('/')}//{path.lstrip('/')}"


def _open_file(url, path, flags=OpenFlags.READ):
    f = client.File()
    st, _ = f.open(_url(url, path), flags)
    return f, st


def _read_all(url, path):
    f, st = _open_file(url, path)
    if not st.ok:
        return st, None
    st2, info = f.stat()
    st3, data = f.read(size=info.size)
    f.close()
    return st3, data


def _md5(data):
    return hashlib.md5(data).hexdigest()


def _seed(size, name_prefix=""):
    name    = f"_{name_prefix}_{os.getpid()}_{id(size)}.bin"
    content = os.urandom(size)
    with open(os.path.join(DATA_DIR, name), "wb") as fh:
        fh.write(content)
    return f"/{name}", content


def _adler32_hex(data):
    return format(zlib.adler32(data) & 0xFFFFFFFF, "08x")


def _recvall(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        assert chunk, "connection closed unexpectedly"
        buf += chunk
    return buf


def _recv_response(sock):
    hdr = _recvall(sock, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    body = _recvall(sock, dlen) if dlen else b""
    return status, body


def _connect_nginx():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((ANON_HOST, ANON_PORT))
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    hdr = _recvall(sock, 8)
    _recvall(sock, struct.unpack("!I", hdr[4:8])[0])
    sock.sendall(struct.pack("!2sHI8sBBBBI",
                             b"\x00\x01", 3007, 0,
                             b"test\x00\x00\x00\x00",
                             0, 0, 5, 0, 0))
    _recv_response(sock)
    return sock


def _raw_open(sock, sid, path, options):
    path_b = path.encode()
    req = struct.pack("!2sHHH2s6s4sI",
                      bytes([0, sid]), 3010,
                      0o644, options,
                      b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                      len(path_b))
    sock.sendall(req + path_b)
    status, body = _recv_response(sock)
    assert status == 0, f"open({path!r}) failed: status={status} body={body!r}"
    return body[:4]


def _raw_close(sock, sid, fh):
    req = struct.pack("!2sH4s12sI",
                      bytes([0, sid]), 3003, fh, b"\x00" * 12, 0)
    sock.sendall(req)
    _recv_response(sock)


def _raw_clone(sock, sid, dst_fh, items):
    payload = b"".join(
        struct.pack("!4s4sQQQ", src_fh, b"\x00" * 4,
                    src_off, src_len, dst_off)
        for src_fh, src_off, src_len, dst_off in items
    )
    req = struct.pack("!2sH4s12sI",
                      bytes([0, sid]), 3032, dst_fh, b"\x00" * 12,
                      len(payload))
    sock.sendall(req + payload)
    return _recv_response(sock)


# ---------------------------------------------------------------------------
# Vector read (kXR_readv)
# ---------------------------------------------------------------------------
