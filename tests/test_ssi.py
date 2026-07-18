"""
tests/test_ssi.py — §7 minimal unary XrdSsi over root:// (raw wire, real instance).

Self-provisions a stream (root://) nginx with `brix_ssi on` and drives the unary
request/response RPC directly on the wire:
  open(/.ssi/echo) -> write(request) -> read(response) -> close.

  * echo service round-trips a single request                  (unary RPC works)
  * multiple writes accumulate into one request                (streaming request in)
  * unknown service                                            -> open error
  * ssi disabled                                               -> /.ssi/echo is a normal
                                                                  (missing) file -> error

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_ssi.py -v
"""

import os
import socket
import struct

import pytest

from settings import NGINX_BIN, BIND_HOST
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.uses_lifecycle_harness

kXR_login, kXR_open, kXR_read, kXR_write, kXR_close = 3007, 3010, 3013, 3019, 3003
kXR_ok, kXR_error = 0, 4003


def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("connection closed")
        b += c
    return b


def _resp(s):
    h = _recv_exact(s, 8)
    status = struct.unpack("!H", h[2:4])[0]
    dlen = struct.unpack("!I", h[4:8])[0]
    body = _recv_exact(s, dlen) if dlen else b""
    return status, body


def _session(port):
    s = socket.create_connection((BIND_HOST, port), timeout=10)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))   # ClientInitHandShake
    st, _ = _resp(s)
    assert st == kXR_ok, "handshake failed"
    s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                          os.getpid() & 0x7fffffff, b"ssi\x00\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    st, _ = _resp(s)
    assert st == kXR_ok, "anon login failed"
    return s


def _open(s, path, sid=b"\x00\x03"):
    p = path.encode()
    req = struct.pack("!2sHHHH6s4sI", sid, kXR_open, 0, 0x0010, 0,
                      b"\x00" * 6, b"\x00" * 4, len(p)) + p   # options=kXR_open_read
    s.sendall(req)
    return _resp(s)


def _write(s, fhandle, offset, data, sid=b"\x00\x07"):
    s.sendall(struct.pack("!2sH4sqiI", sid, kXR_write, fhandle, offset, 0,
                          len(data)) + data)
    return _resp(s)[0]


def _read(s, fhandle, offset, rlen, sid=b"\x00\x09"):
    s.sendall(struct.pack("!2sH4sqII", sid, kXR_read, fhandle, offset, rlen, 0))
    return _resp(s)


def _close(s, fhandle, sid=b"\x00\x0e"):
    s.sendall(struct.pack("!2sH4s12sI", sid, kXR_close, fhandle, b"\x00" * 12, 0))
    try:
        return _resp(s)[0]
    except EOFError:
        return None


@pytest.fixture()
def ssi_srv(lifecycle):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip("nginx binary not found")
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-ssi-on",
        template="nginx_lc_ssi.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST,
                         "SSI_DIRECTIVES": "        brix_ssi on;"},
        reason="minimal SSI-enabled root:// stream server"))
    return ep.port


@pytest.fixture()
def ssi_off_srv(lifecycle):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip("nginx binary not found")
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-ssi-off",
        template="nginx_lc_ssi.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "SSI_DIRECTIVES": ""},
        reason="SSI-disabled root:// stream server (control)"))
    return ep.port


def test_echo_unary_roundtrip(ssi_srv):
    s = _session(ssi_srv)
    st, body = _open(s, "/.ssi/echo")
    assert st == kXR_ok, (st, body)
    fh = body[0:4]
    assert _write(s, fh, 0, b"hello-SSI") == kXR_ok
    st, resp = _read(s, fh, 0, 4096)
    assert st == kXR_ok
    assert resp == b"hello-SSI", resp
    _close(s, fh)
    s.close()


def test_multi_write_accumulates(ssi_srv):
    s = _session(ssi_srv)
    st, body = _open(s, "/.ssi/echo")
    assert st == kXR_ok
    fh = body[0:4]
    assert _write(s, fh, 0, b"foo") == kXR_ok
    assert _write(s, fh, 0, b"bar") == kXR_ok
    st, resp = _read(s, fh, 0, 4096)
    assert st == kXR_ok
    assert resp == b"foobar", resp
    _close(s, fh)
    s.close()


def test_unknown_service_rejected(ssi_srv):
    s = _session(ssi_srv)
    st, _ = _open(s, "/.ssi/nosuch")
    assert st == kXR_error, st
    s.close()


def test_ssi_disabled_is_normal_path(ssi_off_srv):
    # ssi off → "/.ssi/echo" is just a (missing) file open → error, not an echo.
    s = _session(ssi_off_srv)
    st, _ = _open(s, "/.ssi/echo")
    assert st == kXR_error, st
    s.close()
