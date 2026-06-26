"""
tests/test_ssi.py — §7 minimal unary XrdSsi over root:// (raw wire, real instance).

Self-provisions a stream (root://) nginx with `xrootd_ssi on` and drives the unary
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
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))
from settings import NGINX_BIN, free_port, BIND_HOST  # noqa: E402

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


def _start(tmp_path_factory, ssi_on):
    base = str(tmp_path_factory.mktemp("ssi"))
    data = os.path.join(base, "data")
    os.makedirs(data)
    port = free_port()
    ssi = "  xrootd_ssi on;\n" if ssi_on else ""
    body = (
        "daemon off;\nworker_processes 1;\n"
        f"pid {base}/ssi.pid;\nerror_log {base}/ssi-err.log info;\n"
        "thread_pool default threads=2 max_queue=4096;\n"
        "events { worker_connections 64; }\n"
        "stream { server {\n"
        f"  listen {BIND_HOST}:{port};\n  xrootd on;\n  xrootd_root {data};\n"
        "  xrootd_auth none;\n  xrootd_allow_write on;\n"
        f"{ssi}"
        f"  xrootd_access_log {base}/ssi-access.log;\n}} }}\n"
    )
    cfg = os.path.join(base, "ssi.conf")
    with open(cfg, "w") as f:
        f.write(body)
    p = subprocess.Popen([NGINX_BIN, "-c", cfg, "-p", base],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            socket.create_connection((BIND_HOST, port), timeout=0.5).close()
            return p, port
        except OSError:
            time.sleep(0.1)
    err = p.stderr.read().decode(errors="replace") if p.stderr else ""
    p.terminate()
    pytest.skip(f"ssi server did not start: {err}")


@pytest.fixture(scope="module")
def ssi_srv(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    p, port = _start(tmp_path_factory, ssi_on=True)
    yield port
    p.terminate()
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()


@pytest.fixture(scope="module")
def ssi_off_srv(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    p, port = _start(tmp_path_factory, ssi_on=False)
    yield port
    p.terminate()
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()


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
