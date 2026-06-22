"""
Native-client async response handling (phase-37 §16 gap B):
the client now understands kXR_waitresp → kXR_attn(asynresp), the deferred-reply
flow XRootD uses for async TPC and other long operations.

nginx-xrootd answers every request synchronously, so this path can only be
exercised against a *deferring* server. This test stands up a minimal mock XRootD
server (handshake + login, then for one op: kXR_waitresp followed by an unsolicited
kXR_attn carrying an asynresp envelope) and drives the real `xrdfs` binary at it.

Covered:
  * waitresp → asynresp(kXR_ok)    — op succeeds via the deferred reply
  * waitresp → asynresp(kXR_error) — the embedded error is surfaced
  * waitresp → waitresp → asynresp — a re-armed wait still resolves

Run:
    PYTHONPATH=tests pytest tests/test_client_async_tpc.py -v -p no:xdist
"""

import os
import shutil
import socket
import struct
import subprocess
import threading

import pytest

from settings import HOST, BIND_HOST

pytestmark = pytest.mark.timeout(60)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")

kXR_ok = 0
kXR_attn = 4001
kXR_error = 4003
kXR_waitresp = 4006
kXR_asynresp = 5008


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionResetError(f"closed: wanted {n}, got {len(buf)}")
        buf += chunk
    return buf


def _hdr(streamid, status, dlen):
    return struct.pack(">2sHI", streamid, status, dlen)


def _bootstrap_login_ok(conn):
    """Handshake + kXR_protocol + kXR_login → kXR_ok (anonymous)."""
    _recv_exact(conn, 20)
    conn.sendall(_hdr(b"\x00\x00", kXR_ok, 8) + struct.pack(">II", 0x00000520, 1))
    hdr = _recv_exact(conn, 24)
    conn.sendall(_hdr(hdr[:2], kXR_ok, 8) + struct.pack(">II", 0x00000520, 1))
    hdr = _recv_exact(conn, 24)
    dlen = struct.unpack(">I", hdr[20:24])[0]
    if dlen:
        _recv_exact(conn, dlen)
    conn.sendall(_hdr(hdr[:2], kXR_ok, 16) + b"\x01" * 16)


def _read_request(conn):
    """Read one 24-byte request header (+ payload); return its stream id."""
    hdr = _recv_exact(conn, 24)
    dlen = struct.unpack(">I", hdr[20:24])[0]
    if dlen:
        _recv_exact(conn, dlen)
    return hdr[:2]


def _asynresp_frame(req_sid, inner_status, inner_data=b""):
    """A kXR_attn frame whose body is an asynresp envelope:
    actnum[4]=kXR_asynresp, reserved[4], inner ServerResponseHdr[8], data."""
    inner_hdr = _hdr(req_sid, inner_status, len(inner_data))
    body = struct.pack(">I", kXR_asynresp) + b"\x00\x00\x00\x00" + inner_hdr + inner_data
    return _hdr(req_sid, kXR_attn, len(body)) + body


def _serve_once(port, scenario, ready):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND_HOST, port))
    srv.listen(1)
    srv.settimeout(30)
    ready.set()
    try:
        conn, _ = srv.accept()
    except socket.timeout:
        srv.close()
        return
    try:
        _bootstrap_login_ok(conn)
        sid = _read_request(conn)
        # acknowledge with kXR_waitresp(0s) — the real reply comes async
        conn.sendall(_hdr(sid, kXR_waitresp, 4) + struct.pack(">I", 0))
        if scenario == "double_wait":
            conn.sendall(_hdr(sid, kXR_waitresp, 4) + struct.pack(">I", 0))
            conn.sendall(_asynresp_frame(sid, kXR_ok))
        elif scenario == "error":
            # NOT NUL-terminated on purpose: the inner error message fills the frame
            # exactly, so a naive %s would over-read past the buffer. The client must
            # bound it (%.*s) — this is the regression guard for that security fix.
            err = struct.pack(">I", 3011) + b"deferred op failed"
            conn.sendall(_asynresp_frame(sid, kXR_error, err))
        else:  # ok
            conn.sendall(_asynresp_frame(sid, kXR_ok))
        # drain anything the client sends afterwards until it closes
        conn.settimeout(5)
        try:
            while conn.recv(4096):
                pass
        except OSError:
            pass
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        conn.close()
        srv.close()


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _run_mock(scenario):
    if not os.path.exists(XRDFS):
        if shutil.which("cc") is None and shutil.which("gcc") is None:
            pytest.skip("no C compiler / xrdfs not built")
        subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs"],
                       capture_output=True, text=True, timeout=240)
    if not os.path.exists(XRDFS):
        pytest.skip("xrdfs build failed")
    port = _free_port()
    ready = threading.Event()
    t = threading.Thread(target=_serve_once, args=(port, scenario, ready), daemon=True)
    t.start()
    ready.wait(5)
    url = f"root://{HOST}:{port}"
    p = subprocess.run([XRDFS, url, "rm", "/async/test"],
                       capture_output=True, text=True, timeout=30)
    t.join(10)
    return p


def test_waitresp_asynresp_ok():
    """waitresp → asynresp(kXR_ok): the op resolves via the deferred reply."""
    p = _run_mock("ok")
    assert p.returncode == 0, f"stdout={p.stdout!r} stderr={p.stderr!r}"


def test_waitresp_asynresp_error():
    """waitresp → asynresp(kXR_error): the embedded error is surfaced cleanly."""
    p = _run_mock("error")
    assert p.returncode != 0
    assert "deferred op failed" in p.stderr, p.stderr


def test_double_waitresp_then_asynresp():
    """A re-armed wait (waitresp → waitresp → asynresp) still resolves to success."""
    p = _run_mock("double_wait")
    assert p.returncode == 0, f"stdout={p.stdout!r} stderr={p.stderr!r}"
