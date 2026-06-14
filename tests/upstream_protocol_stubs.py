#!/usr/bin/env python3
"""
Persistent XRootD protocol stub backends for upstream-redirect tests.

Started once by manage_test_servers.sh start-all; stays up for the entire
test session.  Five threads each handle one fixed protocol scenario:

  13121  wait      — login ok; locate → kXR_wait(1) + kXR_redirect retry.example.org:2094
  13122  waitresp  — login ok; locate → kXR_waitresp + kXR_redirect async.example.org:3094
  13124  auth      — login → kXR_authmore challenge; kXR_auth accepted; locate → redirect
                     Received credential written to STUB_RECEIVED_CRED_PATH.
  13125  auth-nofile — login → kXR_authmore challenge then close (no kXR_auth read)
  13126  gotorls   — kXR_protocol response with kXR_gotoTLS flag then close

Ports are read from the same TEST_STUB_*_BACKEND_PORT env vars used by settings.py.
"""

import os
import signal
import socket
import struct
import sys
import threading
import time

# ------------------------------------------------------------------ #
# Wire constants                                                        #
# ------------------------------------------------------------------ #

kXR_ok       = 0
kXR_redirect = 4004
kXR_wait     = 4005
kXR_waitresp = 4006
kXR_authmore = 4002
kXR_gotoTLS  = 0x40000000

# ------------------------------------------------------------------ #
# Configuration                                                         #
# ------------------------------------------------------------------ #

_TEST_ROOT    = os.environ.get("TEST_ROOT", "/tmp/xrd-test")
_LOG_DIR      = os.environ.get("LOG_DIR", os.path.join(_TEST_ROOT, "logs"))
_TMP_DIR      = os.path.join(_TEST_ROOT, "tmp")

PID_FILE      = os.environ.get(
    "STUB_PID_FILE", os.path.join(_LOG_DIR, "upstream-stubs.pid")
)
RECEIVED_CRED = os.environ.get(
    "STUB_RECEIVED_CRED_PATH", os.path.join(_TMP_DIR, "received-auth-cred.bin")
)

WAIT_PORT     = int(os.environ.get("TEST_STUB_WAIT_BACKEND_PORT",       "13121"))
WAITRESP_PORT = int(os.environ.get("TEST_STUB_WAITRESP_BACKEND_PORT",   "13122"))
AUTH_PORT     = int(os.environ.get("TEST_STUB_AUTH_BACKEND_PORT",       "13124"))
NOFILE_PORT   = int(os.environ.get("TEST_STUB_AUTH_NOFILE_BACKEND_PORT","13125"))
GOTORLS_PORT  = int(os.environ.get("TEST_STUB_GOTORLS_BACKEND_PORT",    "13126"))

# ------------------------------------------------------------------ #
# Wire helpers                                                          #
# ------------------------------------------------------------------ #

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionResetError(
                f"connection closed expecting {n} bytes, got {len(buf)}"
            )
        buf += chunk
    return buf


def _hdr(streamid, status, dlen):
    return struct.pack(">2sHI", streamid, status, dlen)


def _bootstrap_login_ok(conn):
    """Handshake + kXR_protocol + kXR_login → kXR_ok."""
    _recv_exact(conn, 20)
    conn.sendall(struct.pack(">2sHI", b"\x00\x00", kXR_ok, 8))
    conn.sendall(struct.pack(">II", 0x00000520, 1))

    hdr = _recv_exact(conn, 24)
    sid = hdr[:2]
    conn.sendall(_hdr(sid, kXR_ok, 8))
    conn.sendall(struct.pack(">II", 0x00000520, 1))

    hdr  = _recv_exact(conn, 24)
    sid  = hdr[:2]
    dlen = struct.unpack(">I", hdr[20:24])[0]
    if dlen:
        _recv_exact(conn, dlen)
    conn.sendall(_hdr(sid, kXR_ok, 16))
    conn.sendall(b"\x01" * 16)


def _read_request(conn):
    """Read one 24-byte request header + payload; return stream ID."""
    hdr  = _recv_exact(conn, 24)
    sid  = hdr[:2]
    dlen = struct.unpack(">I", hdr[20:24])[0]
    if dlen:
        _recv_exact(conn, dlen)
    return sid


def _redirect_body(host, port):
    return struct.pack(">I", port) + host.encode()


# ------------------------------------------------------------------ #
# Stub handlers — one connection per invocation                        #
# ------------------------------------------------------------------ #

def _handle_wait(conn):
    """kXR_wait(1) followed by kXR_redirect retry.example.org:2094."""
    _bootstrap_login_ok(conn)
    sid  = _read_request(conn)
    body = _redirect_body("retry.example.org", 2094)
    conn.sendall(_hdr(sid, kXR_wait,     4))
    conn.sendall(struct.pack(">I", 1))
    conn.sendall(_hdr(sid, kXR_redirect, len(body)))
    conn.sendall(body)


def _handle_waitresp(conn):
    """kXR_waitresp followed by kXR_redirect async.example.org:3094."""
    _bootstrap_login_ok(conn)
    sid  = _read_request(conn)
    body = _redirect_body("async.example.org", 3094)
    conn.sendall(_hdr(sid, kXR_waitresp, 0))
    conn.sendall(_hdr(sid, kXR_redirect, len(body)))
    conn.sendall(body)


def _handle_auth(conn):
    """kXR_authmore challenge → accept credential → kXR_redirect.

    Writes received credential bytes to RECEIVED_CRED so tests can verify
    nginx sent the correct token from its xrootd_upstream_token_file.
    """
    _recv_exact(conn, 20)
    conn.sendall(struct.pack(">2sHI", b"\x00\x00", kXR_ok, 8))
    conn.sendall(struct.pack(">II", 0x00000520, 1))

    hdr = _recv_exact(conn, 24)
    sid = hdr[:2]
    conn.sendall(_hdr(sid, kXR_ok, 8))
    conn.sendall(struct.pack(">II", 0x00000520, 1))

    # kXR_login → issue authmore challenge
    hdr  = _recv_exact(conn, 24)
    sid  = hdr[:2]
    dlen = struct.unpack(">I", hdr[20:24])[0]
    if dlen:
        _recv_exact(conn, dlen)
    challenge = b"&P=ztn,test"
    conn.sendall(_hdr(sid, kXR_authmore, len(challenge)))
    conn.sendall(challenge)

    # kXR_auth → read credential, write to file, accept
    auth_hdr  = _recv_exact(conn, 24)
    auth_sid  = auth_hdr[:2]
    auth_dlen = struct.unpack(">I", auth_hdr[20:24])[0]
    cred = _recv_exact(conn, auth_dlen) if auth_dlen else b""
    os.makedirs(os.path.dirname(RECEIVED_CRED), exist_ok=True)
    with open(RECEIVED_CRED, "wb") as fh:
        fh.write(cred)
    conn.sendall(_hdr(auth_sid, kXR_ok, 16))
    conn.sendall(b"\x02" * 16)

    # Next request (locate) → redirect
    sid  = _read_request(conn)
    body = _redirect_body("storage.example.org", 1094)
    conn.sendall(_hdr(sid, kXR_redirect, len(body)))
    conn.sendall(body)


def _handle_auth_nofile(conn):
    """kXR_authmore challenge then close — nginx has no token file configured."""
    _recv_exact(conn, 20)
    conn.sendall(struct.pack(">2sHI", b"\x00\x00", kXR_ok, 8))
    conn.sendall(struct.pack(">II", 0x00000520, 1))

    hdr = _recv_exact(conn, 24)
    sid = hdr[:2]
    conn.sendall(_hdr(sid, kXR_ok, 8))
    conn.sendall(struct.pack(">II", 0x00000520, 1))

    hdr  = _recv_exact(conn, 24)
    sid  = hdr[:2]
    dlen = struct.unpack(">I", hdr[20:24])[0]
    if dlen:
        _recv_exact(conn, dlen)
    challenge = b"&P=ztn,test"
    conn.sendall(_hdr(sid, kXR_authmore, len(challenge)))
    conn.sendall(challenge)
    time.sleep(0.5)


def _handle_gotorls(conn):
    """kXR_protocol response with kXR_gotoTLS flag set then close."""
    _recv_exact(conn, 20)
    conn.sendall(struct.pack(">2sHI", b"\x00\x00", kXR_ok, 8))
    conn.sendall(struct.pack(">II", 0x00000520, 1))

    hdr = _recv_exact(conn, 24)
    sid = hdr[:2]
    conn.sendall(struct.pack(">2sHI", sid, kXR_ok, 8))
    conn.sendall(struct.pack(">II", 0x00000520, kXR_gotoTLS))


# ------------------------------------------------------------------ #
# Server loop                                                           #
# ------------------------------------------------------------------ #

def _stub_loop(port, handler):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            conn.settimeout(30)
            handler(conn)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


# ------------------------------------------------------------------ #
# Entry point                                                           #
# ------------------------------------------------------------------ #

def main():
    os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
    with open(PID_FILE, "w") as fh:
        fh.write(str(os.getpid()) + "\n")

    for port, handler in [
        (WAIT_PORT,     _handle_wait),
        (WAITRESP_PORT, _handle_waitresp),
        (AUTH_PORT,     _handle_auth),
        (NOFILE_PORT,   _handle_auth_nofile),
        (GOTORLS_PORT,  _handle_gotorls),
    ]:
        threading.Thread(
            target=_stub_loop, args=(port, handler), daemon=True
        ).start()

    def _on_signal(sig, frame):
        try:
            os.unlink(PID_FILE)
        except OSError:
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT,  _on_signal)
    signal.pause()


if __name__ == "__main__":
    main()
