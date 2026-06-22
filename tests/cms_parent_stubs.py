#!/usr/bin/env python3
"""
Persistent CMS parent stub daemons for manager_mode tests.

Started once by manage_test_servers.sh start-all.  Three threads each serve
one CMS parent role, looping to accept successive nginx CMS connections:

  12601  select   — kYR_login accepted; kYR_locate → kYR_select pointing at
                    CLUSTER_SELECT_REDIRECT_PORT (29000)
  12606  try      — kYR_login accepted; kYR_locate → kYR_try with two entries:
                    [CLUSTER_TRY_FIRST_PORT:29001, CLUSTER_TRY_SECOND_PORT:29002]
  12607  escalate — kYR_login accepted; kYR_locate → kYR_select pointing at
                    CLUSTER_ESC_LEAF_PORT (11199)

Ports and redirect targets are read from the same TEST_* env vars used by
settings.py so they can be overridden for parallel test runners.
"""

import os
import signal
import socket
import struct
import sys
import threading

from settings import HOST, BIND_HOST

# ------------------------------------------------------------------ #
# CMS wire constants                                                    #
# ------------------------------------------------------------------ #

CMS_RR_LOGIN  = 0
CMS_RR_LOCATE = 2
CMS_RR_SELECT = 10
CMS_RR_PING   = 17
CMS_RR_PONG   = 18
CMS_RR_TRY    = 24

# ------------------------------------------------------------------ #
# Configuration                                                         #
# ------------------------------------------------------------------ #

_TEST_ROOT = os.environ.get("TEST_ROOT", "/tmp/xrd-test")
_LOG_DIR   = os.environ.get("LOG_DIR", os.path.join(_TEST_ROOT, "logs"))

PID_FILE = os.environ.get(
    "CMS_STUB_PID_FILE", os.path.join(_LOG_DIR, "cms-parent-stubs.pid")
)

SELECT_PORT       = int(os.environ.get("TEST_CLUSTER_SELECT_CMS_PORT",    "12601"))
TRY_PORT          = int(os.environ.get("TEST_CLUSTER_TRY_CMS_PORT",       "12606"))
ESC_PORT          = int(os.environ.get("TEST_CLUSTER_ESC_CMS_PORT",       "12607"))

SELECT_REDIR_HOST = os.environ.get("TEST_CLUSTER_SELECT_REDIR_HOST",      HOST)
SELECT_REDIR_PORT = int(os.environ.get("TEST_CLUSTER_SELECT_REDIRECT_PORT","29000"))

TRY_FIRST_HOST  = os.environ.get("TEST_CLUSTER_TRY_FIRST_HOST",           HOST)
TRY_FIRST_PORT  = int(os.environ.get("TEST_CLUSTER_TRY_FIRST_PORT",       "29001"))
TRY_SECOND_HOST = os.environ.get("TEST_CLUSTER_TRY_SECOND_HOST",          HOST)
TRY_SECOND_PORT = int(os.environ.get("TEST_CLUSTER_TRY_SECOND_PORT",      "29002"))

ESC_REDIR_HOST  = os.environ.get("TEST_CLUSTER_ESC_REDIR_HOST",           HOST)
ESC_REDIR_PORT  = int(os.environ.get("TEST_CLUSTER_ESC_LEAF_PORT",        "11199"))

# ------------------------------------------------------------------ #
# CMS frame helpers                                                     #
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


def _recv_frame(sock):
    """Read one CMS frame; return (streamid, opcode, payload)."""
    hdr = _recv_exact(sock, 8)
    streamid, opcode, _modifier, dlen = struct.unpack(">IBBH", hdr)
    payload = _recv_exact(sock, dlen) if dlen else b""
    return streamid, opcode, payload


def _send_frame(sock, streamid, opcode, payload=b""):
    hdr = struct.pack(">IBBH", streamid, opcode, 0, len(payload))
    sock.sendall(hdr + payload)


def _select_payload(host, port):
    return host.encode() + b"\x00" + struct.pack(">H", port)


def _try_payload(*entries):
    """Build kYR_try payload from (host, port) pairs."""
    return b"".join(
        host.encode() + b"\x00" + struct.pack(">H", port)
        for host, port in entries
    )


# ------------------------------------------------------------------ #
# Connection handler                                                    #
# ------------------------------------------------------------------ #

def _handle_connection(conn, locate_response_fn):
    """Serve one nginx CMS client connection.

    Reads the LOGIN frame, then loops serving LOCATE frames with the
    response computed by locate_response_fn(streamid) until the
    connection drops.
    """
    conn.settimeout(30)
    # Read LOGIN
    _streamid, opcode, _payload = _recv_frame(conn)
    if opcode != CMS_RR_LOGIN:
        return

    while True:
        streamid, opcode, _payload = _recv_frame(conn)
        if opcode == CMS_RR_LOCATE:
            response_opcode, response_payload = locate_response_fn()
            _send_frame(conn, streamid, response_opcode, response_payload)
        elif opcode == CMS_RR_PING:
            _send_frame(conn, streamid, CMS_RR_PONG)
        # Other opcodes (GONE, etc.) are silently absorbed.


# ------------------------------------------------------------------ #
# Per-port stub loops                                                   #
# ------------------------------------------------------------------ #

def _stub_loop(port, locate_response_fn, label):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND_HOST, port))
    srv.listen(8)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            _handle_connection(conn, locate_response_fn)
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

    stubs = [
        (
            SELECT_PORT,
            lambda: (CMS_RR_SELECT, _select_payload(SELECT_REDIR_HOST, SELECT_REDIR_PORT)),
            "cms-select",
        ),
        (
            TRY_PORT,
            lambda: (
                CMS_RR_TRY,
                _try_payload(
                    (TRY_FIRST_HOST, TRY_FIRST_PORT),
                    (TRY_SECOND_HOST, TRY_SECOND_PORT),
                ),
            ),
            "cms-try",
        ),
        (
            ESC_PORT,
            lambda: (CMS_RR_SELECT, _select_payload(ESC_REDIR_HOST, ESC_REDIR_PORT)),
            "cms-escalate",
        ),
    ]

    for port, locate_fn, label in stubs:
        threading.Thread(
            target=_stub_loop, args=(port, locate_fn, label), daemon=True
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
