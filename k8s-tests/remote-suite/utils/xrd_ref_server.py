#!/usr/bin/env python3
"""
Minimal reference XRootD data server — used to calibrate xrdcp/xrdfs
behaviour against a known-correct implementation.

Implements just enough of the XRootD protocol to serve files:
    handshake, kXR_protocol, kXR_login, kXR_ping, kXR_stat,
    kXR_open, kXR_read, kXR_close, kXR_dirlist, kXR_endsess

Usage:
    python3 utils/xrd_ref_server.py [PORT] [ROOT_DIR]

    PORT      defaults to 19942
    ROOT_DIR  defaults to /tmp/xrd-test/data

Example:
    python3 utils/xrd_ref_server.py 19942 /tmp/xrd-test/data &
    xrdfs root://localhost:19942 ls /
    xrdcp root://localhost:19942//test.txt /tmp/out.txt
"""
import os
import socket
import stat
import struct
import sys
import threading

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 19942
ROOT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/xrd-test/data"

HANDSHAKE_LEN = 20
ROOTD_PQ      = 2012
PROTO_VER     = 0x00000520

kXR_protocol  = 3006
kXR_login     = 3007
kXR_ping      = 3011
kXR_stat      = 3017
kXR_open      = 3010
kXR_read      = 3013
kXR_close     = 3003
kXR_dirlist   = 3004
kXR_endsess   = 3023

kXR_ok        = 0
kXR_error     = 4003
kXR_NotFound  = 3011
kXR_IOError   = 3007
kXR_isDir     = 3016
kXR_readable  = 16
kXR_isDirectory = 2

SESSION_ID = os.urandom(16)


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def send_hsk(s):
    pkt = struct.pack(">III", 8, PROTO_VER, 1)  # msglen=8, protover, DataServer
    s.sendall(pkt)
    print(f"  sent handshake ({len(pkt)}B)", flush=True)


def send_resp(s, streamid, status, body=b""):
    hdr = struct.pack(">HHI", streamid, status, len(body))
    s.sendall(hdr + body)
    print(f"  sent resp sid={streamid} status={status} dlen={len(body)}", flush=True)


def _read_request(conn):
    hdr = recv_exact(conn, 24)
    sid = struct.unpack(">H", hdr[0:2])[0]
    reqid = struct.unpack(">H", hdr[2:4])[0]
    body = hdr[4:20]
    dlen = struct.unpack(">I", hdr[20:24])[0]
    payload = recv_exact(conn, dlen) if dlen else b""
    print(f"req sid={sid} reqid={reqid} dlen={dlen} payload={payload!r}", flush=True)
    return sid, reqid, body, payload


def _requested_path(payload):
    path = payload.rstrip(b"\x00").decode()
    full = os.path.realpath(os.path.join(ROOT, path.lstrip("/")))
    root = os.path.realpath(ROOT)
    return full if os.path.commonpath((root, full)) == root else None


def _send_error(conn, sid, code, message):
    send_resp(conn, sid, kXR_error, struct.pack(">I", code) + message + b"\0")


def _send_not_found(conn, sid):
    _send_error(conn, sid, kXR_NotFound, b"not found")


def _handle_protocol(conn, sid, _body, _payload, _open_files):
    packet = struct.pack(">II", PROTO_VER, 1)
    send_resp(conn, sid, kXR_ok, packet)
    return True


def _handle_login(conn, sid, _body, _payload, _open_files):
    send_resp(conn, sid, kXR_ok, SESSION_ID)
    return True


def _handle_ping(conn, sid, _body, _payload, _open_files):
    send_resp(conn, sid, kXR_ok)
    return True


def _handle_endsess(conn, sid, _body, _payload, _open_files):
    send_resp(conn, sid, kXR_ok)
    return False


def _handle_stat(conn, sid, _body, payload, _open_files):
    full = _requested_path(payload)
    if full is None:
        _send_not_found(conn, sid)
        return True
    try:
        info = os.stat(full)
    except FileNotFoundError:
        _send_not_found(conn, sid)
        return True
    flags = kXR_readable | (kXR_isDirectory if stat.S_ISDIR(info.st_mode) else 0)
    stat_body = f"{info.st_ino} {flags} {info.st_size} {int(info.st_mtime)}\0".encode()
    send_resp(conn, sid, kXR_ok, stat_body)
    return True


def _handle_open(conn, sid, _body, payload, open_files):
    full = _requested_path(payload)
    if full is None:
        _send_not_found(conn, sid)
        return True
    try:
        fd = os.open(full, os.O_RDONLY)
    except FileNotFoundError:
        _send_not_found(conn, sid)
        return True
    index = len(open_files)
    open_files[index] = fd
    response = struct.pack(">I", index) + struct.pack(">I", 0) + b"\x00" * 4
    send_resp(conn, sid, kXR_ok, response)
    return True


def _handle_read(conn, sid, body, _payload, open_files):
    handle, offset, length = struct.unpack(">4sqI", body[:16])
    index = struct.unpack(">I", handle)[0]
    if index not in open_files:
        _send_error(conn, sid, kXR_IOError, b"bad handle")
        return True
    os.lseek(open_files[index], offset, os.SEEK_SET)
    data = os.read(open_files[index], min(length, 4 * 1024 * 1024))
    send_resp(conn, sid, kXR_ok, data)
    return True


def _handle_close(conn, sid, body, _payload, open_files):
    index = struct.unpack(">I", body[:4])[0]
    descriptor = open_files.pop(index, None)
    if descriptor is not None:
        os.close(descriptor)
    send_resp(conn, sid, kXR_ok)
    return True


def _handle_unsupported(conn, sid, _body, _payload, _open_files):
    _send_error(conn, sid, 3013, b"unsupported")
    return True


def _request_handler(reqid):
    return {
        kXR_protocol: _handle_protocol,
        kXR_login: _handle_login,
        kXR_ping: _handle_ping,
        kXR_endsess: _handle_endsess,
        kXR_stat: _handle_stat,
        kXR_open: _handle_open,
        kXR_read: _handle_read,
        kXR_close: _handle_close,
    }.get(reqid, _handle_unsupported)


def handle(conn):
    conn.settimeout(15)

    # Handshake
    raw = recv_exact(conn, HANDSHAKE_LEN)
    _, _, _, fourth, fifth = struct.unpack(">iiiii", raw)
    print(f"handshake: fourth={fourth} fifth={fifth}", flush=True)
    if fourth != 4 or fifth != ROOTD_PQ:
        print("bad handshake", flush=True)
        return
    send_hsk(conn)

    open_files = {}

    while True:
        sid, reqid, body, payload = _read_request(conn)
        handler = _request_handler(reqid)
        if not handler(conn, sid, body, payload, open_files):
            break


def main():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    server.settimeout(30)
    print(f"reference server on {PORT}, root={ROOT}", flush=True)
    while True:
        try:
            conn, addr = server.accept()
        except socket.timeout:
            break
        print(f"connect from {addr}", flush=True)
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
