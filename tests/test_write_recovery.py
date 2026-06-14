"""
kXR_recoverWrts (write recovery) functional tests.
"""

import socket
import struct
import os
import pytest
import time

from settings import (
    NGINX_ANON_PORT,
    SERVER_HOST,
    DATA_ROOT,
    LOG_DIR,
)

# Flag constants
_kXR_recoverWrts  = 0x00001000
_kXR_open_updt    = 0x0020
_kXR_delete       = 0x0002

# Opcode constants
_kXR_protocol     = 3006
_kXR_login        = 3007
_kXR_open         = 3010
_kXR_write        = 3019
_kXR_close        = 3004

# Status codes
_kXR_ok           = 0

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk: raise EOFError("socket closed")
        buf += chunk
    return buf

def _read_response(sock):
    hdr = _recv_exact(sock, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body

class XrdConnection:
    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect((host, port))
        # Initial handshake (20 bytes)
        self.sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        _recv_exact(self.sock, 16)
        self.sid = b"\x00\x01"

    def protocol(self):
        # kXR_protocol (24 bytes)
        # 2B sid + 2B opcode + 4B pval + 1B flags + 1B capver + 10B reserved + 4B dlen
        req = struct.pack(">BB H I BB 10x I",
                          self.sid[0], self.sid[1], _kXR_protocol,
                          0x00000520, 0x02, 0x03, 0)
        self.sock.sendall(req)
        return _read_response(self.sock)

    def login(self):
        # kXR_login (24 bytes + payload)
        # 2B sid + 2B opcode + 4B pid + 8B user + 2B reserved + 2B capver + 4B dlen
        username = b"nobody"
        req = struct.pack(">BB H I 8s H H I",
                          self.sid[0], self.sid[1], _kXR_login,
                          os.getpid(), username, 0, 0, 0)
        self.sock.sendall(req)
        return _read_response(self.sock)

    def open(self, path):
        # kXR_open (24 bytes + payload)
        # 2B sid + 2B opcode + 2B mode + 2B options + 2B optiont + 6B reserved + 4B fht + 4B dlen
        payload = path.encode() + b"\x00"
        options = _kXR_open_updt | _kXR_delete
        req = struct.pack(">BB H HH H 6s 4s I",
                          self.sid[0], self.sid[1], _kXR_open,
                          0o644, options, 0, b"\x00"*6, b"\x00"*4, len(payload))
        self.sock.sendall(req + payload)
        status, body = _read_response(self.sock)
        if status != 0:
            if len(body) >= 4:
                errnum = struct.unpack(">I", body[0:4])[0]
                errmsg = body[4:].decode(errors='replace')
                print(f"OPEN FAILED: status={status} errnum={errnum} msg={errmsg}")
        return status, body

    def write(self, handle, offset, data):
        # kXR_write (24 bytes + payload)
        # 2B sid + 2B opcode + 4B fhandle + 8B offset + 4B reserved + 4B dlen
        req = struct.pack(">BB H 4s Q I I",
                          self.sid[0], self.sid[1], _kXR_write,
                          handle, offset, 0, len(data))
        self.sock.sendall(req + data)
        return _read_response(self.sock)

    def close(self, handle):
        # kXR_close (24 bytes)
        req = struct.pack(">BB H 4s 12x I",
                          self.sid[0], self.sid[1], _kXR_close,
                          handle, 0)
        self.sock.sendall(req)
        return _read_response(self.sock)

    def disconnect(self):
        self.sock.close()

@pytest.mark.requires_local_server
def test_write_idempotency():
    conn = XrdConnection(SERVER_HOST, NGINX_ANON_PORT)
    status, body = conn.protocol()
    assert status == _kXR_ok
    flags = struct.unpack(">I", body[4:8])[0]
    assert flags & _kXR_recoverWrts
    
    status, _ = conn.login()
    assert status == _kXR_ok
    
    path = "_test_wrts_idempotency.bin"
    status, body = conn.open(path)
    assert status == _kXR_ok
    handle = body[0:4]
    
    data = b"idempotency test data"

    # Snapshot log position before the writes so we only scan new output.
    # Under parallel test load the log grows fast and a fixed tail window
    # would miss the replay-skip message written by our specific request.
    error_log = os.path.join(LOG_DIR, "error.log")
    try:
        log_start = os.path.getsize(error_log)
    except FileNotFoundError:
        log_start = 0

    status, _ = conn.write(handle, 0, data)
    assert status == _kXR_ok

    # Replay
    status, _ = conn.write(handle, 0, data)
    assert status == _kXR_ok

    # Wait for nginx to flush the replay-skip log entry.
    time.sleep(0.1)
    with open(error_log, "rb") as fh:
        fh.seek(log_start)
        new_log = fh.read().decode(errors="replace")
    assert "write recovery replay skip" in new_log
    
    conn.close(handle)
    conn.disconnect()
