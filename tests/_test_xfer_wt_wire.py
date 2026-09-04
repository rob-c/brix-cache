"""Minimal XRootD write client for the offline write-back lifecycle tests.

Stock ``xrdcp`` stats a destination before opening it.  That is unsuitable for
the dead-origin fixture: the test is specifically proving that a write can land
in the local stage while the authoritative origin is unavailable.  These small
helpers drive the server operation being tested directly.
"""

import os
import socket
import struct


KXR_CLOSE = 3003
KXR_PROTOCOL = 3006
KXR_LOGIN = 3007
KXR_OPEN = 3010
KXR_WRITE = 3019
KXR_OK = 0

KXR_DELETE = 0x0002
KXR_OPEN_UPDT = 0x0020
KXR_MKPATH = 0x0100


def _recv_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("XRootD connection closed mid-response")
        data.extend(chunk)
    return bytes(data)


def _response(sock):
    header = _recv_exact(sock, 8)
    _stream_id, status, length = struct.unpack("!2sHI", header)
    return status, _recv_exact(sock, length) if length else b""


def _request(sock, stream_id, opcode, body=b"", payload=b""):
    header = stream_id + struct.pack("!H", opcode)
    header += body.ljust(16, b"\x00") + struct.pack("!I", len(payload))
    sock.sendall(header + payload)
    return _response(sock)


def _require_ok(operation, response):
    status, body = response
    if status != KXR_OK:
        code = struct.unpack("!I", body[:4])[0] if len(body) >= 4 else None
        message = body[4:].rstrip(b"\x00").decode(errors="replace")
        raise AssertionError(
            f"{operation} failed: status={status}, code={code}, message={message!r}")
    return body


def _connect(host, port):
    sock = socket.create_connection((host, port), timeout=15)
    sock.settimeout(15)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _require_ok("handshake", _response(sock))
    _require_ok("protocol", _request(sock, b"\x00\x01", KXR_PROTOCOL))
    login = struct.pack(
        "!I8sBBBB", os.getpid() & 0xFFFFFFFF, b"pytest\x00\x00", 0, 0, 5, 0)
    _require_ok("login", _request(sock, b"\x00\x02", KXR_LOGIN, login))
    return sock


def write_file(host, port, path, payload):
    """Create or replace *path*, write *payload*, and cleanly commit it."""
    sock = _connect(host, port)
    try:
        options = KXR_OPEN_UPDT | KXR_DELETE | KXR_MKPATH
        open_body = struct.pack("!HH", 0o644, options)
        handle = _require_ok(
            "open",
            _request(sock, b"\x00\x03", KXR_OPEN, open_body, path.encode()),
        )[:4]
        write_body = handle + struct.pack("!q", 0) + b"\x00" * 4
        _require_ok(
            "write",
            _request(sock, b"\x00\x04", KXR_WRITE, write_body, payload),
        )
        _require_ok("close", _request(sock, b"\x00\x05", KXR_CLOSE, handle))
    finally:
        sock.close()
