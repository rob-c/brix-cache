"""
Security-level negotiation and default enforcement behavior.

These tests keep the wire-level checks small:
  - default sec.level none keeps unsigned reads working
  - configured levels are advertised in the kXR_protocol secreqs trailer
  - pedantic advertises kXR_secOData so clients sign write payload bytes
"""

import socket
import struct

import pytest

from settings import (
    SECURITY_LEVEL_STANDARD_PORT,
    SECURITY_LEVEL_PEDANTIC_PORT,
    SERVER_HOST,
)

_CONNECT_HOST = SERVER_HOST


kXR_ok = 0
kXR_protocol = 3006
kXR_login = 3007
kXR_open = 3010
kXR_read = 3013
kXR_close = 3003

kXR_open_read = 0x0010
kXR_secOData = 0x01

PROTOVER = 0x00000520
ROOTD_PQ = 2012


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _send_req(sock, streamid, reqid, body=b"", payload=b""):
    hdr = (
        streamid
        + struct.pack(">H", reqid)
        + body[:16].ljust(16, b"\x00")
        + struct.pack(">I", len(payload))
    )
    sock.sendall(hdr + payload)
    rsp_hdr = _recv_exact(sock, 8)
    assert rsp_hdr is not None, "no response received"
    status = struct.unpack(">H", rsp_hdr[2:4])[0]
    dlen = struct.unpack(">I", rsp_hdr[4:8])[0]
    data = _recv_exact(sock, dlen) if dlen else b""
    assert data is not None
    return status, data


def _connect(port, host=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect((host or _CONNECT_HOST, port))

    handshake = struct.pack(">IIIII", 0, 0, 0, 4, ROOTD_PQ)
    sock.sendall(handshake)
    assert _recv_exact(sock, 16) is not None
    return sock


def _protocol(sock, flags=0x01):
    body = struct.pack(">I", PROTOVER) + bytes([flags]) + b"\x00" * 11
    return _send_req(sock, b"\x00\x01", kXR_protocol, body=body)


def _login(sock):
    login_body = struct.pack(">I", 0) + b"pytest\x00\x00" + b"\x00" * 4
    status, _ = _send_req(sock, b"\x00\x02", kXR_login, body=login_body)
    assert status == kXR_ok


def _open_read(sock, path):
    body = struct.pack(">HHH", 0, kXR_open_read, 0) + b"\x00" * 10
    status, data = _send_req(sock, b"\x00\x03", kXR_open,
                             body=body, payload=path + b"\x00")
    assert status == kXR_ok
    assert len(data) >= 4
    return data[:4]


def _read(sock, fhandle, length):
    body = fhandle + struct.pack(">QI", 0, length)
    return _send_req(sock, b"\x00\x04", kXR_read, body=body)


def _close(sock, fhandle):
    body = fhandle + b"\x00" * 12
    _send_req(sock, b"\x00\x05", kXR_close, body=body)


def _security_requirements(body):
    assert len(body) >= 18
    sec_count = body[10]
    offset = 8 + 4 + sec_count * 8
    reqs = body[offset:offset + 6]
    assert len(reqs) == 6
    assert reqs[0:1] == b"S"
    return {
        "secopt": reqs[3],
        "seclvl": reqs[4],
        "secvsz": reqs[5],
    }


@pytest.fixture
def security_nginx():
    def start(level):
        if level == "standard":
            return {"port": SECURITY_LEVEL_STANDARD_PORT}
        elif level == "pedantic":
            return {"port": SECURITY_LEVEL_PEDANTIC_PORT}
        pytest.skip(f"unknown security level: {level}")
    yield start


class TestSecurityLevel:
    def test_default_none_allows_unsigned_read(self, test_env):
        sock = _connect(test_env["anon_port"])
        try:
            status, _ = _protocol(sock, flags=0x00)
            assert status == kXR_ok
            _login(sock)
            fhandle = _open_read(sock, b"/test.txt")
            status, data = _read(sock, fhandle, 5)
            assert status == kXR_ok
            assert data == b"hello"
            _close(sock, fhandle)
        finally:
            sock.close()

    def test_standard_protocol_advertises_security_level(self, security_nginx):
        info = security_nginx("standard")
        sock = _connect(info["port"])
        try:
            status, body = _protocol(sock, flags=0x01)
            assert status == kXR_ok
            reqs = _security_requirements(body)
            assert reqs == {"secopt": 0, "seclvl": 2, "secvsz": 0}
        finally:
            sock.close()

    def test_pedantic_protocol_advertises_payload_signing(self, security_nginx):
        info = security_nginx("pedantic")
        sock = _connect(info["port"])
        try:
            status, body = _protocol(sock, flags=0x01)
            assert status == kXR_ok
            reqs = _security_requirements(body)
            assert reqs == {"secopt": kXR_secOData, "seclvl": 4, "secvsz": 0}
        finally:
            sock.close()
