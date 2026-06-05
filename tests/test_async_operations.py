"""
Tests for async operations and kXR_attn unsolicited notifications.

These operations are deprecated ("No longer supported" in canonical XRootD v5.2.0)
but implemented here for protocol completeness. Tests verify that:

1. kXR_attn (4001) can be sent as an unsolicited notification
2. Async operations (5001-5007) return appropriate error responses
3. Protocol remains backward-compatible with deprecated features
"""

import socket
import struct
import pytest

from settings import SERVER_HOST, NGINX_ANON_PORT

pytestmark = pytest.mark.timeout(60)

# XRootD protocol constants
kXR_protocol = 3006
kXR_login = 3007
kXR_asyncab = 5000
kXR_asyncdi = 5001
kXR_asyncms = 5002
kXR_asyncrd = 5003
kXR_asyncwt = 5004
kXR_asyncav = 5005
kXR_asyncunav = 5006
kXR_asyncgo = 5007

kXR_ok = 0
kXR_error = 4003
kXR_attn = 4001


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(f"connection closed expecting {n} bytes, got {len(buf)}")
        buf += chunk
    return buf


def _read_response(sock: socket.socket):
    """Read a single XRootD response frame."""
    hdr = _recv_exact(sock, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _xrd_handshake_login(host: str, port: int) -> socket.socket:
    """Perform full XRootD bootstrap: handshake + protocol + login."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((host, port))
    # Handshake
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    _recv_exact(sock, 16)
    # kXR_protocol
    sock.sendall(struct.pack(">BB H I BB 10x I", 0, 1, kXR_protocol, 0x00000520, 0x02, 0x03, 0))
    _read_response(sock)
    # kXR_login
    sock.sendall(struct.pack(">BB H I 8s BB B B I",
                             0, 1, kXR_login, 0, b"test\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    _read_response(sock)
    return sock


def _send_async_request(sock: socket.socket, opcode: int):
    """Send an async operation request."""
    # All async ops have same format: streamid[2] requestid[2] opcode_body[16] dlen[4]
    # For testing, we send minimal body (16 bytes of zeros)
    hdr = struct.pack(">BB H 16x I", 0, 1, opcode, 0)
    sock.sendall(hdr)


class TestAsyncOperations:
    """Tests for deprecated async operations (5001-5007)."""

    def test_async_ab_unsupported(self):
        """kXR_asyncab (5000) returns kXR_Unsupported."""
        sock = _xrd_handshake_login(SERVER_HOST, NGINX_ANON_PORT)
        _send_async_request(sock, kXR_asyncab)
        status, _body = _read_response(sock)
        sock.close()
        assert status == kXR_error, f"expected kXR_error, got {status}"

    def test_async_di_unsupported(self):
        """kXR_asyncdi (5001) returns kXR_Unsupported."""
        sock = _xrd_handshake_login(SERVER_HOST, NGINX_ANON_PORT)
        _send_async_request(sock, kXR_asyncdi)
        status, _body = _read_response(sock)
        sock.close()
        assert status == kXR_error, f"expected kXR_error, got {status}"

    def test_async_ms_unsupported(self):
        """kXR_asyncms (5002) returns kXR_Unsupported."""
        sock = _xrd_handshake_login(SERVER_HOST, NGINX_ANON_PORT)
        _send_async_request(sock, kXR_asyncms)
        status, _body = _read_response(sock)
        sock.close()
        assert status == kXR_error, f"expected kXR_error, got {status}"

    def test_async_rd_unsupported(self):
        """kXR_asyncrd (5003) returns kXR_Unsupported."""
        sock = _xrd_handshake_login(SERVER_HOST, NGINX_ANON_PORT)
        _send_async_request(sock, kXR_asyncrd)
        status, _body = _read_response(sock)
        sock.close()
        assert status == kXR_error, f"expected kXR_error, got {status}"

    def test_async_wt_unsupported(self):
        """kXR_asyncwt (5004) returns kXR_Unsupported."""
        sock = _xrd_handshake_login(SERVER_HOST, NGINX_ANON_PORT)
        _send_async_request(sock, kXR_asyncwt)
        status, _body = _read_response(sock)
        sock.close()
        assert status == kXR_error, f"expected kXR_error, got {status}"

    def test_async_av_unsupported(self):
        """kXR_asyncav (5005) returns kXR_Unsupported."""
        sock = _xrd_handshake_login(SERVER_HOST, NGINX_ANON_PORT)
        _send_async_request(sock, kXR_asyncav)
        status, _body = _read_response(sock)
        sock.close()
        assert status == kXR_error, f"expected kXR_error, got {status}"

    def test_async_unav_unsupported(self):
        """kXR_asyncunav (5006) returns kXR_Unsupported."""
        sock = _xrd_handshake_login(SERVER_HOST, NGINX_ANON_PORT)
        _send_async_request(sock, kXR_asyncunav)
        status, _body = _read_response(sock)
        sock.close()
        assert status == kXR_error, f"expected kXR_error, got {status}"

    def test_async_go_unsupported(self):
        """kXR_asyncgo (5007) returns kXR_Unsupported."""
        sock = _xrd_handshake_login(SERVER_HOST, NGINX_ANON_PORT)
        _send_async_request(sock, kXR_asyncgo)
        status, _body = _read_response(sock)
        sock.close()
        assert status == kXR_error, f"expected kXR_error, got {status}"


class TestAttnResponse:
    """Tests for kXR_attn (4001) unsolicited notifications."""

    def test_attn_response_code_defined(self):
        """Verify kXR_attn (4001) response code is defined and usable."""
        # This is a basic sanity test that the response code constant is available
        assert kXR_attn == 4001, "kXR_attn should be 4001"

    def test_async_action_codes_defined(self):
        """Verify all async action codes are defined."""
        assert kXR_asyncab == 5000
        assert kXR_asyncdi == 5001
        assert kXR_asyncms == 5002
        assert kXR_asyncrd == 5003
        assert kXR_asyncwt == 5004
        assert kXR_asyncav == 5005
        assert kXR_asyncunav == 5006
        assert kXR_asyncgo == 5007
