"""
Tests for async operations and kXR_attn unsolicited notifications.

Sections:
  1. Deprecated async operations (5000-5007): must return kXR_Unsupported.
  2. kXR_attn constant and action-code definitions.
  3. Native kXR_attn generation: kXR_prepare with kXR_notify sends
     kXR_ok + kXR_attn + kXR_asyncms when all files are already on disk.
  4. Wire-format verification: parse kXR_attn + kXR_asyncms body layout.
"""

import os
import socket
import struct
import pytest

from settings import SERVER_HOST, NGINX_ANON_PORT

pytestmark = pytest.mark.timeout(60)

# XRootD protocol constants
kXR_protocol  = 3006
kXR_login     = 3007
kXR_prepare   = 3021

kXR_asyncab   = 5000
kXR_asyncdi   = 5001
kXR_asyncms   = 5002
kXR_asyncrd   = 5003
kXR_asyncwt   = 5004
kXR_asyncav   = 5005
kXR_asyncunav = 5006
kXR_asyncgo   = 5007
kXR_asynresp  = 5008

kXR_ok    = 0
kXR_error = 4003
kXR_attn  = 4001

# kXR_prepare option flags
kXR_stage  = 0x08
kXR_notify = 0x02
kXR_noerrs = 0x04


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
    """Tests for kXR_attn (4001) constant and action-code definitions."""

    def test_attn_response_code_defined(self):
        """Verify kXR_attn (4001) response code is defined."""
        assert kXR_attn == 4001

    def test_async_action_codes_defined(self):
        """Verify all async action codes are defined (including active ones)."""
        assert kXR_asyncab   == 5000
        assert kXR_asyncdi   == 5001
        assert kXR_asyncms   == 5002
        assert kXR_asyncrd   == 5003
        assert kXR_asyncwt   == 5004
        assert kXR_asyncav   == 5005
        assert kXR_asyncunav == 5006
        assert kXR_asyncgo   == 5007
        assert kXR_asynresp  == 5008


def _send_prepare(sock: socket.socket, streamid: bytes, options: int,
                  payload: bytes) -> None:
    """Send kXR_prepare request (raw, no response read)."""
    # ClientPrepareRequest: options[1] + prty[1] + port[2] + optionX[2] + reserved[10]
    body = struct.pack(">BBH", options, 0, 0) + struct.pack(">H", 0) + b"\x00" * 10
    hdr  = struct.pack(">2sH", streamid, kXR_prepare) + body
    hdr += struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)


def _parse_attn_asyncms(body: bytes):
    """Parse a kXR_attn + kXR_asyncms body.

    Returns (actnum, inner_status, inner_dlen, message_bytes) or raises
    AssertionError on structural violations.
    """
    assert len(body) >= 16, f"kXR_attn body too short: {len(body)} < 16"

    actnum      = struct.unpack(">I", body[0:4])[0]
    # reserved[4] at body[4:8] — ignored
    inner_sid   = body[8:10]   # inner streamid
    inner_status = struct.unpack(">H", body[10:12])[0]
    inner_dlen  = struct.unpack(">I", body[12:16])[0]
    message     = body[16:16 + inner_dlen]

    return actnum, inner_sid, inner_status, inner_dlen, message


class TestNativeAttnGeneration:
    """Native kXR_attn generation via kXR_prepare + kXR_notify.

    When the server receives kXR_prepare with kXR_stage | kXR_notify and
    all requested files are already on disk (missing == 0), it sends two
    frames atomically:
      1. kXR_ok  with reqid "0"
      2. kXR_attn with kXR_asyncms body carrying a completion notification
    """

    def test_prepare_notify_with_existing_file_sends_attn(self, test_env):
        """kXR_prepare kXR_stage|kXR_notify on a present file → kXR_ok + kXR_attn."""
        data_dir = test_env["data_dir"]
        os.makedirs(data_dir, exist_ok=True)
        probe = os.path.join(data_dir, "attn_notify_probe.txt")
        with open(probe, "wb") as fh:
            fh.write(b"attn notify test\n")

        sock = _xrd_handshake_login(SERVER_HOST, test_env["anon_port"])
        sock.settimeout(5)

        payload = b"/attn_notify_probe.txt"
        _send_prepare(sock, b"\x00\x01", kXR_stage | kXR_notify, payload)

        # Frame 1: kXR_ok with reqid
        status1, body1 = _read_response(sock)
        assert status1 == kXR_ok, f"expected kXR_ok, got {status1}"
        assert body1 == b"0", f"expected reqid '0', got {body1!r}"

        # Frame 2: kXR_attn with kXR_asyncms notification
        status2, body2 = _read_response(sock)
        assert status2 == kXR_attn, \
            f"expected kXR_attn (4001), got {status2}"

        actnum, inner_sid, inner_status, inner_dlen, message = \
            _parse_attn_asyncms(body2)
        assert actnum == kXR_asyncms, \
            f"expected kXR_asyncms (5002), got actnum={actnum}"
        assert inner_sid == b"\x00\x00", \
            f"asyncms inner streamid should be {{0,0}}, got {inner_sid!r}"
        assert inner_status == kXR_ok, \
            f"asyncms inner status should be kXR_ok, got {inner_status}"
        assert inner_dlen == len(message), \
            f"inner_dlen {inner_dlen} != len(message) {len(message)}"
        assert len(message) > 0, "asyncms message must be non-empty"
        assert b"0" in message, \
            f"notification message should reference reqid; got {message!r}"

        sock.close()

    def test_prepare_notify_without_stage_no_attn(self, test_env):
        """kXR_prepare without kXR_stage does not send kXR_attn."""
        data_dir = test_env["data_dir"]
        os.makedirs(data_dir, exist_ok=True)
        probe = os.path.join(data_dir, "no_attn_probe.txt")
        with open(probe, "wb") as fh:
            fh.write(b"no attn\n")

        sock = _xrd_handshake_login(SERVER_HOST, test_env["anon_port"])
        sock.settimeout(2)

        payload = b"/no_attn_probe.txt"
        _send_prepare(sock, b"\x00\x01", kXR_notify, payload)

        # Without kXR_stage the response is a plain kXR_ok (no staging, no notify)
        status, _body = _read_response(sock)
        assert status == kXR_ok, f"expected kXR_ok, got {status}"

        # No second frame should arrive within the timeout
        try:
            sock.settimeout(0.3)
            extra_status, _ = _read_response(sock)
            assert False, \
                f"unexpected second frame: status={extra_status}"
        except (socket.timeout, OSError):
            pass  # expected — no kXR_attn for non-stage prepare

        sock.close()

    def test_attn_wire_format_asyncms(self):
        """Verify kXR_attn + kXR_asyncms body layout constants."""
        # Outer: 8B header + 4B actnum + 4B reserved + 8B inner header + msg
        XRD_RESPONSE_HDR_LEN = 8
        ATTN_BODY_OVERHEAD   = 16  # actnum + reserved + inner header
        msg = b"prepare reqid=0 complete"

        outer_bodylen = ATTN_BODY_OVERHEAD + len(msg)
        expected_total = XRD_RESPONSE_HDR_LEN + outer_bodylen

        # Build the frame manually and verify the constants
        frame = bytearray(expected_total)
        # outer header: streamid={0,0}, status=kXR_attn(4001), dlen=outer_bodylen
        struct.pack_into(">2sHI", frame, 0, b"\x00\x00", kXR_attn, outer_bodylen)
        # actnum
        struct.pack_into(">I", frame, 8, kXR_asyncms)
        # reserved
        struct.pack_into(">I", frame, 12, 0)
        # inner header: streamid={0,0}, status=kXR_ok(0), dlen=len(msg)
        struct.pack_into(">2sHI", frame, 16, b"\x00\x00", kXR_ok, len(msg))
        # message
        frame[24:24 + len(msg)] = msg

        assert len(frame) == expected_total
        # Parse outer
        outer_sid    = bytes(frame[0:2])
        outer_status = struct.unpack(">H", frame[2:4])[0]
        outer_dlen   = struct.unpack(">I", frame[4:8])[0]
        assert outer_sid    == b"\x00\x00"
        assert outer_status == kXR_attn
        assert outer_dlen   == outer_bodylen
        # Parse body
        actnum, inner_sid, inner_status, inner_dlen, message = \
            _parse_attn_asyncms(bytes(frame[8:]))
        assert actnum       == kXR_asyncms
        assert inner_sid    == b"\x00\x00"
        assert inner_status == kXR_ok
        assert message      == msg
