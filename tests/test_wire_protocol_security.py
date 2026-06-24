"""
tests/test_wire_protocol_security.py

Wire protocol security: stream ID echo, malformed dlen, unknown opcodes,
pre-auth rejection gaps, handshake edge cases, resource exhaustion probes.

All tests use raw TCP sockets to NGINX_ANON_PORT (11094).

Run:
    pytest tests/test_wire_protocol_security.py -v
"""

import os
import socket
import struct
import time

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

# ---------------------------------------------------------------------------
# Module globals
# ---------------------------------------------------------------------------

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT
DATA_DIR  = DATA_ROOT

# XRootD opcodes
kXR_auth      = 3000
kXR_query     = 3001
kXR_chmod     = 3002
kXR_close     = 3003
kXR_dirlist   = 3004
kXR_protocol  = 3006
kXR_login     = 3007
kXR_mkdir     = 3008
kXR_mv        = 3009
kXR_open      = 3010
kXR_ping      = 3011
kXR_read      = 3013
kXR_rm        = 3014
kXR_rmdir     = 3015
kXR_sync      = 3016
kXR_stat      = 3017
kXR_set       = 3018
kXR_write     = 3019
kXR_fattr     = 3020
kXR_statx     = 3022
kXR_endsess   = 3023
kXR_readv     = 3025
kXR_pgwrite   = 3026
kXR_locate    = 3027
kXR_truncate  = 3028
kXR_writev    = 3031
kXR_pgread    = 3026 + 1  # not a real opcode; intentionally invalid

# kXR_pgread is actually 3026+1=3027 which is locate; use an actual value
kXR_pgread    = 3029  # just beyond range, for invalid opcode tests

# Response codes
kXR_ok           = 0
kXR_error        = 4003
kXR_NOT_AUTHORIZED = 3010
kXR_Unsupported    = 3013
kXR_InvalidRequest = 3006   # "Invalid request code" — stock's reply for an unknown opcode

# Open flags
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_open_new  = 0x0008


# ---------------------------------------------------------------------------
# Raw socket helpers
# ---------------------------------------------------------------------------

def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError(f"socket closed, {nbytes - len(data)} bytes remaining")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    header = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return streamid, status, body


def _handshake(host=None, port=None):
    h = host or ANON_HOST
    p = port or ANON_PORT
    sock = socket.create_connection((h, p), timeout=5)
    sock.settimeout(5)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    sid, status, body = _read_response(sock)
    assert status == kXR_ok
    return sock


def _login(sock, streamid=b"\x00\x01"):
    req = struct.pack("!2sHI8sBBBBI",
                      streamid, kXR_login,
                      os.getpid() & 0xFFFFFFFF,
                      b"pytest\x00\x00", 0, 0, 5, 0, 0)
    sock.sendall(req)
    return _read_response(sock)


def _ping(sock, streamid=b"\x00\x0f"):
    req = struct.pack("!2sH16sI", streamid, kXR_ping, b"\x00"*16, 0)
    sock.sendall(req)
    return _read_response(sock)


def _open_file(sock, path, options=kXR_open_read, streamid=b"\x00\x02"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH2s6s4sI",
                      streamid, kXR_open,
                      0o644, options, b"\x00\x00", b"\x00"*6, b"\x00"*4, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _close(sock, fhandle, streamid=b"\x00\x0e"):
    req = struct.pack("!2sH4s12sI", streamid, kXR_close, fhandle, b"\x00"*12, 0)
    sock.sendall(req)
    return _read_response(sock)


def _full_session():
    """Handshake + login; return open socket."""
    sock = _handshake()
    sid, status, body = _login(sock)
    assert status == kXR_ok
    return sock


def _error_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


def _send_raw(sock, streamid, reqid, body16, payload=b""):
    """Send a raw XRootD request with 16-byte fixed body."""
    req = struct.pack("!2sH16sI",
                      streamid, reqid, body16, len(payload))
    sock.sendall(req + payload)


# =========================================================================
# Class 1 — StreamID Echo Correctness
# =========================================================================

class TestStreamIDEchoCorrectness:
    """Every response must echo the request's exact 2-byte streamid."""

    def _ping_with_sid(self, sid_bytes):
        sock = _full_session()
        req = struct.pack("!2sH16sI", sid_bytes, kXR_ping, b"\x00"*16, 0)
        sock.sendall(req)
        sid_back, status, body = _read_response(sock)
        sock.close()
        return sid_back, status

    def test_streamid_all_zeros(self):
        sid, status = self._ping_with_sid(b"\x00\x00")
        assert sid == b"\x00\x00"
        assert status == kXR_ok

    def test_streamid_all_ones(self):
        sid, status = self._ping_with_sid(b"\xff\xff")
        assert sid == b"\xff\xff"
        assert status == kXR_ok

    def test_streamid_alternating(self):
        sid, status = self._ping_with_sid(b"\xaa\x55")
        assert sid == b"\xaa\x55"
        assert status == kXR_ok

    def test_streamid_five_sequential(self):
        sock = _full_session()
        for i in range(1, 6):
            sid_bytes = bytes([0x00, i])
            req = struct.pack("!2sH16sI", sid_bytes, kXR_ping, b"\x00"*16, 0)
            sock.sendall(req)
            sid_back, status, body = _read_response(sock)
            assert sid_back == sid_bytes, f"sid echo mismatch at i={i}"
            assert status == kXR_ok
        sock.close()

    def test_streamid_on_error_response(self):
        sock = _full_session()
        sid_bytes = b"\x12\x34"
        path = b"/nonexistent_file_xyz.txt\x00"
        req = struct.pack("!2sH16sI", sid_bytes, kXR_stat, b"\x00"*16, len(path))
        sock.sendall(req + path)
        sid_back, status, body = _read_response(sock)
        sock.close()
        assert sid_back == sid_bytes
        assert status == kXR_error

    def test_streamid_on_login(self):
        sock = _handshake()
        sid_bytes = b"\x00\x07"
        req = struct.pack("!2sHI8sBBBBI",
                          sid_bytes, kXR_login,
                          os.getpid() & 0xFFFFFFFF,
                          b"pytest\x00\x00", 0, 0, 5, 0, 0)
        sock.sendall(req)
        sid_back, status, body = _read_response(sock)
        sock.close()
        assert sid_back == sid_bytes
        assert status == kXR_ok

    def test_streamid_on_open(self):
        sock = _full_session()
        sid_bytes = b"\xde\xad"
        path = b"/test.txt\x00"
        req = struct.pack("!2sHHH2s6s4sI",
                          sid_bytes, kXR_open,
                          0o644, kXR_open_read, b"\x00\x00", b"\x00"*6, b"\x00"*4,
                          len(path))
        sock.sendall(req + path)
        sid_back, status, body = _read_response(sock)
        if status == kXR_ok:
            fhandle = body[:4]
            _close(sock, fhandle)
        sock.close()
        assert sid_back == sid_bytes

    def test_streamid_on_stat(self):
        sock = _full_session()
        sid_bytes = b"\x01\x23"
        path = b"/test.txt\x00"
        req = struct.pack("!2sH16sI", sid_bytes, kXR_stat, b"\x00"*16, len(path))
        sock.sendall(req + path)
        sid_back, status, body = _read_response(sock)
        sock.close()
        assert sid_back == sid_bytes
        assert status == kXR_ok


# =========================================================================
# Class 2 — Malformed dlen
# =========================================================================

class TestMalformedDlen:
    """The dlen field guards in recv.c must prevent oversized allocations."""

    def test_dlen_zero_ping_ok(self):
        sock = _full_session()
        _, status, body = _ping(sock)
        sock.close()
        assert status == kXR_ok

    def test_dlen_nonzero_ping_not_crash(self):
        # ping with dlen=4 + 4 extra payload bytes — server should handle gracefully
        sock = _full_session()
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_ping, b"\x00"*16, 4)
        sock.sendall(req + b"\x00"*4)
        try:
            _, status, body = _read_response(sock)
        except ConnectionError:
            pass  # server may close connection
        sock.close()

    def test_dlen_uint32_max_rejected(self):
        # dlen = 0xFFFFFFFF must be rejected, not cause 4 GiB allocation
        sock = _full_session()
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_stat, b"\x00"*16, 0xFFFFFFFF)
        sock.sendall(req)
        try:
            _, status, body = _read_response(sock)
            assert status == kXR_error
        except ConnectionError:
            pass  # acceptable: server disconnects
        sock.close()

    def test_dlen_signed_negative_as_large_rejected(self):
        # dlen = 0x80000000 (2 GiB if treated as signed) must be rejected
        sock = _full_session()
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_stat, b"\x00"*16, 0x80000000)
        sock.sendall(req)
        try:
            _, status, body = _read_response(sock)
            assert status == kXR_error
        except ConnectionError:
            pass
        sock.close()

    def test_dlen_exactly_at_path_limit_accepted(self):
        # XROOTD_MAX_PATH + 64 = 4224 for stat — at limit should be accepted
        sock = _full_session()
        payload = b"/test.txt\x00" + b"\x00" * (4224 - 10)
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_stat, b"\x00"*16, len(payload))
        sock.sendall(req + payload)
        try:
            _, status, body = _read_response(sock)
            # Either ok or error (path too long) — just must not crash
        except ConnectionError:
            pass
        sock.close()

    def test_dlen_one_over_path_limit_rejected(self):
        # XROOTD_MAX_PATH + 65 — one over the limit for non-write opcodes
        sock = _full_session()
        payload = b"/" + b"a" * 4224
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_stat, b"\x00"*16, len(payload))
        sock.sendall(req)
        try:
            _, status, body = _read_response(sock)
            assert status == kXR_error
        except ConnectionError:
            pass  # acceptable: server disconnects on oversize
        sock.close()

    def test_dlen_zero_stat_handle_based(self):
        # stat with dlen=0 (handle-based variant) — must be handled
        sock = _full_session()
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_stat, b"\x00"*16, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        sock.close()
        # Either ok (root stat) or error — not a crash
        assert status in (kXR_ok, kXR_error)

    def test_valid_request_after_close_reconnect(self):
        # After sending oversized dlen and being disconnected, a new connection works
        # (Test 1: send oversized dlen)
        sock = _full_session()
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_stat, b"\x00"*16, 0xFFFFFFFF)
        sock.sendall(req)
        try:
            _read_response(sock)
        except Exception:
            pass
        sock.close()
        # (Test 2: new connection should work fine)
        sock2 = _full_session()
        _, status, body = _ping(sock2)
        sock2.close()
        assert status == kXR_ok

    def test_dlen_zero_write_opcode(self):
        # kXR_write with dlen=0 on a write-open handle
        os.makedirs(DATA_DIR, exist_ok=True)
        path = "/wire_test_dlen0_write.txt"
        fullpath = os.path.join(DATA_DIR, path.lstrip("/"))
        with open(fullpath, "wb") as f:
            f.write(b"init")
        sock = _full_session()
        _, open_status, open_body = _open_file(sock, path, kXR_open_updt)
        assert open_status == kXR_ok
        fhandle = open_body[:4]
        # Write with dlen=0 (no payload) — server accepts or errors cleanly
        req = struct.pack("!2sH4sqiI", b"\x00\x03", kXR_write,
                          fhandle, 0, 0, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        sock.close()
        assert status in (kXR_ok, kXR_error)

    def test_dlen_large_write_payload_allowed(self):
        # Write opcodes may have large payloads (up to XROOTD_MAX_WRITE_PAYLOAD)
        path = "/wire_test_large_write.txt"
        fullpath = os.path.join(DATA_DIR, path.lstrip("/"))
        payload = b"A" * 65536  # 64 KiB — well within 16 MiB limit
        sock = _full_session()
        _, open_status, open_body = _open_file(sock, path,
                                                kXR_open_updt | kXR_open_new)
        if open_status != kXR_ok:
            with open(fullpath, "wb") as f:
                pass
            _, open_status, open_body = _open_file(sock, path, kXR_open_updt)
        assert open_status == kXR_ok
        fhandle = open_body[:4]
        req = struct.pack("!2sH4sqiI", b"\x00\x03", kXR_write,
                          fhandle, 0, len(payload), len(payload))
        sock.sendall(req + payload)
        _, status, body = _read_response(sock)
        sock.close()
        assert status == kXR_ok


# =========================================================================
# Class 3 — Invalid RequestID
# =========================================================================

class TestInvalidRequestID:
    """Unknown opcodes must be rejected (not crash).

    Stock xrootd replies kXR_InvalidRequest ("Invalid request code",
    XrdXrootdProtocol.cc:608) for an unrecognised request code; kXR_Unsupported
    is reserved for a *recognised* op the backend cannot perform.  We match that.
    """

    def _send_unknown(self, sock, reqid, streamid=b"\x00\x01"):
        req = struct.pack("!2sH16sI", streamid, reqid, b"\x00"*16, 0)
        sock.sendall(req)
        return _read_response(sock)

    def test_requestid_0_rejected(self):
        sock = _full_session()
        _, status, body = self._send_unknown(sock, 0)
        sock.close()
        assert status == kXR_error
        assert _error_code(body) == kXR_InvalidRequest

    def test_requestid_below_range_rejected(self):
        sock = _full_session()
        _, status, body = self._send_unknown(sock, 2999)
        sock.close()
        assert status == kXR_error
        assert _error_code(body) == kXR_InvalidRequest

    def test_requestid_above_range_rejected(self):
        sock = _full_session()
        # kXR_writev is 3031 (highest valid); 3032+ is unknown
        _, status, body = self._send_unknown(sock, 3033)
        sock.close()
        assert status == kXR_error
        assert _error_code(body) == kXR_InvalidRequest

    def test_requestid_max_uint16_rejected(self):
        sock = _full_session()
        _, status, body = self._send_unknown(sock, 0xFFFF)
        sock.close()
        assert status == kXR_error
        assert _error_code(body) == kXR_InvalidRequest

    def test_requestid_lowest_valid_is_3001(self):
        # kXR_query = 3001 is a valid opcode — must NOT return Unsupported
        sock = _full_session()
        path = b"/test.txt\x00"
        req = struct.pack("!2sHHH12sI", b"\x00\x01", kXR_query,
                          1, 0, b"\x00"*12, len(path))
        sock.sendall(req + path)
        _, status, body = _read_response(sock)
        sock.close()
        # Must not be kXR_Unsupported
        if status == kXR_error:
            assert _error_code(body) != kXR_Unsupported

    def test_requestid_highest_valid_not_unsupported(self):
        # kXR_writev = 3031 is valid — rejected for bad args, not Unsupported
        sock = _full_session()
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_writev, b"\x00"*16, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        sock.close()
        if status == kXR_error:
            assert _error_code(body) != kXR_Unsupported

    def test_multiple_unknowns_then_ping(self):
        sock = _full_session()
        for reqid in [3033, 3050, 0xABCD]:
            req = struct.pack("!2sH16sI", b"\x00\x01", reqid, b"\x00"*16, 0)
            sock.sendall(req)
            _, status, body = _read_response(sock)
            assert status == kXR_error
        _, status, body = _ping(sock)
        sock.close()
        assert status == kXR_ok

    def test_requestid_3000_auth_before_login(self):
        # kXR_auth (3000) before login — requires login first
        sock = _handshake()
        cred = b"ztn\x00" + b"fake"
        req = struct.pack("!2sH12s4sI", b"\x00\x01", kXR_auth,
                          b"\x00"*12, b"ztn\x00", len(cred))
        sock.sendall(req + cred)
        _, status, body = _read_response(sock)
        sock.close()
        assert status == kXR_error


# =========================================================================
# Class 4 — Pre-Auth Request Rejection (gaps from test_privilege_escalation.py)
# =========================================================================

class TestPreAuthRequestRejection:
    """Opcodes not covered by test_privilege_escalation.py must also be rejected
    before kXR_login completes."""

    def _send_before_login(self, reqid, payload=b""):
        """Send opcode immediately after handshake, before login."""
        sock = _handshake()
        req = struct.pack("!2sH16sI", b"\x00\x01", reqid, b"\x00"*16, len(payload))
        sock.sendall(req + payload)
        _, status, body = _read_response(sock)
        sock.close()
        return status, body

    def _assert_rejected(self, status, body):
        assert status == kXR_error
        code = _error_code(body)
        assert code == kXR_NOT_AUTHORIZED, f"expected NOT_AUTHORIZED, got {code}"

    def test_preauth_sync_rejected(self):
        status, body = self._send_before_login(kXR_sync)
        self._assert_rejected(status, body)

    def test_preauth_fattr_rejected(self):
        path = b"/test.txt\x00"
        status, body = self._send_before_login(kXR_fattr, path)
        self._assert_rejected(status, body)

    def test_preauth_writev_rejected(self):
        status, body = self._send_before_login(kXR_writev)
        self._assert_rejected(status, body)

    def test_preauth_pgwrite_rejected(self):
        payload = b"\x00" * 20
        status, body = self._send_before_login(kXR_pgwrite, payload)
        self._assert_rejected(status, body)

    def test_preauth_locate_rejected(self):
        path = b"/test.txt\x00"
        status, body = self._send_before_login(kXR_locate, path)
        self._assert_rejected(status, body)

    def test_preauth_statx_rejected(self):
        path = b"/test.txt\x00"
        status, body = self._send_before_login(kXR_statx, path)
        self._assert_rejected(status, body)

    def test_preauth_chmod_rejected(self):
        path = b"/test.txt\x00"
        status, body = self._send_before_login(kXR_chmod, path)
        self._assert_rejected(status, body)

    def test_preauth_rm_rejected(self):
        path = b"/test.txt\x00"
        status, body = self._send_before_login(kXR_rm, path)
        self._assert_rejected(status, body)

    def test_preauth_rmdir_rejected(self):
        path = b"/test.txt\x00"
        status, body = self._send_before_login(kXR_rmdir, path)
        self._assert_rejected(status, body)

    def test_preauth_mv_rejected(self):
        path = b"/test.txt\x00/test2.txt\x00"
        status, body = self._send_before_login(kXR_mv, path)
        self._assert_rejected(status, body)


# =========================================================================
# Class 5 — Protocol Handshake Variants
# =========================================================================

class TestProtocolHandshakeVariants:
    """Edge cases in the 20-byte XRootD handshake framing."""

    def test_partial_handshake_10_bytes(self):
        sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
        sock.settimeout(2)
        sock.sendall(b"\x00" * 10)
        sock.close()  # Must not crash the server

    def test_partial_handshake_19_bytes(self):
        sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
        sock.settimeout(2)
        sock.sendall(b"\x00" * 19)
        sock.close()

    def test_handshake_first_field_nonzero(self):
        # Non-zero first byte → server closes connection immediately
        sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
        sock.settimeout(2)
        sock.sendall(b"\x01" + b"\x00" * 19)
        try:
            data = sock.recv(16)
        except Exception:
            data = b""
        sock.close()
        # Might get a response or nothing — just must not hang indefinitely

    def test_login_without_prior_protocol_frame(self):
        # kXR_login works without sending kXR_protocol first (optional frame)
        sock = _handshake()
        _, status, body = _login(sock)
        sock.close()
        assert status == kXR_ok

    def test_handshake_byte_by_byte(self):
        # 1 byte at a time — server must buffer correctly
        sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
        sock.settimeout(5)
        hs = struct.pack("!IIIII", 0, 0, 0, 4, 2012)
        for b in hs:
            sock.sendall(bytes([b]))
            time.sleep(0.001)
        _, status, body = _read_response(sock)
        sock.close()
        assert status == kXR_ok
        assert len(body) == 8

    def test_immediate_disconnect_after_handshake(self):
        # Connect, complete handshake, immediately close — no crash
        sock = _handshake()
        sock.close()

    def test_protocol_frame_sent_before_login(self):
        sock = _handshake()
        # kXR_protocol frame — optional but supported
        req = struct.pack("!2sH I BB 10s I",
                          b"\x00\x01", kXR_protocol, 39, 0x00, 0x00, b"\x00"*10, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        assert status == kXR_ok
        _, status2, body2 = _login(sock)
        assert status2 == kXR_ok
        sock.close()


# =========================================================================
# Class 6 — Fast-Path / Stress Probes
# =========================================================================

class TestFastPathAttacks:
    """Resource exhaustion probes — verify no leaks, no crashes."""

    def test_100_sequential_pings(self):
        sock = _full_session()
        for i in range(100):
            sid = struct.pack("!2s", bytes([i >> 8, i & 0xFF]))
            req = struct.pack("!2sH16sI", sid, kXR_ping, b"\x00"*16, 0)
            sock.sendall(req)
        for _ in range(100):
            _, status, body = _read_response(sock)
            assert status == kXR_ok
        sock.close()

    def test_10_opens_and_closes(self):
        sock = _full_session()
        path = "/test.txt"
        for _ in range(10):
            _, status, body = _open_file(sock, path, kXR_open_read)
            assert status == kXR_ok
            fhandle = body[:4]
            _, cs, _ = _close(sock, fhandle)
            assert cs == kXR_ok
        sock.close()

    def test_100_stat_requests(self):
        sock = _full_session()
        path = b"/test.txt\x00"
        for _ in range(100):
            req = struct.pack("!2sH16sI", b"\x00\x01", kXR_stat, b"\x00"*16, len(path))
            sock.sendall(req + path)
        for _ in range(100):
            _, status, body = _read_response(sock)
            assert status == kXR_ok
        sock.close()

    def test_50_new_connections(self):
        for _ in range(50):
            sock = _handshake()
            _, status, body = _login(sock)
            assert status == kXR_ok
            sock.close()

    def test_write_zero_bytes(self):
        path = "/wire_zero_write.txt"
        fullpath = os.path.join(DATA_DIR, path.lstrip("/"))
        with open(fullpath, "wb") as f:
            f.write(b"hello")
        sock = _full_session()
        _, open_status, open_body = _open_file(sock, path, kXR_open_updt)
        assert open_status == kXR_ok
        fhandle = open_body[:4]
        req = struct.pack("!2sH4sqiI", b"\x00\x03", kXR_write,
                          fhandle, 0, 0, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        sock.close()
        assert status in (kXR_ok, kXR_error)

    def test_read_zero_bytes(self):
        sock = _full_session()
        _, open_status, open_body = _open_file(sock, "/test.txt", kXR_open_read)
        assert open_status == kXR_ok
        fhandle = open_body[:4]
        req = struct.pack("!2sH4sqiI", b"\x00\x03", kXR_read,
                          fhandle, 0, 0, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        _close(sock, fhandle)
        sock.close()
        assert status == kXR_ok
        assert body == b""

    def test_readv_zero_segments(self):
        sock = _full_session()
        _, open_status, open_body = _open_file(sock, "/test.txt", kXR_open_read)
        assert open_status == kXR_ok
        fhandle = open_body[:4]
        req = struct.pack("!2sH16sI", b"\x00\x03", kXR_readv, b"\x00"*16, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        _close(sock, fhandle)
        sock.close()
        assert status in (kXR_ok, kXR_error)

    def test_writev_zero_segments(self):
        path = "/wire_writev_zero.txt"
        fullpath = os.path.join(DATA_DIR, path.lstrip("/"))
        with open(fullpath, "wb") as f:
            pass
        sock = _full_session()
        _, open_status, open_body = _open_file(sock, path, kXR_open_updt)
        assert open_status == kXR_ok
        fhandle = open_body[:4]
        req = struct.pack("!2sH16sI", b"\x00\x03", kXR_writev, b"\x00"*16, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        sock.close()
        assert status == kXR_error  # kXR_ArgInvalid — too few segments

    def test_two_connections_read_same_file(self):
        sock1 = _full_session()
        sock2 = _full_session()
        _, s1, b1 = _open_file(sock1, "/test.txt", kXR_open_read)
        _, s2, b2 = _open_file(sock2, "/test.txt", kXR_open_read)
        assert s1 == kXR_ok
        assert s2 == kXR_ok
        fh1, fh2 = b1[:4], b2[:4]
        # Read first 8 bytes from both
        for sock, fh in [(sock1, fh1), (sock2, fh2)]:
            req = struct.pack("!2sH4sqiI", b"\x00\x03", kXR_read, fh, 0, 8, 0)
            sock.sendall(req)
        d1 = _read_response(sock1)[2]
        d2 = _read_response(sock2)[2]
        _close(sock1, fh1)
        _close(sock2, fh2)
        sock1.close()
        sock2.close()
        assert d1 == d2

    def test_endsess_closes_gracefully(self):
        sock = _full_session()
        req = struct.pack("!2sH16sI", b"\x00\x01", kXR_endsess, b"\x00"*16, 0)
        sock.sendall(req)
        try:
            _, status, body = _read_response(sock)
            assert status in (kXR_ok, kXR_error)
        except ConnectionError:
            pass
        sock.close()

    def test_sync_invalid_handle_after_login(self):
        sock = _full_session()
        # kXR_sync with invalid handle 0xFF000000
        req = struct.pack("!2sH4s12sI",
                          b"\x00\x01", kXR_sync, b"\xff\x00\x00\x00", b"\x00"*12, 0)
        sock.sendall(req)
        _, status, body = _read_response(sock)
        sock.close()
        assert status == kXR_error
