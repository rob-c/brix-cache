"""
tests/test_handshake_protocol_wire.py — raw-wire conformance of the XRootD
connection bring-up sequence: the 20-byte ClientInitHandShake, the kXR_protocol
capability negotiation, and the kXR_login session establishment, all driven over
plain TCP sockets so the hostile / edge-case framing the official Python client
would never emit reaches the real handler code (src/handshake/client_hello.c,
src/session/protocol.c, src/session/login.c).  Each hostile request is followed
by a sanity op (kXR_ping / kXR_protocol) proving the connection or a fresh
session survived intact, exactly like tests/test_readv_security.py.  The suite
runs against the shared anon stream fleet (root://localhost:11094, auth none)
and skips cleanly with a clear reason when that fleet is unreachable.

Wire framing verified against /tmp/xrootd-src/src/XProtocol/XProtocol.hh:
  * ClientInitHandShake  — five 32-bit BE words; only word4==4 and word5==2012
    are validated (src/handshake/client_hello.c).
  * ClientProtocolRequest — streamid[2] requestid[2] clientpv[4] flags[1]
    expect[1] reserved[10] dlen[4]; the flags byte lands at request offset 12,
    which is ctx->cur_body[4] after recv.c copies hdr->body (src/session/protocol.c).
  * ClientLoginRequest    — streamid[2] requestid[2] pid[4] username[8]
    ability2[1] ability[1] capver[1] reserved2[1] dlen[4] (src/session/login.c).

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_handshake_protocol_wire.py -v
"""

import socket
import struct

import pytest

from settings import NGINX_ANON_PORT, SERVER_HOST


# ---------------------------------------------------------------------------
# Wire constants (from src/protocol/opcodes.h + src/protocol/flags.h, which
# mirror /tmp/xrootd-src/src/XProtocol/XProtocol.hh)
# ---------------------------------------------------------------------------

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT

ROOTD_PQ         = 2012          # handshake 5th word ("fifth") magic
HANDSHAKE_FOURTH = 4             # handshake 4th word magic

kXR_protocol = 3006
kXR_login    = 3007
kXR_ping     = 3011

kXR_ok          = 0
kXR_error       = 4003
kXR_ArgInvalid  = 3000
kXR_TLSRequired = 3028

# ServerResponseBody_Protocol: pval[4] flags[4]
kXR_PROTOCOLVERSION = 0x00000520
kXR_DataServer      = 1            # kind-of-server reported in the handshake body
kXR_isServer        = 0x00000001   # bit set in the kXR_protocol flags word

# ClientProtocolRequest::flags (RequestFlags enum)
kXR_secreqs = 0x01                 # ask the server to return its security requirements
kXR_ableTLS = 0x02                 # client is TLS capable
kXR_wantTLS = 0x04                 # client DEMANDS the connection switch to TLS

XROOTD_SESSION_ID_LEN = 16         # opaque session id returned by kXR_login


# ---------------------------------------------------------------------------
# Raw socket helpers (mirror tests/test_readv_security.py exactly)
# ---------------------------------------------------------------------------

def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError(
                f"socket closed, {nbytes - len(data)} bytes remaining")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    """Read one ServerResponseHdr (streamid[2] status[2] dlen[4]) + its body."""
    header = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return streamid, status, body


def _error_code(body):
    """Extract the big-endian errnum from a kXR_error body ([errnum:4B][msg])."""
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


def _connect():
    sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=8)
    sock.settimeout(8)
    return sock


def _handshake_bytes(first=0, second=0, third=0,
                     fourth=HANDSHAKE_FOURTH, fifth=ROOTD_PQ):
    """The 20-byte ClientInitHandShake: five 32-bit big-endian words."""
    return struct.pack("!IIIII", first, second, third, fourth, fifth)


def _handshake(sock):
    """Send a valid handshake and consume the 8-byte-body server reply."""
    sock.sendall(_handshake_bytes())
    sid, status, body = _read_response(sock)
    assert status == kXR_ok, "valid handshake unexpectedly rejected"
    return sid, status, body


def _protocol_request(streamid=b"\x00\x01", clientpv=kXR_PROTOCOLVERSION,
                      flags=0, expect=0, reserved=b"\x00" * 10, dlen=0,
                      trailer=b""):
    """Build a ClientProtocolRequest (the fixed 24-byte request header):

        streamid[2] requestid[2] clientpv[4] flags[1] expect[1] reserved[10] dlen[4]

    On src/connection/recv.c framing, recv copies hdr->body (request bytes
    [8:24]) into ctx->cur_body, so the flags byte at request offset 12 is read
    as ctx->cur_body[4] — exactly where the handler looks."""
    hdr = struct.pack("!2sHIBB10sI", streamid, kXR_protocol, clientpv,
                      flags, expect, reserved, dlen)
    return hdr + trailer


def _protocol(sock, flags=0, **kw):
    sock.sendall(_protocol_request(flags=flags, **kw))
    return _read_response(sock)


def _login_request(streamid=b"\x00\x02", pid=None, username=b"pytest\x00\x00",
                   ability2=0, ability=0, capver=5, reserved2=0, dlen=0):
    """Build a ClientLoginRequest:

        streamid[2] requestid[2] pid[4] username[8]
        ability2[1] ability[1] capver[1] reserved2[1] dlen[4]
    """
    if pid is None:
        pid = 0x1234
    uname = (username + b"\x00" * 8)[:8]
    return struct.pack("!2sHI8sBBBBI", streamid, kXR_login,
                       pid & 0xFFFFFFFF, uname,
                       ability2, ability, capver, reserved2, dlen)


def _login(sock, **kw):
    sock.sendall(_login_request(**kw))
    return _read_response(sock)


def _ping(sock, streamid=b"\x00\x0f"):
    """16-byte reserved body + dlen=0; a liveness round-trip that must succeed."""
    req = struct.pack("!2sH16sI", streamid, kXR_ping, b"\x00" * 16, 0)
    sock.sendall(req)
    return _read_response(sock)


def _after_login(sock):
    """Drive an already-handshaken socket through anon login; return it ready
    for a sanity op."""
    _, status, _ = _login(sock)
    assert status == kXR_ok, "login after handshake failed"
    return sock


def _session():
    """handshake + anonymous login -> a fully established read session."""
    sock = _connect()
    _handshake(sock)
    _, status, _ = _login(sock)
    assert status == kXR_ok, "anonymous login rejected"
    return sock


def _expect_closed(sock):
    """Return True if the peer has closed / no further response is readable.

    Used after a rejected handshake: xrootd_process_handshake() returns
    NGX_ERROR which breaks the recv loop and finalises the session, so the
    server sends NOTHING and drops the connection."""
    try:
        data = sock.recv(8)
    except (socket.timeout, ConnectionError, OSError):
        return True
    return data == b""


# ---------------------------------------------------------------------------
# Module-scoped guard: skip cleanly when the anon fleet is down.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _require_server():
    try:
        s = socket.create_connection((ANON_HOST, ANON_PORT), timeout=3)
        s.close()
    except OSError as exc:
        pytest.skip(
            f"anon stream server {ANON_HOST}:{ANON_PORT} unreachable: {exc}")


# ===========================================================================
# Class 1 — the 20-byte ClientInitHandShake
# ===========================================================================

class TestHandshake:
    """The server validates only the two magic words it relies on
    (fourth==4 AND fifth==ROOTD_PQ) before switching into request framing."""

    def test_valid_handshake_body_shape(self):
        """Positive control + the documented response shape: an 8-byte body
        whose first word is the protocol version (0x520) and second word is the
        dataserver kind (kXR_DataServer=1), under a streamid={0,0} header."""
        sock = _connect()
        try:
            sock.sendall(_handshake_bytes())
            sid, status, body = _read_response(sock)
            assert sid == b"\x00\x00", "handshake reply must use streamid {0,0}"
            assert status == kXR_ok
            assert len(body) == 8, "handshake body must be exactly 8 bytes"
            protover, kind = struct.unpack("!II", body)
            assert protover == kXR_PROTOCOLVERSION, f"protover=0x{protover:x}"
            assert kind == kXR_DataServer
            # Connection is live: a follow-up protocol request succeeds.
            _, pstatus, _ = _protocol(sock)
            assert pstatus == kXR_ok
        finally:
            sock.close()

    def test_bad_magic_fifth_word(self):
        """5th word != ROOTD_PQ(2012): the magic check fails, the handler
        returns NGX_ERROR, and the server drops the connection with no reply."""
        sock = _connect()
        try:
            sock.sendall(_handshake_bytes(fifth=9999))
            assert _expect_closed(sock), \
                "bad-magic handshake must NOT receive a kXR_ok reply"
        finally:
            sock.close()

    def test_bad_magic_fourth_word(self):
        """4th word != 4: same rejection path — no handshake reply, socket closed."""
        sock = _connect()
        try:
            sock.sendall(_handshake_bytes(fourth=7))
            assert _expect_closed(sock), \
                "handshake with fourth!=4 must be rejected (no reply)"
        finally:
            sock.close()

    def test_handshake_split_across_segments(self):
        """The recv state machine accumulates the 20-byte hello across multiple
        TCP segments (avail < need -> continue), so a byte-dribbled handshake
        still completes and returns the standard 8-byte body."""
        sock = _connect()
        try:
            blob = _handshake_bytes()
            # Three deliberately uneven slices.  No artificial inter-send delay
            # is needed: nginx services each readable segment as it arrives, so
            # the state machine sees short reads regardless of coalescing.
            for piece in (blob[:3], blob[3:11], blob[11:]):
                sock.sendall(piece)
            sid, status, body = _read_response(sock)
            assert status == kXR_ok, "split handshake should still be accepted"
            assert len(body) == 8
            protover, kind = struct.unpack("!II", body)
            assert protover == kXR_PROTOCOLVERSION
            assert kind == kXR_DataServer
            # Connection survived intact through login + a ping round-trip.
            assert _ping(_after_login(sock))[1] == kXR_ok
        finally:
            sock.close()


# ===========================================================================
# Class 2 — kXR_protocol capability negotiation
# ===========================================================================

class TestProtocol:
    """kXR_protocol advertises pval/flags and, when asked, a security trailer.
    It also enforces the TLS-required-but-unavailable rejection."""

    def test_protocol_body_advertises_version_and_server(self):
        """A bare kXR_protocol returns the fixed 8-byte ServerResponseBody_Protocol:
        pval == protocol version, flags has kXR_isServer set."""
        sock = _connect()
        try:
            _handshake(sock)
            sid, status, body = _protocol(sock)
            assert status == kXR_ok, _error_code(body)
            assert len(body) >= 8, "short protocol response missing pval/flags"
            pval, flags = struct.unpack("!Ii", body[:8])
            assert pval == kXR_PROTOCOLVERSION, f"pval=0x{pval:x}"
            assert flags & kXR_isServer, "server must advertise kXR_isServer"
        finally:
            sock.close()

    def test_protocol_minimal_header_no_trailer(self):
        """The kXR_protocol 'body' lives in the fixed 24-byte request header
        (recv.c copies 16 bytes into ctx->cur_body); a request with dlen=0 and
        no separate trailer is fully formed and accepted — the handler reads the
        flags byte at body offset 4 from that header, never from a <5-byte body.
        With no kXR_secreqs flag, the reply is exactly the 8-byte short form."""
        sock = _connect()
        try:
            _handshake(sock)
            sid, status, body = _protocol(sock, flags=0)
            assert status == kXR_ok, _error_code(body)
            assert len(body) == 8, \
                "without kXR_secreqs the response must be the 8-byte short form"
            assert _ping(_after_login(sock))[1] == kXR_ok
        finally:
            sock.close()

    def test_protocol_secreqs_trailer(self):
        """With kXR_secreqs set the response appends a security trailer.  On the
        anon fleet (auth none) there are zero auth-method entries, but the
        ServerResponseReqs_Protocol record (tag 'S') is still present, so the
        body grows past the 8-byte short form and carries the 'S' tag.

        Trailer layout (src/session/protocol.c): the 8-byte ServerProtocolBody
        is followed by a 4-byte SecurityInfo header at body[8:12]
        (si[0]=0, si[1]=required, si[2]=sec_count, si[3]=0); the
        ServerResponseReqs_Protocol begins at body[12] with the 'S' tag."""
        sock = _connect()
        try:
            _handshake(sock)
            sid, status, body = _protocol(sock, flags=kXR_secreqs)
            assert status == kXR_ok, _error_code(body)
            assert len(body) > 8, \
                "kXR_secreqs reply must be longer than the short form"
            assert len(body) >= 13, "secreqs trailer truncated"
            pval, flags = struct.unpack("!Ii", body[:8])
            assert pval == kXR_PROTOCOLVERSION
            sec_count = body[10]
            assert sec_count == 0, \
                f"anon (auth none) advertises no auth methods, got {sec_count}"
            assert body[12:13] == b"S", \
                "ServerResponseReqs 'S' tag must follow the SecurityInfo header"
            assert _ping(_after_login(sock))[1] == kXR_ok
        finally:
            sock.close()

    def test_protocol_wanttls_on_plaintext_port_rejected(self):
        """kXR_wantTLS demands the connection switch to TLS.  The anon listener
        has no TLS configured, so the handler MUST answer kXR_error/kXR_TLSRequired
        rather than silently proceeding in plaintext.  The error response is
        queued (xrootd_send_error returns NGX_OK), so the session survives."""
        sock = _connect()
        try:
            _handshake(sock)
            sid, status, body = _protocol(sock, flags=kXR_wantTLS | kXR_ableTLS)
            assert status == kXR_error, \
                "wantTLS on a non-TLS port must be an error, not kXR_ok"
            assert _error_code(body) == kXR_TLSRequired, \
                f"expected kXR_TLSRequired ({kXR_TLSRequired}), " \
                f"got {_error_code(body)}"
            # The session survives the rejection: a fresh protocol succeeds.
            _, status2, _ = _protocol(sock, streamid=b"\x00\x03")
            assert status2 == kXR_ok, "session must survive a TLSRequired error"
        finally:
            sock.close()

    def test_protocol_renegotiation_after_initial(self):
        """kXR_protocol carries no one-shot state; a client may re-issue it
        (e.g. to re-read capabilities) and each call returns the same advert."""
        sock = _connect()
        try:
            _handshake(sock)
            _, s1, b1 = _protocol(sock, streamid=b"\x00\x01")
            _, s2, b2 = _protocol(sock, streamid=b"\x00\x02")
            assert s1 == kXR_ok and s2 == kXR_ok
            assert b1[:8] == b2[:8], \
                "repeated kXR_protocol must return a stable capability advert"
            assert _ping(_after_login(sock))[1] == kXR_ok
        finally:
            sock.close()


# ===========================================================================
# Class 3 — kXR_login session establishment
# ===========================================================================

class TestLogin:
    """Username/pid edge cases against src/session/login.c.  Anonymous mode
    returns a 16-byte session id and completes in a single round-trip."""

    def test_login_baseline_session_id(self):
        """Positive control: a clean login returns a 16-byte opaque session id."""
        sock = _connect()
        try:
            _handshake(sock)
            sid, status, body = _login(sock)
            assert status == kXR_ok, _error_code(body)
            assert len(body) == XROOTD_SESSION_ID_LEN, \
                "anon login body must be exactly the 16-byte session id"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_login_username_embedded_nul(self):
        """A username with an embedded NUL ("a\\x00evil"): the handler treats
        the 8-byte field as NUL-padded ASCII and only validates bytes BEFORE the
        first NUL (login.c loops `while i<8 && user[i] != '\\0'`), so "a\\x00evil"
        is read as user "a" and the login succeeds — crucially the post-NUL
        "evil" bytes cannot change identity, and must not error.  (A control byte
        BEFORE the NUL would be rejected; here the leading byte is printable 'a'.)"""
        sock = _connect()
        try:
            _handshake(sock)
            sid, status, body = _login(sock, username=b"a\x00evil12")
            assert status == kXR_ok, \
                "NUL-truncated printable username must be accepted as user 'a'"
            assert len(body) == XROOTD_SESSION_ID_LEN
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_login_username_control_byte_rejected(self):
        """A username whose first byte is a non-printable control byte (before
        any NUL) violates the 'null-padded ASCII' rule and is rejected with
        kXR_ArgInvalid — the negative-security counterpart proving the NUL
        handling above is a deliberate parse, not a missing check."""
        sock = _connect()
        try:
            _handshake(sock)
            sid, status, body = _login(sock, username=b"\x01evil123")
            assert status == kXR_error, "control-byte username must be rejected"
            assert _error_code(body) == kXR_ArgInvalid, \
                f"expected kXR_ArgInvalid ({kXR_ArgInvalid}), got {_error_code(body)}"
            # A fresh, clean session still works after the rejection.
            sock2 = _session()
            try:
                assert _ping(sock2)[1] == kXR_ok
            finally:
                sock2.close()
        finally:
            sock.close()

    def test_login_all_nul_username(self):
        """An all-NUL username (8 zero bytes) is the empty-string user.  The
        validation loop sees user[0]=='\\0' and stops immediately, so login is
        accepted with a normal session id."""
        sock = _connect()
        try:
            _handshake(sock)
            sid, status, body = _login(sock, username=b"\x00" * 8)
            assert status == kXR_ok, "all-NUL (empty) username must be accepted"
            assert len(body) == XROOTD_SESSION_ID_LEN
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_login_pid_zero(self):
        """pid is recorded, not validated; pid=0 logs in cleanly."""
        sock = _connect()
        try:
            _handshake(sock)
            sid, status, body = _login(sock, pid=0)
            assert status == kXR_ok, "pid=0 must be accepted"
            assert len(body) == XROOTD_SESSION_ID_LEN
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_login_pid_max(self):
        """pid=0xffffffff (the extreme other end of the 32-bit range) is also
        accepted — no signedness/overflow rejection on the pid field."""
        sock = _connect()
        try:
            _handshake(sock)
            sid, status, body = _login(sock, pid=0xFFFFFFFF)
            assert status == kXR_ok, "pid=0xffffffff must be accepted"
            assert len(body) == XROOTD_SESSION_ID_LEN
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_login_repeated_on_same_session(self):
        """A second kXR_login on an already-logged-in session is REJECTED, matching
        stock xrootd (our server replies kXR_error 'duplicate login; already logged
        in'; stock replies kXR_error 'Required argument not present').  Crucially
        the duplicate cannot wedge or crash the session: the ORIGINAL login stays
        valid, so the connection remains usable (ping still ok).  Verified
        differentially against stock."""
        sock = _connect()
        try:
            _handshake(sock)
            _, s1, b1 = _login(sock, streamid=b"\x00\x02")
            assert s1 == kXR_ok and len(b1) == XROOTD_SESSION_ID_LEN
            _, s2, _b2 = _login(sock, streamid=b"\x00\x03", username=b"second12")
            assert s2 == kXR_error, "a duplicate login must be rejected (stock parity)"
            # The first session is untouched by the rejected duplicate.
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()
