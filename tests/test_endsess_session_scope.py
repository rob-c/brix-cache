"""
tests/test_endsess_session_scope.py — kXR_endsess must be session-scoped.

WHAT: Raw-wire proof that kXR_endsess terminates the session it NAMES (its
      sessid argument), not simply the connection it arrives on.

WHY:  The official XRootD client (XrdCl / xrdcp / xrootdfs), recovering from a
      dropped connection, opens a NEW connection, logs in afresh, and THEN sends
      kXR_endsess for its PREVIOUS (now-dead) session to release it. If the
      server clears the *current* connection's auth state on ANY endsess, that
      freshly-authenticated connection is de-authed and the client's next request
      (its recovery kXR_open) fails with kXR_NotAuthorized — which broke official
      client transfer recovery against this server on a lossy link. This test
      locks in the fix (src/session/lifecycle.c).

HOW:  Two raw sessions against the shared anon fleet:
       1. endsess naming a DIFFERENT sessid → the connection STAYS authenticated
          (a subsequent open succeeds). [the regression]
       2. endsess naming the connection's OWN sessid → the connection IS torn
          down (a subsequent open is rejected). [security property preserved]

Run: TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_endsess_session_scope.py -v
"""
import os
import socket
import struct

import pytest

from settings import NGINX_ANON_PORT, REMOTE_SERVER, SERVER_HOST

kXR_login = 3007
kXR_open = 3010
kXR_close = 3003
kXR_write = 3019
kXR_endsess = 3023
kXR_ok = 0
kXR_error = 4003
kXR_NotAuthorized = 3010          # XErrorCode (base 3000)
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_open_new = 0x0008
kXR_delete = 0x0004
kXR_mkpath = 0x0100

PROBE = "/endsess_probe.bin"


def _recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("socket closed")
        data.extend(chunk)
    return bytes(data)


def _resp(sock):
    sid, status, dlen = struct.unpack("!2sHI", _recv_exact(sock, 8))
    return sid, status, (_recv_exact(sock, dlen) if dlen else b"")


def _handshake():
    s = socket.create_connection((SERVER_HOST, NGINX_ANON_PORT), timeout=8)
    s.settimeout(8)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _, status, _ = _resp(s)
    assert status == kXR_ok, "handshake rejected"
    return s


def _login(s, streamid=b"\x00\x01"):
    req = struct.pack("!2sHI8sBBBBI", streamid, kXR_login,
                      os.getpid() & 0xFFFFFFFF, b"pytest\x00\x00", 0, 0, 5, 0, 0)
    s.sendall(req)
    sid, status, body = _resp(s)
    assert status == kXR_ok, "login rejected"
    return body[:16]                      # ServerResponseBody_Login.sessid[16]


def _open(s, path, options=kXR_open_read, streamid=b"\x00\x02"):
    p = path.encode() + b"\x00"
    req = struct.pack("!2sHHH2s6s4sI", streamid, kXR_open, 0o644, options,
                      b"\x00\x00", b"\x00" * 6, b"\x00" * 4, len(p))
    s.sendall(req + p)
    return _resp(s)


def _write(s, fh, off, payload, streamid=b"\x00\x09"):
    req = struct.pack("!2sH4sqiI", streamid, kXR_write, fh, off, 0, len(payload))
    s.sendall(req + payload)
    return _resp(s)


def _close(s, fh, streamid=b"\x00\x0e"):
    s.sendall(struct.pack("!2sH4s12sI", streamid, kXR_close, fh, b"\x00" * 12, 0))
    return _resp(s)


def _endsess(s, sessid16, streamid=b"\x00\x03"):
    s.sendall(struct.pack("!2sH16sI", streamid, kXR_endsess, sessid16, 0))
    return _resp(s)


def _err_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else None


@pytest.fixture(scope="module", autouse=True)
def _probe_file():
    """Create the probe file once via the wire (anon fleet allows writes)."""
    if REMOTE_SERVER:
        pytest.skip("needs the local anon fleet")
    try:
        s = _handshake()
    except OSError:
        pytest.skip(f"anon server {SERVER_HOST}:{NGINX_ANON_PORT} unreachable")
    _login(s)
    sid, status, body = _open(s, PROBE,
                              kXR_open_updt | kXR_open_new | kXR_delete | kXR_mkpath)
    if status != kXR_ok:
        s.close()
        pytest.skip("could not create probe file (writes disabled?)")
    fh = body[:4]
    _write(s, fh, 0, b"endsess-probe\n")
    _close(s, fh)
    s.close()


def test_endsess_other_session_keeps_connection_authenticated():
    """endsess naming a DIFFERENT session must NOT de-authenticate this
    connection — the official client's reconnect-recovery sequence."""
    s = _handshake()
    sessid = _login(s)
    assert _open(s, PROBE)[1] == kXR_ok, "baseline open should succeed"

    # endsess for a different (e.g. previous/dead) session id.
    other = bytes([sessid[0] ^ 0xFF]) + sessid[1:]
    _, status, _ = _endsess(s, other)
    assert status == kXR_ok, "endsess(other) should be acknowledged"

    # The connection must still be authenticated — this is the recovery open.
    sid, status, body = _open(s, PROBE, streamid=b"\x00\x04")
    s.close()
    assert status == kXR_ok, (
        "open after endsess(other-session) was rejected "
        f"(status={status}, err={_err_code(body)}) — endsess de-authed the wrong "
        "session; official-client recovery would fail here")


def test_endsess_own_session_tears_down_connection():
    """endsess naming THIS connection's own session still ends it — a later op
    must be rejected (auth-expiry / session-end semantics preserved)."""
    s = _handshake()
    sessid = _login(s)
    assert _open(s, PROBE)[1] == kXR_ok

    _, status, _ = _endsess(s, sessid)        # end our own session
    assert status == kXR_ok

    try:
        sid, status, body = _open(s, PROBE, streamid=b"\x00\x05")
    except (ConnectionError, OSError):
        s.close()
        return                                # connection dropped — also acceptable
    s.close()
    assert status == kXR_error and _err_code(body) == kXR_NotAuthorized, (
        "open after endsess(own-session) should be NotAuthorized "
        f"(status={status}, err={_err_code(body)})")
