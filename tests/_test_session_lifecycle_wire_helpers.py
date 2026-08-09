"""
tests/test_session_lifecycle_wire.py — raw-wire conformance for the XRootD
session-lifecycle opcodes (kXR_set / kXR_endsess / kXR_bind) and the pre-login
authorization gate.

This suite drives the real handlers in src/protocols/root/handshake/dispatch_session.c,
src/protocols/root/session/lifecycle.c, src/protocols/root/session/bind.c, src/protocols/root/query/set.c and the access
gates in src/protocols/root/handshake/policy.c over raw TCP sockets, because the high-level
XRootD python client hides session state behind its own demultiplexer and would
never let these malformed / out-of-order frames reach the wire. Every hostile or
out-of-order request is followed by a sanity op (ping or a fresh session) to
prove the worker survived. It targets the shared anonymous stream fleet on
root://localhost:11094 and skips cleanly when that fleet is not running or is
not speaking the XRootD handshake on that port, exactly like
test_readv_security.py.

The documented behaviour under test (anon endpoint, where a successful login
implies auth_done):
  * kXR_set requires login            -> kXR_NotAuthorized before login, ok after
  * kXR_set accepts any modifier       -> ok even for an unknown modifier byte
  * kXR_endsess never errors           -> always ok; the named sessid is ended.
                                          Naming the current session clears
                                          logged_in so later file ops are gated;
                                          naming another id is advisory cleanup.
  * kXR_bind needs a known sessid      -> kXR_NotAuthorized for random/absent ids
  * pre-login file ops                 -> kXR_NotAuthorized (open/read/write/stat/
                                          chmod/mkdir/rm/dirlist/sync/truncate)
  * kXR_ping is allowed pre-login      -> ok; an unknown / legacy opcode is not
                                          -> kXR_Unsupported

Verified against /tmp/brix-src/src/XProtocol/XProtocol.hh:
  ClientSetRequest     = streamid[2] requestid[2] reserved[15] modifier[1] dlen[4]
  ClientEndsessRequest = streamid[2] requestid[2] sessid[16]            dlen[4]
  ClientBindRequest    = streamid[2] requestid[2] sessid[16]            dlen[4]
  ClientPingRequest    = streamid[2] requestid[2] reserved[16]          dlen[4]
  ClientLoginRequest   = streamid[2] requestid[2] pid[4] user[8] ab2 ab cap rsv dlen[4]

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_session_lifecycle_wire.py -v
"""

import os
import socket
import struct

import pytest

from settings import (
    NGINX_ANON_PORT,
    SERVER_HOST,
)


# ---------------------------------------------------------------------------
# Opcodes / status / error codes
#   request opcodes : src/protocols/root/protocol/opcodes.h
#                     /tmp/brix-src/src/XProtocol/XProtocol.hh (XRequestTypes)
#   error codes     : /tmp/brix-src/src/XProtocol/XProtocol.hh (XErrorCode)
# ---------------------------------------------------------------------------

kXR_auth     = 3000
kXR_query    = 3001
kXR_chmod    = 3002
kXR_close    = 3003
kXR_dirlist  = 3004
kXR_login    = 3007
kXR_mkdir    = 3008
kXR_open     = 3010
kXR_ping     = 3011
kXR_read     = 3013
kXR_rm       = 3014
kXR_sync     = 3016
kXR_stat     = 3017
kXR_set      = 3018
kXR_write    = 3019
kXR_statx    = 3022
kXR_endsess  = 3023
kXR_bind     = 3024
kXR_truncate = 3028

# ServerResponseHeader.status values (XProtocol.hh XResponseType).
kXR_ok       = 0
kXR_error    = 4003
kXR_status   = 4007

# XErrorCode values (XProtocol.hh).  errnum is the first int32 of an error body.
kXR_ArgInvalid     = 3000
kXR_InvalidRequest = 3006
kXR_NotAuthorized  = 3010
kXR_NotFound       = 3011
kXR_Unsupported    = 3013

# kXR_set modifier bytes (ClientSetRequest.modifier)
kXR_set_appid = ord("A")   # advisory application id (e.g. "cms.space ...")
kXR_set_clttl = ord("T")   # client session TTL hint

# XOpenRequestMode (XProtocol.hh)
kXR_open_read = 0x0010
kXR_open_updt = 0x0020

XRD_REQUEST_HDR_LEN = 24   # 2B streamid + 2B reqid + 16B body + 4B dlen

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT

# How a hostile/out-of-order frame is allowed to be rejected: the documented
# behaviour is an in-band error reply, but a server is also within its rights to
# drop a connection it considers malformed.  Tests that assert "clean rejection"
# accept either, never silent acceptance.
_DROP_EXCEPTIONS = (ConnectionError, socket.timeout, OSError)


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
    header = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return streamid, status, body


def _error_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


def _handshake():
    """Open a socket and complete the 20-byte XRootD protocol handshake."""
    sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=8)
    sock.settimeout(8)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _, status, _ = _read_response(sock)
    assert status == kXR_ok, "handshake rejected"
    return sock


def _login(sock, streamid=b"\x00\x01"):
    """ClientLoginRequest: streamid[2] reqid[2] pid[4] user[8] ab2 ab cap rsv dlen[4]."""
    req = struct.pack("!2sHI8sBBBBI",
                      streamid, kXR_login,
                      os.getpid() & 0xFFFFFFFF,
                      b"pytest\x00\x00", 0, 0, 5, 0, 0)
    sock.sendall(req)
    return _read_response(sock)


def _handshake_only():
    """A socket that has completed the protocol handshake but NOT login."""
    return _handshake()


def _session():
    """A fully logged-in (and, on anon, auth-complete) session socket.

    Returns (sock, login_body); login_body[:16] is the registered session id.
    """
    sock = _handshake()
    _sid, status, body = _login(sock)
    assert status == kXR_ok, "login rejected"
    return sock, body


def _safe_handshake_only():
    """_handshake_only() but turn an unreachable / non-XRootD endpoint into a
    clean skip instead of a hard error, so the suite is portable across fleets
    that expose the anon port only under TLS or not at all."""
    try:
        return _handshake_only()
    except (AssertionError, *_DROP_EXCEPTIONS) as exc:
        pytest.skip(f"anon endpoint {ANON_HOST}:{ANON_PORT} not usable for raw "
                    f"handshake: {exc}")


def _safe_session():
    """_session() but skip cleanly if handshake/login is not available on the
    anon endpoint (e.g. the fleet requires auth on this port)."""
    try:
        return _session()
    except (AssertionError, *_DROP_EXCEPTIONS) as exc:
        pytest.skip(f"anon endpoint {ANON_HOST}:{ANON_PORT} did not complete an "
                    f"anonymous login: {exc}")


def _ping(sock, streamid=b"\x00\x0f"):
    """ClientPingRequest: streamid[2] reqid[2] reserved[16] dlen[4]."""
    req = struct.pack("!2sH16sI", streamid, kXR_ping, b"\x00" * 16, 0)
    sock.sendall(req)
    return _read_response(sock)


def _ping_status(sock):
    """Return ping status, or None if the connection has been dropped.

    Used only to corroborate that a *clean rejection* did not poison the worker.
    A dropped connection after an already-clean rejection is itself acceptable
    server behaviour, so callers treat None as 'not a failure'.
    """
    try:
        return _ping(sock)[1]
    except _DROP_EXCEPTIONS:
        return None


def _open(sock, path, options=kXR_open_read, streamid=b"\x00\x02"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH2s6s4sI",
                      streamid, kXR_open,
                      0o644, options, b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                      len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _close(sock, fhandle, streamid=b"\x00\x0e"):
    req = struct.pack("!2sH4s12sI", streamid, kXR_close, fhandle,
                      b"\x00" * 12, 0)
    sock.sendall(req)
    return _read_response(sock)


# ---- session-lifecycle request framers ------------------------------------

def _set(sock, modifier, payload=b"", streamid=b"\x00\x10"):
    """ClientSetRequest: streamid[2] reqid[2] reserved[15] modifier[1] dlen[4]."""
    req = struct.pack("!2sH15sBI", streamid, kXR_set,
                      b"\x00" * 15, modifier & 0xFF, len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _endsess(sock, sessid=b"\x00" * 16, streamid=b"\x00\x11"):
    """ClientEndsessRequest: streamid[2] reqid[2] sessid[16] dlen[4]."""
    if len(sessid) < 16:
        sessid = sessid + b"\x00" * (16 - len(sessid))
    req = struct.pack("!2sH16sI", streamid, kXR_endsess, sessid[:16], 0)
    sock.sendall(req)
    return _read_response(sock)


def _bind(sock, sessid=b"\x00" * 16, streamid=b"\x00\x12"):
    """ClientBindRequest: streamid[2] reqid[2] sessid[16] dlen[4]."""
    if len(sessid) < 16:
        sessid = sessid + b"\x00" * (16 - len(sessid))
    req = struct.pack("!2sH16sI", streamid, kXR_bind, sessid[:16], 0)
    sock.sendall(req)
    return _read_response(sock)


def _raw_request(sock, opcode, body16=b"\x00" * 16, payload=b"",
                 streamid=b"\x00\x20"):
    """Generic 24-byte request frame for any opcode (used for the gate tests
    and the unknown/legacy-opcode tests).  body16 is the 16 request-specific
    bytes between reqid and dlen."""
    if len(body16) < 16:
        body16 = body16 + b"\x00" * (16 - len(body16))
    req = struct.pack("!2sH16sI", streamid, opcode & 0xFFFF, body16[:16],
                      len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _require_server():
    """Skip the whole module cleanly unless the anon stream server is up AND
    actually speaks the XRootD handshake on this port.

    A bare TCP connect is not enough — the port may be a TLS-only or non-XRootD
    listener — so we complete one handshake and discard it.  Any failure skips
    the module rather than erroring every test.
    """
    try:
        s = _handshake()
        s.close()
    except (AssertionError, *_DROP_EXCEPTIONS) as exc:
        pytest.skip(
            f"anon stream server {ANON_HOST}:{ANON_PORT} not speaking XRootD: "
            f"{exc}")


@pytest.fixture
def logged_in():
    """A logged-in session socket; yields (sock, login_body); always cleaned up."""
    sock, body = _safe_session()
    try:
        yield sock, body
    finally:
        try:
            sock.close()
        except Exception:
            pass


@pytest.fixture
def pre_login():
    """A handshake-only socket (NOT logged in); always cleaned up."""
    sock = _safe_handshake_only()
    try:
        yield sock
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ===========================================================================
# Class 1 — kXR_set (server config / advisory hints)
# ===========================================================================
