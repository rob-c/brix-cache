# _test_conf_sessions_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_conf_sessions.py.  `from _test_conf_sessions_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.


"""Differential conformance for SESSION & CONCURRENCY behavior (root://).

Every case drives RAW WIRE against BOTH servers — our nginx-xrootd and the stock
XRootD data server (via official_interop_lib.start_pair) — and asserts they agree
on the observable contract:

  * handshake / login / protocol / ping / endsess REPLY framing & status,
  * streamid echo across many concurrent in-flight requests,
  * multiple open handles per session (distinct, independently usable),
  * many parallel connections (each login+stat+read byte-exact, no cross-talk),
  * kXR_bind parallel-stream behavior (pinned to stock — accept or reject),
  * request pipelining, framing-robustness (oversized/negative dlen, unknown
    opcode, partial send), idle-then-request, and disconnect-mid-request.

Philosophy (per the maintainer): a divergence — handshake/login/protocol/ping/
endsess reply differs, streamid mismatch, lost concurrency, bind behavior
differs, framing-robustness differs — is a BUG IN OUR SERVER. We pin the stock
server's behavior. No xfail/skip is used to hide a real diff.

Reference facts pinned (XProtocol.hh / XrdXrootdXeq.cc):
  * handshake init = IIIII {0,0,0,4,2012}; reply body = protover(0x520) +
    server type kXR_DataServer(1) (XrdXrootdProtocol.cc:297-330).
  * ClientLoginRequest: streamid[2] requestid[2] pid[4] username[8] ability2
    ability capver reserved2 dlen[4] (XProtocol.hh:422).
  * ServerResponseBody_Login: sessid[16] + sec[] (XProtocol.hh:1081) — anon
    login carries a 16-byte sessid.
  * kXR_protocol reply: pval[4] + flags[4] with kXR_isServer(0x1) set
    (XProtocol.hh:1233, Xeq do_Protocol:2050).
  * kXR_ping -> empty kXR_ok (Xeq do_Ping:1815).
  * kXR_endsess: a sessid that does not refer to this server (Pid != myPID) is
    IGNORED -> empty kXR_ok; it is session-scoped, NOT a connection kill
    (Xeq do_Endsess:925, Response.Send()).
  * ClientBindRequest: streamid[2] requestid[2] sessid[16] dlen[4]
    (XProtocol.hh:180); a bogus/zero sessid -> kXR_NotFound / kXR_ArgInvalid
    (do_Bind:274), reply body = substreamid[1] on success.
  * streamid is echoed verbatim, never byte-swapped (XrdXrootdResponse.cc).

Self-provisioning on high ports; skips entirely without the stock toolchain.

Run:
  TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
    python -m pytest tests/test_conf_sessions.py -q
"""

import os
import socket
import struct
import threading

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(360),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]

# Raw-socket modules connect to these ports DIRECTLY (not via ctx["our"/"off"]
# urls), so they must be the live fleet ports. worker_port() is a dead leftover
# from the retired self-provisioning era (it shifts into a per-worker band that
# no server listens on → ConnectionRefused); the fleet-attach model serves every
# worker from the one fixed pair, exactly like the ctx-based conf modules.
OUR_PORT = L.FLEET_OUR_PORT
OFF_PORT = L.FLEET_OFF_PORT
BIND = "127.0.0.1"

# opcodes
kXR_query, kXR_close, kXR_dirlist = 3001, 3003, 3004
kXR_protocol, kXR_login, kXR_open = 3006, 3007, 3010
kXR_ping, kXR_read, kXR_stat = 3011, 3013, 3017
kXR_endsess, kXR_bind = 3023, 3024

# response status
kXR_ok, kXR_oksofar = 0, 4000
kXR_error, kXR_redirect, kXR_wait, kXR_status = 4003, 4004, 4005, 4007

# error codes (XErrorCode)
kXR_ArgInvalid, kXR_FileLocked, kXR_InvalidRequest = 3000, 3003, 3006
kXR_NotFound, kXR_NotAuthorized, kXR_Unsupported = 3011, 3010, 3013

# flags / options
kXR_open_read = 0x0010
kXR_isServer = 0x00000001
kXR_DataServer = 1
PROTOVER = 0x00000520

DROPPED = -1   # sentinel: server dropped the link instead of replying

# A representative slice of the rich tree (start_pair seeds these byte-identically).
TREE_FILES = {
    "/hello.txt": 12,
    "/data.bin": 4096,
    "/sz_1.bin": 1,
    "/sz_255.bin": 255,
    "/sz_4095.bin": 4095,
    "/sz_4096.bin": 4096,
    "/sz_4097.bin": 4097,
    "/sz_8192.bin": 8192,
    "/sz_65536.bin": 65536,
    "/empty.txt": 0,
    "/cksum.bin": 10000,
    "/big1m.bin": 1024 * 1024,
    "/sub/nested.txt": 7,
    "/deep/a/b/c/leaf.txt": 5,
    "/many/f00.txt": 7,
    "/many/f05.txt": 7,
    "/many/f11.txt": 8,
}


# --------------------------------------------------------------------------- #
# raw-wire client
# --------------------------------------------------------------------------- #
def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        try:
            c = s.recv(n - len(b))
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            raise EOFError("connection reset")
        if not c:
            raise EOFError("connection closed")
        b += c
    return b


def _resp(s):
    h = _recv_exact(s, 8)
    sid = h[0:2]
    status = struct.unpack("!H", h[2:4])[0]
    dlen = struct.unpack("!I", h[4:8])[0]
    body = _recv_exact(s, dlen) if dlen else b""
    return sid, status, body


def _connect(port):
    s = socket.create_connection((BIND, port), timeout=10)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    return s   # caller reads the handshake reply


def _handshake(s):
    _, st, body = _resp(s)
    return st, body


def _login(s, username=b"sess", sid=b"\x00\x01"):
    uname = (username + b"\x00" * 8)[:8]
    s.sendall(struct.pack("!2sHI8sBBBBI", sid, kXR_login,
                          os.getpid() & 0x7fffffff, uname, 0, 0, 0, 0, 0))
    return _resp(s)


def _session(port, username=b"sess"):
    s = _connect(port)
    st, _ = _handshake(s)
    assert st == kXR_ok, "handshake failed"
    sid, st, body = _login(s, username)
    assert st == kXR_ok, "anon login failed"
    return s, body[0:16]   # (socket, 16-byte session id)


def _ping(s, sid=b"\x00\x0f"):
    s.sendall(struct.pack("!2sH16sI", sid, kXR_ping, b"\x00" * 16, 0))


def _stat(s, path, sid=b"\x00\x02"):
    p = path.encode()
    s.sendall(struct.pack("!2sH16sI", sid, kXR_stat, b"\x00" * 16, len(p)) + p)


def _open(s, path, options=kXR_open_read, sid=b"\x00\x03"):
    p = path.encode()
    s.sendall(struct.pack("!2sHHH12sI", sid, kXR_open, 0, options,
                          b"\x00" * 12, len(p)) + p)
    _, st, body = _resp(s)
    return st, body


def _read(s, fhandle, offset, rlen, sid=b"\x00\x06"):
    s.sendall(struct.pack("!2sH4sqiI", sid, kXR_read, fhandle, offset, rlen, 0))


def _read_all(s, fhandle, offset, rlen, sid=b"\x00\x06"):
    """kXR_read then drain kXR_oksofar chunks until kXR_ok. Returns (status, data)."""
    _read(s, fhandle, offset, rlen, sid)
    data = b""
    while True:
        _, st, body = _resp(s)
        if st not in (kXR_ok, kXR_oksofar):
            return st, data
        data += body
        if st == kXR_ok:
            return kXR_ok, data


def _close(s, fhandle, sid=b"\x00\x0e"):
    s.sendall(struct.pack("!2sH4s12sI", sid, kXR_close, fhandle, b"\x00" * 12, 0))
    try:
        _, st, _ = _resp(s)
        return st
    except EOFError:
        return None


def _endsess(s, sessid, sid=b"\x00\x20"):
    s.sendall(struct.pack("!2sH16sI", sid, kXR_endsess, sessid, 0))


def _bind(s, sessid, sid=b"\x00\x24"):
    s.sendall(struct.pack("!2sH16sI", sid, kXR_bind, sessid, 0))


def _errnum(body):
    return struct.unpack("!i", body[0:4])[0] if len(body) >= 4 else None


def _category(status, body):
    """Coarse success/failure category for differential comparison."""
    if status == kXR_ok:
        return "ok"
    if status == kXR_oksofar:
        return "oksofar"
    if status == kXR_wait:
        return "wait"
    if status == DROPPED:
        return "dropped"
    if status == kXR_error:
        return "err:%s" % _errnum(body)
    return "status:%s" % status


def _safe_resp(s):
    """_resp that maps a link drop to the DROPPED sentinel instead of raising."""
    try:
        return _resp(s)
    except (EOFError, OSError):
        return None, DROPPED, b""


def _expected(path):
    """The deterministic bytes start_pair wrote for `path` (seed == size)."""
    n = TREE_FILES[path]
    if path == "/hello.txt":
        return b"hello world\n"
    if path == "/sub/nested.txt":
        return b"nested\n"
    if path == "/deep/a/b/c/leaf.txt":
        return b"leaf\n"
    if path.startswith("/many/f"):
        i = int(path[len("/many/f"):-len(".txt")])
        return ("file %d\n" % i).encode()
    if path == "/data.bin":
        return L._det(4096)            # make_tree: seed 0
    if path == "/cksum.bin":
        return L._det(10000, seed=3)
    if path == "/big1m.bin":
        return L._det(1024 * 1024, seed=7)
    if path == "/empty.txt":
        return b""
    return L._det(n, seed=n)           # sz_N.bin: seed == n


# --------------------------------------------------------------------------- #
# server pair fixture
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("sessions"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


# =========================================================================== #
# H. MANY PARALLEL CONNECTIONS — login+stat+read, no cross-talk
# =========================================================================== #
def _worker_login_stat_read(port, path, results, idx):
    """One independent connection: login, stat, open, read byte-exact."""
    try:
        s, _ = _session(port)
    except Exception as e:                       # noqa: BLE001
        results[idx] = ("connect-fail", str(e))
        return
    try:
        _stat(s, path, sid=b"\x00\x02")
        _, st, _ = _resp(s)
        if st != kXR_ok:
            results[idx] = ("stat-fail", st)
            return
        st, body = _open(s, path)
        if st != kXR_ok:
            results[idx] = ("open-fail", st)
            return
        want = _expected(path)
        n = min(len(want), 4096)
        if n == 0:
            results[idx] = ("ok", b"")
            return
        rst, data = _read_all(s, body[0:4], 0, n, sid=b"\x00\x06")
        if rst != kXR_ok or data != want[:n]:
            results[idx] = ("read-mismatch", len(data))
            return
        results[idx] = ("ok", path)
    except Exception as e:                        # noqa: BLE001
        results[idx] = ("exc", str(e))
    finally:
        s.close()

__all__ = [n for n in dir() if not n.startswith('__')]
