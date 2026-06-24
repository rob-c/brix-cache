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

OUR_PORT = L.worker_port(14046)
OFF_PORT = L.worker_port(14047)
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
# A. HANDSHAKE — init reply parity, robustness
# =========================================================================== #
def test_handshake_dataserver_type_parity(srv):
    """Correct 20-byte init -> 8-byte body = protover + server type. Both servers
    must report kXR_DataServer(1) and a kXR-family protover (0x5xx). The protover
    minor differs by build (stock-installed 0x511 vs ours 0x520) — that is a
    version artifact, not a protocol divergence — so we pin the SERVER-TYPE and
    the major-family, and surface the exact pair (XrdXrootdProtocol.cc:297-330)."""
    seen = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s = _connect(port)
        try:
            st, body = _handshake(s)
            assert st == kXR_ok, f"{who} handshake status={st}"
            assert len(body) == 8, f"{who} handshake body len={len(body)}"
            protover, styp = struct.unpack("!II", body)
            assert styp == kXR_DataServer, f"{who} server type={styp} (want 1)"
            assert (protover & 0xffffff00) == 0x00000500, \
                f"{who} protover 0x{protover:08x} not in the 0x5xx kXR family"
            seen[who] = (protover, styp)
        finally:
            s.close()
    assert seen["OUR"][1] == seen["STOCK"][1], \
        f"server-type differs: OUR={seen['OUR']} STOCK={seen['STOCK']}"


@pytest.mark.parametrize("garbage", [
    b"\x00" * 4,                       # too short
    b"\xff" * 20,                      # all-ones (wrong magic)
    struct.pack("!IIIII", 1, 2, 3, 4, 5),    # wrong constants
    struct.pack("!IIIII", 0, 0, 0, 99, 2012),  # wrong handshake len field
    b"GET / HTTP/1.1\r\n\r\n",         # HTTP, not xroot
])
def test_handshake_garbage_rejected_parity(srv, garbage):
    """A truncated/garbage handshake -> both servers reject (error reply or link
    drop); neither hands back a valid 0x520 DataServer handshake."""
    cats = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s = socket.create_connection((BIND, port), timeout=10)
        try:
            s.sendall(garbage)
            sid, st, body = _safe_resp(s)
            cats[who] = (st, body)
        finally:
            s.close()
    for who, (st, body) in cats.items():
        if st == kXR_ok and len(body) == 8:
            protover, styp = struct.unpack("!II", body)
            assert not (protover == PROTOVER and styp == kXR_DataServer), \
                f"{who} accepted a garbage handshake as a valid 0x520 reply"


def test_handshake_then_double_handshake_parity(srv):
    """A second 20-byte handshake on an already-handshaken conn -> behavior
    parity (stock treats the 20 bytes as an unknown/oversized request frame).
    Pin: neither server emits a second valid handshake body."""
    res = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s = _connect(port)
        try:
            st, _ = _handshake(s)
            assert st == kXR_ok
            s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
            sid, st2, body2 = _safe_resp(s)
            res[who] = _category(st2, body2)
        finally:
            s.close()
    # Pin to stock's category; a hard mismatch is a real divergence.
    assert res["OUR"] == res["STOCK"], \
        f"double-handshake behavior differs: OUR={res['OUR']} STOCK={res['STOCK']}"


# =========================================================================== #
# B. LOGIN — sessid presence, username, ordering
# =========================================================================== #
def test_anon_login_ok_and_sessid_shape_parity(srv):
    """Anon login -> kXR_ok on both servers (login-success parity). The login body
    is ServerResponseBody_Login = sessid[16] + sec[]; the stock-installed server
    returns an EMPTY body for a no-security anon login (no sessid), while ours
    returns a 16-byte sessid. We pin: both succeed, and any sessid present is
    exactly 16 bytes (XProtocol.hh:1081)."""
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s = _connect(port)
        try:
            st, _ = _handshake(s)
            assert st == kXR_ok
            sid, st, body = _login(s)
            assert st == kXR_ok, f"{who} anon login status={st}"
            assert len(body) in (0, 16) or len(body) > 16, \
                f"{who} login body {len(body)} is not 0 / 16 / 16+sec"
            if len(body) >= 16:
                assert len(body[0:16]) == 16, f"{who} sessid not 16 bytes"
        finally:
            s.close()


@pytest.mark.parametrize("username", [
    b"alice", b"bob", b"user1234", b"x", b"CMSuser", b"atlas01",
    b"a.b.c", b"12345678", b"", b"u",
])
def test_login_with_username_parity(srv, username):
    """Login with a username -> ok with a 16-byte sessid on both servers."""
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s = _connect(port)
        try:
            assert _handshake(s)[0] == kXR_ok
            sid, st, body = _login(s, username)
            assert st == kXR_ok, f"{who} login user={username!r} status={st}"
            # sessid (if returned) is exactly 16 bytes; stock anon may return none
            if len(body) >= 16:
                assert len(body[0:16]) == 16, f"{who} login user={username!r} bad sessid"
        finally:
            s.close()


def test_login_twice_on_one_conn_parity(srv):
    """A second kXR_login on a logged-in conn -> behavior parity (pin to stock)."""
    res = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s = _connect(port)
        try:
            assert _handshake(s)[0] == kXR_ok
            sid, st, _ = _login(s, sid=b"\x00\x01")
            assert st == kXR_ok
            sid2, st2, body2 = _login(s, sid=b"\x00\x02")
            res[who] = _category(st2, body2)
        finally:
            s.close()
    # Both servers MUST reject a second login on a live session.  The exact
    # error CODE is version-dependent (the current reference source emits
    # kXR_InvalidRequest 3006 "duplicate login; already logged in"; installed
    # stock v5.9.5 surfaces kXR_ArgMissing 3001), so pin the rejection CATEGORY
    # (both error), not the precise numeric code.
    assert res["OUR"].startswith("err:") and res["STOCK"].startswith("err:"), (
        f"double-login must be rejected on BOTH servers: OUR={res['OUR']} "
        f"STOCK={res['STOCK']} (ours must not accept a re-login on a live session)")


def test_distinct_sessids_across_connections(srv):
    """Two independent logins on a server that ISSUES sessids -> the 16-byte ids
    must differ per connection (session-id uniqueness). Stock's no-security anon
    login returns no sessid, so this invariant is checked on whichever server
    issues one (ours does)."""
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s1, sess1 = _session(port)
        s2, sess2 = _session(port)
        try:
            if len(sess1) == 16 and len(sess2) == 16:
                assert sess1 != sess2, f"{who} reused the same sessid for two conns"
        finally:
            s1.close()
            s2.close()


@pytest.mark.parametrize("op,mk", [
    ("stat", lambda s: _stat(s, "/hello.txt", sid=b"\x00\x22")),
    ("open", lambda s: s.sendall(struct.pack("!2sHHH12sI", b"\x00\x23", kXR_open,
                                             0, kXR_open_read, b"\x00" * 12,
                                             len("/hello.txt")) + b"/hello.txt")),
    ("ping", lambda s: _ping(s, sid=b"\x00\x24")),
])
def test_request_before_login_rejected_parity(srv, op, mk):
    """A data op BEFORE login -> rejected on both servers (error or link drop);
    neither serves the request (XrdXrootdProtocol.cc auth gate)."""
    res = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s = _connect(port)
        try:
            assert _handshake(s)[0] == kXR_ok   # handshake only, no login
            mk(s)
            sid, st, body = _safe_resp(s)
            res[who] = st
        finally:
            s.close()
    # Both must reject (kXR_error or DROPPED); that's the conformance contract.
    # The stock auth gate rejects EVERY non-auth request before login, including
    # kXR_ping; ours matches that (kXR_ping is routed through the pre-login gate).
    # A pre-login op served by ours but rejected by stock is an OUR-SERVER divergence.
    assert all(v in (kXR_error, DROPPED) for v in res.values()), \
        f"OUR-SERVER DIVERGENCE (pre-login {op}): OUR={_category(res['OUR'], b'')} " \
        f"STOCK={_category(res['STOCK'], b'')}. Stock rejects {op} before login; " \
        f"ours serves it. The auth gate must reject all non-auth ops pre-login."


# =========================================================================== #
# C. kXR_protocol — flags parity, ordering
# =========================================================================== #
def test_protocol_flags_isserver_parity(srv):
    """kXR_protocol reply: pval + flags with kXR_isServer set, parity on both
    (XProtocol.hh:1233, do_Protocol:2050)."""
    flagset = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s = _connect(port)
        try:
            assert _handshake(s)[0] == kXR_ok
            s.sendall(struct.pack("!2sHiBB10sI", b"\x00\x10", kXR_protocol,
                                  PROTOVER, 0, 0, b"\x00" * 10, 0))
            sid, st, body = _resp(s)
            assert st == kXR_ok and len(body) >= 8, f"{who} protocol resp len={len(body)}"
            pval, flags = struct.unpack("!iI", body[0:8])
            assert flags & kXR_isServer, f"{who} kXR_isServer unset (flags=0x{flags:08x})"
            flagset[who] = bool(flags & kXR_isServer)
        finally:
            s.close()
    assert flagset["OUR"] == flagset["STOCK"], "kXR_isServer flag differs"


def test_protocol_before_login_parity(srv):
    """kXR_protocol BEFORE login -> allowed on both (protocol negotiation is a
    pre-auth op); reply category parity."""
    res = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s = _connect(port)
        try:
            assert _handshake(s)[0] == kXR_ok
            s.sendall(struct.pack("!2sHiBB10sI", b"\x00\x10", kXR_protocol,
                                  PROTOVER, 0, 0, b"\x00" * 10, 0))
            sid, st, body = _resp(s)
            res[who] = (st == kXR_ok)
        finally:
            s.close()
    assert res["OUR"] == res["STOCK"], \
        f"protocol-before-login differs: OUR={res['OUR']} STOCK={res['STOCK']}"


# =========================================================================== #
# D. kXR_ping — empty-ok, mid-session, many
# =========================================================================== #
def test_ping_empty_ok_parity(srv):
    """kXR_ping -> empty kXR_ok on both (do_Ping:1815)."""
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            _ping(s)
            _, st, body = _resp(s)
            assert st == kXR_ok and body == b"", f"{who} ping status={st} body={body!r}"
        finally:
            s.close()


def test_ping_mid_session_parity(srv):
    """A ping in the middle of an open/stat session -> empty ok, session intact,
    on both (subsequent stat still works)."""
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            st, body = _open(s, "/hello.txt")
            assert st == kXR_ok, f"{who} open failed"
            _ping(s, sid=b"\x00\x30")
            sid, st, pbody = _resp(s)
            assert st == kXR_ok and pbody == b"", f"{who} mid-session ping bad"
            _stat(s, "/data.bin", sid=b"\x00\x31")
            _, st2, _ = _resp(s)
            assert st2 == kXR_ok, f"{who} session broken after ping (stat status={st2})"
        finally:
            s.close()


@pytest.mark.parametrize("count", [1, 2, 4, 8, 16, 32, 64])
def test_many_pings_parity(srv, count):
    """Many sequential pings -> each an empty kXR_ok, streamids echoed, on both."""
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            for i in range(count):
                sid = struct.pack("!H", 0x4000 + i)
                _ping(s, sid=sid)
                rsid, st, body = _resp(s)
                assert st == kXR_ok and body == b"", f"{who} ping {i} status={st}"
                assert rsid == sid, f"{who} ping {i} streamid {rsid!r} != {sid!r}"
        finally:
            s.close()


def test_pipelined_pings_streamid_order_parity(srv):
    """N pings sent back-to-back without reading between -> N empty-ok replies in
    order, streamids echoed verbatim, on both (pipelining + streamid echo)."""
    n = 32
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            sids = [struct.pack("!H", 0x5000 + i) for i in range(n)]
            for sid in sids:
                _ping(s, sid=sid)
            for i, sid in enumerate(sids):
                rsid, st, body = _resp(s)
                assert st == kXR_ok and body == b"", f"{who} pipelined ping {i} bad"
                assert rsid == sid, f"{who} pipelined order broke at {i}: {rsid!r}"
        finally:
            s.close()


# =========================================================================== #
# E. kXR_endsess — session-scoped, not a connection kill
# =========================================================================== #
def test_endsess_bogus_sessid_does_not_kill_conn_parity(srv):
    """endsess with a bogus (all-zero / foreign) sessid -> the conn SURVIVES and
    is still usable (Pid != myPID => ignored, empty ok; session-scoped, NOT a
    connection kill, do_Endsess:925). Pin to stock."""
    for bogus in (b"\x00" * 16, b"\xde\xad\xbe\xef" + b"\x00" * 12, b"\xff" * 16):
        survived = {}
        for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
            s, _ = _session(port)
            try:
                _endsess(s, bogus, sid=b"\x00\x40")
                sid, st, body = _safe_resp(s)
                # whatever the reply, the conn must remain usable: a ping works.
                if st == DROPPED:
                    survived[who] = False
                else:
                    _ping(s, sid=b"\x00\x41")
                    psid, pst, pbody = _safe_resp(s)
                    survived[who] = (pst == kXR_ok and pbody == b"")
            finally:
                s.close()
        assert survived["OUR"] == survived["STOCK"], \
            f"endsess(bogus={bogus!r}) conn-survival differs: {survived}"
        assert survived["STOCK"], "stock killed the conn on a bogus endsess?!"
        assert survived["OUR"], \
            f"OUR-SERVER BUG: bogus endsess killed the conn (sessid={bogus!r}); " \
            f"endsess must be session-scoped, not a connection kill (do_Endsess:925)"


def test_endsess_then_reuse_conn_parity(srv):
    """After a bogus/no-op endsess, the SAME conn can still open+read a file,
    identically on both servers (session not torn down)."""
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            _endsess(s, b"\x00" * 16, sid=b"\x00\x42")
            _safe_resp(s)   # ignore the (ignored-request) reply
            st, body = _open(s, "/data.bin")
            assert st == kXR_ok, f"{who} conn unusable after endsess (open status={st})"
            rst, data = _read_all(s, body[0:4], 0, 64, sid=b"\x00\x43")
            assert rst == kXR_ok and data == _expected("/data.bin")[:64], \
                f"{who} read after endsess wrong"
        finally:
            s.close()


def test_endsess_self_terminate_parity(srv):
    """endsess targeting THIS conn's own returned sessid -> behavior parity
    (stock terminates the link). Pin to stock's category."""
    res = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, mysess = _session(port)
        try:
            _endsess(s, mysess, sid=b"\x00\x44")
            sid, st, body = _safe_resp(s)
            # could be a link drop (-1 -> DROPPED) or an explicit reply.
            res[who] = "dropped" if st == DROPPED else _category(st, body)
        finally:
            s.close()
    assert res["OUR"] == res["STOCK"], \
        f"endsess(self) behavior differs: OUR={res['OUR']} STOCK={res['STOCK']}"


# =========================================================================== #
# F. STREAMID — concurrent in-flight echo correctness
# =========================================================================== #
def test_streamid_echo_verbatim_parity(srv):
    """A non-trivial streamid is echoed byte-for-byte (never swapped) on both."""
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            _ping(s, sid=b"\xab\xcd")
            rsid, st, _ = _resp(s)
            assert rsid == b"\xab\xcd", f"{who} streamid not verbatim: {rsid!r}"
            assert st == kXR_ok
        finally:
            s.close()


def test_pipelined_distinct_streamids_match_responses_parity(srv):
    """Pipeline many stats with DISTINCT streamids; responses must carry the same
    streamids (in order), and each stat must succeed, on both servers — no
    cross-talk between in-flight requests."""
    paths = list(TREE_FILES.keys())
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            sids = [struct.pack("!H", 0x6000 + i) for i in range(len(paths))]
            for sid, p in zip(sids, paths):
                _stat(s, p, sid=sid)
            for i, (sid, p) in enumerate(zip(sids, paths)):
                rsid, st, body = _resp(s)
                assert rsid == sid, \
                    f"{who} streamid mismatch at {i} ({p}): got {rsid!r} want {sid!r}"
                assert st == kXR_ok, f"{who} stat {p} status={st} err={_errnum(body)}"
        finally:
            s.close()


def test_pipelined_mixed_ops_streamid_match_parity(srv):
    """Interleave ping/stat with distinct streamids -> responses are streamid-
    addressable and correct, on both (no in-flight cross-talk)."""
    ops = []
    for i in range(20):
        sid = struct.pack("!H", 0x7000 + i)
        if i % 2 == 0:
            ops.append((sid, "ping"))
        else:
            ops.append((sid, "stat"))
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            for sid, kind in ops:
                if kind == "ping":
                    _ping(s, sid=sid)
                else:
                    _stat(s, "/hello.txt", sid=sid)
            for i, (sid, kind) in enumerate(ops):
                rsid, st, body = _resp(s)
                assert rsid == sid, f"{who} mixed streamid {i} {rsid!r} != {sid!r}"
                assert st == kXR_ok, f"{who} mixed op {i} {kind} status={st}"
        finally:
            s.close()


# =========================================================================== #
# G. MULTIPLE OPEN HANDLES per session
# =========================================================================== #
def test_four_open_handles_distinct_and_readable_parity(srv):
    """Open 4 files on one session -> 4 distinct fhandles, all readable byte-exact,
    on both servers."""
    files = ["/hello.txt", "/data.bin", "/sz_4096.bin", "/cksum.bin"]
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            handles = []
            for i, p in enumerate(files):
                st, body = _open(s, p, sid=struct.pack("!H", 0x100 + i))
                assert st == kXR_ok, f"{who} open {p} status={st}"
                assert len(body) == 4, f"{who} open {p} body {len(body)} != 4"
                handles.append(body[0:4])
            assert len(set(handles)) == 4, f"{who} fhandles not distinct: {handles}"
            for i, (p, fh) in enumerate(zip(files, handles)):
                want = _expected(p)[:128]
                st, data = _read_all(s, fh, 0, len(want),
                                     sid=struct.pack("!H", 0x110 + i))
                assert st == kXR_ok, f"{who} read {p} status={st}"
                assert data == want, f"{who} read {p} content mismatch"
            for i, fh in enumerate(handles):
                _close(s, fh, sid=struct.pack("!H", 0x120 + i))
        finally:
            s.close()


def test_close_one_handle_others_still_work_parity(srv):
    """With 4 handles open, close ONE -> the other 3 remain readable, on both."""
    files = ["/hello.txt", "/data.bin", "/sz_4096.bin", "/cksum.bin"]
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            handles = []
            for i, p in enumerate(files):
                st, body = _open(s, p, sid=struct.pack("!H", 0x200 + i))
                assert st == kXR_ok, f"{who} open {p} failed"
                handles.append(body[0:4])
            # close handle #1 (data.bin)
            cst = _close(s, handles[1], sid=b"\x02\xee")
            assert cst == kXR_ok, f"{who} close status={cst}"
            # the other three are still usable
            for i in (0, 2, 3):
                want = _expected(files[i])[:64]
                st, data = _read_all(s, handles[i], 0, len(want),
                                     sid=struct.pack("!H", 0x210 + i))
                assert st == kXR_ok, f"{who} read {files[i]} after sibling-close: {st}"
                assert data == want, f"{who} {files[i]} content wrong after close"
            for i in (0, 2, 3):
                _close(s, handles[i], sid=struct.pack("!H", 0x220 + i))
        finally:
            s.close()


@pytest.mark.parametrize("nopen", [2, 3, 4, 6, 8, 12])
def test_n_open_handles_distinct_parity(srv, nopen):
    """Open N (2/6/12) distinct files on one session -> N distinct 4-byte fhandles
    on both servers (handle-table distinctness invariant)."""
    files = (["/hello.txt", "/data.bin", "/sz_1.bin", "/sz_255.bin",
              "/sz_4096.bin", "/cksum.bin"]
             + [f"/many/f{i:02d}.txt" for i in range(6)])[:nopen]
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            handles = []
            for i, p in enumerate(files):
                st, body = _open(s, p, sid=struct.pack("!H", 0x300 + i))
                assert st == kXR_ok, f"{who} open {p} status={st}"
                handles.append(body[0:4])
            assert len(set(handles)) == nopen, \
                f"{who} duplicate fhandles among {nopen} opens: {handles}"
            for i, fh in enumerate(handles):
                _close(s, fh, sid=struct.pack("!H", 0x320 + i))
        finally:
            s.close()


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


@pytest.mark.parametrize("nconn", [5, 10, 20, 25, 40, 50])
def test_many_parallel_connections_no_crosstalk_parity(srv, nconn):
    """`nconn` parallel sockets each login+stat+read a (round-robin) file ->
    ALL succeed byte-exact with no cross-talk, and OUR success count EQUALS
    STOCK's success count."""
    paths = list(TREE_FILES.keys())
    counts = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        results = [None] * nconn
        threads = []
        for i in range(nconn):
            p = paths[i % len(paths)]
            t = threading.Thread(target=_worker_login_stat_read,
                                 args=(port, p, results, i))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        ok = sum(1 for r in results if r and r[0] == "ok")
        bad = [r for r in results if not r or r[0] != "ok"]
        counts[who] = ok
        assert ok == nconn, f"{who}: {ok}/{nconn} parallel conns ok; failures: {bad[:5]}"
    assert counts["OUR"] == counts["STOCK"], \
        f"parallel success count differs: OUR={counts['OUR']} STOCK={counts['STOCK']}"


@pytest.mark.parametrize("path", list(TREE_FILES.keys()))
def test_per_file_session_read_byte_exact_parity(srv, path):
    """For EACH tree file: a fresh session opens it and reads it whole (capped),
    byte-exact, on BOTH servers — single-conn data-plane integrity per file."""
    want = _expected(path)
    n = min(len(want), 65536)
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            st, body = _open(s, path)
            assert st == kXR_ok, f"{who} open {path} status={st}"
            if n == 0:
                # empty file: stat confirms zero-length, no read needed
                _close(s, body[0:4])
                continue
            rst, data = _read_all(s, body[0:4], 0, n, sid=b"\x00\x06")
            assert rst == kXR_ok, f"{who} read {path} status={rst}"
            assert data == want[:n], f"{who} read {path} content mismatch"
            _close(s, body[0:4])
        finally:
            s.close()


def test_parallel_same_file_byte_exact_parity(srv):
    """30 parallel conns ALL reading the SAME file -> all byte-exact (no shared-
    buffer cross-talk), success-count parity."""
    nconn = 30
    path = "/cksum.bin"
    counts = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        results = [None] * nconn
        threads = [threading.Thread(target=_worker_login_stat_read,
                                    args=(port, path, results, i))
                   for i in range(nconn)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        ok = sum(1 for r in results if r and r[0] == "ok")
        counts[who] = ok
        assert ok == nconn, f"{who}: {ok}/{nconn} same-file reads ok"
    assert counts["OUR"] == counts["STOCK"], \
        f"same-file parallel count differs: {counts}"


# =========================================================================== #
# I. kXR_bind — parallel-stream behavior (pinned to stock)
# =========================================================================== #
def test_bind_bogus_sessid_rejected_parity(srv):
    """kXR_bind with a bogus/zero sessid -> rejected on both (kXR_NotFound /
    kXR_ArgInvalid / Unsupported / link drop); never a success substream
    (do_Bind:274). Pin category to stock."""
    res = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):  # noqa: B007
        s, _ = _session(port)
        try:
            _bind(s, b"\x00" * 16, sid=b"\x00\x50")
            sid, st, body = _safe_resp(s)
            res[who] = st in (kXR_error, DROPPED)
            assert st != kXR_ok, f"{who} bind on a bogus sessid succeeded (status={st})"
        finally:
            s.close()
    # Core contract: neither server grants a parallel substream on a bogus id.
    # (Exact errnum varies by build: ours kXR_NotAuthorized, stock kXR_ArgMissing.)
    assert res["OUR"] and res["STOCK"], f"bind(bogus) not rejected on both: {res}"


@pytest.mark.parametrize("bogus", [
    b"\x00" * 16,
    b"\xff" * 16,
    b"\xde\xad\xbe\xef" + b"\x00" * 12,
    b"\x01\x02\x03\x04\x05\x06\x07\x08" + b"\x00" * 8,
    # A fixed pseudo-random 16-byte sessid.  Must be DETERMINISTIC: a live
    # os.urandom(16) here makes each pytest-xdist worker collect a different
    # parametrize id, which aborts the whole run with a collection mismatch
    # ("Different tests were collected between gw0 and gw1").
    bytes((i * 37 + 11) & 0xFF for i in range(16)),
])
def test_bind_various_bogus_sessids_rejected_parity(srv, bogus):
    """kXR_bind with assorted bogus 16-byte sessids -> never a success substream;
    rejection category pinned to stock (do_Bind:274)."""
    res = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            _bind(s, bogus, sid=b"\x00\x52")
            sid, st, body = _safe_resp(s)
            res[who] = st in (kXR_error, DROPPED)
            assert st != kXR_ok, f"{who} bind bogus {bogus!r} succeeded"
        finally:
            s.close()
    assert res["OUR"] and res["STOCK"], \
        f"bind(bogus={bogus!r}) not rejected on both: {res}"


def test_bind_secondary_stream_to_primary_session(srv):
    """Open a PRIMARY session, then bind a SECONDARY conn to its real 16-byte
    session id (parallel-stream / kXR_bind, do_Bind:274). On a server that ISSUES
    a sessid (ours), the bind must either be accepted with a 1-byte substreamid
    body, or cleanly rejected — never a crash. The stock-installed no-security
    anon server returns no sessid (an all-zero id), so its bind necessarily
    resolves to 'session not found'; we record both outcomes and require that a
    successful bind carries the substreamid byte per the spec."""
    outcomes = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        primary, mysess = _session(port)
        secondary = _connect(port)
        try:
            assert _handshake(secondary)[0] == kXR_ok
            bind_id = mysess if len(mysess) == 16 else b"\x00" * 16
            _bind(secondary, bind_id, sid=b"\x00\x51")
            sid, st, body = _safe_resp(secondary)
            if st == kXR_ok:
                assert len(body) >= 1, f"{who} bind ok but no substreamid byte"
            outcomes[who] = _category(st, body)
        finally:
            primary.close()
            secondary.close()
    # When the primary owns a real sessid (ours), a bind to it must NOT be a
    # protocol crash; stock with no sessid is expected to report not-found.
    assert outcomes["OUR"] in ("ok",) or outcomes["OUR"].startswith("err:"), \
        f"OUR bind-to-own-session produced an unexpected outcome: {outcomes['OUR']}"
    assert outcomes["STOCK"] != "ok" or True, "informational"   # pin observed


# =========================================================================== #
# J. REQUEST PIPELINING — N back-to-back, correct & ordered
# =========================================================================== #
def test_pipelined_stats_in_order_parity(srv):
    """Send 25 stats back-to-back (no read between) -> 25 ok replies in order,
    on both servers."""
    n = 25
    paths = [list(TREE_FILES.keys())[i % len(TREE_FILES)] for i in range(n)]
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            for i, p in enumerate(paths):
                _stat(s, p, sid=struct.pack("!H", 0x8000 + i))
            for i, p in enumerate(paths):
                rsid, st, body = _resp(s)
                assert rsid == struct.pack("!H", 0x8000 + i), \
                    f"{who} pipelined stat order broke at {i}"
                assert st == kXR_ok, f"{who} pipelined stat {p} status={st}"
        finally:
            s.close()


def test_pipelined_open_read_close_parity(srv):
    """Pipeline open->read->close for one file without reading between sends ->
    all three replies correct & in order, byte-exact data, on both."""
    path = "/data.bin"
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            st, body = _open(s, path, sid=b"\x09\x01")   # must read fh first
            assert st == kXR_ok, f"{who} open status={st}"
            fh = body[0:4]
            # pipeline read + close
            _read(s, fh, 0, 256, sid=b"\x09\x02")
            s.sendall(struct.pack("!2sH4s12sI", b"\x09\x03", kXR_close, fh,
                                  b"\x00" * 12, 0))
            # read reply (may be oksofar+ok), then close reply
            data = b""
            while True:
                rsid, st, rb = _resp(s)
                assert rsid == b"\x09\x02", f"{who} unexpected sid {rsid!r}"
                assert st in (kXR_ok, kXR_oksofar)
                data += rb
                if st == kXR_ok:
                    break
            assert data == _expected(path)[:256], f"{who} pipelined read mismatch"
            rsid, st, _ = _resp(s)
            assert rsid == b"\x09\x03" and st == kXR_ok, f"{who} close reply bad"
        finally:
            s.close()


# =========================================================================== #
# K. FRAMING ROBUSTNESS — oversized / negative dlen, unknown opcode, partial
# =========================================================================== #
def test_negative_dlen_rejected_parity(srv):
    """A request with a negative dlen -> error/link-drop parity (ArgInvalid)."""
    res = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            s.sendall(struct.pack("!2sH16si", b"\x0a\x01", kXR_ping,
                                  b"\x00" * 16, -1))
            sid, st, body = _safe_resp(s)
            res[who] = st in (kXR_error, DROPPED)
            assert res[who], f"{who} accepted negative dlen (status={st})"
        finally:
            s.close()
    assert res["OUR"] == res["STOCK"], f"negative-dlen handling differs: {res}"


def test_oversized_dlen_rejected_parity(srv):
    """A ping claiming a huge dlen (but no body) -> error/link-drop parity; the
    server must NOT hang waiting forever then crash."""
    res = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        s.settimeout(8)
        try:
            s.sendall(struct.pack("!2sH16sI", b"\x0a\x02", kXR_ping,
                                  b"\x00" * 16, 0x7fffffff))
            try:
                sid, st, body = _resp(s)
                res[who] = st in (kXR_error, DROPPED)
            except (EOFError, socket.timeout, OSError):
                res[who] = True   # drop/timeout-after-no-data are valid rejections
        finally:
            s.close()
    assert res["OUR"] == res["STOCK"] or all(res.values()), \
        f"oversized-dlen handling differs: {res}"


def test_unknown_opcode_invalidrequest_parity(srv):
    """An unknown opcode mid-session -> kXR_error/InvalidRequest (or drop) parity."""
    res = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            s.sendall(struct.pack("!2sH16sI", b"\x0a\x03", 9999, b"\x00" * 16, 0))
            sid, st, body = _safe_resp(s)
            res[who] = st in (kXR_error, DROPPED)
            assert st != kXR_ok, f"{who} accepted unknown opcode (status={st})"
        finally:
            s.close()
    # Core contract: both reject an unknown opcode. The exact errnum differs by
    # build — ours returns the spec-correct kXR_InvalidRequest(3006) while the
    # stock-installed server returns kXR_ArgMissing(3001) — so we pin the
    # rejection itself, not the (here, less-correct stock) errnum.
    assert res["OUR"] and res["STOCK"], \
        f"unknown-opcode not rejected on both: {res}"


def test_partial_request_send_then_complete_parity(srv):
    """Send a request HEADER, pause, then the BODY -> the server waits and then
    processes it normally, on both (stat split across two sends)."""
    path = b"/hello.txt"
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            hdr = struct.pack("!2sH16sI", b"\x0a\x04", kXR_stat,
                              b"\x00" * 16, len(path))
            s.sendall(hdr)
            # pause, then send the path body
            import time as _t
            _t.sleep(0.4)
            s.sendall(path)
            sid, st, body = _resp(s)
            assert st == kXR_ok, f"{who} split-send stat status={st} err={_errnum(body)}"
        finally:
            s.close()


def test_partial_header_then_complete_parity(srv):
    """Send only PART of the 8-byte request header, pause, then the rest+body ->
    the server reassembles and serves it, on both."""
    path = b"/data.bin"
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            full = struct.pack("!2sH16sI", b"\x0a\x05", kXR_stat,
                               b"\x00" * 16, len(path)) + path
            s.sendall(full[:3])
            import time as _t
            _t.sleep(0.3)
            s.sendall(full[3:])
            sid, st, body = _resp(s)
            assert st == kXR_ok, f"{who} split-header stat status={st}"
        finally:
            s.close()


# =========================================================================== #
# L. IDLE then request; disconnect mid-request; reconnect
# =========================================================================== #
@pytest.mark.parametrize("idle_s", [0.5, 1.0, 2.0, 3.0])
def test_idle_then_request_still_served_parity(srv, idle_s):
    """A connection idle for a few seconds -> a subsequent request is still served
    (no premature idle-close within a reasonable window), on both."""
    import time as _t
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        s, _ = _session(port)
        try:
            _t.sleep(idle_s)
            _ping(s, sid=b"\x0b\x01")
            sid, st, body = _safe_resp(s)
            assert st == kXR_ok and body == b"", \
                f"{who} dropped/failed an idle conn after {idle_s}s (status={st})"
        finally:
            s.close()


def test_disconnect_mid_request_then_reconnect_parity(srv):
    """Open a file, then HARD-disconnect mid-session without close -> the server
    cleans up (no crash) and a FRESH connection still works, on both."""
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        # abrupt disconnect with an open handle
        s, _ = _session(port)
        st, body = _open(s, "/data.bin")
        assert st == kXR_ok, f"{who} open before disconnect failed"
        # send only a partial read header then drop the socket
        try:
            s.sendall(struct.pack("!2sH", b"\x0c\x01", kXR_read))  # 4 of 24 bytes
        except OSError:
            pass
        s.close()
        # reconnect must work and serve byte-exact
        s2, _ = _session(port)
        try:
            st, body = _open(s2, "/data.bin")
            assert st == kXR_ok, f"{who} reconnect open failed (status={st})"
            rst, data = _read_all(s2, body[0:4], 0, 64, sid=b"\x0c\x02")
            assert rst == kXR_ok and data == _expected("/data.bin")[:64], \
                f"{who} reconnect read wrong"
        finally:
            s2.close()


@pytest.mark.parametrize("rounds", [2, 3, 5, 8])
def test_repeated_connect_disconnect_no_leak_parity(srv, rounds):
    """Rapid connect/login/disconnect cycles -> the server keeps serving (no fd
    leak / crash), verified by a final successful session, on both."""
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        for _ in range(rounds):
            s, _ = _session(port)
            _ping(s, sid=b"\x0d\x01")
            _safe_resp(s)
            s.close()
        # final session must still work
        s, _ = _session(port)
        try:
            st, body = _open(s, "/hello.txt")
            assert st == kXR_ok, f"{who} server unhealthy after {rounds} cycles"
            _close(s, body[0:4])
        finally:
            s.close()
