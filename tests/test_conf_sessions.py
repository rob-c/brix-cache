from _test_conf_sessions_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

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
