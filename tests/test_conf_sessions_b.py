from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_sessions_helpers")

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
