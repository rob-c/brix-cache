from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_sessions_helpers")


def _bogus_endsess_survives(port, bogus):
    connection, _ = _session(port)
    try:
        _endsess(connection, bogus, sid=b"\x00\x40")
        _sid, status, _body = _safe_resp(connection)
        if status == DROPPED:
            return False
        _ping(connection, sid=b"\x00\x41")
        _ping_sid, ping_status, ping_body = _safe_resp(connection)
        return ping_status == kXR_ok and ping_body == b""
    finally:
        connection.close()


def _assert_stat_response(who, index, path, expected_id, response):
    actual_id, status, body = response
    assert actual_id == expected_id, (
        f"{who} streamid mismatch at {index} ({path}): "
        f"got {actual_id!r} want {expected_id!r}"
    )
    assert status == kXR_ok, (
        f"{who} stat {path} status={status} err={_errnum(body)}"
    )


def _assert_pipelined_stats(port, who, paths):
    connection, _ = _session(port)
    try:
        stream_ids = [struct.pack("!H", 0x6000 + index)
                      for index in range(len(paths))]
        for stream_id, path in zip(stream_ids, paths):
            _stat(connection, path, sid=stream_id)
        for index, (stream_id, path) in enumerate(zip(stream_ids, paths)):
            _assert_stat_response(who, index, path, stream_id, _resp(connection))
    finally:
        connection.close()


def _mixed_operations():
    operations = []
    for index in range(20):
        stream_id = struct.pack("!H", 0x7000 + index)
        kind = "ping" if index % 2 == 0 else "stat"
        operations.append((stream_id, kind))
    return operations


def _send_mixed_operation(connection, stream_id, kind):
    if kind == "ping":
        _ping(connection, sid=stream_id)
    else:
        _stat(connection, "/hello.txt", sid=stream_id)


def _assert_mixed_operations(port, who, operations):
    connection, _ = _session(port)
    try:
        for stream_id, kind in operations:
            _send_mixed_operation(connection, stream_id, kind)
        for index, (stream_id, kind) in enumerate(operations):
            actual_id, status, _body = _resp(connection)
            assert actual_id == stream_id, (
                f"{who} mixed streamid {index} {actual_id!r} != {stream_id!r}"
            )
            assert status == kXR_ok, (
                f"{who} mixed op {index} {kind} status={status}"
            )
    finally:
        connection.close()


def test_endsess_bogus_sessid_does_not_kill_conn_parity(srv):
    """endsess with a bogus (all-zero / foreign) sessid -> the conn SURVIVES and
    is still usable (Pid != myPID => ignored, empty ok; session-scoped, NOT a
    connection kill, do_Endsess:925). Pin to stock."""
    for bogus in (b"\x00" * 16, b"\xde\xad\xbe\xef" + b"\x00" * 12, b"\xff" * 16):
        survived = {
            "OUR": _bogus_endsess_survives(OUR_PORT, bogus),
            "STOCK": _bogus_endsess_survives(OFF_PORT, bogus),
        }
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
        _assert_pipelined_stats(port, who, paths)


def test_pipelined_mixed_ops_streamid_match_parity(srv):
    """Interleave ping/stat with distinct streamids -> responses are streamid-
    addressable and correct, on both (no in-flight cross-talk)."""
    ops = _mixed_operations()
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        _assert_mixed_operations(port, who, ops)
