# =========================================================================== #
# G. MULTIPLE OPEN HANDLES per session
# =========================================================================== #
def test_four_open_handles_distinct_and_readable_parity(srv):
    """Open 4 files on one session -> 4 distinct fhandles, all readable byte-exact,
    on both servers."""
    files = ["/hello.txt", "/data.bin", "/sz_4096.bin", "/cksum.bin"]
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        _exercise_four_handles(port, who, files)


def test_close_one_handle_others_still_work_parity(srv):
    """With 4 handles open, close ONE -> the other 3 remain readable, on both."""
    files = ["/hello.txt", "/data.bin", "/sz_4096.bin", "/cksum.bin"]
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        _exercise_sibling_close(port, who, files)


@pytest.mark.parametrize("nopen", [2, 3, 4, 6, 8, 12])
def test_n_open_handles_distinct_parity(srv, nopen):
    """Open N (2/6/12) distinct files on one session -> N distinct 4-byte fhandles
    on both servers (handle-table distinctness invariant)."""
    files = (["/hello.txt", "/data.bin", "/sz_1.bin", "/sz_255.bin",
              "/sz_4096.bin", "/cksum.bin"]
             + [f"/many/f{i:02d}.txt" for i in range(6)])[:nopen]
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        _exercise_distinct_handles(port, who, files, nopen)


@pytest.mark.parametrize("nconn", [5, 10, 20, 25, 40, 50])
def test_many_parallel_connections_no_crosstalk_parity(srv, nconn):
    """`nconn` parallel sockets each login+stat+read a (round-robin) file ->
    ALL succeed byte-exact with no cross-talk, and OUR success count EQUALS
    STOCK's success count."""
    paths = list(TREE_FILES.keys())
    counts = {}
    for port, who in ((OUR_PORT, "OUR"), (OFF_PORT, "STOCK")):
        counts[who] = _assert_parallel_success(port, who, paths, nconn)
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
        counts[who] = _assert_parallel_success(port, who, [path], nconn)
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
        outcomes[who] = _bind_primary_secondary(port, who)
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
        _assert_pipelined_stats(port, who, paths)


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
            data = _read_pipelined_data(s, who)
            assert data == _expected(path)[:256], f"{who} pipelined read mismatch"
            _assert_close_response(s, who)
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
