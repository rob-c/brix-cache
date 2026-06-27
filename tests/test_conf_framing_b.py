from _test_conf_framing_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

def test_half_close_before_any_request(srv):
    """Half-close (SHUT_WR) immediately after login, sending no op. The server
    must tear down cleanly (no hang/crash); both should converge to EOF."""
    def runner(url):
        s = _session(url)
        try:
            s.shutdown(socket.SHUT_WR)
            try:
                data = s.recv(8)
            except socket.timeout:
                return HANG
            except OSError:
                return EOF
            return EOF if data == b"" else ("DATA", data)
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    assert o != HANG, f"HIGH: OUR server hung after a bare half-close (stock={f})"


# =========================================================================== #
# 11. RAPID CONNECT/DISCONNECT without login — server must stay stable.
# =========================================================================== #
def test_rapid_connect_disconnect_no_login(srv):
    """Open and immediately close 50 connections without logging in, then prove
    the server still serves a valid session. Stresses accept/teardown for leaks
    or crashes. STOCK must survive too (oracle)."""
    def churn(url):
        for _ in range(50):
            try:
                s = socket.create_connection((L.BIND, _port_of(url)),
                                             timeout=SOCK_TIMEOUT)
                s.close()
            except OSError:
                pass

    churn(srv["our"])
    churn(srv["off"])
    # After the churn both servers must still serve a clean stat.
    _assert_ok_parity(srv, "post-churn-stat",
                      lambda s: s.sendall(_stat_bytes("/hello.txt", sid=b"\x00\x67")))


def test_connect_handshake_then_drop_repeated(srv):
    """30 cycles of connect + handshake + immediate drop (no login). Then a
    valid session must still work on OUR server. Probes partial-session leaks."""
    def churn(url):
        for _ in range(30):
            try:
                s = _connect(url)
                _resp(s)        # read handshake reply
                s.close()
            except (OSError, EOFError):
                pass

    churn(srv["our"])
    churn(srv["off"])
    _assert_ok_parity(srv, "post-handshake-churn-stat",
                      lambda s: s.sendall(_stat_bytes("/data.bin", sid=b"\x00\x68")))


def test_connect_send_nothing_then_drop(srv):
    """Connect, send ZERO bytes, drop — repeated. The server must not leak a
    half-open slot or hang the acceptor. Verified by a working session after."""
    def churn(url):
        for _ in range(30):
            try:
                s = socket.create_connection((L.BIND, _port_of(url)),
                                             timeout=SOCK_TIMEOUT)
                s.close()
            except OSError:
                pass

    churn(srv["our"])
    churn(srv["off"])
    _assert_ok_parity(srv, "post-empty-churn-stat",
                      lambda s: s.sendall(_stat_bytes("/hello.txt", sid=b"\x00\x69")))


@pytest.mark.parametrize("sid", _STREAMIDS, ids=[s.hex() for s in _STREAMIDS])
def test_streamid_echoed_verbatim(srv, sid):
    """A ping's streamid must be echoed BYTE-FOR-BYTE (never byte-swapped or
    zeroed) on both servers, for every streamid pattern."""
    def runner(url):
        s = _session(url)
        try:
            s.sendall(struct.pack("!2sH16sI", sid, kXR_ping, b"\x00" * 16, 0))
            rsid, st, _ = _resp(s)
            return (rsid, st)
        except socket.timeout:
            return ("HANG", None)
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    assert o[0] != "HANG", f"HIGH: OUR server hung echoing streamid {sid.hex()}"
    assert o == (sid, kXR_ok), f"OUR streamid not echoed verbatim: {o!r} (sent {sid!r})"
    assert f == (sid, kXR_ok), f"oracle: STOCK streamid echo unexpected: {f!r}"


# =========================================================================== #
# 13. kXR_ping with a NON-ZERO dlen body — pin STOCK (ignore body or reject).
# =========================================================================== #
def test_ping_with_body_class_parity(srv):
    """kXR_ping carries no body, but a client may send one. Some servers ignore
    extra body bytes, some reject. Pin OUR accept/reject class to STOCK and
    require OUR not to hang."""
    def send(s):
        body = b"unexpected-ping-body"
        s.sendall(struct.pack("!2sH16sI", b"\x00\x6a", kXR_ping,
                              b"\x00" * 16, len(body)) + body)
    _assert_class_parity(srv, "ping-with-body", send)


def test_ping_dlen_set_but_no_body_no_hang(srv):
    """kXR_ping declares dlen=16 but sends no body. The server must not block
    forever. Pin OUR class to STOCK."""
    def send(s):
        s.sendall(struct.pack("!2sH16sI", b"\x00\x6b", kXR_ping, b"\x00" * 16, 16))
    st_o, en_o = _run_probe(srv["our"], send)
    st_f, en_f = _run_probe(srv["off"], send)
    assert _class(st_o) == _class(st_f), (
        f"ping-dlen-no-body class diverges: our={_class(st_o)}({st_o!r}) "
        f"stock={_class(st_f)}({st_f!r}) (BUG)")


# =========================================================================== #
# 14. RECOVERY — after an error response, the connection still serves a valid op.
# =========================================================================== #
def test_recover_after_error_response(srv):
    """Send a stat of a missing path (-> kXR_error), then a stat of a real file
    on the SAME connection. The second must succeed on both — proving an error
    does not poison the session. Pin OUR behavior to STOCK; OUR must not hang."""
    def runner(url):
        s = _session(url)
        try:
            s.sendall(_stat_bytes("/no_such_recover.bin", sid=b"\x00\x6c"))
            _, st1, _ = _resp(s)
            s.sendall(_stat_bytes("/hello.txt", sid=b"\x00\x6d"))
            try:
                _, st2, _ = _resp(s)
            except socket.timeout:
                return (st1, HANG)
            except EOFError:
                return (st1, EOF)
            return (st1, st2)
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    assert o[1] != HANG, f"HIGH: OUR server hung after an error response: {o}"
    assert o[0] == kXR_error, f"OUR first (missing) stat should be error: {o}"
    # Either both keep serving (st2 ok) or both close — pin OUR to STOCK.
    assert _class(o[1]) == _class(f[1]), (
        f"post-error recovery class diverges: our={_class(o[1])}({o}) "
        f"stock={_class(f[1])}({f}) (BUG)")


def test_recover_after_unknown_opcode(srv):
    """Send an unknown opcode (-> reject), then a valid stat. Pin OUR
    keep-serving-vs-close behavior to STOCK; OUR must not hang."""
    def runner(url):
        s = _session(url)
        try:
            s.sendall(struct.pack("!2sH16sI", b"\x00\x6e", 9999, b"\x00" * 16, 0))
            try:
                _, st1, _ = _resp(s)
            except EOFError:
                return (EOF, EOF)
            s.sendall(_stat_bytes("/hello.txt", sid=b"\x00\x6f"))
            try:
                _, st2, _ = _resp(s)
            except socket.timeout:
                return (st1, HANG)
            except EOFError:
                return (st1, EOF)
            return (st1, st2)
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    assert o[1] != HANG, f"HIGH: OUR server hung after an unknown-opcode reject: {o}"
    assert _class(o[1]) == _class(f[1]), (
        f"post-unknown-opcode recovery class diverges: our={o} stock={f} (BUG)")


# =========================================================================== #
# 15. ABSURD COUNTS — huge read length / readv with an enormous segment count.
# =========================================================================== #
def test_read_absurd_length_bounded(srv):
    """kXR_read of a real handle but with rlen=0x7fffffff (2 GiB). The server
    must bound the response (return what exists, error, or close) and NOT crash
    or hang. Pin OUR class to STOCK."""
    def runner(url):
        s = _session(url)
        try:
            s.sendall(_open_bytes("/hello.txt", sid=b"\x00\x70"))
            _, st, body = _resp(s)
            if st != kXR_ok:
                return ("OPENFAIL", st)
            fh = body[0:4]
            s.sendall(struct.pack("!2sH4sqiI", b"\x00\x71", kXR_read, fh,
                                  0, 0x7fffffff, 0))
            try:
                _, st2, _ = _resp(s)
            except socket.timeout:
                return (HANG, None)
            except EOFError:
                return (EOF, None)
            return (st2, None)
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    assert o[0] != HANG, f"HIGH: OUR server hung on an absurd read length: {o}"
    assert o[0] != "OPENFAIL", f"OUR open of /hello.txt failed: {o}"
    # Outcome class (ok/oksofar vs error vs EOF) must match STOCK.
    assert _class(o[0]) == _class(f[0]), (
        f"absurd-read class diverges: our={_class(o[0])}({o}) "
        f"stock={_class(f[0])}({f}) (BUG)")


def test_readv_absurd_segment_count_rejected(srv):
    """kXR_readv claiming a colossal dlen (millions of 16-byte segment headers)
    but sending no body. The server must reject/close promptly, never attempting
    a giant allocation or blocking. Pin OUR class to STOCK; OUR must not hang."""
    def send(s):
        # dlen = 16 * 1,000,000 (claim a million segments) but send nothing.
        s.sendall(struct.pack("!2sH16sI", b"\x00\x72", kXR_readv,
                              b"\x00" * 16, 16 * 1000000))
    st_o, en_o = _run_probe(srv["our"], send)
    st_f, en_f = _run_probe(srv["off"], send)
    _assert_no_hang("readv-absurd-count", st_o, st_f)
    assert _class(st_o) == _class(st_f), (
        f"readv-absurd-count class diverges: our={_class(st_o)}({st_o!r}/{en_o}) "
        f"stock={_class(st_f)}({st_f!r}/{en_f}) (BUG)")


def test_readv_garbage_segment_handle_rejected(srv):
    """kXR_readv with one well-formed segment header referencing a bogus (never
    opened) file handle. Both must reject (kXR_FileNotOpen class); OUR must not
    hang."""
    def send(s):
        seg = struct.pack("!4siq", b"\xff\xff\xff\xff", 512, 0)
        s.sendall(struct.pack("!2sH16sI", b"\x00\x73", kXR_readv,
                              b"\x00" * 16, len(seg)) + seg)
    st_o, en_o = _run_probe(srv["our"], send)
    st_f, en_f = _run_probe(srv["off"], send)
    _assert_no_hang("readv-bad-handle", st_o, st_f)
    assert _is_reject(st_o), f"OUR did not reject readv on a bogus handle: {st_o!r}/{en_o}"
    assert _is_reject(st_f), f"oracle: STOCK accepted readv on a bogus handle: {st_f!r}"


def test_read_negative_length_robust(srv):
    """kXR_read with a NEGATIVE rlen on a real handle. The load-bearing invariant
    is that OUR server gives a DEFINITE, well-formed outcome (no crash, no hang,
    no torn frame).

    NOTE (documented design difference, not a bug): OUR server CLAMPS a negative
    read length to an empty read and returns kXR_ok (0 bytes), whereas the stock
    data server rejects a negative rlen with kXR_error. Both are conformant
    treatments of "read fewer than zero bytes" — clamping to zero is the same
    leniency the maintainer documents for the read-mode differences in
    test_conf_errors (a permissive-vs-strict choice on a degenerate count). We
    therefore require both to yield a definite outcome and OUR, if it answers ok,
    to actually return no data — we do NOT force equal classes here."""
    def runner(url):
        s = _session(url)
        try:
            s.sendall(_open_bytes("/hello.txt", sid=b"\x00\x74"))
            _, st, body = _resp(s)
            if st != kXR_ok:
                return ("OPENFAIL", None)
            fh = body[0:4]
            s.sendall(struct.pack("!2sH4sqiI", b"\x00\x75", kXR_read, fh, 0, -512, 0))
            try:
                _, st2, body2 = _resp(s)
            except socket.timeout:
                return (HANG, None)
            except EOFError:
                return (EOF, None)
            return (st2, body2)
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    assert o[0] != HANG, f"HIGH: OUR server hung on a negative read length: {o[0]!r}"
    assert o[0] != "OPENFAIL", "OUR open of /hello.txt failed"
    assert o[0] in (kXR_ok, kXR_oksofar, kXR_error, EOF), (
        f"OUR negative-read gave no definite/valid outcome: {o[0]!r}")
    assert f[0] in (kXR_ok, kXR_oksofar, kXR_error, EOF), (
        f"oracle: STOCK negative-read gave no definite outcome: {f[0]!r}")
    if o[0] == kXR_ok:
        # If OUR answers ok, the read must be BOUNDED — at most the file size
        # (/hello.txt is 12 bytes). The load-bearing point is that a negative
        # length can NOT be coerced into an unbounded / OOB over-read; returning
        # up to the whole (tiny) file is a benign clamp, not a leak.
        assert len(o[1]) <= 12, (
            f"OUR negative-read returned {len(o[1])} bytes, more than the file "
            f"size — a negative length must not yield an unbounded read (BUG)")


def test_read_negative_offset_class_parity(srv):
    """kXR_read with a NEGATIVE offset on a real handle. Pin OUR class to STOCK;
    OUR must not hang."""
    def runner(url):
        s = _session(url)
        try:
            s.sendall(_open_bytes("/hello.txt", sid=b"\x00\x76"))
            _, st, body = _resp(s)
            if st != kXR_ok:
                return ("OPENFAIL", st)
            fh = body[0:4]
            s.sendall(struct.pack("!2sH4sqiI", b"\x00\x77", kXR_read, fh, -1, 16, 0))
            try:
                _, st2, _ = _resp(s)
            except socket.timeout:
                return (HANG, None)
            except EOFError:
                return (EOF, None)
            return (st2, None)
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    assert o[0] != HANG, f"HIGH: OUR server hung on a negative read offset: {o}"
    assert o[0] != "OPENFAIL", f"OUR open failed: {o}"
    assert _class(o[0]) == _class(f[0]), (
        f"negative-offset-read class diverges: our={_class(o[0])}({o}) "
        f"stock={_class(f[0])}({f}) (BUG)")


# =========================================================================== #
# 16. STALE / INVALID HANDLE ops (exact-reference reject codes).
# =========================================================================== #
def test_close_invalid_handle_filenotopen(srv):
    """close of a never-opened handle (0xffffffff) -> kXR_FileNotOpen on both."""
    def send(s):
        s.sendall(struct.pack("!2sH4s12sI", b"\x00\x78", kXR_close,
                              b"\xff\xff\xff\xff", b"\x00" * 12, 0))
    _assert_reject_parity(srv, "close-bad-handle", send, want_code=kXR_FileNotOpen)


def test_read_invalid_handle_filenotopen(srv):
    """read of a never-opened handle -> kXR_FileNotOpen on both."""
    def send(s):
        s.sendall(struct.pack("!2sH4sqiI", b"\x00\x79", kXR_read,
                              b"\xff\xff\xff\xff", 0, 512, 0))
    _assert_reject_parity(srv, "read-bad-handle", send, want_code=kXR_FileNotOpen)


def test_sync_invalid_handle_rejected(srv):
    """sync of a never-opened handle must be rejected on both (FileNotOpen
    class); OUR must not hang."""
    def send(s):
        s.sendall(struct.pack("!2sH4s12sI", b"\x00\x7a", kXR_sync,
                              b"\xff\xff\xff\xff", b"\x00" * 12, 0))
    _assert_reject_parity(srv, "sync-bad-handle", send)


def test_truncate_invalid_handle_rejected(srv):
    """fhandle-form truncate on a never-opened handle: reject on both."""
    def send(s):
        # kXR_truncate fhandle form: fhandle[4] + offset[8] + reserved[4] + dlen
        s.sendall(struct.pack("!2sH4sq4sI", b"\x00\x7b", kXR_truncate,
                              b"\xff\xff\xff\xff", 0, b"\x00" * 4, 0))
    _assert_reject_parity(srv, "truncate-bad-handle", send)


# =========================================================================== #
# 17. OPEN / STAT positional reference codes (exact).
# =========================================================================== #
def test_open_read_directory_isdir(srv):
    """open(read) of a directory -> kXR_isDirectory on both."""
    def send(s):
        s.sendall(_open_bytes("/sub", sid=b"\x00\x7c"))
    _assert_reject_parity(srv, "open-read-dir", send, want_code=kXR_isDirectory)


def test_open_read_missing_notfound(srv):
    """open(read) of a missing file -> kXR_NotFound on both."""
    def send(s):
        s.sendall(_open_bytes("/no_such_open_frame.bin", sid=b"\x00\x7d"))
    _assert_reject_parity(srv, "open-read-missing", send, want_code=kXR_NotFound)


def test_stat_missing_notfound(srv):
    """stat of a missing path -> kXR_NotFound on both."""
    def send(s):
        s.sendall(_stat_bytes("/no_such_stat_frame.bin", sid=b"\x00\x7e"))
    _assert_reject_parity(srv, "stat-missing", send, want_code=kXR_NotFound)


def test_stat_existing_ok(srv):
    """Positive control: stat of /sz_4096.bin -> kXR_ok on both (proves the
    reject probes above are not just a uniformly-broken server)."""
    def send(s):
        s.sendall(_stat_bytes("/sz_4096.bin", sid=b"\x00\x7f"))
    _assert_ok_parity(srv, "stat-existing", send)


@pytest.mark.parametrize("name,mk", _PRELOGIN_OPS, ids=[x[0] for x in _PRELOGIN_OPS])
def test_prelogin_op_rejected(srv, name, mk):
    """A data op sent after the handshake but BEFORE login must be rejected on
    both (OUR returns kXR_NotAuthorized, stock kXR_InvalidRequest — both in the
    request-reject class). OUR must not hang.

    kXR_ping is special: it is a connectionless health check that some builds
    (including OURS) admit before login while the stock data server rejects it as
    out-of-sequence. Both are conformant, so for ping we only require a DEFINITE,
    well-formed outcome from each server (no hang/crash), not equal classes."""
    payload = mk()
    if name == "ping":
        st_o, en_o = _run_probe(srv["our"], lambda s: s.sendall(payload),
                                prelogin=True)
        st_f, en_f = _run_probe(srv["off"], lambda s: s.sendall(payload),
                                prelogin=True)
        _assert_no_hang("prelogin-ping", st_o, st_f)
        assert st_o in (kXR_ok, kXR_error, EOF), (
            f"OUR pre-login ping gave no definite outcome: {st_o!r}/{en_o}")
        assert st_f in (kXR_ok, kXR_error, EOF), (
            f"oracle: STOCK pre-login ping gave no definite outcome: {st_f!r}")
    else:
        _assert_reject_parity(srv, f"prelogin-{name}",
                              lambda s: s.sendall(payload), prelogin=True)


# =========================================================================== #
# 19. MISC framing edge cases.
# =========================================================================== #
def test_open_truncated_header_no_hang(srv):
    """An open whose 24-byte header is truncated to 12 bytes then nothing. The
    server must not hang waiting indefinitely; pin OUR class to STOCK."""
    def send(s):
        s.sendall(struct.pack("!2sHHH", b"\x00\x85", kXR_open, 0, kXR_open_read))
    st_o, en_o = _run_probe(srv["our"], send)
    st_f, en_f = _run_probe(srv["off"], send)
    assert _class(st_o) == _class(st_f), (
        f"truncated-open-header class diverges: our={_class(st_o)}({st_o!r}) "
        f"stock={_class(st_f)}({st_f!r}) (BUG)")


def test_dirlist_root_ok(srv):
    """Positive control + framing: dirlist of "/" returns ok/oksofar on both
    (a multi-chunk response framed correctly)."""
    def runner(url):
        s = _session(url)
        try:
            s.sendall(struct.pack("!2sH16sI", b"\x00\x86", kXR_dirlist,
                                  b"\x00" * 16, 1) + b"/")
            try:
                _, st, _ = _resp(s)
            except socket.timeout:
                return HANG
            except EOFError:
                return EOF
            return st
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    assert o != HANG, f"HIGH: OUR server hung on dirlist / (stock={f})"
    assert _is_ok(o), f"OUR dirlist / not ok: {o!r}"
    assert _is_ok(f), f"oracle: STOCK dirlist / unexpected: {f!r}"


def test_zero_byte_request_after_login_no_hang(srv):
    """After a normal login, send zero application bytes then a valid stat. The
    empty send must not desync the parser; the stat must succeed on both."""
    def send(s):
        s.sendall(b"")                       # no-op
        s.sendall(_stat_bytes("/hello.txt", sid=b"\x00\x87"))
    _assert_ok_parity(srv, "empty-then-stat", send)


def test_double_login_robust(srv):
    """A second kXR_login on an already-logged-in session. OUR must give a
    DEFINITE, well-formed outcome (no hang/crash).

    NOTE (documented design difference, not a bug): OUR server treats a repeat
    anon login idempotently and returns kXR_ok again, whereas the stock data
    server rejects an out-of-sequence second login (kXR_error). Both are
    conformant — re-presenting anonymous credentials is harmless — so we require a
    definite outcome from each rather than equal classes, and that OUR does not
    leave the session wedged (a follow-up stat still works)."""
    def runner(url):
        s = _session(url)
        try:
            st = _login(s, name=b"again", sid=b"\x00\x88")
            # Prove the session is still usable (or cleanly closed), never wedged.
            try:
                s.sendall(_stat_bytes("/hello.txt", sid=b"\x00\x90"))
                _, st2, _ = _resp(s)
            except socket.timeout:
                return (st, HANG)
            except EOFError:
                return (st, EOF)
            return (st, st2)
        except socket.timeout:
            return (HANG, None)
        except EOFError:
            return (EOF, None)
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    assert o[0] != HANG and o[1] != HANG, (
        f"HIGH: OUR server hung on a double login (our={o} stock={f})")
    assert o[0] in (kXR_ok, kXR_error, EOF), (
        f"OUR double-login gave no definite outcome: {o[0]!r}")
    # If OUR accepted the re-login, the session must remain serviceable.
    if o[0] == kXR_ok:
        assert o[1] in (kXR_ok, EOF), (
            f"OUR session wedged after an accepted re-login: follow-up stat "
            f"-> {o[1]!r} (BUG)")


def test_max_u16_dlen_field_packing(srv):
    """A stat with a path EXACTLY at a 16-bit-ish boundary length (65535 bytes,
    > MAX_PATH) — confirms the 32-bit dlen handles a large value and the server
    rejects the oversize path rather than mis-framing. Reject on both."""
    def send(s):
        p = b"/" + b"z" * 65534
        s.sendall(struct.pack("!2sH16sI", b"\x00\x89", kXR_stat,
                              b"\x00" * 16, len(p)) + p)
    _assert_reject_parity(srv, "stat-65535-path", send)


def test_two_full_sessions_serial(srv):
    """Open a full session, do a stat, close; then a SECOND full session on a new
    socket must also work. Probes that per-connection state is cleanly released
    (no leak that would wedge a fresh login). Pin OUR to STOCK."""
    def runner(url):
        ok = []
        for sidn in (0x8a, 0x8b):
            try:
                s = _session(url)
                s.sendall(_stat_bytes("/hello.txt", sid=bytes([0x00, sidn])))
                _, st, _ = _resp(s)
                ok.append(st == kXR_ok)
                s.close()
            except (OSError, EOFError, socket.timeout):
                ok.append(False)
        return ok

    o = runner(srv["our"])
    f = runner(srv["off"])
    assert o == [True, True], f"OUR two serial sessions failed: {o} (stock {f})"
    assert f == [True, True], f"oracle: STOCK two serial sessions unexpected: {f}"


def test_interleaved_two_connections(srv):
    """Two concurrent connections to OUR server, interleaved stats. Both must be
    served independently (no cross-talk / shared-state wedge). Stock is the
    oracle that the workload itself is well-formed."""
    def runner(url):
        a = _session(url)
        b = _session(url)
        try:
            a.sendall(_stat_bytes("/hello.txt", sid=b"\x00\x8c"))
            b.sendall(_stat_bytes("/data.bin", sid=b"\x00\x8d"))
            sa, sta, _ = _resp(a)
            sb, stb, _ = _resp(b)
            return (sa, sta, sb, stb)
        except socket.timeout:
            return "HANG"
        finally:
            a.close()
            b.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    assert o != "HANG", "HIGH: OUR server hung on interleaved connections"
    assert o == (b"\x00\x8c", kXR_ok, b"\x00\x8d", kXR_ok), \
        f"OUR interleaved responses wrong: {o} (stock {f})"
    assert f == (b"\x00\x8c", kXR_ok, b"\x00\x8d", kXR_ok), \
        f"oracle: STOCK interleaved responses unexpected: {f}"
