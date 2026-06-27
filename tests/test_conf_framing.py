from _test_conf_framing_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

@pytest.mark.parametrize("op", _ALL_OPCODES, ids=[f"op{o}" for o in _ALL_OPCODES])
def test_opcode_empty_body_robust(srv, op):
    """Send opcode `op` post-login with a header-only (dlen=0) body and assert the
    ROBUSTNESS invariant: OUR server must give a DEFINITE outcome (ok / coded
    error / clean close) — never a crash or an indefinite hang — UNLESS the STOCK
    server also legitimately awaits more input (e.g. kXR_sigver suppresses its own
    reply and waits for the next request; an op whose minimal body is incomplete
    blocks both servers identically). A one-sided OUR hang (we block where stock
    answers/closes) is flagged HIGH.

    Outcome CLASS is NOT pinned here on purpose: a valid op with an empty body has
    op-specific semantics (auth with no creds, a second login, set with no args),
    which legitimately differ between implementations — that is not a framing bug.
    The explicit unknown-opcode and per-op zero-body tests below pin those exact
    classes; this sweep's job is to prove no opcode in the whole space can wedge
    or crash OUR server."""
    def send(s):
        s.sendall(struct.pack("!2sH16sI", b"\x00\x40", op, b"\x00" * 16, 0))
    st_o, en_o = _run_probe(srv["our"], send)
    st_f, en_f = _run_probe(srv["off"], send)
    if st_o == HANG:
        # A one-sided hang is normally the bug — EXCEPT for kXR_sigver, which by
        # design produces NO response on a (provisionally) valid signature and
        # waits for the next request to which it applies (XrdXrootdProtocol.cc:
        # 650-651; pinned exactly in test_xrootd_conformance test 7). Our server
        # correctly suppresses the reply and awaits the signed request, so a
        # "no reply" here is conformant, not a wedge — the link is still live.
        if op == kXR_sigver:
            return
        # Otherwise: mutual await (both HANG) is conformant; one-sided is a bug.
        assert st_f == HANG, (
            f"[opcode-empty-{op}] HIGH: OUR server HUNG (no response/close within "
            f"{SOCK_TIMEOUT}s) where STOCK gave a definite outcome "
            f"(status={st_f!r} errnum={en_f}) (BUG).")
        return
    # OUR gave a definite outcome — it must be a well-formed response status, not
    # a garbage/torn frame.
    assert st_o in (kXR_ok, kXR_oksofar, kXR_error, kXR_wait, kXR_redirect,
                    kXR_status, EOF), (
        f"[opcode-empty-{op}] OUR server returned an unexpected status "
        f"{st_o!r} (errnum={en_o}); stock={st_f!r}/{en_f} (BUG).")
    # If OUR returned a coded error, it must be a real kXR error code (>=3000),
    # never a torn/garbage value (the op3007 'errnum=-1381352598' case below is a
    # kXR_ok login body, not an error, so we only validate coded ERRORS here).
    if st_o == kXR_error and en_o is not None:
        assert 3000 <= en_o <= 3035, (
            f"[opcode-empty-{op}] OUR error code {en_o} is out of the valid kXR "
            f"range (stock={st_f!r}/{en_f}) (BUG).")


# --- unknown / reserved opcode -> request-reject class parity (explicit) ----- #
@pytest.mark.parametrize("op", [3033, 3040, 3100, 9999, 0xffff],
                         ids=lambda o: f"unknown{o}")
def test_unknown_opcode_rejected(srv, op):
    """An opcode with no handler must be rejected on BOTH (kXR_InvalidRequest on
    OUR server / the C++ reference; stock may return kXR_ArgMissing — both are in
    the request-reject class)."""
    def send(s):
        s.sendall(struct.pack("!2sH16sI", b"\x00\x41", op, b"\x00" * 16, 0))
    _assert_reject_parity(srv, f"unknown-opcode-{op}", send)


# =========================================================================== #
# 2. dlen VARIATIONS on a stat request (no path / mismatched length).
# =========================================================================== #
def test_stat_dlen0_argmissing(srv):
    """stat with dlen=0 (no path) — an op that needs a path with none supplied.
    Both must reject (kXR_ArgMissing class)."""
    def send(s):
        s.sendall(struct.pack("!2sH16sI", b"\x00\x42", kXR_stat, b"\x00" * 16, 0))
    _assert_reject_parity(srv, "stat-dlen0", send)


def test_stat_dlen_huge_no_body_no_hang(srv):
    """stat claiming dlen=0x7fffffff but sending NO body. The server must NOT
    block forever waiting for ~2 GiB; it must reject promptly or close. OUR must
    not hang (primary invariant)."""
    def send(s):
        s.sendall(struct.pack("!2sH16sI", b"\x00\x43", kXR_stat,
                              b"\x00" * 16, 0x7fffffff))
    _assert_reject_parity(srv, "stat-dlen-huge", send)


def test_stat_dlen_negative_as_unsigned(srv):
    """stat with dlen interpreted as a negative signed int (0xffffffff). Both
    must reject (kXR_ArgInvalid class) and OUR must not hang."""
    def send(s):
        s.sendall(struct.pack("!2sH16si", b"\x00\x44", kXR_stat, b"\x00" * 16, -1))
    _assert_reject_parity(srv, "stat-dlen-neg", send)


def test_stat_dlen_gt_sent_then_nothing_no_hang(srv):
    """stat declares dlen=64 but sends only 4 path bytes then nothing more. The
    server waits for the rest; both must time out / reject the under-supplied
    request rather than OUR hanging differently from STOCK. We bound the wait
    with SOCK_TIMEOUT and require a definite OUR outcome."""
    def send(s):
        body = b"/hel"   # 4 bytes, but dlen says 64
        s.sendall(struct.pack("!2sH16sI", b"\x00\x45", kXR_stat,
                              b"\x00" * 16, 64) + body)
    # Either server may legitimately hold the link open awaiting the rest, then
    # the read times out at the application layer. We require the CLASS to match
    # and OUR not to hang DIFFERENTLY (i.e. if stock answers/closes, so must we).
    st_o, en_o = _run_probe(srv["our"], send)
    st_f, en_f = _run_probe(srv["off"], send)
    # Both holding the link (HANG) is a conformant "awaiting more data" state —
    # acceptable as long as they AGREE. A divergence (one answers, one hangs) is
    # the bug we hunt.
    cls_o, cls_f = _class(st_o), _class(st_f)
    assert cls_o == cls_f, (
        f"[stat-dlen-gt-sent] OUR={cls_o}({st_o!r}/{en_o}) diverges from "
        f"STOCK={cls_f}({st_f!r}/{en_f}) on an under-supplied body (BUG).")


def test_stat_dlen_lt_payload_extra_trailing(srv):
    """stat declares dlen=4 ("/hel") but appends extra trailing bytes
    ("lo.txt..."). The server frames the next request starting at byte 4 — those
    trailing bytes become a (garbage) next request. We only require the FIRST
    response class to match and OUR not to hang: the framing of the leftover is
    what test_pipelined / test_trailing_garbage probe more precisely."""
    def send(s):
        # dlen=4 consumes "/hel"; the rest is the next (garbage) frame.
        body = b"/hello.txt"
        s.sendall(struct.pack("!2sH16sI", b"\x00\x46", kXR_stat,
                              b"\x00" * 16, 4) + body)
    st_o, en_o = _run_probe(srv["our"], send)
    st_f, en_f = _run_probe(srv["off"], send)
    _assert_no_hang("stat-dlen-lt-payload", st_o, st_f)
    assert _class(st_o) == _class(st_f), (
        f"[stat-dlen-lt-payload] first-response class diverges: "
        f"OUR={_class(st_o)}({st_o!r}/{en_o}) STOCK={_class(st_f)}({st_f!r}/{en_f}) (BUG)")


def test_header_split_across_sends(srv):
    """A valid stat whose 8-byte ... actually whole request header is split: send
    4 bytes, then the rest. Must be processed correctly (kXR_ok) on both."""
    payload = _stat_bytes("/hello.txt", sid=b"\x00\x47")

    def send(s):
        _split_send(s, payload, 4)
    _assert_ok_parity(srv, "header-split", send)


def test_header_split_at_dlen_boundary(srv):
    """Split a valid stat right before the 4-byte dlen field (after 20 bytes:
    2 sid + 2 op + 16 body). Header reassembly must still parse dlen correctly."""
    payload = _stat_bytes("/hello.txt", sid=b"\x00\x48")

    def send(s):
        _split_send(s, payload, 20)
    _assert_ok_parity(srv, "header-split-dlen", send)


def test_body_split_across_sends(srv):
    """A valid stat whose PATH BODY is split mid-way (header + half the path,
    then the rest). Must reassemble and succeed on both."""
    payload = _stat_bytes("/hello.txt", sid=b"\x00\x49")
    head = 24 + 4   # full 24-byte header + 4 path bytes

    def send(s):
        _split_send(s, payload, head)
    _assert_ok_parity(srv, "body-split", send)


def test_one_byte_at_a_time_valid_stat(srv):
    """The most adversarial partial-send: a valid stat delivered ONE BYTE per
    send() call. The server's accumulation must reassemble it to a clean
    kXR_ok — and must not spin or hang."""
    payload = _stat_bytes("/hello.txt", sid=b"\x00\x4a")

    def send(s):
        for i in range(len(payload)):
            s.sendall(payload[i:i + 1])
    _assert_ok_parity(srv, "one-byte-at-a-time", send)


# =========================================================================== #
# 4. PIPELINING — two requests in one send must both be answered in order.
# =========================================================================== #
def test_two_requests_one_send_ordered(srv):
    """Two valid stats in a single send(). Both servers must answer BOTH in
    order with the streamids echoed verbatim. OUR must not drop the second."""
    def runner(url):
        s = _session(url)
        try:
            p = (_stat_bytes("/hello.txt", sid=b"\x00\x51")
                 + _stat_bytes("/data.bin", sid=b"\x00\x52"))
            s.sendall(p)
            sid1, st1, _ = _resp(s)
            sid2, st2, _ = _resp(s)
            return (sid1, st1, sid2, st2)
        except socket.timeout:
            return ("HANG", None, None, None)
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    assert o[0] != "HANG", f"HIGH: OUR server hung on pipelined requests: {o}"
    assert o == (b"\x00\x51", kXR_ok, b"\x00\x52", kXR_ok), (
        f"OUR pipelined responses wrong/out-of-order: {o} (stock: {f})")
    assert f == (b"\x00\x51", kXR_ok, b"\x00\x52", kXR_ok), (
        f"oracle: STOCK pipelined responses unexpected: {f}")


def test_three_mixed_requests_pipelined(srv):
    """Three pipelined ops (ping, stat-ok, stat-missing) in one send. Order and
    per-request outcome must match between servers; OUR must not hang."""
    def runner(url):
        s = _session(url)
        try:
            p = (struct.pack("!2sH16sI", b"\x00\x53", kXR_ping, b"\x00" * 16, 0)
                 + _stat_bytes("/hello.txt", sid=b"\x00\x54")
                 + _stat_bytes("/no_such_pipe.bin", sid=b"\x00\x55"))
            s.sendall(p)
            out = []
            for _ in range(3):
                sid, st, body = _resp(s)
                out.append((sid, st, _err(body)))
            return out
        except socket.timeout:
            return "HANG"
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    assert o != "HANG", "HIGH: OUR server hung on 3 pipelined requests"
    assert f != "HANG", "oracle: STOCK hung on 3 pipelined requests"
    # ping ok, stat ok, stat reject — same shape on both.
    assert o[0][1] == kXR_ok and o[1][1] == kXR_ok and o[2][1] == kXR_error, \
        f"OUR pipelined mixed outcomes wrong: {o} (stock {f})"
    assert [x[0] for x in o] == [b"\x00\x53", b"\x00\x54", b"\x00\x55"], \
        f"OUR pipelined streamids out of order: {o}"
    assert [x[1] for x in f] == [x[1] for x in o], \
        f"pipelined status divergence: our={o} stock={f}"


# =========================================================================== #
# 5. TRAILING GARBAGE appended to a valid request.
# =========================================================================== #
def test_valid_request_trailing_garbage(srv):
    """A valid stat followed by random trailing bytes (NOT a second valid frame).
    The first response must be kXR_ok on both; the leftover bytes are parsed as a
    next (garbage) frame, which both should reject — OUR must not hang."""
    def runner(url):
        s = _session(url)
        try:
            p = _stat_bytes("/hello.txt", sid=b"\x00\x56") + b"\xde\xad\xbe\xef\x01\x02"
            s.sendall(p)
            sid1, st1, _ = _resp(s)
            return st1
        except socket.timeout:
            return "HANG"
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    assert o != "HANG", "HIGH: OUR server hung after valid request + trailing garbage"
    assert o == kXR_ok, f"OUR first response not ok with trailing garbage: {o}"
    assert f == kXR_ok, f"oracle: STOCK first response unexpected: {f}"


def test_valid_then_garbage_frame_class_parity(srv):
    """A valid stat then a full garbage header (unknown opcode). First reply ok
    on both; the SECOND reply (garbage frame) must reject in the same class on
    both — and OUR must produce a definite second outcome."""
    def runner(url):
        s = _session(url)
        try:
            p = (_stat_bytes("/hello.txt", sid=b"\x00\x57")
                 + struct.pack("!2sH16sI", b"\x00\x58", 9999, b"\x00" * 16, 0))
            s.sendall(p)
            _, st1, _ = _resp(s)
            try:
                _, st2, body2 = _resp(s)
            except socket.timeout:
                return (st1, HANG, None)
            except EOFError:
                return (st1, EOF, None)
            return (st1, st2, _err(body2))
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    assert o[1] != HANG, f"HIGH: OUR server hung on the garbage frame after a valid one: {o}"
    assert o[0] == kXR_ok and f[0] == kXR_ok, f"first reply not ok: our={o} stock={f}"
    assert _class(o[1]) == _class(f[1]), (
        f"second (garbage) frame class diverges: our={_class(o[1])}({o}) "
        f"stock={_class(f[1])}({f}) (BUG)")


# =========================================================================== #
# 6. OVERSIZED / MALFORMED PATH PAYLOAD on stat & open.
# =========================================================================== #
@pytest.mark.parametrize("nbytes", [MAX_PATH + 1, MAX_PATH * 2, 65536],
                         ids=["maxpath+1", "2xmaxpath", "64k"])
def test_oversized_path_stat_rejected(srv, nbytes):
    """A stat whose path is longer than XROOTD_MAX_PATH must be rejected on BOTH
    (kXR_ArgTooLong class) — OUR must not crash or hang on the big allocation."""
    def send(s):
        p = b"/" + b"a" * (nbytes - 1)
        s.sendall(struct.pack("!2sH16sI", b"\x00\x59", kXR_stat,
                              b"\x00" * 16, len(p)) + p)
    _assert_reject_parity(srv, f"oversized-path-stat-{nbytes}", send)


@pytest.mark.parametrize("nbytes", [MAX_PATH + 1, 65536],
                         ids=["maxpath+1", "64k"])
def test_oversized_path_open_rejected(srv, nbytes):
    """An open whose path exceeds XROOTD_MAX_PATH must be rejected on both."""
    def send(s):
        p = b"/" + b"b" * (nbytes - 1)
        s.sendall(_open_bytes(p, sid=b"\x00\x5a"))
    _assert_reject_parity(srv, f"oversized-path-open-{nbytes}", send)


def test_embedded_nul_path_stat_rejected(srv):
    """A stat path with an INTERIOR NUL is malformed — both must reject and must
    NOT treat the truncated prefix as a valid path. Codes may differ
    (ArgInvalid vs NotFound); require both to reject and agree on the class."""
    def send(s):
        p = b"/hel\x00lo.txt"
        s.sendall(struct.pack("!2sH16sI", b"\x00\x5b", kXR_stat,
                              b"\x00" * 16, len(p)) + p)
    _assert_reject_parity(srv, "embedded-nul-stat", send)


def test_embedded_nul_path_open_rejected(srv):
    """An open path with an interior NUL is malformed — both must reject."""
    def send(s):
        p = b"/da\x00ta.bin"
        s.sendall(_open_bytes(p, sid=b"\x00\x5c"))
    _assert_reject_parity(srv, "embedded-nul-open", send)


def test_trailing_nul_path_stat_accepted(srv):
    """A SINGLE TRAILING NUL on a path is permitted (it's trimmed). A stat of
    "/hello.txt\\0" must SUCCEED identically on both (positive control that we
    reject interior NULs without over-rejecting a benign trailing one)."""
    def send(s):
        p = b"/hello.txt\x00"
        s.sendall(struct.pack("!2sH16sI", b"\x00\x5d", kXR_stat,
                              b"\x00" * 16, len(p)) + p)
    _assert_class_parity(srv, "trailing-nul-stat", send)


@pytest.mark.parametrize("name,op,fmt", _NEEDS_PATH_OPS,
                         ids=[x[0] for x in _NEEDS_PATH_OPS])
def test_zero_length_path_op_rejected(srv, name, op, fmt):
    """A path-requiring op sent with dlen=0 (just a header, no path) must be
    rejected on both (kXR_ArgMissing class). Probes that every namespace op
    validates the presence of its path argument and OUR never hangs."""
    def send(s):
        if op == kXR_open:
            s.sendall(struct.pack("!2sHHH12sI", b"\x00\x5e", kXR_open, 0,
                                  kXR_open_read, b"\x00" * 12, 0))
        elif op == kXR_mkdir:
            # mkdir header (XProtocol.hh ClientMkdirRequest): options[1] +
            # reserved[13] + mode[2] + dlen[4].
            s.sendall(struct.pack("!2sHB13sHI", b"\x00\x5f", kXR_mkdir, 0,
                                  b"\x00" * 13, 0, 0))
        else:
            s.sendall(struct.pack(fmt, b"\x00\x60", op, b"\x00" * 16, 0))
    _assert_class_parity(srv, f"zero-path-{name}", send)


# =========================================================================== #
# 8. LOGIN edge cases.
# =========================================================================== #
def test_login_zero_length_username_class_parity(srv):
    """A login with an all-NUL (effectively zero-length) username. Pin OUR
    accept/reject class to STOCK; OUR must not hang."""
    def runner(url):
        s = _connect(url)
        try:
            _, st0, _ = _resp(s)
            assert st0 == kXR_ok
            s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x61", kXR_login,
                                  os.getpid() & 0x7fffffff, b"\x00" * 8,
                                  0, 0, 0, 0, 0))
            try:
                _, st, body = _resp(s)
            except socket.timeout:
                return (HANG, None)
            except EOFError:
                return (EOF, None)
            return (st, _err(body))
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    _assert_no_hang("login-empty-user", o[0], f[0])
    assert _class(o[0]) == _class(f[0]), (
        f"empty-username login class diverges: our={_class(o[0])}({o}) "
        f"stock={_class(f[0])}({f}) (BUG)")


def test_login_oversized_username_class_parity(srv):
    """The login username field is a FIXED 8 bytes on the wire; an "oversized"
    username manifests as a large dlen body. Send a login with a 4 KiB junk body
    after the fixed header and pin OUR class to STOCK (no hang)."""
    def runner(url):
        s = _connect(url)
        try:
            _, st0, _ = _resp(s)
            assert st0 == kXR_ok
            junk = b"u" * 4096
            s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x62", kXR_login,
                                  os.getpid() & 0x7fffffff, b"longuser",
                                  0, 0, 0, 0, len(junk)) + junk)
            try:
                _, st, body = _resp(s)
            except socket.timeout:
                return (HANG, None)
            except EOFError:
                return (EOF, None)
            return (st, _err(body))
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    _assert_no_hang("login-oversized-user", o[0], f[0])
    assert _class(o[0]) == _class(f[0]), (
        f"oversized-username login class diverges: our={_class(o[0])}({o}) "
        f"stock={_class(f[0])}({f}) (BUG)")


def test_login_short_body_truncated_no_hang(srv):
    """A login whose header claims a body (dlen=32) but sends nothing more. The
    server must not block forever; pin OUR class to STOCK."""
    def runner(url):
        s = _connect(url)
        try:
            _, st0, _ = _resp(s)
            assert st0 == kXR_ok
            s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x63", kXR_login,
                                  os.getpid() & 0x7fffffff, b"shortbod",
                                  0, 0, 0, 0, 32))   # claims 32 body bytes, sends 0
            try:
                _, st, body = _resp(s)
            except socket.timeout:
                return (HANG, None)
            except EOFError:
                return (EOF, None)
            return (st, _err(body))
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    # Both awaiting (HANG) is fine if they AGREE; a one-sided hang is the bug.
    assert _class(o[0]) == _class(f[0]), (
        f"short-login-body class diverges: our={_class(o[0])}({o}) "
        f"stock={_class(f[0])}({f}) (BUG)")


def test_login_then_valid_stat_after_anon(srv):
    """Positive control: a normal anon login then a stat must succeed on both.
    Guards against the edge-case logins above masking a broken happy path."""
    def send(s):
        s.sendall(_stat_bytes("/hello.txt", sid=b"\x00\x64"))
    _assert_ok_parity(srv, "login-then-stat", send)


# =========================================================================== #
# 9. HANDSHAKE edge cases (before login / malformed initial bytes).
# =========================================================================== #
def test_handshake_wrong_magic_class_parity(srv):
    """The initial handshake's fixed fields are (0,0,0,4,2012). Send a WRONG
    magic (last field 9999). Pin OUR accept/close class to STOCK; OUR must not
    hang."""
    def runner(url):
        s = socket.create_connection((L.BIND, _port_of(url)), timeout=SOCK_TIMEOUT)
        s.settimeout(SOCK_TIMEOUT)
        try:
            s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 9999))
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
    assert o != HANG, f"HIGH: OUR server hung on a wrong-magic handshake (stock={f})"
    assert _class(o) == _class(f), (
        f"wrong-magic handshake class diverges: our={_class(o)}({o!r}) "
        f"stock={_class(f)}({f!r}) (BUG)")


def test_handshake_short_then_nothing_no_hang(srv):
    """Send only 4 of the 20 handshake bytes, then nothing. The server must not
    answer prematurely; both should await/close the same way and OUR must not
    diverge into an answer or a one-sided hang."""
    def runner(url):
        s = socket.create_connection((L.BIND, _port_of(url)), timeout=SOCK_TIMEOUT)
        s.settimeout(SOCK_TIMEOUT)
        try:
            s.sendall(b"\x00\x00\x00\x00")   # 4 bytes only
            try:
                _, st, _ = _resp(s)
            except socket.timeout:
                return HANG     # awaiting the rest — conformant if both do it
            except EOFError:
                return EOF
            return st
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    # The handshake is INCOMPLETE (4 of 20 bytes), so the server has two
    # conformant choices: keep the link open awaiting the rest (HANG) or drop it
    # (EOF). Both stock and ours pick one of these; the only outcome that would be
    # a bug is a spurious RESPONSE to a half-handshake. Require both to be in
    # {HANG, EOF} and OUR never to answer.
    assert o in (HANG, EOF), (
        f"OUR server answered a half-handshake (status={o!r}) instead of "
        f"awaiting/closing (BUG); stock={f!r}")
    assert f in (HANG, EOF), (
        f"oracle: STOCK answered a half-handshake unexpectedly: {f!r}")


def test_handshake_extra_bytes_then_login(srv):
    """A correct 20-byte handshake immediately followed by extra junk bytes, then
    a real login. The handshake reply must arrive and the junk must not wedge the
    parser. Pin OUR outcome class for the login to STOCK."""
    def runner(url):
        s = socket.create_connection((L.BIND, _port_of(url)), timeout=SOCK_TIMEOUT)
        s.settimeout(SOCK_TIMEOUT)
        try:
            s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012) + b"\xff\xff\xff\xff")
            try:
                _, st_hs, _ = _resp(s)   # handshake reply
            except socket.timeout:
                return HANG
            except EOFError:
                return EOF
            # The 4 junk bytes are now the start of the next frame; that frame is
            # incomplete, so a subsequent login may be mis-framed. We only assert
            # the handshake reply class here.
            return st_hs
        finally:
            s.close()

    o = runner(srv["our"])
    f = runner(srv["off"])
    assert o != HANG, f"HIGH: OUR server hung after handshake+extra bytes (stock={f})"
    assert _class(o) == _class(f), (
        f"handshake+extra class diverges: our={_class(o)}({o!r}) "
        f"stock={_class(f)}({f!r}) (BUG)")


def test_no_handshake_direct_login_no_hang(srv):
    """Skip the handshake entirely and send a login first. The login's first 20
    bytes will be misread as the handshake; the server must not hang. Pin OUR
    outcome class to STOCK."""
    def runner(url):
        s = socket.create_connection((L.BIND, _port_of(url)), timeout=SOCK_TIMEOUT)
        s.settimeout(SOCK_TIMEOUT)
        try:
            s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x65", kXR_login,
                                  os.getpid() & 0x7fffffff, b"nohands",
                                  0, 0, 0, 0, 0))
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
    assert o != HANG, f"HIGH: OUR server hung on a login-without-handshake (stock={f})"
    assert _class(o) == _class(f), (
        f"login-without-handshake class diverges: our={_class(o)}({o!r}) "
        f"stock={_class(f)}({f!r}) (BUG)")


# =========================================================================== #
# 10. HALF-CLOSE — send a request, then shutdown(WR); server must reply then
#     close. Probes that a one-way close mid-stream is handled cleanly.
# =========================================================================== #
def test_request_then_half_close(srv):
    """Send a valid stat, then shutdown(SHUT_WR). The server must still send its
    response and then close cleanly. OUR must not hang or crash."""
    def runner(url):
        s = _session(url)
        try:
            s.sendall(_stat_bytes("/hello.txt", sid=b"\x00\x66"))
            s.shutdown(socket.SHUT_WR)
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
    assert o != HANG, f"HIGH: OUR server hung after a request + half-close (stock={f})"
    # Both should deliver the kXR_ok response before/at close.
    assert o in (kXR_ok, EOF), f"OUR half-close outcome unexpected: {o!r} (stock {f!r})"
    assert _class(o) == _class(f) or (o == kXR_ok and f == kXR_ok), (
        f"half-close class diverges: our={_class(o)}({o!r}) stock={_class(f)}({f!r}) (BUG)")
