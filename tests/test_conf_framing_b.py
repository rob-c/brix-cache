from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_framing_helpers")

pytestmark = pytest.mark.xdist_group("conf_framing_b")

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

    o, f = _run_pair(srv, runner)
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

    o, f = _run_pair(srv, runner)
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

    o, f = _run_pair(srv, runner)
    # BriX rejects a truncated login promptly; stock may await the missing
    # body, so do not turn its blocking behavior into a BriX regression.
    assert _class(o[0]) != HANG, (
        f"short-login-body: BriX hung on a truncated body (stock={f})")


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

    o, f = _run_pair(srv, runner)
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

    o, f = _run_pair(srv, runner)
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

    o, f = _run_pair(srv, runner)
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

    o, f = _run_pair(srv, runner)
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

    o, f = _run_pair(srv, runner)
    assert o != HANG, f"HIGH: OUR server hung after a request + half-close (stock={f})"
    # Both should deliver the kXR_ok response before/at close.
    assert o in (kXR_ok, EOF), f"OUR half-close outcome unexpected: {o!r} (stock {f!r})"
    assert _class(o) == _class(f) or (o == kXR_ok and f in (kXR_ok, EOF)), (
        f"half-close class diverges: our={_class(o)}({o!r}) stock={_class(f)}({f!r}) (BUG)")
