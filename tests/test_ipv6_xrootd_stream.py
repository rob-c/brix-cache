from split_continuation import reexport as _reexport
def _phase_test_ipv6_concurrent_streams_isolation_1_next(socks):
    for s in socks:
        _phase_test_ipv6_concurrent_streams_isolation_1(s)


def _expression_1():
    return (
        [_session() for _ in range(3)]
    )


def _phase_test_ipv6_concurrent_streams_isolation_1(s):
    try:
        s.close()
    except OSError:
        pass


def _check_test_ipv6_concurrent_streams_isolation_1(status, body):
    assert status == kXR_ok, f"open failed: {_error_code(body)}"

def _check_test_ipv6_concurrent_streams_isolation_2(s):
    assert _ping(s)[1] == kXR_ok


_reexport(globals(), "_test_ipv6_xrootd_stream_helpers")

class TestIpv6Bringup:
    """The handshake/protocol/login sequence must complete unchanged over the
    IPv6 loopback transport (REGRESSION / SMOKE)."""

    @pytest.mark.registry_server("ipv6-stream")
    def test_ipv6_connect_handshake_login(self):
        """ClientInitHandShake accepted (8-byte body, protover 0x520);
        kXR_protocol -> kXR_ok with kXR_isServer-bearing advert; kXR_login ->
        a 16-byte session id.  Proves the whole bring-up works over ::1."""
        sock = _connect6()
        try:
            body = _handshake(sock)
            assert len(body) == 8, "handshake body must be 8 bytes"
            protover, _kind = struct.unpack("!II", body)
            assert protover == kXR_PROTOCOLVERSION, f"protover=0x{protover:x}"

            _, pstatus, pbody = _protocol(sock)
            assert pstatus == kXR_ok, _error_code(pbody)
            assert len(pbody) >= 8, "short kXR_protocol advert"

            _, lstatus, lbody = _login(sock)
            assert lstatus == kXR_ok, _error_code(lbody)
            assert len(lbody) == BRIX_SESSION_ID_LEN, \
                "anon login body must be the 16-byte session id"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    @pytest.mark.registry_server("ipv6-stream")
    def test_ipv6_ping_round_trip(self):
        """A kXR_ping liveness round-trip succeeds on an established IPv6
        session — the simplest end-to-end transport check."""
        sock = _session()
        try:
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()


# ===========================================================================
# Class 2 — read path over IPv6
# ===========================================================================

class TestIpv6Read:
    """open + read + close, byte-exact, over IPv6 (REGRESSION / SMOKE)."""

    @pytest.mark.registry_server("ipv6-stream")
    def test_ipv6_open_read_scalar_byte_exact(self):
        """open(read) -> a valid handle; read(HELLO_LEN) returns exactly the
        seeded "hello from nginx-xrootd" bytes."""
        sock = _session()
        try:
            _, status, body = _open(sock, HELLO_NAME, kXR_open_read)
            assert status == kXR_ok, f"open failed: {_error_code(body)}"
            assert len(body) >= 4, "open ok-response missing the 4-byte handle"
            # Handles are slot indices 0-255 (src/protocols/root/connection/fd_table.c), so a
            # value of 0 is a perfectly valid first handle — the read below is
            # the real proof the handle works.
            fh = body[:4]

            _, rstatus, rbody = _read(sock, fh, 0, HELLO_LEN)
            assert rstatus == kXR_ok, f"read failed: {_error_code(rbody)}"
            assert rbody == HELLO_BODY, \
                f"scalar read not byte-exact: {rbody!r}"

            assert _close(sock, fh)[1] == kXR_ok
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    @pytest.mark.registry_server("ipv6-stream")
    def test_ipv6_open_read_binary_byte_exact(self):
        """A larger binary file reads back byte-exact over IPv6 — proves the
        data path (not just a 23-byte payload) is faithful across the transport."""
        sock = _session()
        try:
            _, status, body = _open(sock, BIN_NAME, kXR_open_read)
            assert status == kXR_ok, f"open failed: {_error_code(body)}"
            fh = body[:4]

            _, rstatus, rbody = _read(sock, fh, 0, len(BIN_BODY))
            assert rstatus == kXR_ok, f"read failed: {_error_code(rbody)}"
            assert rbody == BIN_BODY, "binary read not byte-exact over IPv6"

            _close(sock, fh)
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    @pytest.mark.registry_server("ipv6-stream")
    def test_ipv6_open_nonexistent_clean_error(self):
        """open of a path that does not exist returns a clean protocol error
        (NOT a crash / hang) and the session survives — negative control for
        the read path."""
        sock = _session()
        try:
            _, status, body = _open(sock, "/does-not-exist-ipv6.bin",
                                    kXR_open_read)
            assert status == kXR_error, "open of missing file must error"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()


# ===========================================================================
# Class 3 — write path over IPv6
# ===========================================================================

class TestIpv6Write:
    """open(write) + write + read-back, byte-exact, over IPv6 (REGRESSION)."""

    @pytest.mark.registry_server("ipv6-stream")
    def test_ipv6_write_open_new_byte_exact(self):
        """open(updt|delete) creates/truncates a file, write(64 KiB) lands the
        bytes, and an independent re-open+read returns the exact md5.  Also
        confirmed against the on-disk file when the data root is local."""
        sock = _session()
        try:
            _, status, body = _open(sock, WRITE_NAME,
                                    kXR_open_updt | kXR_delete)
            assert status == kXR_ok, f"write-open failed: {_error_code(body)}"
            fh = body[:4]

            _, wstatus, wbody = _write(sock, fh, 0, WRITE_BODY)
            def _assert_test_ipv6_write_open_new_byte_exact_3():
                assert wstatus == kXR_ok, f"write failed: {_error_code(wbody)}"
                assert _close(sock, fh)[1] == kXR_ok

            _assert_test_ipv6_write_open_new_byte_exact_3()
        finally:
            sock.close()

        # Re-open in a fresh session and read the data straight back.
        sock2 = _session()
        try:
            _, status, body = _open(sock2, WRITE_NAME, kXR_open_read)
            assert status == kXR_ok, f"re-open failed: {_error_code(body)}"
            fh = body[:4]
            got = bytearray()
            off = 0
            while off < len(WRITE_BODY):
                _, rstatus, rbody = _read(sock2, fh, off,
                                          len(WRITE_BODY) - off)
                assert rstatus == kXR_ok, f"readback failed: {_error_code(rbody)}"
                if not rbody:
                    break
                got.extend(rbody)
                off += len(rbody)
            _close(sock2, fh)
            assert hashlib.md5(bytes(got)).hexdigest() == \
                hashlib.md5(WRITE_BODY).hexdigest(), \
                "written data did not read back byte-exact over IPv6"
        finally:
            sock2.close()

        # Belt-and-braces on-disk check when the data root is local to us.
        disk = os.path.join(IPV6_STREAM_DATA_ROOT, WRITE_NAME.lstrip("/"))
        if os.path.exists(disk):
            with open(disk, "rb") as f:
                assert f.read() == WRITE_BODY, "on-disk file mismatch"


# ===========================================================================
# Class 4 — metadata path over IPv6
# ===========================================================================

class TestIpv6Metadata:
    """stat + dirlist over IPv6 (REGRESSION / SMOKE)."""

    @pytest.mark.registry_server("ipv6-stream")
    def test_ipv6_stat_size(self):
        """stat of the seeded text file returns a kXR_ok ASCII body
        "<id> <size> <flags> <mtime>" whose size field equals HELLO_LEN."""
        sock = _session()
        try:
            _, status, body = _stat(sock, HELLO_NAME)
            assert status == kXR_ok, f"stat failed: {_error_code(body)}"
            fields = body.split(b"\x00", 1)[0].split()
            assert len(fields) >= 4, f"malformed stat body: {body!r}"
            size = int(fields[1])
            assert size == HELLO_LEN, \
                f"stat size {size} != {HELLO_LEN} (body {body!r})"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    @pytest.mark.registry_server("ipv6-stream")
    def test_ipv6_stat_nonexistent_clean_error(self):
        """stat of a missing path returns a clean error, session survives —
        negative control proving stat is a real parse, not a blanket ok."""
        sock = _session()
        try:
            _, status, _body = _stat(sock, "/missing-ipv6-xyz.bin")
            assert status == kXR_error, "stat of missing path must error"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    @pytest.mark.registry_server("ipv6-stream")
    def test_ipv6_dirlist(self):
        """A dirlist of the root lists the seeded entries.  The name-only body
        is newline-delimited; test.txt must appear, and after the write test
        runs test_ipv6_write.bin would too — we only require the always-present
        seed files so the test is order-independent."""
        sock = _session()
        try:
            _, status, body = _dirlist(sock, "/")
            assert status == kXR_ok, f"dirlist failed: {_error_code(body)}"
            names = set(body.replace(b"\x00", b"").split(b"\n"))
            assert b"test.txt" in names, \
                f"test.txt missing from dirlist: {body!r}"
            assert b"random.bin" in names, \
                f"random.bin missing from dirlist: {body!r}"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()


# ===========================================================================
# Class 5 — locate bracketing (the IPv6 wire-format assertion)
# ===========================================================================

class TestIpv6Locate:
    """kXR_locate on a data server reached over IPv6.  The local-locate path
    (src/protocols/root/read/locate.c, AF_INET6 branch) formats the response from
    c->local_sockaddr and MUST bracket the address."""

    @pytest.mark.registry_server("ipv6-stream")
    def test_ipv6_locate_local_brackets_regression(self):
        """GATING for the bracket-on-emit contract over IPv6: the kXR_locate
        reply for a file on this IPv6 data server is the "S<acc>..." location
        token, and the host portion MUST be the bracketed form

            Sr[::1]:<port>   (or Sw[::1]:<port> when allow_write)

        and MUST NOT be the bare, colon-ambiguous form "S?::1:<port>".

        src/protocols/root/read/locate.c emits "S%c[%s]:%d" via inet_ntop on the AF_INET6
        local sockaddr; a regression to bare "%s:%d" would make the client
        mis-parse the embedded colons.  Asserting "[::1]:" appears proves the
        bracket is on the wire.
        """
        sock = _session()
        try:
            _, status, body = _locate(sock, HELLO_NAME)
            assert status == kXR_ok, \
                f"locate of an existing file failed: {_error_code(body)}"
            token = body.split(b"\x00", 1)[0]
            assert token[:1] == b"S", \
                f"locate token must start with 'S': {token!r}"
            # The data server reached us over ::1, so the emitted host is the
            # bracketed IPv6 loopback literal followed by ':<port>'.
            assert b"[::1]:" in token, (  # net-literal-allow: asserting locate token is bracketed [::1]
                f"IPv6 locate token not bracketed (expected 'Sr[::1]:<port>'): "  # net-literal-allow: expected bracket-format in assertion message
                f"{token!r}")
            # And explicitly NOT the bare un-bracketed form that the fix replaces.
            assert b"S" + token[1:2] + b"::1:" not in token, (
                f"locate token used the bare un-bracketed IPv6 form: {token!r}")
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    @pytest.mark.registry_server("ipv6-stream")
    def test_ipv6_locate_wildcard_self(self):
        """The '*' wildcard locate (locate the local server itself) also returns
        a bracketed IPv6 location token — exercises the same emit path without
        requiring a real file to exist."""
        sock = _session()
        try:
            _, status, body = _locate(sock, "*")
            assert status == kXR_ok, \
                f"wildcard locate failed: {_error_code(body)}"
            token = body.split(b"\x00", 1)[0]
            assert token[:1] == b"S", f"bad wildcard locate token: {token!r}"
            assert b"[::1]:" in token, (  # net-literal-allow: asserting locate token is bracketed [::1]
                f"wildcard IPv6 locate not bracketed: {token!r}")
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()


# ===========================================================================
# Class 6 — concurrency isolation over IPv6
# ===========================================================================

class TestIpv6Concurrency:
    """Multiple IPv6 sessions are independent (REGRESSION)."""

    @pytest.mark.registry_server("ipv6-stream")
    def test_ipv6_concurrent_streams_isolation(self):
        """Three simultaneous IPv6 sessions each open+read the same file
        byte-exact; closing one leaves the others usable.  Proves per-stream
        state isolation holds over the IPv6 transport."""
        socks = _expression_1()
        try:
            handles = []
            for s in socks:
                _, status, body = _open(s, HELLO_NAME, kXR_open_read)
                _check_test_ipv6_concurrent_streams_isolation_1(status, body)
                handles.append(body[:4])

            # Read on every stream — all byte-exact and independent.
            for s, fh in zip(socks, handles):
                _, rstatus, rbody = _read(s, fh, 0, HELLO_LEN)
                def _assert_test_ipv6_concurrent_streams_isolation_1():
                    assert rstatus == kXR_ok, f"read failed: {_error_code(rbody)}"
                    assert rbody == HELLO_BODY

                _assert_test_ipv6_concurrent_streams_isolation_1()

            # Close the first stream entirely; the rest must keep working.
            _close(socks[0], handles[0])
            socks[0].close()
            for s, fh in zip(socks[1:], handles[1:]):
                _, rstatus, rbody = _read(s, fh, 0, HELLO_LEN)
                def _assert_test_ipv6_concurrent_streams_isolation_2():
                    assert rstatus == kXR_ok, "surviving stream broke after a peer closed"
                    assert rbody == HELLO_BODY

                _assert_test_ipv6_concurrent_streams_isolation_2()
                _check_test_ipv6_concurrent_streams_isolation_2(s)
        finally:
            _phase_test_ipv6_concurrent_streams_isolation_1_next(socks)
