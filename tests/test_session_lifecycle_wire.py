from split_continuation import reexport as _reexport
def _check_test_bind_with_primary_sessid_3(secondary):
    assert _ping(secondary)[1] == kXR_ok

def _check_test_bind_with_primary_sessid_1(body):
    assert len(body) >= 1, "successful bind must carry a pathid byte"

def _check_test_bind_with_primary_sessid_2(pathid):
    assert 1 <= pathid <= 253, (
        f"bind pathid {pathid} outside reserved range 1..253")


_reexport(globals(), "_test_session_lifecycle_wire_helpers")

class TestSetOpcode:
    """kXR_set is login-gated (src/protocols/root/handshake/dispatch_session.c) and otherwise
    accepts every modifier with kXR_ok (src/protocols/root/query/set.c)."""

    def test_set_before_login_rejected(self, pre_login):
        """kXR_set before kXR_login must be rejected with NotAuthorized, not ok.

        The dispatcher runs brix_dispatch_require_login() for kXR_set before
        the handler ever sees the request (dispatch_session.c case kXR_set).
        """
        sock = pre_login
        _, status, body = _set(sock, kXR_set_appid, b"anything")
        assert status == kXR_error, "kXR_set before login must be an error"
        assert _error_code(body) == kXR_NotAuthorized
        # Connection still alive: a pre-login ping is answered with kXR_error
        # ("not logged in", stock parity), or the connection is dropped — never ok.
        assert _ping_status(sock) in (kXR_error, None)

    def test_set_after_login_ok(self, logged_in):
        """A known modifier (appid) on a logged-in session returns ok."""
        sock, _ = logged_in
        _, status, body = _set(sock, kXR_set_appid, b"myapp\n")
        assert status == kXR_ok, _error_code(body)
        assert _ping(sock)[1] == kXR_ok

    def test_set_unknown_option_accepted(self, logged_in):
        """An unrecognised modifier byte is still accepted with ok per spec —
        the server logs it but never rejects (src/protocols/root/query/set.c default case)."""
        sock, _ = logged_in
        _, status, body = _set(sock, 0xEE, b"opaque-value")
        assert status == kXR_ok, _error_code(body)
        # And the session is still fully functional afterwards.
        assert _ping(sock)[1] == kXR_ok

    def test_set_cms_space_appid_ok(self, logged_in):
        """The CMS-grid 'cms.space <total> <free>' appid report is parsed and
        accepted (src/protocols/root/query/set.c cms.space handling)."""
        sock, _ = logged_in
        _, status, body = _set(sock, kXR_set_appid, b"cms.space 1000000 250000")
        assert status == kXR_ok, _error_code(body)
        assert _ping(sock)[1] == kXR_ok


# ===========================================================================
# Class 2 — kXR_endsess (graceful session termination)
# ===========================================================================

class TestEndsessOpcode:
    """kXR_endsess always returns ok. It terminates the session named in the
    request body; only the current session id clears this connection's
    logged_in/auth_done state (src/protocols/root/session/lifecycle.c brix_handle_endsess)."""

    def test_endsess_without_login_ok(self, pre_login):
        """kXR_endsess on a never-logged-in connection is a harmless no-op ok.

        The handler clears already-clear flags and returns ok; it does not gate
        on login (unlike kXR_set, which is dispatched after require_login).
        Prove the connection is still alive afterwards.
        """
        sock = pre_login
        _, status, _ = _endsess(sock)
        assert status == kXR_ok, "endsess without login should be a clean ok"
        # Liveness on a NOT-logged-in connection: stock and our server both reject
        # a pre-login ping (kXR_error "not logged in"); a server that drops the
        # connection is equally acceptable.  kXR_ok is never the right expectation
        # here — it would require a pre-login ping to succeed, which it does not.
        assert _ping_status(sock) in (kXR_error, None)

    def test_endsess_wrong_sessid_ok(self, logged_in):
        """A non-current sessid is advisory cleanup for another session id.

        It returns ok but must not de-authorize the current connection; official
        clients use this recovery pattern after reconnecting from a stale session.
        """
        sock, _ = logged_in
        _, status, _ = _endsess(sock, sessid=b"\xab" * 16)
        assert status == kXR_ok
        _, ostatus, obody = _open(sock, "/definitely-missing-endsess-probe",
                                  kXR_open_read)
        assert ostatus == kXR_error
        assert _error_code(obody) == kXR_NotFound

    def test_endsess_idempotent_second_call(self, logged_in):
        """A second kXR_endsess on the same connection is still ok (idempotent)."""
        sock, login_body = logged_in
        sessid = login_body[:16]
        _, s1, _ = _endsess(sock, sessid=sessid)
        assert s1 == kXR_ok
        _, s2, _ = _endsess(sock, sessid=sessid)
        assert s2 == kXR_ok

    def test_request_after_endsess_rejected(self, logged_in):
        """After kXR_endsess the session is de-authorized: a file op (open) on
        the same connection must be rejected with NotAuthorized.

        SECURITY: src/protocols/root/session/lifecycle.c clears logged_in/auth_done precisely so
        a client cannot keep using the connection after ending its session
        (e.g. after the GSI proxy certificate that triggered the endsess has
        expired).
        """
        sock, login_body = logged_in
        sessid = login_body[:16]
        _, status, _ = _endsess(sock, sessid=sessid)
        assert status == kXR_ok
        # open now hits the pre-auth gate (require_auth) -> NotAuthorized.
        _, ostatus, obody = _open(sock, "/nonexistent.bin", kXR_open_read)
        assert ostatus == kXR_error, "file op after endsess must be rejected"
        assert _error_code(obody) == kXR_NotAuthorized
        # On a DE-authorized connection a ping is no longer answered with ok:
        # like a pre-login ping it is rejected (kXR_error "not logged in"), or the
        # server drops the connection.  Either proves the de-auth took effect; the
        # security property — open rejected — has already been proven above.
        ps = _ping_status(sock)
        assert ps in (kXR_error, None)


# ===========================================================================
# Class 3 — kXR_bind (secondary data channel)
# ===========================================================================

class TestBindOpcode:
    """kXR_bind attaches a secondary connection to an existing session and is
    only honoured for a sessid present in the shared registry; everything else
    is NotAuthorized (src/protocols/root/session/bind.c brix_handle_bind)."""

    def test_bind_random_sessid_rejected(self, pre_login):
        """A random/unknown 16-byte sessid is not in the registry -> rejected."""
        sock = pre_login
        _, status, body = _bind(sock, sessid=b"\x5a" * 16)
        assert status == kXR_error, "bind with unknown sessid must fail"
        assert _error_code(body) == kXR_NotAuthorized
        # The connection survives a rejected bind: a pre-login ping is answered
        # (with kXR_error "not logged in", never kXR_ok) or the conn is dropped.
        assert _ping_status(sock) in (kXR_error, None)

    def test_bind_before_primary_login_rejected(self, pre_login):
        """kXR_bind dispatches before the login gate (it is meant for secondary
        connections), but an all-zero sessid that was never registered by any
        primary is still rejected with NotAuthorized."""
        sock = pre_login
        _, status, body = _bind(sock, sessid=b"\x00" * 16)
        assert status == kXR_error
        assert _error_code(body) == kXR_NotAuthorized
        # Still alive after the rejected bind: pre-login ping -> error, or dropped.
        assert _ping_status(sock) in (kXR_error, None)

    def test_bind_with_primary_sessid(self, logged_in):
        """kXR_bind from a SECOND connection naming the primary's real sessid.

        On the anon endpoint the primary registers its session at login
        (src/protocols/root/session/login.c calls brix_session_register), so a secondary that
        presents that sessid should bind (ok + 1-byte pathid in 1..253).  If
        this deployment does not register anon sessions in the cross-process
        registry, the documented fallback is NotAuthorized — both are valid
        conformance outcomes, so assert on whichever the server gives and prove
        the pathid invariant when it succeeds.
        """
        _primary, login_body = logged_in
        sessid = login_body[:16]
        if len(sessid) < 16 or sessid == b"\x00" * 16:
            pytest.fail("anon login did not return a usable 16-byte sessid")

        secondary = _safe_handshake_only()
        try:
            _, status, body = _bind(secondary, sessid=sessid)
            if status == kXR_ok:
                # Pathid 0 is reserved for the primary; secondaries get 1..253
                # (src/protocols/root/session/bind.c brix_next_pathid).  Body byte 0 is the
                # pathid (it follows the 8-byte response header stripped by
                # _read_response).
                _check_test_bind_with_primary_sessid_1(body)
                pathid = body[0]
                _check_test_bind_with_primary_sessid_2(pathid)
            else:
                def _assert_test_bind_with_primary_sessid_3():
                    assert status == kXR_error
                    assert _error_code(body) == kXR_NotAuthorized

                _assert_test_bind_with_primary_sessid_3()
            # Either way the secondary connection is intact.
            _check_test_bind_with_primary_sessid_3(secondary)
        finally:
            secondary.close()

    def test_bound_pathid_zero_reserved(self, logged_in):
        """Pathid 0 is reserved for the primary connection: a successful bind
        must NEVER hand out pathid 0 (src/protocols/root/session/bind.c cycles 1..253).

        We can only check this when the registry honours the bind; otherwise we
        skip with the documented reason rather than hard-fail an unregistered
        anon session.
        """
        _primary, login_body = logged_in
        sessid = login_body[:16]
        if len(sessid) < 16 or sessid == b"\x00" * 16:
            pytest.fail("anon login did not return a usable 16-byte sessid")

        secondary = _safe_handshake_only()
        try:
            _, status, body = _bind(secondary, sessid=sessid)
            if status != kXR_ok:
                def _assert_test_bound_pathid_zero_reserved_2():
                    assert status == kXR_error
                    assert _error_code(body) == kXR_NotAuthorized

                _assert_test_bound_pathid_zero_reserved_2()
                return
            def _assert_test_bound_pathid_zero_reserved_1():
                assert len(body) >= 1
                assert body[0] != 0, "pathid 0 is reserved for the primary"

            _assert_test_bound_pathid_zero_reserved_1()
        finally:
            secondary.close()


# ===========================================================================
# Class 4 — pre-login authorization gate (no file op before login)
# ===========================================================================

# (opcode label, 16-byte request body, payload) for each gated operation.
# The require_auth / require_write gate fires in the dispatcher BEFORE any
# request-specific parsing (src/protocols/root/handshake/dispatch_read.c / dispatch_write.c,
# src/protocols/root/handshake/policy.c), so a minimally-framed valid request is sufficient to
# exercise the gate.  Both gates return kXR_NotAuthorized when unauthenticated:
# require_write calls require_auth first, so the auth failure precedes the
# allow_write / read-only check.
_PATH = b"/gate_probe.bin\x00"

_GATED_OPS = [
    ("open",     kXR_open,     b"\x02\x9c\x00\x10" + b"\x00" * 12, _PATH),
    ("read",     kXR_read,     b"\x00" * 16,                       b""),
    ("write",    kXR_write,    b"\x00" * 16,                       b"data"),
    ("stat",     kXR_stat,     b"\x00" * 16,                       _PATH),
    ("chmod",    kXR_chmod,    b"\x00" * 16,                       _PATH),
    ("mkdir",    kXR_mkdir,    b"\x00" * 16,                       b"/gate_dir\x00"),
    ("rm",       kXR_rm,       b"\x00" * 16,                       _PATH),
    ("dirlist",  kXR_dirlist,  b"\x00" * 16,                       b"/\x00"),
    ("sync",     kXR_sync,     b"\x00" * 16,                       b""),
    ("truncate", kXR_truncate, b"\x00" * 16,                       _PATH),
]


class TestPreLoginGate:
    """No file-system opcode may be performed before kXR_login.  Read-class ops
    hit require_auth, write-class ops hit require_write — both return
    kXR_NotAuthorized while the connection is unauthenticated
    (src/protocols/root/handshake/policy.c)."""

    @pytest.mark.parametrize("label,opcode,body16,payload", _GATED_OPS,
                             ids=[o[0] for o in _GATED_OPS])
    def test_file_op_before_login_rejected(self, label, opcode, body16,
                                           payload):
        """Each gated op before login -> kXR_NotAuthorized, session survives."""
        sock = _safe_handshake_only()
        try:
            _, status, body = _raw_request(sock, opcode, body16, payload)
            assert status == kXR_error, (
                f"{label} before login must be rejected, got status {status}")
            assert _error_code(body) == kXR_NotAuthorized, (
                f"{label} before login should be NotAuthorized, "
                f"got errnum {_error_code(body)}")
            # The hostile request did not poison the worker: the server either
            # answers a follow-up pre-login ping with kXR_error ("not logged in",
            # as ours does) or drops the connection (as stock does after a rejected
            # pre-login file op).  kXR_ok is impossible — a pre-login ping is never
            # answered ok by either server.
            assert _ping_status(sock) in (kXR_error, None)
        finally:
            sock.close()

    def test_gate_lifts_after_login(self):
        """Positive control: the SAME op that was rejected pre-login succeeds
        (or returns a benign data-level error like NotFound) once logged in —
        proving the gate is about login, not the op itself."""
        sock, _ = _safe_session()
        try:
            # stat of a path that may or may not exist: must NOT be
            # NotAuthorized once logged in.
            _, status, body = _raw_request(sock, kXR_stat, b"\x00" * 16, _PATH)
            if status == kXR_error:
                assert _error_code(body) != kXR_NotAuthorized, (
                    "stat must not be NotAuthorized once logged in")
            else:
                assert status in (kXR_ok, kXR_status)
        finally:
            sock.close()


# ===========================================================================
# Class 5 — ping liveness + unknown / legacy opcodes
# ===========================================================================

class TestPingAndUnknownOpcodes:
    """kXR_ping is login-gated (the reference auth gate rejects every non-auth
    request before login, ping included — verified against stock xrootd, which
    answers a pre-login ping with kXR_error "Invalid request; user not logged
    in"); truly unknown opcodes (including legacy ids below kXR_auth=3000) fall
    through every dispatcher to an error (src/protocols/root/handshake/dispatch.c)."""

    def test_ping_before_login_rejected(self, pre_login):
        """kXR_ping before login is rejected with kXR_error, matching stock
        xrootd (src/protocols/root/handshake/dispatch_session.c routes kXR_ping through
        brix_dispatch_require_login).  A pre-login ping is NOT a liveness
        probe a stock server answers ok."""
        sock = pre_login
        _sid, status, _ = _ping(sock)
        assert status == kXR_error, "ping must be rejected pre-login (stock parity)"

    def test_unknown_opcode_rejected(self, pre_login):
        """An opcode the server does not implement (e.g. 3999, well above the
        defined range) is rejected with kXR_InvalidRequest, and the connection
        remains usable for a subsequent ping (src/protocols/root/handshake/dispatch.c default
        falls through to brix_send_error(kXR_InvalidRequest), matching stock
        xrootd's "Invalid request code" reply for an unrecognised opcode)."""
        sock = pre_login
        try:
            _, status, body = _raw_request(sock, 3999)
        except _DROP_EXCEPTIONS:
            # Dropping an unimplemented opcode is also a clean rejection.
            return
        assert status == kXR_error, "unknown opcode must be an error"
        assert _error_code(body) == kXR_InvalidRequest, (
            f"unknown opcode should be InvalidRequest, got {_error_code(body)}")
        # Connection still alive: a pre-login ping is answered with kXR_error, or
        # the connection was dropped — never kXR_ok (ping is login-gated).
        assert _ping_status(sock) in (kXR_error, None)

    def test_legacy_opcode_below_auth_rejected(self, pre_login):
        """A legacy opcode below kXR_auth (3000), e.g. 2999, is not in any
        dispatch table and must be rejected (Unsupported), never silently
        accepted.  The connection should survive (pre-login ping answered with
        kXR_error, or dropped) afterwards."""
        sock = pre_login
        try:
            _, status, body = _raw_request(sock, 2999)
        except _DROP_EXCEPTIONS:
            # A recv-layer that classifies a sub-protocol id as malformed and
            # drops the connection is an acceptable clean rejection.
            return
        # The central dispatcher answers unmatched opcodes with Unsupported;
        # accept the close-cousin ArgInvalid/InvalidRequest in case the recv
        # layer classifies a sub-protocol id differently, but never ok.
        assert status != kXR_ok, "legacy <3000 opcode must not be accepted"
        assert status == kXR_error, (
            f"legacy <3000 opcode must be an error, got status {status}")
        assert _error_code(body) in (
            kXR_Unsupported, kXR_InvalidRequest, kXR_ArgInvalid), (
            f"legacy opcode errnum {_error_code(body)} unexpected")
        # Alive afterwards: pre-login ping -> kXR_error, or dropped; never ok.
        assert _ping_status(sock) in (kXR_error, None)
