"""Test cases for audit16s_krb5_delegate_arms — preamble (fixtures/helpers/mocks) lives in
_test_audit16s_krb5_delegate_arms_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16s_krb5_delegate_arms_helpers")


class TestTheValueAtConfigTime:
    """The three planes, and the one thing an operator is told about them."""

    def test_the_rendered_config_writes_both_arms_literally(self, planes):
        """success: the pair this file closes, in the form the audit's own
        census greps for.  `on` was already in two configs; `off` is written
        here for the first time anywhere in the corpus."""
        rendered = _read(planes.endpoint.config)
        for value in ("on", "off"):
            assert _writes(rendered, value), (
                f"`{DIRECTIVE} {value};` is not in the rendered config — the "
                f"arm is not closed\n{rendered}")

    def test_the_third_plane_writes_the_directive_nowhere(self, planes):
        """The absent plane has to be absence, not a third spelling: its whole
        job is to measure the merge default instead of reading it off
        server_conf_merge_security.c:241."""
        rendered = _read(planes.endpoint.config)
        written = re.findall(rf"^\s*{DIRECTIVE}\s+(\S+)\s*;\s*$", rendered,
                             re.MULTILINE)
        assert written == ["on", "off"], (
            f"expected exactly two {DIRECTIVE} lines, one per arm, in server "
            f"order; found {written}\n{rendered}")

    def test_the_planes_differ_in_nothing_else(self, planes):
        """One principal, one keytab, one export.  Any other difference would
        give a refusal a second explanation."""
        rendered = _read(planes.endpoint.config)
        for directive, expected in ((f"brix_krb5_principal {KRB5_SERVICE_PRINCIPAL};", 3),
                                    (f"brix_krb5_keytab    {KRB5_KEYTAB};", 3),
                                    (f"brix_storage_backend posix:{planes.endpoint.data_root};", 3)):
            assert rendered.count(directive) == expected, (
                f"{directive!r} appears {rendered.count(directive)} times, "
                f"expected {expected}\n{rendered}")

    def test_the_start_up_notice_never_names_the_directive(self, planes):
        """FINDING #95, the config-time half: the krb5 acceptor announces its
        principal, its keytab and its ip_check value — and says nothing at all
        about delegation, so the three planes emit identical notices and an
        operator cannot tell from the log which server is armed."""
        notices = [line for line in planes.errlog().splitlines()
                   if NOTICE in line]
        def _assert_test_the_start_up_notice_never_names_the_directive_2():
            assert notices, f"no krb5 configuration notice at all\n{planes.errlog()}"
            assert all("ip_check=" in line for line in notices), notices

        _assert_test_the_start_up_notice_never_names_the_directive_2()
        assert not any("delegate" in line for line in notices), (
            "the notice has learned to mention delegation — #95's config-time "
            "half is fixed and this case should become its regression pin\n"
            + "\n".join(notices))

    def test_the_notices_are_indistinguishable(self, planes):
        """The same statement from the other side: strip the position each
        notice carries and the three planes' lines are one string."""
        bodies = {line.split(NOTICE, 1)[1].split(" in ")[0].strip()
                  for line in planes.errlog().splitlines() if NOTICE in line}
        assert len(bodies) == 1, (
            f"the planes' notices already differ, so #95 is narrower than "
            f"recorded: {bodies}")


# --------------------------------------------------------------------------- #
# B. The instrument                                                            #
# --------------------------------------------------------------------------- #

class TestTheTickets:
    """The one flag the whole table is a function of."""

    def test_the_forwardable_ticket_carries_the_f_flag(self, planes):
        """success: `kinit -f` really did get a forwardable TGT.  Without this
        the refusals below would be measuring a KDC policy, not a directive."""
        assert "F" in _ticket_flags(planes.forwardable), (
            f"the -f ticket is not forwardable: "
            f"{_ticket_flags(planes.forwardable)!r}")

    def test_the_stock_ticket_does_not(self, planes):
        """And the cache every other krb5 test in the suite uses does not —
        which is what makes it the right stand-in for a real client."""
        assert "F" not in _ticket_flags(planes.stock), (
            f"the stock ticket is forwardable after all: "
            f"{_ticket_flags(planes.stock)!r}")

    def test_both_tickets_name_the_same_principal(self, planes):
        """Same user, same realm, same keytab: the only difference between the
        two caches is the flag above."""
        for ccache in (planes.forwardable, planes.stock):
            out = subprocess.run([SYS_KLIST, "-c", "FILE:" + str(ccache)],
                                 env={**os.environ, "KRB5_CONFIG": KRB5_CONF},
                                 capture_output=True, text=True,
                                 timeout=30).stdout
            assert KRB5_CLIENT_PRINCIPAL in out, out


# --------------------------------------------------------------------------- #
# C. The armed arm                                                             #
# --------------------------------------------------------------------------- #

class TestTheArmedPlane:
    """`brix_krb5_delegate on` — what the corpus already wrote, measured for
    the first time against the arms that did not."""

    def test_a_forwardable_ticket_logs_in(self, planes):
        """success: the arm is not a refusal machine — a client that can meet
        the requirement is served normally."""
        result = _xrdfs(planes.on, planes.forwardable, "stat", READ_FILE)
        assert result.returncode == 0, (
            f"a forwardable ticket was refused by the armed plane\n"
            f"{_text(result)}\n{planes.errlog()}")

    def test_the_session_can_read(self, planes):
        """And the session is a real one: the login yields file access, not a
        bare handshake."""
        result = _xrdfs(planes.on, planes.forwardable, "cat", READ_FILE)
        assert result.returncode == 0, _text(result)
        assert READ_BODY.decode() in result.stdout, (
            f"the delegated session read nothing\n{_text(result)}")

    def test_the_login_costs_exactly_one_extra_round(self, planes):
        """The mechanism, on the wire: one kXR_authmore, which is the
        continuation the acceptor sends INSTEAD of the session it had already
        earned the right to grant."""
        result, rounds = _counted(planes, planes.on, planes.forwardable,
                                  "stat", READ_FILE)
        assert result.returncode == 0, _text(result)
        assert rounds == 1, (
            f"expected exactly one kXR_authmore, saw {rounds}: "
            f"{planes.relay.statuses}")

    def test_the_capture_marker_names_the_user(self, planes):
        """The airtight proof the capture ran rather than the challenge merely
        being sent: the acceptor logs the marker only after it has decrypted
        and imported the forwarded KRB_CRED."""
        mark = planes.errmark()
        assert _xrdfs(planes.on, planes.forwardable, "stat",
                      READ_FILE).returncode == 0
        slice_ = planes.errsince(mark)
        assert MARKER in slice_, f"no capture marker\n{slice_}"
        assert 'for "alice"' in slice_, (
            f"the marker does not name the mapped principal\n{slice_}")

    def test_the_armed_plane_is_answered_by_the_stock_client(self, planes):
        """Every verdict in this file is upstream's client, which is worth
        saying once explicitly: the fwdtgt continuation is XrdSeckrb5's own
        forwarding exchange, so arming it does not require this repo's."""
        result = _xrdfs(planes.on, planes.forwardable, "stat", READ_FILE)
        assert result.returncode == 0, _text(result)
        assert SYS_XRDFS is not None and "client/bin" not in SYS_XRDFS


# --------------------------------------------------------------------------- #
# D. The arm nobody wrote                                                      #
# --------------------------------------------------------------------------- #

class TestTheArmNobodyWrote:
    """`brix_krb5_delegate off` — written here for the first time."""

    def test_a_forwardable_ticket_logs_in_with_no_extra_round(self, planes):
        """success: the same client and the same ticket as §C, one directive
        later — and the continuation is gone."""
        result, rounds = _counted(planes, planes.off, planes.forwardable,
                                  "stat", READ_FILE)
        assert result.returncode == 0, _text(result)
        assert rounds == 0, (
            f"the off arm still sent {rounds} kXR_authmore: "
            f"{planes.relay.statuses}")

    def test_the_ticket_the_armed_plane_refuses_is_accepted_here(self, planes):
        """The pair, in one sentence: the credential §E measures being turned
        away is served by the arm nobody had written."""
        result = _xrdfs(planes.off, planes.stock, "stat", READ_FILE)
        assert result.returncode == 0, (
            f"the off arm refused a stock ticket\n{_text(result)}\n"
            f"{planes.errlog()}")

    def test_nothing_is_captured(self, planes):
        """No marker, and no ccache: `off` does not merely skip the challenge,
        it never touches the client's credentials at all."""
        mark = planes.errmark()
        before = set(_captures())
        assert _xrdfs(planes.off, planes.forwardable, "stat",
                      READ_FILE).returncode == 0
        assert MARKER not in planes.errsince(mark), planes.errsince(mark)
        assert set(_captures()) - before == set(), (
            "the off arm wrote a forwarded-TGT ccache")

    def test_the_login_is_recorded_exactly_as_a_delegated_one(self, planes):
        """The off arm is not a downgrade in the log either: the access record
        carries the same method and the same mapped identity."""
        mark = planes.mark("off")
        assert _xrdfs(planes.off, planes.forwardable, "stat",
                      READ_FILE).returncode == 0
        records = planes.since("off", mark)
        assert any('"AUTH - krb5" OK' in line for line in records), records
        assert any('krb5 "alice"' in line for line in records), records

    def test_the_off_arm_still_refuses_a_credential_it_cannot_read(self, planes):
        """security-negative: removing the delegation requirement removes
        nothing else.  A blob that is not an AP-REQ is refused on this plane
        exactly as on the armed one — the arm governs what an authenticated
        client is additionally asked for, never whether it is authenticated."""
        status, errcode, message = _bad_credential(planes.off)
        assert status == kXR_error and errcode == kXR_NotAuthorized, (
            f"the off arm answered {status}/{errcode} to a malformed "
            f"credential")
        assert b"malformed krb5 credential" in message, message


# --------------------------------------------------------------------------- #
# E. The silent plane                                                          #
# --------------------------------------------------------------------------- #

class TestTheSilentPlane:
    """The directive unwritten — every krb5 server that never heard of it."""

    def test_absence_behaves_as_off(self, planes):
        """success: a stock ticket, which the armed plane refuses, is served."""
        result, rounds = _counted(planes, planes.absent, planes.stock,
                                  "stat", READ_FILE)
        assert result.returncode == 0, _text(result)
        assert rounds == 0, planes.relay.statuses

    def test_absence_captures_nothing_from_a_forwardable_ticket(self, planes):
        """And the other half: a client that COULD be asked is not."""
        mark = planes.errmark()
        before = set(_captures())
        assert _xrdfs(planes.absent, planes.forwardable, "stat",
                      READ_FILE).returncode == 0
        assert MARKER not in planes.errsince(mark)
        assert set(_captures()) - before == set()

    def test_the_merge_default_is_off(self):
        """Where the behaviour above comes from, pinned so a change to the
        default has to come past this file."""
        merge = _read(MERGE_C)
        assert "ngx_conf_merge_value(conf->krb5.delegate,       " \
               "prev->krb5.delegate,   0);" in merge, (
            "the delegate merge default is no longer 0")

    def test_all_three_planes_are_one_worker(self, planes):
        """The control file 17's #92 failed: three verdicts about one directive
        out of ONE process, which is what says the flag is per-server rather
        than a process global the last server in configuration order wins."""
        pid = int(_read(os.path.join(planes.logs, "nginx.pid")).strip())
        children = subprocess.run(["pgrep", "-P", str(pid)],
                                  capture_output=True, text=True).stdout.split()
        assert len(children) == 1, (
            f"expected one worker under {pid}, found {children}")
        refused = _xrdfs(planes.on, planes.stock, "stat", READ_FILE)
        assert refused.returncode != 0, _text(refused)
        for port, plane in ((planes.off, "off"), (planes.absent, "absent")):
            served = _xrdfs(port, planes.stock, "stat", READ_FILE)
            assert served.returncode == 0, (
                f"the {plane} plane in the same worker refused the ticket the "
                f"armed plane had just turned away\n{_text(served)}")


# --------------------------------------------------------------------------- #
# F. What the armed arm costs                                                  #
# --------------------------------------------------------------------------- #

class TestWhatTheArmCosts:
    """A client that authenticates and is refused anyway."""

    def test_a_stock_ticket_is_refused_on_the_armed_plane(self, planes):
        """security-negative: the client fails CLOSED.  It cannot answer the
        challenge and does not fall back to the single-round login it would
        have got from either other plane."""
        result = _xrdfs(planes.on, planes.stock, "stat", READ_FILE)
        assert result.returncode != 0, (
            f"a non-forwardable ticket was served by the armed plane\n"
            f"{_text(result)}")
        assert "Auth failed" in _text(result), _text(result)

    def test_the_refusal_is_the_forwarding_step_and_not_the_login(self, planes):
        """Which step failed, in the client's own words: the AP-REQ was fine
        and the KDC refused to issue a forwarded credential for it."""
        result = _xrdfs(planes.on, planes.stock, "stat", READ_FILE)
        assert "Unable to get forwarded credentials" in _text(result), (
            f"the stock client's diagnosis has changed\n{_text(result)}")

    def test_the_challenge_was_still_sent(self, planes):
        """The refusal is the client's, not the server's: the acceptor issued
        its one continuation and then never heard back."""
        result, rounds = _counted(planes, planes.on, planes.stock,
                                  "stat", READ_FILE)
        assert result.returncode != 0
        assert rounds == 1, (
            f"expected the challenge to go out anyway, saw {rounds}: "
            f"{planes.relay.statuses}")

    def test_the_refused_session_reads_nothing(self, planes):
        """security-negative: no partial grant.  The connection that failed the
        second round gets no file access at all."""
        result = _xrdfs(planes.on, planes.stock, "cat", READ_FILE)
        assert result.returncode != 0
        assert READ_BODY.decode() not in result.stdout, (
            f"a session that never completed authentication read the file\n"
            f"{_text(result)}")

    def test_this_repo_s_client_names_the_fix_and_upstream_s_does_not(self,
                                                                     planes):
        """The one place the clean-room client is the subject: both refuse, and
        only one tells the user which kinit flag they are missing.  Skipped
        rather than failed when the client has not been built — its absence
        says nothing about the directive."""
        if not BRIX_XRDFS.exists():
            pytest.skip("clean-room xrdfs not built")
        mine = _brix_xrdfs(planes.on, planes.stock, "stat", READ_FILE)
        assert mine.returncode != 0, _text(mine)
        assert "kinit -f" in _text(mine), (
            f"the clean-room client no longer names the fix\n{_text(mine)}")
        assert "kinit -f" not in _text(
            _xrdfs(planes.on, planes.stock, "stat", READ_FILE))


# --------------------------------------------------------------------------- #
# G. What an operator can see of it — DEFECT CANDIDATE #95                     #
# --------------------------------------------------------------------------- #

def _bad_credential(port):
    """One kXR_auth carrying a credtype the acceptor cannot read.

    The contrast case for #95, and the reason it is a wire client rather than
    xrdfs: no real client sends this, and the point is precisely that a refusal
    the SERVER makes is recorded while the refusal above is not.
    """
    from _test_pgwrite_cse_helpers import _handshake_login, _read_response

    sock = _handshake_login(url_host(HOST), port)
    try:
        cred = b"not-an-ap-req"
        sock.sendall(struct.pack("!2sH12s4sI", b"\x00\x03", kXR_auth,
                                 b"\x00" * 12, b"krb5", len(cred)) + cred)
        status, body = _read_response(sock)
    finally:
        _shutdown(sock)
    errcode = (struct.unpack("!I", body[:4])[0]
               if status == kXR_error and len(body) >= 4 else None)
    return status, errcode, body[4:]


class TestWhatAnOperatorCanSee:
    """FINDING #95 — the refusal that is neither logged nor counted."""

    def test_a_completed_delegation_is_logged(self, planes):
        """The baseline: the armed plane does write an AUTH record when the
        exchange finishes, so the silence below is about the failure and not
        about the plane."""
        mark = planes.mark("on")
        assert _xrdfs(planes.on, planes.forwardable, "stat",
                      READ_FILE).returncode == 0
        records = planes.since("on", mark)
        assert any('"AUTH - krb5" OK' in line for line in records), records

    def test_the_refusal_leaves_no_auth_record_at_all(self, planes):
        """FINDING #95: the same plane, one flag of the ticket different.  The
        client authenticated and got nothing, and the access log carries the
        LOGIN and the DISCONNECT with nothing between them."""
        mark = planes.mark("on")
        assert _xrdfs(planes.on, planes.stock, "stat",
                      READ_FILE).returncode != 0
        records = planes.since("on", mark)
        assert records, "the refused login is not in the access log at all"
        assert not any('"AUTH ' in line for line in records), (
            "the armed plane has learned to record a delegation refusal — #95 "
            "is fixed and this case should be inverted\n" + "\n".join(records))

    def test_the_refusal_moves_no_counter(self, planes):
        """The other face, and the one an operator watches: neither `ok` nor
        `fail` moves for a login that was refused."""
        mark = planes.mark("on")
        before = planes.auth_counts()
        assert _xrdfs(planes.on, planes.stock, "stat",
                      READ_FILE).returncode != 0
        # Read the counter only once the connection has finished logging, so a
        # counter that is merely LATE cannot pass for one that never moves.
        planes.since("on", mark)
        after = planes.auth_counts()
        assert after == before, (
            "brix_auth_total moved for a delegation refusal — #95 is fixed and "
            f"this case should be inverted: {before} -> {after}")

    def test_a_credential_the_server_rejects_is_both_logged_and_counted(
            self, planes):
        """The contrast that makes the two cases above a defect rather than a
        design: on the SAME plane in the same run, a refusal the acceptor
        itself makes writes an ERR record and moves `fail`."""
        mark = planes.mark("on")
        before = planes.auth_counts()
        status, errcode, _ = _bad_credential(planes.on)
        assert status == kXR_error and errcode == kXR_NotAuthorized
        records = planes.since("on", mark, needle="AUTH")
        assert any('"AUTH - krb5" ERR' in line for line in records), records
        after = planes.auth_counts()
        assert after.get("fail", 0) > before.get("fail", 0), (
            f"a malformed credential moved no fail counter: {before} -> "
            f"{after}")

    def test_a_delegated_login_is_counted_like_any_other(self, planes):
        """And the success side is no more informative: the armed plane's
        completed login moves `ok` by exactly what the off plane's does, so the
        counter cannot tell an operator whether delegation is happening."""
        before = planes.auth_counts()
        assert _xrdfs(planes.on, planes.forwardable, "stat",
                      READ_FILE).returncode == 0
        armed = planes.auth_counts()
        assert _xrdfs(planes.off, planes.forwardable, "stat",
                      READ_FILE).returncode == 0
        plain = planes.auth_counts()
        armed_delta = armed.get("ok", 0) - before.get("ok", 0)
        plain_delta = plain.get("ok", 0) - armed.get("ok", 0)
        assert armed_delta == plain_delta > 0, (
            f"armed +{armed_delta} vs plain +{plain_delta}: the counter has "
            f"learned to distinguish them, so #95 is narrower than recorded")

    def test_the_challenge_path_accounts_for_nothing(self):
        """Where #95 comes from, pinned in the C: every failure inside
        brix_krb5_begin_delegation is metered and logged, and the success
        return — the challenge itself — is not, because from the acceptor's
        point of view nothing has failed yet and nothing ever will."""
        source = _read(AUTH_C)
        body = source.split("brix_krb5_begin_delegation(brix_krb5_req_t *rq,",
                            1)[1].split("\n}\n", 1)[0]
        assert "brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_KRB5, 0);" in body
        tail = body.split("return brix_krb5_send_fwdtgt(ctx, c);", 1)[-1]
        assert "brix_metric_auth" not in tail and "brix_log_access" not in tail, (
            "the challenge path has learned to account for itself — #95 is "
            f"fixed and this case should be inverted\n{tail}")


# --------------------------------------------------------------------------- #
# H. Where the captured ticket lands — DEFECT CANDIDATE #96                    #
# --------------------------------------------------------------------------- #

