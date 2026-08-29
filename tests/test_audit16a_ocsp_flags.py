"""Test cases for audit16a_ocsp_flags — preamble (fixtures/helpers/mocks) lives in
_test_audit16a_ocsp_flags_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16a_ocsp_flags_helpers")


class TestTheEnableFlagDecidesWhetherRevocationIsChecked:

    def test_off_accepts_a_revoked_credential(self, ocsp, pki, responder):
        """The security-negative, and the reason the flag has to be tested by
        value.  The responder calls this certificate REVOKED — §A pins that
        from the other plane — and `off` never asks it, so the login succeeds.
        A site that writes `off` to work around a flaky responder is running
        with online revocation switched off, not degraded."""
        ok, result = _accepted(ocsp, OFF, pki, "revoked")
        assert ok, ("brix_ocsp off refused a revoked credential; either "
                    "the flag no longer gates the check (update this test) or "
                    f"the chain is broken for an unrelated reason\n"
                    f"{result.stderr}\n{_errlog(ocsp)[-2000:]}")

    def test_off_sends_no_request_at_all(self, ocsp, pki, responder):
        """The flag gates the QUERY, not just the verdict.  Written separately
        from the row above because a `enable off` that still queried and then
        ignored the answer would pass that one — and would still leak every
        user's certificate serial to the CA on every login."""
        responder.reset()
        _accepted(ocsp, OFF, pki, "revoked")
        assert responder.queries() == [], \
            f"brix_ocsp off queried the responder: {responder.queries()}"

    def test_on_rejects_a_revoked_credential(self, ocsp, pki, responder):
        """REVOKED is never overridden (ocsp.c:116), so this holds on the
        soft-fail plane as well as the strict one."""
        responder.reset()
        ok, result = _accepted(ocsp, ON, pki, "revoked")
        assert not ok, ("brix_ocsp on accepted a credential the "
                        f"responder calls REVOKED\n{result.stdout}")
        assert {"serial": CREDENTIALS["revoked"]["serial"],
                "verdict": "revoked"} in responder.queries(), (
            "the login was refused without the responder being asked — the "
            f"deny is not a revocation verdict: {responder.queries()}")

    def test_the_same_credential_differs_only_by_the_flag(self, ocsp, pki,
                                                          responder):
        """Two listeners, one process, one trust store, one certificate, and
        opposite verdicts.  Stated as one assertion so the pair cannot quietly
        become the same answer."""
        assert _accepted(ocsp, OFF, pki, "revoked")[0] is True
        assert _accepted(ocsp, ON, pki, "revoked")[0] is False


# --------------------------------------------------------------------------- #
# §B — brix_ocsp_soft_fail: what a NON-answer means                            #
# --------------------------------------------------------------------------- #

class TestTheSoftFailFlagDecidesWhatSilenceMeans:
    """Every credential in this class is a perfectly good certificate that the
    responder does not vouch for: UNKNOWN, unreachable, or with no responder
    published at all.  The flag is the whole difference between them being
    admitted and being refused."""

    @pytest.mark.parametrize("credential", ["unknown", "dead", "plain"])
    def test_soft_fail_on_admits_what_nobody_vouched_for(self, ocsp, pki,
                                                         credential):
        ok, result = _accepted(ocsp, ON, pki, credential)
        assert ok, (f"brix_ocsp_soft_fail on refused the {credential} "
                    f"credential\n{result.stderr}\n{_errlog(ocsp)[-2000:]}")

    @pytest.mark.parametrize("credential", ["unknown", "dead", "plain"])
    def test_soft_fail_off_refuses_what_nobody_vouched_for(self, ocsp, pki,
                                                           credential):
        ok, result = _accepted(ocsp, HARD, pki, credential)
        assert not ok, (f"brix_ocsp_soft_fail off accepted the {credential} "
                        f"credential — the strict token is not strict\n"
                        f"{result.stdout}")

    def test_the_strict_token_still_admits_a_good_answer(self, ocsp, pki,
                                                         responder):
        """The attribution control for the class: `soft_fail off` refuses a
        non-answer, not every login.  Without this row a strict plane that
        denied unconditionally — the obvious way to get the three rows above
        green — would read as strictness working."""
        responder.reset()
        ok, result = _accepted(ocsp, HARD, pki, "good")
        assert ok, ("brix_ocsp_soft_fail off refused a credential the "
                    f"responder calls GOOD\n{result.stderr}\n"
                    f"{responder.queries()}\n{_errlog(ocsp)[-2000:]}")
        assert {"serial": CREDENTIALS["good"]["serial"], "verdict": "good"} \
            in responder.queries(), responder.queries()

    def test_a_dead_responder_is_reached_for_and_not_merely_skipped(
            self, ocsp, pki, responder):
        """The `dead` credential's AIA names DEAD_PORT, which nothing binds, so
        its refusal above must come from a failed connection — never from the
        live responder having answered something.  Pins the two unreachable
        cases apart from each other."""
        responder.reset()
        _accepted(ocsp, HARD, pki, "dead")
        assert responder.queries() == [], (
            "the dead credential's query reached the LIVE responder — its AIA "
            f"is pointing at the wrong port: {responder.queries()}")


# --------------------------------------------------------------------------- #
# §C — the merge default                                                       #
# --------------------------------------------------------------------------- #

class TestTheMergeDefault:
    """conf_structs.h:532 merges the unset field to 1.  Soft-fail is therefore
    the token every deployment that writes only `brix_ocsp on` runs, and
    until this class existed nothing asserted it from outside the C."""

    def test_the_absent_flag_tolerates_a_missing_answer(self, ocsp, pki):
        ok, result = _accepted(ocsp, DEFAULT, pki, "dead")
        assert ok, ("with brix_ocsp_soft_fail absent an unreachable responder "
                    f"denied the login — the default is not on\n"
                    f"{result.stderr}\n{_errlog(ocsp)[-2000:]}")

    def test_the_absent_flag_still_enforces_revocation(self, ocsp, pki):
        """The half that keeps the default from being vacuous: soft-fail is not
        no-fail, and REVOKED denies under it."""
        ok, result = _accepted(ocsp, DEFAULT, pki, "revoked")
        assert not ok, ("with brix_ocsp_soft_fail absent a revoked credential "
                        f"was accepted\n{result.stdout}")

    def test_the_absent_plane_answers_exactly_as_the_on_plane(self, ocsp, pki):
        """Both directions at once, over every credential, so a future change
        to the default has to break this test rather than drift past the two
        above."""
        for credential in CREDENTIALS:
            assert (_accepted(ocsp, DEFAULT, pki, credential)[0]
                    == _accepted(ocsp, ON, pki, credential)[0]), \
                f"default and `on` disagree on the {credential} credential"


# --------------------------------------------------------------------------- #
# §D — attribution: which certificate is asked about, and every plane agrees   #
# --------------------------------------------------------------------------- #

class TestWhatIsActuallyAskedAbout:

    def test_the_query_is_about_the_proxy_the_client_presented(
            self, ocsp, pki, responder):
        """``leaf = sk_X509_value(chain, 0)`` (auth_cert.c:280) and the client
        puts its proxy first, so the certificate whose revocation is checked is
        the short-lived proxy — not the EEC that identifies the user.  Both
        carry an AIA here, so the log says which one it was rather than which
        one happened to have a URL."""
        responder.reset()
        assert _accepted(ocsp, ON, pki, "good")[0]
        assert responder.serials() == [CREDENTIALS["good"]["serial"]], (
            "the OCSP query was not about the proxy the client presented: "
            f"{responder.queries()}")

    @pytest.mark.parametrize("plane", ALL_PLANES)
    def test_every_plane_accepts_the_good_credential(self, ocsp, pki, plane):
        """The attribution control for the whole file: one credential the
        responder vouches for, accepted on all four listeners.  Without it a
        broken chain — a mis-hashed CA directory, an expired proxy — would read
        as revocation working."""
        ok, result = _accepted(ocsp, plane, pki, "good")
        assert ok, (f"{plane}: a GOOD credential was refused\n{result.stderr}"
                    f"\n{_errlog(ocsp)[-2000:]}")

    def test_four_listeners_over_one_store_still_disagree(self, ocsp, pki):
        """The four planes name an IDENTICAL brix_trusted_ca and differ only in
        two flags.  Were the per-server OCSP config merged from a shared parent
        — or were the store cache keyed on the CA path alone — this whole file
        would collapse to a single row."""
        verdicts = {plane: _accepted(ocsp, plane, pki, "unknown")[0]
                    for plane in ALL_PLANES}
        assert verdicts == {OFF: True, ON: True, HARD: False, DEFAULT: True}, \
            verdicts


# --------------------------------------------------------------------------- #
# §E — the finding (DEFECT CANDIDATE #55)                                      #
# --------------------------------------------------------------------------- #

class TestTheStrictTokenIsUndeployable:
    """`soft_fail off` is documented as "require a definitive answer".  On a GSI
    site it means "refuse everyone"."""

    def test_the_strict_token_refuses_an_ordinary_globus_proxy(self, ocsp, pki,
                                                               responder):
        """DEFECT CANDIDATE #65.  The `plain` credential is exactly what
        xrdgsiproxy mints: a valid RFC 3820 proxy off a valid EEC, with no AIA,
        because a proxy has no reason to carry one.  X509_get1_ocsp(leaf)
        returns nothing, ocsp.c:147 takes the soft-fail default, and under the
        strict token that default is a deny — with no responder involved at
        all, which the empty query log proves.

        Pinning the defect, not endorsing it: when the check learns to walk the
        chain for an AIA (the EEC has one, two certificates away), or to
        separate "no responder published" from "the responder did not answer",
        this assertion should be inverted."""
        responder.reset()
        ok, result = _accepted(ocsp, HARD, pki, "plain")
        assert not ok, ("brix_ocsp_soft_fail off now admits a proxy with no "
                        "AIA — defect candidate #65 is fixed; invert this "
                        f"test\n{result.stdout}")
        assert responder.queries() == [], (
            "a credential with no AIA reached the responder — the URL is being "
            f"found somewhere other than the leaf: {responder.queries()}")

    def test_the_same_proxy_is_admitted_by_every_other_plane(self, ocsp, pki):
        """The scale of the defect: the credential the strict plane refuses is
        the one every other configuration in the file accepts, and it is the
        only shape real users have."""
        verdicts = {plane: _accepted(ocsp, plane, pki, "plain")[0]
                    for plane in ALL_PLANES}
        assert verdicts == {OFF: True, ON: True, HARD: False, DEFAULT: True}, \
            verdicts


# --------------------------------------------------------------------------- #
# §G — the crash this file found (DEFECT CANDIDATE #64, fixed)                 #
# --------------------------------------------------------------------------- #

class TestTheWorkerSurvivesTheQuery:
    """The regression pin for the double free.

    Every other assertion in this file reads a single login's verdict, and a
    worker that dies AFTER answering still produces the right verdict for that
    login — which is exactly how the bug hid: the first run of this file was
    green on the `enable off` plane and timed out everywhere else.  These tests
    ask the different question of whether the process is still there.
    """

    def test_the_process_serves_a_second_login_after_a_query(self, ocsp, pki,
                                                             responder):
        """Two logins on one worker.  Before the fix the first one freed the
        OCSP_CERTID twice and the worker took SIGSEGV on the way out, so the
        second login met a freshly respawned process — or nothing at all."""
        assert _accepted(ocsp, ON, pki, "good")[0]
        assert _accepted(ocsp, ON, pki, "good")[0], (
            "the second login on the same worker failed — the OCSP query is "
            f"killing the process again\n{_errlog(ocsp)[-3000:]}")

    @pytest.mark.parametrize("credential", ["good", "revoked", "unknown",
                                            "dead"])
    def test_no_verdict_kills_the_worker(self, ocsp, pki, credential,
                                         responder):
        """Every outcome the responder can produce, plus the unreachable one.
        The crash was in the shared teardown, so it fired on GOOD, REVOKED,
        UNKNOWN and connect-failure alike — a security-negative in its own
        right, since the AIA URL comes from the client's certificate and any
        client could therefore choose to take the worker down."""
        _accepted(ocsp, HARD, pki, credential)
        log = _errlog(ocsp)
        assert "exited on signal" not in log, (
            f"the {credential} credential crashed the worker:\n{log[-3000:]}")

    def test_the_error_log_records_no_crash_across_the_whole_table(self, ocsp,
                                                                   pki,
                                                                   responder):
        """The whole matrix against one process.  Cheaper than it looks — the
        instance is already up — and it is the only test here that would catch
        a crash that needs two different verdicts in sequence to trigger."""
        for plane in ALL_PLANES:
            for credential in CREDENTIALS:
                _accepted(ocsp, plane, pki, credential)
        log = _errlog(ocsp)
        assert "exited on signal" not in log, log[-3000:]


# --------------------------------------------------------------------------- #
# §F — the parse tier                                                          #
# --------------------------------------------------------------------------- #

FLAGS = ("brix_ocsp", "brix_ocsp_soft_fail", "brix_ocsp_stapling",
         "brix_ocsp_require_nonce")


def _parse(tmp_path, knobs="", stream_extra=""):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit16aparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, DATA_ROOT=str(data),
                     LOG_DIR=str(tmp_path), KNOBS=knobs,
                     STREAM_EXTRA=stream_extra)
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


class TestTheParseTier:
    """`on` and `off` are the only two tokens ngx_conf_set_flag_slot accepts,
    matched case-insensitively after a length test — so `On` parses and `1`,
    `true` and `yes` do not, for all four OCSP flags at once."""

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("token", ["on", "off"])
    def test_each_token_is_accepted(self, tmp_path, flag, token):
        rc, out = _parse(tmp_path, f"        brix_auth none;\n"
                                   f"        {flag} {token};\n")
        assert rc == 0, f"{flag} {token} was refused:\n{out}"

    @pytest.mark.parametrize("token", ["ON", "Off", "oN"])
    def test_the_token_is_matched_case_insensitively(self, tmp_path, token):
        """ngx_conf_set_flag_slot compares with ngx_strcasecmp, so an
        operator's `On` parses.  Written down because a future hand-rolled
        setter using ngx_strcmp would silently reject it — and, worse, a
        hand-rolled one that defaulted instead of erroring would turn `ON` into
        `off` with no diagnostic."""
        rc, out = _parse(tmp_path, f"        brix_auth none;\n"
                                   f"        brix_ocsp {token};\n")
        assert rc == 0, f"brix_ocsp {token} was refused:\n{out}"

    @pytest.mark.parametrize("token", ["1", "true", "yes", "soft"])
    def test_a_value_outside_the_pair_is_refused(self, tmp_path, token):
        """`1`, `true` and `yes` are the three words an operator reaches for
        that are not the pair, and none of them may parse into a silent
        default: `brix_ocsp 1` quietly meaning `off` would be a
        revocation check that never runs."""
        rc, out = _parse(tmp_path, f"        brix_auth none;\n"
                                   f"        brix_ocsp {token};\n")
        assert rc != 0, f"brix_ocsp {token} parsed:\n{out}"
        assert "invalid value" in out, out

    @pytest.mark.parametrize("line", ["brix_ocsp;",
                                      "brix_ocsp on off;"])
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, line):
        rc, out = _parse(tmp_path, f"        brix_auth none;\n        {line}\n")
        assert rc != 0, f"{line} parsed:\n{out}"
        assert "invalid number of arguments" in out, out

    def test_the_directive_is_refused_outside_a_server(self, tmp_path):
        """NGX_STREAM_SRV_CONF only (module.c:509).  A stream-level line is a
        parse error, not a default inherited by every server — which matters
        because an operator who wrote one stream-wide `brix_ocsp on`
        must not believe every listener is checking revocation."""
        rc, out = _parse(tmp_path, "        brix_auth none;\n",
                         stream_extra="    brix_ocsp on;\n")
        assert rc != 0, f"brix_ocsp was accepted in stream {{}}:\n{out}"
        assert "directive is not allowed here" in out, out
