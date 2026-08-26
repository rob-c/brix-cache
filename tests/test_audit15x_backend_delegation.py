"""Test cases for audit15x_backend_delegation — preamble (fixtures/helpers/mocks) lives in
_test_audit15x_backend_delegation_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit15x_backend_delegation_helpers")


class TestWhatTheOriginIsShown:
    """The directive's only purpose is the credential on the outbound leg, so
    every case here reads that leg directly.  All six locations share one
    origin, one JWKS and one empty credential directory: the mode is the only
    thing that differs."""

    def test_passthrough_forwards_the_callers_own_bearer(self, deleg):
        """success: the mode that works, and the reference every other row is
        read against.  The origin is shown the exact bytes the client
        presented — not a re-issued token, not the service credential."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, saw = _saw(endpoint, origin, PASSTHROUGH, token)
        assert status == 200, status
        assert saw == ["CALLER"], (
            "brix_backend_delegation passthrough stopped forwarding the "
            f"caller's bearer to the backend: origin saw {saw}")

    def test_exchange_without_an_endpoint_forwards_verbatim(self, deleg):
        """success: the documented §5.4 fallback (deleg_wire.c:49-54).  With no
        endpoint to exchange AT, EXCHANGE is the second live-bag mode and
        behaves as passthrough — which is worth pinning, because the failure
        mode of a misconfigured exchange must be "forwarded the original", not
        "forwarded nothing"."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, saw = _saw(endpoint, origin, EXCHANGE, token)
        assert status == 200, status
        assert saw == ["CALLER"], (
            "exchange without an endpoint no longer forwards the bearer "
            f"verbatim: origin saw {saw}")

    def test_the_absent_directive_sends_no_credential(self, deleg):
        """The control.  With no per-user credential on disk the SELECT export
        proceeds on the service credential, and this backend has none — so the
        origin is asked without any Authorization at all."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, saw = _saw(endpoint, origin, SELECT, token)
        assert status == 200, status
        assert saw == ["none"], (
            f"a non-delegating export put a credential on the wire: {saw}")

    @pytest.mark.parametrize("mode", DROPPING)
    def test_the_three_unwritten_modes_forward_nothing(self, deleg, mode):
        """DEFECT CANDIDATE #56(a), the core measurement.

        Each of these locations differs from /select/ by exactly one line — the
        delegation mode — and the outbound leg is identical.  The caller's
        bearer was captured at the front door and bound onto the VFS ctx
        (access.c:515); vfs_cred_live_bag (vfs_cred.c:119-132) handles
        PASSTHROUGH and EXCHANGE only, so the bag is never opened."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, saw = _saw(endpoint, origin, mode, token)
        assert status == 200, status
        assert saw == ["none"], (
            f"brix_backend_delegation {mode} now puts something on the backend "
            f"leg ({saw}).  If the mode was implemented, this file's table, "
            "§D's fail-closed rows and §E's counters all change with it")

    def test_the_six_row_table(self, deleg):
        """success + error in one measurement: the shape of the claim is the
        SPLIT, not any single row.  Six locations, one caller, one token."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        expected = {mode: (["CALLER"] if mode in FORWARDING else ["none"])
                    for mode in ALL_MODES}
        got = {mode: _saw(endpoint, origin, mode, token)[1]
               for mode in ALL_MODES}
        assert got == expected, (
            "the mode -> forwarded-credential table moved:\n"
            + "\n".join(f"  {mode:<12} {str(got[mode]):>28}"
                        f"  (expected {expected[mode]})"
                        for mode in ALL_MODES if got[mode] != expected[mode]))

    def test_a_dropping_mode_logs_what_a_plain_export_logs(self, deleg):
        """DEFECT CANDIDATE #56(a), the operator's half: there is no line to
        find.  The INFO written on a /delegate/ request is the same sentence a
        /select/ request writes, and it names neither the mode nor the
        credential that was captured and discarded."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "delegwitness")
        _probe(endpoint, origin, DELEGATE, token)
        text = _await(endpoint, 'principal="delegwitness"')
        lines = [ln for ln in text.splitlines()
                 if 'principal="delegwitness"' in ln]
        def _assert_test_a_dropping_mode_logs_what_a_plain_export_logs_1():
            assert lines, f"the delegate leg logged nothing at all\n{text[-2000:]}"
            assert all(FALLBACK_LINE in ln for ln in lines), (
                "the delegate leg now says something other than the plain "
                "service-credential fallback — pin the new wording here\n"
                + "\n".join(lines))

        _assert_test_a_dropping_mode_logs_what_a_plain_export_logs_1()
        assert not any("delegat" in _message(ln) for ln in lines), (
            "the log now names the delegation mode; #56(a) is diagnosable and "
            "this assertion should become the pin for the new line\n"
            + "\n".join(lines))


# --------------------------------------------------------------------------- #
# §B — the front door DOES know the mode                                       #
# --------------------------------------------------------------------------- #

class TestTheFrontDoorKnowsTheMode:
    """The three modes are not inert everywhere: access.c:256 arms
    X-Brix-Delegate-Proxy capture for every mode except SELECT, and the shared
    parser refuses that header outright over a cleartext transport
    (deleg_capture.c:78-84).  So they change a verdict — just not the one the
    directive exists to change."""

    PROXY_HEADER = "X-Brix-Delegate-Proxy"
    # Never a real proxy: the transport check runs first, so the bytes are only
    # ever required to be present.
    JUNK = "bm90LWEtcHJveHkK"

    @pytest.mark.parametrize("mode", DROPPING)
    def test_a_dropping_mode_still_refuses_a_cleartext_proxy_header(
            self, deleg, mode):
        """security-negative, and the only measurable difference these three
        modes make on this plane: a private key must never ride cleartext, so
        the header is 403'd before the request reaches storage."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, tags = _probe(endpoint, origin, mode, token,
                              headers={self.PROXY_HEADER: self.JUNK})
        assert status == 403, (
            f"a delegating export ({mode}) accepted {self.PROXY_HEADER} over "
            f"cleartext (http={status})")
        assert tags == [], (
            "the request was refused but the origin was contacted anyway: "
            f"{tags}")

    def test_passthrough_refuses_it_too(self, deleg):
        """The contrast within the delegating half: the gate is keyed on
        "not SELECT", not on "the mode the live bag implements"."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, tags = _probe(endpoint, origin, PASSTHROUGH, token,
                              headers={self.PROXY_HEADER: self.JUNK})
        assert (status, tags) == (403, []), (status, tags)

    def test_a_non_delegating_export_ignores_the_header(self, deleg):
        """success: /select/ never runs the capture, so the same header on the
        same listener is served — which is what makes the 403s above an
        observable property of the MODE rather than of the header."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, saw = _saw(endpoint, origin, SELECT, token,
                           headers={self.PROXY_HEADER: self.JUNK})
        assert status == 200, (
            "a plain SELECT export started policing X-Brix-Delegate-Proxy; "
            "the capture gate is supposed to be skipped for it")
        assert saw == ["none"], saw


# --------------------------------------------------------------------------- #
# §C — minting: the mode, or the CA?                                           #
# --------------------------------------------------------------------------- #

def _minted(directory, sub):
    path = Path(directory) / f"{sub}.pem"
    return path if path.exists() else None


class TestWhatIsMinted:
    """``mint`` is documented LANDED.  It is — but nothing about it is driven
    by the mode: vfs_cred_maybe_mint (vfs_cred.c:152-174) reads the mint CA and
    never the mode.  /mintca/ and /selmint/ are identical configurations except
    for that one line, over two separate directories."""

    def test_the_mode_alone_mints_nothing(self, deleg):
        """error: /mint/ carries the token and no mint CA.  Nothing is written,
        and the request completes on the service credential — the same outcome
        as /select/."""
        endpoint, origin, dirs, issuer = deleg
        token = _token(issuer, "mintnoca")
        status, saw = _saw(endpoint, origin, MINT, token)
        assert (status, saw) == (200, ["none"]), (status, saw)
        assert list(dirs["empty"].iterdir()) == [], (
            "brix_backend_delegation mint minted into a directory with no mint "
            f"CA configured: {sorted(p.name for p in dirs['empty'].iterdir())}")

    def test_the_ca_mints_under_mint_mode(self, deleg):
        """success: with a CA, the leg mints a per-user proxy keyed on the
        token subject and re-resolves it in the same request."""
        endpoint, origin, dirs, issuer = deleg
        token = _token(issuer, "mintca")
        status, _tags = _saw(endpoint, origin, "mintca", token)
        assert status == 200, status
        assert _minted(dirs["mint"], "mintca"), (
            "a mint CA + mint mode minted nothing: "
            f"{sorted(p.name for p in dirs['mint'].iterdir())}")

    def test_the_same_ca_mints_under_select_too(self, deleg):
        """DEFECT CANDIDATE #56(b): the mode is neither necessary nor
        sufficient.  /selmint/ writes ``brix_backend_delegation select`` beside
        the same CA and mints the identical artefact."""
        endpoint, origin, dirs, issuer = deleg
        token = _token(issuer, "selmint")
        status, _tags = _saw(endpoint, origin, "selmint", token)
        assert status == 200, status
        assert _minted(dirs["sel"], "selmint"), (
            "the mint CA no longer mints under SELECT — if minting became "
            "mode-gated, #56(b) is closed and this test states the new rule: "
            f"{sorted(p.name for p in dirs['sel'].iterdir())}")

    def test_the_minted_credential_is_not_world_readable(self, deleg):
        """security-negative: what is minted is a private key on disk.  0600 is
        the only acceptable mode for it, and the check is worth making on the
        artefact rather than trusting the umask that produced it."""
        endpoint, origin, dirs, issuer = deleg
        token = _token(issuer, "mintperm")
        _saw(endpoint, origin, "mintca", token)
        path = _minted(dirs["mint"], "mintperm")
        assert path is not None, "nothing was minted to inspect"
        assert path.stat().st_mode & 0o077 == 0, (
            f"minted credential {path.name} is group/other-accessible "
            f"(mode {path.stat().st_mode & 0o777:04o})")

    def test_the_minted_credential_never_reaches_a_cleartext_origin(self, deleg):
        """security-negative, and the honest limit of minting on this plane: an
        x509 proxy is not a bearer, and this backend speaks http.  So the mint
        succeeds, a private key is written per principal, and the outbound leg
        carries no credential at all — the cost is paid and the benefit is
        not."""
        endpoint, origin, dirs, issuer = deleg
        token = _token(issuer, "mintwire")
        status, saw = _saw(endpoint, origin, "mintca", token)
        assert status == 200, status
        assert _minted(dirs["mint"], "mintwire"), "nothing was minted"
        assert saw == ["none"], (
            "a minted x509 proxy reached an http:// origin as an "
            f"Authorization header: {saw}")


# --------------------------------------------------------------------------- #
# §D — the fail-closed posture                                                 #
# --------------------------------------------------------------------------- #

class TestTheFailClosedPosture:
    """``brix_storage_credential_fallback deny`` is how an operator hardens a
    delegated export: never touch the origin on the service credential.  A mode
    that really carries the caller's credential satisfies it.  The four /deny*/
    locations share one empty credential directory and differ only in mode."""

    def test_passthrough_survives_the_fail_closed_posture(self, deleg):
        """success: the live bag is a credential, so the deny policy is
        satisfied without any file on disk."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, saw = _saw(endpoint, origin, "denypass", token)
        assert (status, saw) == (200, ["CALLER"]), (status, saw)

    def test_a_hardened_select_export_refuses(self, deleg):
        """error: the control.  No per-user credential, deny policy, so the
        request is refused BEFORE the origin is contacted."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, tags = _probe(endpoint, origin, "denyselect", token)
        assert status == 403, status
        assert tags == [], f"a refused request still contacted the origin: {tags}"

    @pytest.mark.parametrize("leg", ["denydeleg", "denyauto"])
    def test_a_hardened_delegating_export_refuses_identically(self, deleg, leg):
        """DEFECT CANDIDATE #56(a), the deployment shape.  An operator who
        writes ``delegate`` (or ``auto``) and then hardens the export gets an
        export that refuses every request — the mode contributed no credential,
        so the deny policy has nothing to accept."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, tags = _probe(endpoint, origin, leg, token)
        assert (status, tags) == (403, []), (
            f"/{leg}/ no longer refuses like a plain hardened export "
            f"(http={status}, origin={tags})")

    def test_the_refusal_names_the_directory_and_the_policy(self, deleg):
        """The one thing the operator IS told, pinned so the diagnostic cannot
        regress into a bare 403: the principal, the key, the directory that was
        searched, and that the fallback policy is what refused."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "denywitness")
        _probe(endpoint, origin, "denydeleg", token)
        text = _await(endpoint, 'principal="denywitness"')
        lines = [ln for ln in text.splitlines()
                 if 'principal="denywitness"' in ln]
        assert lines, f"the refusal was not logged\n{text[-2000:]}"
        assert all(REFUSE_LINE in ln for ln in lines), (
            "the fail-closed refusal changed wording\n" + "\n".join(lines))

    def test_the_hardened_table(self, deleg):
        """The whole posture in one measurement: hardening separates the modes
        that carry a credential from the modes that only claim to."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        got = {leg: _probe(endpoint, origin, leg, token)[0]
               for leg in ("denyselect", "denydeleg", "denyauto", "denypass")}
        assert got == {"denyselect": 403, "denydeleg": 403,
                       "denyauto": 403, "denypass": 200}, got


# --------------------------------------------------------------------------- #
# §E — what Prometheus reports                                                 #
# --------------------------------------------------------------------------- #

class TestWhatPrometheusReports:
    """``brix_cred_deleg_total`` is the only mode-labelled credential counter.
    Its emitters are the live-bag path (vfs_deleg.c) and a successful mint
    (vfs_cred.c:166) — so what an operator can and cannot see from a dashboard
    is decided by which modes reach those two sites."""

    @pytest.mark.parametrize("mode", FORWARDING)
    def test_a_forwarding_mode_moves_its_own_row(self, deleg, mode):
        """success: exactly one counter moves, and it carries the mode."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        before = _scrape(endpoint)
        _saw(endpoint, origin, mode, token)
        moved = _moved(endpoint, before)
        assert moved == {_deleg(mode, "user"): 1}, (
            f"the {mode} leg no longer records exactly one delegation "
            f"outcome: {moved}")

    @pytest.mark.parametrize("mode", DROPPING)
    def test_a_dropping_mode_moves_the_mode_blind_counter(self, deleg, mode):
        """DEFECT CANDIDATE #56(c): the drop is invisible on a dashboard.

        No row of brix_cred_deleg_total moves for these three; what moves is
        brix_cred_select_fallback_total, which carries a proto label and no
        mode label — the same series a non-delegating export moves."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        before = _scrape(endpoint)
        _saw(endpoint, origin, mode, token)
        moved = _moved(endpoint, before)
        assert moved == {SELECT_FALLBACK: 1}, (
            f"the {mode} leg's counters changed: {moved}.  If a mode-labelled "
            "row moved, #56(c) is closed and this test should assert it")

    def test_the_hardened_refusal_is_mode_blind_too(self, deleg):
        """security-negative: a fail-closed delegating export refuses, and the
        refusal is counted under the mode-blind deny series.  An operator
        alerting on brix_cred_deleg_total{outcome="deny"} would see nothing at
        all while every request was being refused."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        before = _scrape(endpoint)
        status, tags = _probe(endpoint, origin, "denydeleg", token)
        assert (status, tags) == (403, []), (status, tags)
        moved = _moved(endpoint, before)
        assert moved == {SELECT_DENY: 1}, moved

    def test_the_select_control_is_indistinguishable(self, deleg):
        """The comparison that makes the three rows above a finding rather than
        a description: a plain export with no delegation directive at all moves
        the SAME series by the same amount."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        before = _scrape(endpoint)
        _saw(endpoint, origin, SELECT, token)
        assert _moved(endpoint, before) == {SELECT_FALLBACK: 1}

    def test_every_mode_name_is_exported_whether_or_not_it_fires(self, deleg):
        """INVARIANT #8.  The label vocabulary is a closed set rendered from a
        fixed table (unified.c:126-134), so the exposition carries a row for
        every (proto, mode, outcome) triple — including the modes that can
        never increment.  A mode rendered from user input, or a row that
        appeared only after first use, would be an unbounded label."""
        endpoint, _origin, _dirs, _issuer = deleg
        series = _scrape(endpoint)
        missing = [mode for mode in ALL_MODES
                   for outcome in ("user", "fallback", "deny")
                   if _deleg(mode, outcome) not in series]
        assert not missing, (
            f"brix_cred_deleg_total is missing rows for: {sorted(set(missing))}")

    def test_no_row_carries_a_mode_outside_the_table(self, deleg):
        """security-negative: an out-of-range mode renders "unknown" by design
        rather than emitting whatever integer was stored.  Nothing on this
        listener should produce even that."""
        endpoint, _origin, _dirs, _issuer = deleg
        known = set(ALL_MODES)
        seen = set()
        for series in _scrape(endpoint):
            if series.startswith("brix_cred_deleg_total") and 'mode="' in series:
                seen.add(series.split('mode="', 1)[1].split('"', 1)[0])
        assert seen == known, (
            f"brix_cred_deleg_total's mode label vocabulary is {sorted(seen)}, "
            f"expected exactly {sorted(known)}")


# --------------------------------------------------------------------------- #
# §F — per-caller isolation                                                    #
# --------------------------------------------------------------------------- #

class TestPerCallerIsolation:
    """A forwarding mode is only useful if it forwards the RIGHT credential.
    One listener, one location, three requests from two callers."""

    def test_each_caller_gets_its_own_bearer_on_the_backend_leg(self, deleg):
        """success: alice, then bob, then alice again — the origin sees each
        caller's own token, and the first caller's credential is not still in
        play when the second arrives."""
        endpoint, origin, _dirs, issuer = deleg
        alice = _token(issuer, "alice")
        bob = _token(issuer, "bob")
        for who, token in (("alice", alice), ("bob", bob), ("alice", alice)):
            status, saw = _saw(endpoint, origin, PASSTHROUGH, token)
            assert (status, saw) == (200, ["CALLER"]), (
                f"{who}'s request forwarded something else: {saw}")

    def test_a_second_callers_token_is_never_the_first_callers(self, deleg):
        """security-negative, stated on the bytes rather than on a tag: bob's
        request must not carry alice's token.  A per-conf credential cache keyed
        on anything but the caller would fail exactly here."""
        endpoint, origin, _dirs, issuer = deleg
        alice = _token(issuer, "alice")
        bob = _token(issuer, "bob")
        _get(endpoint, PASSTHROUGH, alice)
        del origin.recorded[:]
        _get(endpoint, PASSTHROUGH, bob)
        headers = [rec.get("authorization") or "" for rec in origin.recorded]
        def _assert_test_a_second_callers_token_is_never_the_first_callers_2():
            assert headers, "bob's request never reached the origin"
            assert all(bob in value for value in headers), \
                "bob's request did not carry bob's token"

        _assert_test_a_second_callers_token_is_never_the_first_callers_2()
        assert not any(alice in value for value in headers), (
            "alice's bearer was replayed on bob's request — the forwarded "
            "credential is being cached across callers")

    def test_a_caller_the_front_door_refuses_never_reaches_the_origin(
            self, deleg):
        """security-negative: a token for a different audience is refused at the
        WebDAV auth gate, so no delegation decision is ever taken.  Worth
        measuring on the origin: a mode that forwarded first and authorised
        afterwards would leak a rejected caller's token to the backend."""
        endpoint, origin, _dirs, issuer = deleg
        wrong = _token(issuer, "mallory", audience="somewhere-else.example")
        status, tags = _probe(endpoint, origin, PASSTHROUGH, wrong)
        assert status == 401, (
            f"a wrong-audience token was not refused at the front door: {status}")
        assert tags == [], (
            f"a refused caller's request reached the backend anyway: {tags}")


# --------------------------------------------------------------------------- #
# §G — the documentation against the C                                         #
# --------------------------------------------------------------------------- #

VFS_CRED_C = ROOT / "src" / "fs" / "vfs" / "vfs_cred.c"
DELEG_DOC = ROOT / "docs" / "10-reference" / "backend-delegation.md"
FALLTHROUGH = "DELEGATE/MINT are left to fall through to select+mint for now."


def _mode_row(text, mode):
    for line in text.splitlines():
        if line.startswith(f"| `{mode}`"):
            return line
    return ""


class TestTheDocumentationAgainstTheC:
    """Static, and deliberately so: the run-time sections above measure what
    happens, and these two measure what a reader is told it will.  Both sides
    are pinned, so closing the gap from either end fails this class."""

    def test_the_c_still_says_two_modes_fall_through(self):
        """The source of truth for §A.  When this comment goes, either the
        modes were implemented (and §A's table changes) or the comment rotted
        away from the code (and this test is the only thing that would say
        so)."""
        assert VFS_CRED_C.exists(), VFS_CRED_C
        assert FALLTHROUGH in VFS_CRED_C.read_text(encoding="utf-8"), (
            f"{VFS_CRED_C.name} no longer documents the fall-through; if "
            "DELEGATE/MINT are now live-bag modes, §A's table is the thing to "
            "update")

    def test_the_live_bag_still_handles_exactly_two_modes(self):
        """The comment could be true and the code not.  vfs_cred_live_bag's
        condition is the actual gate, so it is read directly."""
        text = VFS_CRED_C.read_text(encoding="utf-8")
        assert "if (m == BRIX_CRED_PASSTHROUGH || m == BRIX_CRED_EXCHANGE) {" \
            in text, ("vfs_cred_live_bag's mode test changed shape — re-measure "
                      "§A before trusting this file's table")

    def test_the_docs_are_honest_about_delegate(self):
        """The one row that already says so.  Kept as a positive assertion so
        the finding below is scoped to the two rows that do not."""
        row = _mode_row(DELEG_DOC.read_text(encoding="utf-8"), "delegate")
        assert row, "the Modes table lost its `delegate` row"
        assert "Partial" in row, (
            f"the `delegate` row's status changed: {row.strip()}")

    def test_the_docs_over_claim_auto(self):
        """DEFECT CANDIDATE #56, the documentation half.

        `auto` is documented as "Best available of the above for the backend"
        and LANDED.  Measured (§A), it is the worst available: on the same
        listener, with the same caller and the same origin, `auto` forwards
        nothing where `passthrough` forwards the caller's own bearer.  Pinned
        rather than tolerated — when the row is corrected this test fails, and
        the fix is to assert the new status."""
        row = _mode_row(DELEG_DOC.read_text(encoding="utf-8"), "auto")
        assert row, "the Modes table lost its `auto` row"
        assert "LANDED" in row, (
            "the `auto` row no longer claims LANDED — update this test to the "
            f"corrected status and close #56: {row.strip()}")

    def test_the_docs_credit_the_mode_for_what_the_ca_does(self):
        """DEFECT CANDIDATE #56(b), the documentation half: the `mint` row
        reads as though the mode drives the minting.  §C measures that the CA
        does, under any mode."""
        row = _mode_row(DELEG_DOC.read_text(encoding="utf-8"), "mint")
        assert row, "the Modes table lost its `mint` row"
        assert "LANDED" in row and "brix_storage_credential_mint_ca" in row, (
            f"the `mint` row changed; re-read §C against it: {row.strip()}")


# --------------------------------------------------------------------------- #
# §H — the parse tier                                                          #
# --------------------------------------------------------------------------- #

def _knobs(*lines):
    return "".join(f"            {line}\n" for line in lines)


def _diagnostics(out):
    """The lines of an `nginx -t` transcript that would tell an operator
    something is wrong.  Matching on the transcript as a whole cannot work: the
    prefix is a tmp_path named after the test, so every mode name this file
    tests appears in the output as part of a directory."""
    return [ln for ln in out.splitlines()
            if any(sev in ln for sev in ("[warn]", "[error]", "[crit]",
                                         "[emerg]"))]


def _parse(tmp_path, knobs="", http_extra="", outer=""):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit15x_delegparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, DATA_ROOT=str(data),
                     LOG_DIR=str(tmp_path), KNOBS=knobs,
                     HTTP_EXTRA=http_extra, OUTER=outer)
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


class TestTheParseTier:
    """What the enum accepts and refuses.  Nothing here starts a server, and
    every case damages only its own tmp_path copy of the scaffold."""

    @pytest.mark.parametrize("token", ALL_MODES)
    def test_every_token_in_the_table_parses(self, tmp_path, token):
        """success: the enum table, the stream-plane mirror
        (protocols/root/stream/module.c:56-67) and the documentation all agree
        on the spelling of all six — including the three no config writes."""
        rc, out = _parse(tmp_path, _knobs(f"brix_backend_delegation {token};"))
        assert rc == 0, f"brix_backend_delegation {token} was rejected\n{out}"

    @pytest.mark.parametrize("token", ["PassThrough", "AUTO"])
    def test_the_token_is_case_insensitive(self, tmp_path, token):
        """ngx_conf_set_enum_slot compares with ngx_strcasecmp, so the config
        language is case-insensitive here while the audit's own grep for
        written values is not — which is the reason a value-granularity sweep
        has to read the enum table rather than the configs alone."""
        rc, out = _parse(tmp_path, _knobs(f"brix_backend_delegation {token};"))
        assert rc == 0, f"the enum rejected {token!r}\n{out}"

    def test_an_unknown_token_is_refused(self, tmp_path):
        """error: a misspelt mode must not silently leave SELECT in place — the
        failure mode would be an export that quietly stops delegating."""
        rc, out = _parse(tmp_path, _knobs("brix_backend_delegation forward;"))
        assert rc != 0 and 'invalid value "forward"' in out, out

    def test_the_enum_number_is_not_a_token(self, tmp_path):
        """error: the mode is a small integer internally and appears as one in
        conf dumps.  The enum takes names only, and says so."""
        rc, out = _parse(tmp_path, _knobs("brix_backend_delegation 1;"))
        assert rc != 0 and 'invalid value "1"' in out, out

    def test_an_empty_value_is_refused(self, tmp_path):
        """security-negative: an unset shell variable expanding to "" must not
        quietly become SELECT — an operator templating the mode per site would
        silently un-delegate every export."""
        rc, out = _parse(tmp_path, _knobs('brix_backend_delegation "";'))
        assert rc != 0 and 'invalid value ""' in out, out

    @pytest.mark.parametrize("line", ["brix_backend_delegation;",
                                      "brix_backend_delegation select mint;"])
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, line):
        """error: NGX_CONF_TAKE1.  "select mint" is the shape an operator
        reaches for when they want `auto`, and it must not parse as either."""
        rc, out = _parse(tmp_path, _knobs(line))
        assert rc != 0, f"{line!r} parsed\n{out}"
        assert 'invalid number of arguments in "brix_backend_delegation"' \
            in out, out

    def test_a_duplicate_directive_is_refused(self, tmp_path):
        """security-negative: two modes in one location would leave which one
        wins to the parser's ordering — and the two might differ in whether the
        caller's credential is forwarded at all."""
        rc, out = _parse(tmp_path, _knobs("brix_backend_delegation select;",
                                          "brix_backend_delegation mint;"))
        assert rc != 0 and \
            '"brix_backend_delegation" directive is duplicate' in out, out

    def test_the_directive_is_accepted_at_http_level(self, tmp_path):
        """success: BRIX_HTTP_ALL_CONF — a site-wide default is a legitimate
        way to write this, and brix_shared_adopt_unified (http_common.c:428)
        carries it down to a location that does not restate it."""
        rc, out = _parse(tmp_path,
                         http_extra="    brix_backend_delegation delegate;\n")
        assert rc == 0, f"an http-level brix_backend_delegation was rejected\n{out}"

    def test_the_directive_is_refused_outside_http(self, tmp_path):
        """security-negative: written at the top of the file it reads like a
        global default and would apply to nothing.  nginx must refuse it rather
        than ignore it."""
        rc, out = _parse(tmp_path, outer="brix_backend_delegation delegate;\n")
        assert rc != 0, f"a main-context brix_backend_delegation parsed\n{out}"
        assert '"brix_backend_delegation" directive is not allowed here' in out, \
            out

    @pytest.mark.parametrize("token", DROPPING)
    def test_an_unimplemented_mode_parses_without_a_word(self, tmp_path, token):
        """DEFECT CANDIDATE #56, parse-time half.

        Config parse is the last moment the fall-through is diagnosable: the
        mode is a compile-time-known constant and the C already knows it is not
        wired.  Nothing is said — no warning, no notice, nothing naming the
        directive — so an operator's only feedback is a backend leg that
        silently carries the service credential (§A)."""
        rc, out = _parse(tmp_path, _knobs(f"brix_backend_delegation {token};"))
        assert rc == 0, f"the mode stopped parsing\n{out}"
        assert _diagnostics(out) == [], (
            "the unimplemented mode is now diagnosed at parse time — pin the "
            f"new diagnostic here and close #56\n{out}")

    def test_mint_mode_without_a_mint_ca_parses_without_a_word(self, tmp_path):
        """DEFECT CANDIDATE #56(b), parse-time half: `mint` with nothing to
        mint with is accepted in silence, and so is a mint CA with no `mint`
        mode.  Neither half of the pair is checked against the other."""
        rc, out = _parse(tmp_path, _knobs("brix_backend_delegation mint;"))
        assert rc == 0, f"mint without a CA stopped parsing\n{out}"
        assert _diagnostics(out) == [], (
            f"the incomplete mint configuration is now diagnosed\n{out}")
