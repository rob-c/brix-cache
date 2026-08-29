"""Test cases for audit15z_disable_tokens — preamble (fixtures/helpers/mocks) lives in
_test_audit15z_disable_tokens_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit15z_disable_tokens_helpers")


# --------------------------------------------------------------------------- #
# A. every disabling token is the merged default — which is why none is written
# --------------------------------------------------------------------------- #
class TestTheTokensAreAllTheDefault:

    @pytest.mark.parametrize("directive,token,field,unit,default",
                             TOKENS, ids=TOKEN_IDS)
    def test_the_merge_folds_the_field_to_the_disabling_value(
            self, directive, token, field, unit, default):
        got = _merge_default(unit, field)
        assert got == default, (
            f"{directive}: the merge default moved from {default} to {got}; "
            "the premise of this whole file — that writing the disabling token "
            "is writing the default — no longer holds, so re-measure before "
            "editing the assertions", unit)

    @pytest.mark.parametrize("directive,token,field,unit,default",
                             TOKENS, ids=TOKEN_IDS)
    def test_the_token_is_spelled_in_the_enum_table(
            self, directive, token, field, unit, default):
        """The token has to be in the table, or the operator cannot write the
        default even when they want it stated explicitly in the config."""
        table = _source("src/protocols/root/stream/module_enums.c")
        flat = re.sub(r"\s+", " ", table)
        assert f'{{ ngx_string("{token}"), {default} }}' in flat, (
            f'{directive}: no enum entry mapping "{token}" to {default}', )

    def test_no_disabling_token_is_written_by_any_shipped_config(self):
        """The audit's count, re-derived rather than quoted: none of the five
        appears in tests/configs/ (which is what made them unwritten values in
        the first place).  A future test that DOES write one should be here, in
        this file, so update the exception list rather than deleting this."""
        allowed = {"nginx_audit15z_disable.conf",
                   "nginx_audit15z_disableparse.conf"}
        offenders = []
        for conf in sorted((ROOT / "tests/configs").glob("*.conf")):
            if conf.name in allowed:
                continue
            text = conf.read_text(errors="replace")
            for directive, token, _, _, _ in TOKENS:
                if re.search(rf"^\s*{directive}\s+{token}\s*;", text, re.M):
                    offenders.append(f"{conf.name}: {directive} {token}")
        assert not offenders, (
            "a shipped config now writes a disabling token — good, but this "
            "file's premise changed; fold the new coverage in", offenders)


# --------------------------------------------------------------------------- #
# B. brix_min_sec_level none — the floor really is per-server
# --------------------------------------------------------------------------- #
class TestTheSessionPostureFloor:

    def test_none_serves_what_compat_refuses(self, lifecycle, tmp_path, pki):
        endpoint = _start(lifecycle, tmp_path, pki,
                          a=("brix_min_sec_level compat;",),
                          b=("brix_min_sec_level none;",))
        assert _stat_status(endpoint.port) == KXR_ERROR, (
            "a cleartext anonymous session is below the compat floor",
            _errlog(endpoint))
        assert _stat_status(SECOND_PORT) == KXR_OK, (
            "the same session at `none` must be served", _errlog(endpoint))

    def test_writing_none_is_indistinguishable_from_writing_nothing(
            self, lifecycle, tmp_path, pki):
        endpoint = _start(lifecycle, tmp_path, pki,
                          a=("brix_min_sec_level compat;",), b=())
        assert _stat_status(endpoint.port) == KXR_ERROR, _errlog(endpoint)
        assert _stat_status(SECOND_PORT) == KXR_OK, (
            "silence must behave exactly as `none` did", _errlog(endpoint))

    def test_the_floor_is_not_decided_by_declaration_order(
            self, lifecycle, tmp_path, pki):
        """The mirror image of the first case.  A directive whose merge wrote a
        process-global would give the same answer on both ports here; this one
        swaps with the config, so it is decided per server."""
        endpoint = _start(lifecycle, tmp_path, pki,
                          a=("brix_min_sec_level none;",),
                          b=("brix_min_sec_level compat;",))
        assert _stat_status(endpoint.port) == KXR_OK, _errlog(endpoint)
        assert _stat_status(SECOND_PORT) == KXR_ERROR, _errlog(endpoint)


# --------------------------------------------------------------------------- #
# C. brix_gsi_signed_dh off — read off the advertised login sec token
# --------------------------------------------------------------------------- #
class TestTheAdvertisedGsiVersion:

    def test_off_advertises_the_universally_compatible_version(
            self, lifecycle, tmp_path, pki):
        endpoint = _start(lifecycle, tmp_path, pki,
                          c=("brix_gsi_signed_dh off;",))
        token = _sec_token(GSI_PORT)
        assert token.startswith("&P=gsi,"), (token, _errlog(endpoint))
        assert "v:10000" in token, (
            "off must advertise the unsigned-DH version", token)

    def test_silence_advertises_the_same_version_as_off(
            self, lifecycle, tmp_path, pki):
        endpoint = _start(lifecycle, tmp_path, pki, c=())
        token = _sec_token(GSI_PORT)
        assert "v:10000" in token, (
            "writing nothing must advertise exactly what `off` advertised",
            token, _errlog(endpoint))

    def test_auto_advertises_the_signed_dh_version(
            self, lifecycle, tmp_path, pki):
        """The control: 10000 is a choice, not a constant."""
        endpoint = _start(lifecycle, tmp_path, pki,
                          c=("brix_gsi_signed_dh auto;",))
        token = _sec_token(GSI_PORT)
        assert "v:10600" in token, (
            "auto must advertise the signed-DH-capable version",
            token, _errlog(endpoint))


# --------------------------------------------------------------------------- #
# D. brix_seccomp off — the token that cannot turn anything off
# --------------------------------------------------------------------------- #
def _worker_settled(endpoint):
    """A completed login proves the worker finished init_process: the worker
    answers requests only from its event loop, which it enters after every
    init hook — the seccomp install and its NOTICE included — has run.  The
    harness's TCP readiness proves only that the MASTER bound the listener,
    so reading the error log straight after lifecycle.start races the
    worker's first write (and loses on a warm back-to-back restart)."""
    sock, status, _ = _login(endpoint.port)
    sock.close()
    assert status == KXR_OK, ("login while settling the worker", status)
    return endpoint


class TestTheSeccompRatchet:

    def test_silence_everywhere_installs_no_filter(
            self, lifecycle, tmp_path, pki):
        endpoint = _worker_settled(_start(lifecycle, tmp_path, pki))
        assert _filter_lines(endpoint) == [], _errlog(endpoint)

    def test_off_everywhere_installs_no_filter(self, lifecycle, tmp_path, pki):
        endpoint = _worker_settled(_start(
            lifecycle, tmp_path, pki,
            a=("brix_seccomp off;",), b=("brix_seccomp off;",)))
        assert _filter_lines(endpoint) == [], (
            "`off` must not be more than silence", _errlog(endpoint))

    def _assert_one_audit_notice(self, endpoint):
        """The two cases below differ only in whether server B writes `off`,
        and the finding is that they are the same run.  One spec name can be
        registered once per test, so the two configurations cannot be started
        side by side; holding both to this one expectation — the whole message,
        counts included, not merely "a filter appeared" — is what makes the
        comparison a comparison rather than two loose assertions."""
        lines = [FILTER_LINE.search(ln) for ln in _filter_lines(endpoint)]
        assert len(lines) == 1, (
            "one worker installs the filter once, so one NOTICE",
            _filter_lines(endpoint), _errlog(endpoint))
        assert lines[0] is not None, (
            "the install NOTICE changed shape — re-measure both arms",
            _filter_lines(endpoint))

    def test_off_cannot_lower_a_sibling_servers_filter(
            self, lifecycle, tmp_path, pki):
        """DEFECT CANDIDATE #60, the operator-visible half: server B says off
        and gets the filter anyway, because the mode is a process-global that
        only ratchets up (0 is never greater than audit)."""
        self._assert_one_audit_notice(_worker_settled(_start(
            lifecycle, tmp_path, pki,
            a=("brix_seccomp audit;",), b=("brix_seccomp off;",))))

    def test_not_writing_off_beside_audit_is_the_same_run(
            self, lifecycle, tmp_path, pki):
        """The other half of the pair: delete server B's `off` line and nothing
        about the process changes.  The edit an operator would make to take the
        filter off their own server is inert."""
        self._assert_one_audit_notice(_worker_settled(_start(
            lifecycle, tmp_path, pki, a=("brix_seccomp audit;",), b=())))


# --------------------------------------------------------------------------- #
# E. where the token lands — DEFECT CANDIDATE #60
# --------------------------------------------------------------------------- #
class TestWhereTheValueLands:

    @pytest.mark.parametrize("field", READ_FIELDS)
    def test_the_per_server_field_has_a_reader(self, field):
        sites = _field_sites(field)
        assert sites, (
            f"conf->{field} is written by its directive and read by nothing — "
            "if this fired, a fifth directive just joined DEFECT CANDIDATE #60")

    def test_the_seccomp_field_is_written_and_never_read(self):
        """DEFECT CANDIDATE #60.  brix_seccomp is declared per-server in two
        directive tables and merged like a per-server value, but the merged
        value cannot reach any decision: the effect comes entirely from the
        process-global the setter bumps."""
        sites = _field_sites("seccomp")
        assert sites == [], (
            "conf->seccomp now has a reader — DEFECT CANDIDATE #60 may be "
            "fixed; re-measure and retire this assertion", sites)

    def test_the_setter_bumps_a_process_global_instead(self):
        source = _source("src/core/seccomp/seccomp.c")
        assert "brix_seccomp_worker_mode = e[i].value;" in source, source[:400]
        assert "if (e[i].value > brix_seccomp_worker_mode)" in source, (
            "the ratchet is what makes `off` inert: 0 is never greater than a "
            "mode another server already requested")


# --------------------------------------------------------------------------- #
# F. the duplicate guard — DEFECT CANDIDATE #59
# --------------------------------------------------------------------------- #
class TestTheDuplicateGuard:

    def test_the_guard_treats_off_as_unset(self):
        source = _source("src/core/seccomp/seccomp.c")
        flat = re.sub(r"\s+", " ", source)
        assert ("if (*field != NGX_CONF_UNSET_UINT && *field != "
                "BRIX_SECCOMP_OFF) { return \"is duplicate\"; }") in flat, (
            "DEFECT CANDIDATE #59's guard changed shape — re-measure the "
            "four order cases below before trusting them")

    def test_seccomp_off_twice_is_accepted(self, tmp_path):
        rc, out = _parse(tmp_path, knobs=_knob("brix_seccomp off;",
                                               "brix_seccomp off;"))
        assert rc == 0, (
            "pinned defect: the guard cannot see a repeated `off`", out)

    def test_seccomp_off_then_audit_is_accepted(self, tmp_path):
        rc, out = _parse(tmp_path, knobs=_knob("brix_seccomp off;",
                                               "brix_seccomp audit;"))
        assert rc == 0, ("pinned defect: `off` leaves the slot looking unset",
                         out)

    def test_seccomp_audit_then_off_is_refused(self, tmp_path):
        rc, out = _parse(tmp_path, knobs=_knob("brix_seccomp audit;",
                                               "brix_seccomp off;"))
        assert rc != 0, ("the same two lines, reversed, are a config error", out)
        assert '"brix_seccomp" directive is duplicate' in out, out

    def test_seccomp_audit_twice_is_refused(self, tmp_path):
        rc, out = _parse(tmp_path, knobs=_knob("brix_seccomp audit;",
                                               "brix_seccomp audit;"))
        assert rc != 0, out
        assert '"brix_seccomp" directive is duplicate' in out, out

    @pytest.mark.parametrize("directive,token", [
        (d, t) for d, t, _, _, _ in TOKENS if d != "brix_seccomp"],
        ids=[d for d, _, _, _, _ in TOKENS if d != "brix_seccomp"])
    def test_the_stock_enum_slot_catches_its_own_default_token(
            self, tmp_path, directive, token):
        """The control for DEFECT CANDIDATE #59.  These tokens are the merged
        default too, and every one of them is still diagnosed when doubled —
        ngx_conf_set_enum_slot tests against NGX_CONF_UNSET_UINT, which is what
        "the operator did not write this" actually means."""
        rc, out = _parse(tmp_path, knobs=_knob(f"{directive} {token};",
                                               f"{directive} {token};"))
        assert rc != 0, (f"{directive} {token} doubled must be refused", out)
        assert f'"{directive}" directive is duplicate' in out, out


# --------------------------------------------------------------------------- #
# G. brix_io_uring — DEFECT CANDIDATE #61
# --------------------------------------------------------------------------- #
class TestTheIoUringDefault:

    def test_the_merge_default_is_off(self):
        assert _merge_default("src/core/config/server_conf_merge_storage.c",
                              "io_uring") == "BRIX_IO_URING_OFF"

    @pytest.mark.parametrize("site,fragment",
                             [(s, f) for _, s, f in STALE_AUTO_SITES],
                             ids=[i for i, _, _ in STALE_AUTO_SITES])
    def test_the_documented_default_still_says_auto(self, site, fragment):
        """DEFECT CANDIDATE #61.  Pinned as a contradiction, not as a wish: the
        C is right and the prose is stale.  Each of these fragments is a place
        that tells the reader io_uring is best-effort-on out of the box, which
        it has not been since the auto->off flip.  When one is corrected this
        case fails — that is the signal to strike the site from the list, and
        when the last one goes, to close #61."""
        assert fragment in _source(site), (
            f"{site} no longer carries the stale `auto` default — DEFECT "
            f"CANDIDATE #61 is partly or wholly fixed; drop this entry",
            fragment)

    def test_off_and_auto_both_parse(self, tmp_path):
        for token in ("off", "auto"):
            rc, out = _parse(tmp_path, knobs=_knob(f"brix_io_uring {token};"))
            assert rc == 0, (f"brix_io_uring {token} must always parse — it "
                             "asks for nothing the build may lack", out)

    def test_on_is_the_only_token_a_build_can_refuse(self, tmp_path):
        """`on` is a hard requirement, so its verdict depends on the build.
        Both outcomes are correct; what must not happen is a silent accept that
        leaves the operator believing a ring is up."""
        rc, out = _parse(tmp_path, knobs=_knob("brix_io_uring on;"))
        if rc != 0:
            assert "requires a build with liburing" in out, out
        else:
            assert "brix_io_uring" not in out, (
                "an accepted `on` must not also be complaining about itself",
                out)


# --------------------------------------------------------------------------- #
# H. the parse tier — placement and spelling
# --------------------------------------------------------------------------- #
class TestTheParseTier:

    @pytest.mark.parametrize("directive,token", [(d, t) for d, t, _, _, _ in TOKENS],
                             ids=TOKEN_IDS)
    def test_the_token_parses_where_the_directive_is_declared(
            self, tmp_path, directive, token):
        rc, out = _parse(tmp_path, knobs=_knob(f"{directive} {token};"))
        assert rc == 0, out

    @pytest.mark.parametrize("directive,token", [(d, t) for d, t, _, _, _ in TOKENS],
                             ids=TOKEN_IDS)
    def test_the_token_is_matched_case_insensitively(
            self, tmp_path, directive, token):
        """Both setters compare with ngx_strcasecmp, so the audit has to count
        tokens from the enum table rather than from the spelling in a config."""
        rc, out = _parse(tmp_path, knobs=_knob(f"{directive} {token.upper()};"))
        assert rc == 0, (f"{directive} {token.upper()} must be the same token",
                         out)

    @pytest.mark.parametrize("directive,token", [(d, t) for d, t, _, _, _ in TOKENS],
                             ids=TOKEN_IDS)
    def test_the_directive_is_refused_in_the_main_context(
            self, tmp_path, directive, token):
        rc, out = _parse(tmp_path, outer=f"{directive} {token};\n")
        assert rc != 0, (f"{directive} at the top of the file must be refused, "
                         "not silently ignored", out)
        assert directive in out, out

    @pytest.mark.parametrize("directive", [d for d, _, _, _, _ in TOKENS
                                           if d != "brix_seccomp"])
    def test_the_stream_only_directives_are_refused_in_http(
            self, tmp_path, directive):
        token = dict((d, t) for d, t, _, _, _ in TOKENS)[directive]
        rc, out = _parse(tmp_path, http_lines=_knob(f"{directive} {token};"))
        assert rc != 0, (f"{directive} is NGX_STREAM_SRV_CONF only", out)
        assert directive in out, out

    def test_seccomp_off_is_accepted_in_an_http_server(self, tmp_path):
        """brix_seccomp is the one of the five declared for the http contexts
        as well (BRIX_HTTP_ALL_CONF) — an http-only WebDAV/S3 worker gets the
        same filter, so it must be spellable there."""
        rc, out = _parse(tmp_path, http_lines=_knob("brix_seccomp off;"))
        assert rc == 0, out

    @pytest.mark.parametrize("directive", TOKEN_IDS)
    def test_an_unknown_token_is_refused(self, tmp_path, directive):
        rc, out = _parse(tmp_path, knobs=_knob(f"{directive} banana;"))
        assert rc != 0, (f"{directive} must not accept an unknown token", out)
        assert "invalid value" in out, out

    def test_the_two_servers_may_disagree_without_a_diagnostic(self, tmp_path):
        """Recorded, not endorsed: two servers asking for different seccomp
        modes parse cleanly even though only one of them can win.  Nothing at
        parse time tells the operator which."""
        rc, out = _parse(tmp_path, knobs=_knob("brix_seccomp enforce;"),
                         second=_knob("brix_seccomp off;"))
        assert rc == 0, out
        assert "seccomp" not in out.lower(), (
            "a diagnostic appeared — the disagreement is now reported, which "
            "would be an improvement worth folding into this file", out)
