"""Test cases for audit16v_tpc_off_arms — preamble (fixtures/helpers/mocks) lives in
_test_audit16v_tpc_off_arms_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16v_tpc_off_arms_helpers")


# --------------------------------------------------------------------------- #
# G — brix_tpc_outbound_tls off: refusing to be dragged into TLS
# --------------------------------------------------------------------------- #
class TestTheOutboundTlsArm:

    def test_the_disarmed_arm_refuses_a_tls_demanding_source(self, planes,
                                                             clean_proxy):
        """[the token, and it is the fail-CLOSED one] Uniquely among the seven,
        this arm's ``off`` refuses where ``on`` continues: a source that answers
        kXR_gotoTLS is telling the destination that everything after the
        protocol reply must ride TLS, and a destination that cannot do that must
        stop rather than keep talking in cleartext."""
        clean_proxy.arm_gate(gototls=True)
        name = planes.seed()
        status, err, dst = planes.pull("pulling", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_error, (status, err)
        assert "TPC source requires TLS" in err, err
        assert "set brix_tpc_outbound_tls on" in err, err
        _assert_no_poison(planes, dst)

    def test_the_armed_arm_attempts_the_upgrade_instead(self, planes,
                                                        clean_proxy):
        """The other side of the same frame: with the directive on the
        destination honours the demand and starts a handshake.  The splice is
        not a TLS endpoint, so the pull still fails — but on the handshake, not
        on the policy, and the two are told apart by the message."""
        clean_proxy.arm_gate(gototls=True)
        name = planes.seed()
        status, err, dst = planes.pull("armed", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_error, (status, err)
        assert "set brix_tpc_outbound_tls on" not in err, err
        _assert_no_poison(planes, dst)

    def test_a_clean_source_is_unaffected_by_either_arm(self, planes,
                                                        clean_proxy):
        """[no false positive] Neither arm changes a pull from a source that
        never asks for TLS — which is what keeps the armed plane's clean pull in
        §F honest."""
        name = planes.seed()
        for plane in ("armed", "pulling"):
            status, err, dst = planes.pull(plane, planes.source_url(name),
                                           source_name=name)
            assert status == kXR_OK, (plane, status, err)
            assert planes.disk(dst).read_bytes() == PAYLOAD

    def test_the_advertisement_is_gated_by_the_same_flag(self):
        """Source pin: the flag decides both what is advertised and what is done
        with the answer, which is why an off destination normally never sees a
        gotoTLS at all and the splice has to forge one."""
        text = _source(BOOTSTRAP_C)
        assert "t->conf->tpc_outbound_tls ? kXR_ableTLS : 0" in text
        assert "if (!t->conf->tpc_outbound_tls) {" in text
        assert "TPC source requires TLS; set brix_tpc_outbound_tls on" in text


# --------------------------------------------------------------------------- #
# H — brix_tpc_outbound_passthrough on: a default-on flag that must never deny
# --------------------------------------------------------------------------- #
class TestTheOutboundPassthroughArm:

    def test_the_on_arm_never_denies_an_anonymous_pull(self, planes,
                                                       clean_proxy):
        """The property the default exists to preserve: an anonymous pull that
        worked before the flag became default-on still works, because the
        opportunistic mode treats a missing inbound token as "nothing to
        forward" rather than as a refusal."""
        name = planes.seed()
        status, err, dst = planes.pull("pulling", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_OK, (status, err)
        assert planes.disk(dst).read_bytes() == PAYLOAD

    def test_the_off_arm_does_not_deny_one_either(self, planes, clean_proxy):
        """And the arm the corpus writes costs nothing here — the difference
        between the two is which token is FORWARDED, not who is admitted."""
        name = planes.seed()
        status, err, dst = planes.pull("armed", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_OK, (status, err)
        assert planes.disk(dst).read_bytes() == PAYLOAD

    def test_an_explicit_passthrough_is_refused_on_the_on_arm(self, planes,
                                                              clean_proxy):
        """[security-neg] The distinction the default-on flag must not blur: a
        CLIENT that explicitly asks for ``tpc.token_mode=passthrough`` gets
        strict, fail-closed semantics, and the server-side default does not
        quietly downgrade that request to the opportunistic mode."""
        name = planes.seed()
        status, err, dst = planes.pull(
            "pulling", planes.source_url(name), source_name=name,
            extra_opaque="tpc.token_mode=passthrough")
        assert status == kXR_error, (status, err)
        assert "passthrough requested but no inbound bearer" in err, err
        _assert_no_poison(planes, dst)

    def test_an_explicit_passthrough_is_refused_on_the_off_arm_too(
            self, planes, clean_proxy):
        """Neither arm rescues it: the client's own field wins verbatim, which
        is what makes the flag's two arms a choice about the DEFAULT and not
        about what a client may ask for."""
        name = planes.seed()
        status, err, dst = planes.pull(
            "armed", planes.source_url(name), source_name=name,
            extra_opaque="tpc.token_mode=passthrough")
        assert status == kXR_error, (status, err)
        assert "passthrough requested but no inbound bearer" in err, err
        _assert_no_poison(planes, dst)

    def test_the_three_way_decision_is_in_one_place(self):
        """Source pin.  The behavioural cases above cannot separate "flag off"
        from "flag on with no inbound token" — both leave nothing to forward —
        so what the arms differ in is pinned to the C that decides it."""
        text = _source(PREPARE_C)
        idx = text.index("if (tpc->has_token_mode && tpc->token_mode[0]")
        window = text[idx:idx + 600]
        assert "} else if (conf->tpc_outbound_passthrough) {" in window, window
        assert '"passthrough-opt"' in window, window
        assert "file->tpc_token_mode[0] = '\\0';" in window, window


# --------------------------------------------------------------------------- #
# I — brix_tpc_delegate off, and the postconfiguration that ignores it
# --------------------------------------------------------------------------- #
class TestTheDelegationArmAndItsOverride:
    """DEFECT CANDIDATE #99.

    ``brix_config_prepare_server`` (``runtime_server.c:441-448``) turns delegation
    back ON whenever a tap proxy authenticates with GSI, guarded by
    ``!xcf->tpc_delegate``.  It runs from ``postconfiguration``, i.e. AFTER the
    merge — and after the merge an explicit ``off`` and an unwritten directive
    are the same zero.  So the operator who deliberately wrote
    ``brix_tpc_delegate off`` beside a GSI tap proxy gets delegation enabled
    anyway, and the NOTICE that reports it reads as though nothing was
    overridden.  The upgrade may well be the right default; being unable to
    decline it is the finding.
    """

    NOTICE = "brix_tap_proxy_auth gsi: enabling GSI proxy delegation capture"

    def test_the_override_plane_reports_the_upgrade(self, planes):
        """The OVERRIDE plane writes ``off`` and the server says it enabled it."""
        assert self.NOTICE in planes.errorlog(), (
            "the tap-proxy delegation upgrade no longer reports itself; if it "
            "now honours the explicit off, this file's finding is fixed and the "
            "section should say so")

    def test_no_other_plane_reports_it(self, planes):
        """One plane per LOAD, which is the only form the claim can take.

        The upgrade is decided at configuration time and the config is loaded
        more than once into one error.log (the launcher validates the file, then
        starts it), so a bare count over the log counts loads rather than planes.
        The line nginx cites cannot separate them either — postconfiguration runs
        after the parse, so every conf-time notice cites the last line of the
        file.  What does separate them is that each plane announces its own access
        log once per load: count the announcements of a plane that has NO tap
        proxy and that is the load count, and the NOTICE must appear exactly that
        often.  Five planes write or omit ``brix_tpc_delegate`` without a proxy
        and none of them is reported, so the upgrade follows the proxy rather
        than the directive.
        """
        log = planes.errorlog()
        loads = log.count('/armed.log" registered')
        assert loads >= 1, log
        assert log.count(self.NOTICE) == loads, log

    def test_the_c_cannot_tell_an_explicit_off_from_an_omission(self):
        """Why the operator has no way to decline: by the time the test runs,
        the value it inspects has already been merged."""
        text = _source(RUNTIME_C)
        idx = text.index("BRIX_PROXY_AUTH_GSI")
        window = text[idx:idx + 400]
        assert "!xcf->tpc_delegate" in window, window
        assert "xcf->tpc_delegate = 1;" in window, window
        assert "brix_config_prepare_server" in _source(POSTCONF_C), (
            "the upgrade is no longer reached from postconfiguration; recheck "
            "whether it still runs after the merge")

    def test_the_directive_has_no_third_state(self):
        """``ngx_conf_set_flag_slot`` stores 0 or 1 and ``NGX_CONF_UNSET`` is
        gone after the merge — so "the operator said off" is not recoverable
        later even in principle.  Any fix has to record the write, not re-read
        the value."""
        text = _source(DIRECTIVES_H)
        block = text.split('ngx_string("brix_tpc_delegate")')[1][:300]
        assert "ngx_conf_set_flag_slot" in block, block
        assert "NGX_CONF_FLAG" in block, block

    def test_the_arm_governs_a_login_round_and_not_only_a_pull(self):
        """Source pin: what the operator is unable to decline.

        The overridden flag is not read only at pull launch.  It also decides
        whether a VERIFIED GSI login is completed or answered with kXGS_pxyreq —
        an extra handshake round demanded of every GSI client on the server
        (``auth/gsi/auth_cert.c``), where a client that cannot sign the
        delegated proxy is refused kXR_NotAuthorized.  So an operator who writes
        ``off`` beside a GSI tap proxy is silently opted back in to a change in
        what logging in REQUIRES, which is why the override is a finding rather
        than a note about a default.
        """
        text = _source(AUTH_CERT_C)
        idx = text.index("if (conf->tpc_delegate && !ctx->gsi.deleg_await")
        window = text[idx:idx + 500]
        assert "brix_gsi_begin_delegation" in window, window
        assert "GSI proxy delegation failed" in window, window
        assert "kXR_NotAuthorized" in window, window


# --------------------------------------------------------------------------- #
# J — the census: the gap is a fact about the corpus, so it is asserted there
# --------------------------------------------------------------------------- #
class TestTheArmsAtConfigTime:

    def test_this_file_is_the_only_writer_of_the_disarming_arms(self):
        """All seven rows of the census, in one assertion.

        If another config starts writing one of these arms, this is where that
        becomes visible — either the new writer covers it and a plane here is
        redundant, or it is a placeholder rendering and the census is being
        satisfied by something ungreppable.
        """
        # nginx_audit16w_wdegress.conf joined the census when its
        # brix_webdav_tpc_* spellings were unified onto the bare brix_tpc_*
        # names — its egress-off arms are the same directives now.
        allowed = {"nginx_audit16v_tpc_off_arms.conf",
                   "nginx_audit16w_wdegress.conf"}
        for directive, value in sorted(DISARMING_ARM.items()):
            writers = _corpus_writers(directive, value)
            assert writers and set(writers) <= allowed, (
                f"{directive} {value} is written by {writers}")

    def test_the_arming_arm_was_already_written(self):
        """The asymmetry that IS the gap: every one of the seven had its other
        arm spelled somewhere before this file existed."""
        for directive, value in sorted(ARMING_ARM.items()):
            writers = [w for w in _corpus_writers(directive, value)
                       if w != "nginx_audit16v_tpc_off_arms.conf"]
            assert writers, f"{directive} {value} was never written either"

    def test_the_template_spells_every_arm_literally(self):
        """Not through a placeholder.  The audit counts an arm as covered only
        when ``<directive> <value>;`` is greppable, so a ``{SLOT}`` that renders
        to ``off`` would exercise the path and leave the next census reporting
        the same gap."""
        text = _source(TEMPLATE)
        for directive, value in sorted(DISARMING_ARM.items()):
            assert _writes(text, directive, value), \
                f"{directive} {value}; is not spelled literally"
            assert _writes(text, directive, ARMING_ARM[directive]), \
                f"{directive} {ARMING_ARM[directive]}; is not spelled literally"

    def test_the_template_writes_each_arm_the_expected_number_of_times(self):
        """A whole-line scan, not a substring count — the file's own header
        names all seven directives repeatedly, and counting those would let a
        config that writes nothing at all look fully armed."""
        text = _source(TEMPLATE)
        expected = {
            # ARMED, DISARMED, PULLING, ORDERING
            "brix_tpc_allow_local": ["on", "off", "on", "off"],
            # ARMED, DISARMED, PULLING, ORDERING
            "brix_tpc_source_guard": ["on", "off", "off", "on"],
            # ARMED, DISARMED, PULLING
            "brix_require_pgwrite": ["on", "off", "off"],
            "brix_tpc_outbound_tls": ["on", "off", "off"],
            "brix_tpc_require_source_size": ["on", "off", "off"],
            "brix_tpc_outbound_passthrough": ["off", "on", "on"],
            # ARMED, DISARMED, PULLING, OVERRIDE
            "brix_tpc_delegate": ["on", "off", "off", "off"],
        }
        for directive, arms in sorted(expected.items()):
            found = re.findall(rf"^\s*{directive}\s+(on|off)\s*;\s*$",
                               text, re.MULTILINE)
            assert found == arms, (directive, found)

    def test_the_absent_plane_writes_none_of_the_seven(self):
        """The plane that measures the defaults must not accidentally set one."""
        text = _source(TEMPLATE)
        block = text.split("ABSENT:")[1].split("PULLING:")[0]
        for directive in sorted(DISARMING_ARM):
            assert directive not in block, (directive, block)

    def test_the_ledger_names_every_plane_the_file_uses(self):
        """The instance is shared-port; a plane the ledger does not know about
        is a port nothing reserves.  Read back from the config rather than from
        this module's own constants, so a listener added to the template without
        a ledger slot fails here."""
        text = _source(TEMPLATE)
        placeholders = set(re.findall(r"listen \{(\w+)\}", text))
        assert placeholders == {"PORT"} | set(_EXTRA), (placeholders,
                                                        set(_EXTRA))
        assert len(set(_EXTRA.values())) == len(_EXTRA), _EXTRA
        assert LIFECYCLE_SHARED_PORTS[NAME]["port"] not in _EXTRA.values()

    def test_every_directive_is_a_server_scoped_flag(self):
        """Why the file has six planes and no ``stream {}``-level case: not one
        of the seven carries ``NGX_STREAM_MAIN_CONF``, so a plane is the only
        thing that can hold a value and there is no inheritance to override."""
        text = _source(DIRECTIVES_H)
        for directive in sorted(DISARMING_ARM):
            block = text.split(f'ngx_string("{directive}")')[1][:300]
            assert "NGX_STREAM_SRV_CONF | NGX_CONF_FLAG" in block, \
                (directive, block)
            assert "NGX_STREAM_MAIN_CONF" not in block, (directive, block)
            assert "ngx_conf_set_flag_slot" in block, (directive, block)
