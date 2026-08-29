"""Test cases for audit16p_proxy_certs — preamble (fixtures/helpers/mocks) lives in
_test_audit16p_proxy_certs_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16p_proxy_certs_helpers")


class TestTheServerScopeArms:
    """What the flag decides, and what it does not.  Every row is a GET of the
    same URI against the same bytes; only the socket and the credential change."""

    def test_the_armed_server_admits_an_rfc3820_proxy_chain(self, arms):
        """The control every other row is measured against.  A proxy chain is
        three certificates deep and its leaf is not a CA, so OpenSSL admits it
        only because X509_V_FLAG_ALLOW_PROXY_CERTS was set on this listener's
        verify parameters — nothing else in the configuration differs."""
        r = arms.get("srv-on", "rfc3820")
        assert r.status_code == 200, (r.status_code, arms.errlog()[-2000:])
        assert r.content == SEED, r.content[:80]

    def test_the_off_arm_refuses_the_same_chain(self, arms):
        """The arm the corpus never wrote.  Same CA, same EEC, same proxy, same
        bytes behind the export — refused, because this SSL_CTX was never told
        that a proxy is admissible."""
        r = arms.get("srv-off", "rfc3820")
        assert r.status_code == 400, (r.status_code, arms.errlog()[-2000:])
        assert r.content != SEED

    def test_the_refusal_names_the_flag(self, arms):
        """security-neg: the refusal must be about the proxy policy and not about
        trust.  OpenSSL's error 40 says the chain was well-formed and its issuer
        trusted, and that a proxy certificate was not allowed — which is the only
        reading that makes the 200 above a statement about the flag."""
        arms.get("srv-off", "rfc3820")
        reasons = arms.awaited_reasons("srv-off", NO_PROXY_ALLOWED)
        assert any(NO_PROXY_ALLOWED in line for line in reasons), reasons

    def test_the_armed_server_never_logs_that_refusal(self, arms):
        """The other half of the same reading: the flag removes the error rather
        than moving it somewhere else.  The armed listener is asked for the same
        chain, and the log is given the same time to say so as the row above."""
        assert arms.get("srv-on", "rfc3820").status_code == 200
        reasons = arms.awaited_reasons("srv-on", NO_PROXY_ALLOWED)
        assert not any(NO_PROXY_ALLOWED in line for line in reasons), reasons

    @pytest.mark.parametrize("arm", ARMS)
    def test_the_plain_eec_is_admitted_everywhere(self, arms, arm):
        """The attribution control.  The SAME identity without a proxy in front
        of it verifies on all three sockets, so the proxy row above cannot be
        read as "client certificates work here and not there" — the CA, the
        depth, the host certificate and the export are shared."""
        r = arms.get(arm, "eec")
        assert r.status_code == 200, (r.status_code, arms.errlog()[-2000:])
        assert r.content == SEED, r.content[:80]

    @pytest.mark.parametrize("arm", ARMS)
    def test_no_client_certificate_is_refused_everywhere(self, arms, arm):
        """security-neg: ``ssl_verify_client on`` is mandatory on every arm, so
        the flag is never the thing that lets an anonymous client in.  A 200 here
        would make every other row in the file meaningless."""
        r = arms.get(arm, "none")
        assert r.status_code == 400, (r.status_code, arms.errlog()[-2000:])
        assert r.content != SEED

    @pytest.mark.parametrize("cred", CREDS)
    @pytest.mark.parametrize("arm", ARMS)
    def test_every_cell_of_the_grid(self, arms, arm, cred):
        """The measurement itself, cell by cell: twelve (arm, credential) pairs
        against one table.  Written out rather than derived so a change in any
        one cell fails as itself."""
        expected = GRID[(arm, cred)]
        r = arms.get(arm, cred)
        assert r.status_code == expected, (
            f"{arm}/{cred}: {r.status_code} != {expected}\n"
            f"{arms.errlog()[-2000:]}")
        assert (r.content == SEED) is (expected == 200), r.content[:80]

    def test_only_the_proxy_row_moves_between_the_arms(self, arms):
        """The differential, in one pass over one running process-set.

        Three of the four credentials answer identically on all three sockets;
        the RFC 3820 proxy chain does not.  A file that asserted only the twelve
        cells above could pass with an unrelated difference between the arms —
        this asserts that there is no such difference.
        """
        grid = arms.grid()
        moved = {cred for cred in CREDS
                 if len({grid[(arm, cred)] for arm in ARMS}) > 1}
        def _assert_test_only_the_proxy_row_moves_between_the_arms_2():
            assert moved == {"rfc3820"}, grid
            # And the two clear arms are not merely both "not the armed one": they
            # answer every credential identically, which is §D's whole claim.
            assert {c: grid[("srv-off", c)] for c in CREDS} \
                == {c: grid[("loc-on", c)] for c in CREDS}, grid

        _assert_test_only_the_proxy_row_moves_between_the_arms_2()


# --------------------------------------------------------------------------- #
# §B — what `on` does not admit                                               #
# --------------------------------------------------------------------------- #

class TestTheLegacyProxyIsNotAdmitted:
    """X509_V_FLAG_ALLOW_PROXY_CERTS admits RFC 3820 proxies — chains whose leaf
    carries the proxyCertInfo extension.  A pre-RFC-3820 Globus proxy is not one,
    and the flag does not reach it: it is refused on the armed listener too, and
    for a different reason.  Without this section the `on` arm would read as
    "proxies are accepted" rather than "RFC 3820 proxies are accepted"."""

    @pytest.mark.parametrize("arm", ARMS)
    def test_a_legacy_proxy_is_refused_on_every_arm(self, arms, arm):
        r = arms.get(arm, "legacy")
        assert r.status_code == 400, (r.status_code, arms.errlog()[-2000:])
        assert r.content != SEED

    def test_the_armed_arms_refusal_is_not_the_proxy_policy(self, arms):
        """The reason separates §B from §A: error 32 is about the issuer's key
        usage — a legacy proxy's issuer is an end-entity certificate that never
        claimed the right to sign one — where error 40 is about proxy policy.
        Same status, different mechanism."""
        arms.get("srv-on", "legacy")
        reasons = arms.awaited_reasons("srv-on", NO_CERT_SIGN)
        assert any(NO_CERT_SIGN in line for line in reasons), reasons
        assert not any(NO_PROXY_ALLOWED in line for line in reasons), reasons

    def test_the_two_proxies_differ_by_the_proxycertinfo_extension(self, creds):
        """The cert-level pin for the reading above.  If the forge stopped
        putting proxyCertInfo in the RFC 3820 proxy — or started putting it in
        the legacy one — §A and §B would swap verdicts while every assertion
        above still passed."""
        pci = "1.3.6.1.5.5.7.1.14"
        rfc = creds["certs"]["rfc3820"].cert
        legacy = creds["certs"]["legacy"].cert
        assert any(e.oid.dotted_string == pci for e in rfc.extensions), \
            [e.oid.dotted_string for e in rfc.extensions]
        assert not any(e.oid.dotted_string == pci for e in legacy.extensions), \
            [e.oid.dotted_string for e in legacy.extensions]

    def test_both_proxies_are_issued_by_the_same_eec(self, creds):
        """And the pin that keeps §B from being a statement about trust: both
        proxies hang off the one EEC the CA signed, so the CA path is identical
        and the leaf is the only difference."""
        eec_subject = creds["certs"]["eec"].cert.subject
        for kind in ("rfc3820", "legacy"):
            assert creds["certs"][kind].cert.issuer == eec_subject, kind


# --------------------------------------------------------------------------- #
# §C — `off` and ABSENT                                                       #
# --------------------------------------------------------------------------- #

class TestTheAbsentArmIsTheOffArm:
    """The two routes to a clear flag carry different values —
    ``conf->proxy_certs = NGX_CONF_UNSET`` (config.c:128) when nothing is
    written, 0 when ``off`` is — and ``ngx_conf_merge_value`` folds both to 0
    (config_merge.c:85).  A consultation relaxed from truthiness to ``!= 0``
    would arm every server in the tree that writes nothing, so both routes are
    measured on the SAME socket, with the directive emptied in place: nothing but
    the token differs between the two halves.
    """

    @staticmethod
    def _absent(lifecycle):
        lifecycle.reconfigure(NAME, OFF_ARM="")
        lifecycle.restart(NAME)

    def test_the_reconfigure_really_removed_the_token(self, arms, lifecycle):
        """The precondition, asserted rather than assumed: an emptied slot must
        leave no spelling of the directive in THAT server{} and every spelling in
        the other two.  A test that measured an unchanged configuration would
        pass for the wrong reason."""
        before = _server_block(Path(arms.endpoint.config).read_text(),
                               "srv-off")
        assert DIRECTIVE in before, before
        self._absent(lifecycle)
        rendered = Path(arms.endpoint.config).read_text()
        assert DIRECTIVE not in _server_block(rendered, "srv-off"), \
            _server_block(rendered, "srv-off")
        assert DIRECTIVE in _server_block(rendered, "srv-on")
        assert DIRECTIVE in _server_block(rendered, "loc-on")

    def test_the_absent_arm_refuses_the_proxy_chain(self, arms, lifecycle):
        self._absent(lifecycle)
        r = arms.get("srv-off", "rfc3820")
        assert r.status_code == 400, (r.status_code, arms.errlog()[-2000:])
        assert NO_PROXY_ALLOWED in "\n".join(arms.verify_reasons("srv-off")), \
            arms.verify_reasons("srv-off")

    def test_the_absent_arm_still_admits_the_eec(self, arms, lifecycle):
        """The clear flag disables proxy acceptance and nothing else: mandatory
        client-certificate verification is still in force and still passes for a
        credential that needs no proxy policy."""
        self._absent(lifecycle)
        r = arms.get("srv-off", "eec")
        assert r.status_code == 200, (r.status_code, arms.errlog()[-2000:])
        assert r.content == SEED

    def test_the_absent_arm_grid_is_the_off_arm_grid(self, arms, lifecycle):
        """The comparison the section exists for: every cell of the middle
        listener, before and after the token is removed."""
        before = {cred: arms.get("srv-off", cred).status_code for cred in CREDS}
        self._absent(lifecycle)
        after = {cred: arms.get("srv-off", cred).status_code for cred in CREDS}
        def _assert_test_the_absent_arm_grid_is_the_off_arm_grid_1():
            assert before == after, (before, after)
            assert before == {cred: GRID[("srv-off", cred)] for cred in CREDS}, \
                before

        _assert_test_the_absent_arm_grid_is_the_off_arm_grid_1()

    def test_removing_it_leaves_the_other_two_listeners_alone(self, arms,
                                                              lifecycle):
        """security-neg: the flag is per-server, so emptying it on one listener
        must not disarm — or arm — another.  Both would be a merge crossing a
        server boundary."""
        self._absent(lifecycle)
        assert arms.get("srv-on", "rfc3820").status_code == 200, \
            arms.errlog()[-2000:]
        assert arms.get("loc-on", "rfc3820").status_code == 400, \
            arms.errlog()[-2000:]

    def test_the_census_still_names_only_the_armed_server(self, arms,
                                                          lifecycle):
        """And the config-time half: with the token gone, the set of servers the
        hook armed is unchanged, because ``off`` never armed one either."""
        armed_before = arms.armed_servers()
        self._absent(lifecycle)
        assert armed_before == {SERVER_NAMES["srv-on"]}, armed_before
        assert arms.armed_servers() == {SERVER_NAMES["srv-on"]}, \
            arms.errlog()[-3000:]


# --------------------------------------------------------------------------- #
# §D — the finding: a location-scoped write is inert                          #
# --------------------------------------------------------------------------- #

class TestTheLocationScopedWriteIsInert:
    """DEFECT CANDIDATE #91.  ``NGX_HTTP_LOC_CONF`` is in the scope mask, so the
    write parses; the hook reads ``cscf->ctx->loc_conf[...]``, so it is never
    consulted.  These tests assert what the code does TODAY and name the arm they
    are measuring, so a fix that narrows the declaration fails them as itself
    rather than leaving them quietly measuring nothing."""

    def test_the_location_scoped_on_refuses_the_proxy_chain(self, arms):
        """The defect, measured.  ``brix_webdav_proxy_certs on;`` is written
        inside this listener's ``location /`` — the same token that admits the
        chain one port over — and the chain is refused."""
        r = arms.get("loc-on", "rfc3820")
        assert r.status_code == 400, (r.status_code, arms.errlog()[-2000:])
        assert r.content != SEED

    def test_its_refusal_is_the_off_arms_refusal(self, arms):
        """Not merely a failure: the same OpenSSL reason the listener that wrote
        ``off`` gives.  The write did not fail late or partially — it was never
        applied."""
        arms.get("loc-on", "rfc3820")
        reasons = arms.awaited_reasons("loc-on", NO_PROXY_ALLOWED)
        assert any(NO_PROXY_ALLOWED in line for line in reasons), reasons

    def test_the_startup_census_names_only_the_server_scoped_arm(self, arms):
        """The config-time fingerprint of the same fact.  The hook logs an INFO
        line naming each server whose SSL context it armed; the
        location-scoped listener is absent from that list, so the flag was
        already lost before any handshake."""
        armed = arms.armed_servers()
        assert armed == {SERVER_NAMES["srv-on"]}, arms.errlog()[-3000:]
        assert SERVER_NAMES["loc-on"] not in armed, armed

    def test_the_mirror_is_inert_too(self, arms):
        """The other direction, and the reason the defect is not "the write is
        ignored, so write it at server scope instead": ``off`` inside a location
        under a server that wrote ``on`` does not restrict that subtree either.
        The placement cannot narrow acceptance any more than it can grant it."""
        r = arms.get("srv-on", "rfc3820", SUBTREE_URI)
        assert r.status_code == 200, (r.status_code, arms.errlog()[-2000:])
        assert r.content == SEED, r.content[:80]

    def test_the_subtree_is_the_same_verdict_as_its_parent(self, arms):
        """Cell for cell: the ``off`` subtree of the armed listener answers every
        credential exactly as the armed listener's root does."""
        root = {cred: arms.get("srv-on", cred, URI).status_code
                for cred in CREDS}
        sub = {cred: arms.get("srv-on", cred, SUBTREE_URI).status_code
               for cred in CREDS}
        assert root == sub, (root, sub)

    def test_the_hook_reads_the_servers_loc_conf(self):
        """The source pin for the whole section.  ``cscf->ctx`` is the server's
        configuration context, so ``ctx->loc_conf[...]`` is the value written at
        server scope — a location's own loc_conf is a different allocation and is
        never reached."""
        text = POSTCONFIG_C.read_text()
        head = text.index("webdav_postconf_setup_ssl_ctx(ngx_conf_t *cf,")
        body = " ".join(
            text[head:text.index("if (wdcf->proxy_certs) {", head)].split())
        assert "ngx_http_conf_ctx_t *ctx = cscf->ctx;" in body, body
        assert "wdcf = ctx->loc_conf[ngx_http_brix_webdav_module.ctx_index];" \
            in body, body

    def test_the_hook_runs_once_per_server_and_walks_no_locations(self):
        """And the pin that makes "never consulted" a statement about the code
        rather than about one configuration: the caller iterates
        ``cmcf->servers`` and calls the hook once per entry.  There is no
        location walk to reach."""
        text = POSTCONFIG_C.read_text()
        loop = text.index("for (s = 0; s < cmcf->servers.nelts; s++) {")
        call = text.index("webdav_postconf_setup_ssl_ctx(cf, cscfp[s])", loop)
        assert loop < call
        assert "locations" not in text[loop:call], text[loop:call]

    def test_the_declaration_still_invites_the_placement(self):
        """The last leg: the defect exists because the mask and the hook
        disagree.  When the mask loses ``NGX_HTTP_LOC_CONF`` this fails, which is
        the signal to retire this section rather than adjust it."""
        text = MODULE_COMMANDS_C.read_text()
        block = text.split(f'{{ ngx_string("{DIRECTIVE}"),', 1)[1]
        mask = block.splitlines()[1].strip()
        assert mask == ("NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | "
                        "NGX_CONF_FLAG,"), mask


# --------------------------------------------------------------------------- #
# §E — the config-time advertisement                                          #
# --------------------------------------------------------------------------- #

class TestTheEndpointSummaryDisagreesWithTheSocket:
    """``webdav_log_endpoint_summary`` reads the LOCATION's flag, and the SSL
    context reads the server's.  Wherever those two differ, the startup banner
    describes an endpoint that does not exist — in both directions."""

    def test_the_census_is_one_block_per_location_in_configuration_order(
            self, arms):
        """The frame for the two readings below.  Four WebDAV locations, four
        blocks, in the order the file writes them: the armed listener's root
        (which inherits ``on``), its ``off`` subtree, the ``off`` listener's
        root, and the location-scoped listener's root.

        Every config pass over the file — the launcher's ``nginx -t`` and the
        start itself — appends one census, and they must all read the same.
        """
        groups = arms.summary_groups()
        assert groups and len(groups) % len(EXPECTED_SUMMARY) == 0, groups
        for census in arms.passes():
            assert census == EXPECTED_SUMMARY, groups

    def test_the_inert_location_advertises_x509(self, arms):
        """The sharpening.  The last block is the location whose write does
        nothing, and it is one of only two that announce ``credentials accepted:
        x509/GSI-proxy`` — an advertisement of proxy acceptance by a socket that
        refuses every proxy chain (§D)."""
        census = arms.passes()[-1]
        assert census[-1][0] is True, arms.summary_groups()
        assert arms.get("loc-on", "rfc3820").status_code == 400, \
            arms.errlog()[-2000:]

    def test_it_also_earns_the_revocation_warning(self, arms):
        """And the warning that follows from the claim: no CRL is configured, so
        the operator is told that REVOKED certificates will be accepted — about
        credentials this listener will not accept at all.  The advice is not
        wrong so much as addressed to the wrong endpoint."""
        assert arms.passes()[-1][-1][1] is True, arms.summary_groups()
        assert CRL_NOTE_MARK in arms.errlog(), arms.errlog()[-3000:]

    def test_the_off_subtree_advertises_nothing_though_its_socket_admits(
            self, arms):
        """The inverse disagreement, on the other listener: the subtree that
        wrote ``off`` claims no x509 credentials, and its socket admits a proxy
        chain anyway (§D's mirror)."""
        assert arms.passes()[-1][1] == (False, False), arms.summary_groups()
        assert arms.get("srv-on", "rfc3820", SUBTREE_URI).status_code == 200, \
            arms.errlog()[-2000:]

    def test_the_inherited_location_advertises_and_delivers(self, arms):
        """The control: where the two readers see the same value — a location
        under a server that wrote ``on``, with nothing of its own — the banner
        and the socket agree, which is what makes the two rows above
        disagreements and not a broken banner."""
        assert arms.passes()[-1][0] == (True, True), arms.summary_groups()
        assert arms.get("srv-on", "rfc3820").status_code == 200, \
            arms.errlog()[-2000:]

    def test_the_census_reads_the_locations_own_flag(self):
        """The source pin for §E.  ``has_x509`` is computed from ``conf``, the
        location being merged, so a location-scoped write does reach THIS reader
        — the one that only prints."""
        squashed = " ".join(CONFIG_C.read_text().split())
        assert ("ngx_uint_t has_x509 = (conf->common.trusted_ca_dir.len > 0 "
                "|| conf->common.trusted_ca.len > 0 || conf->proxy_certs);") \
            in squashed, "has_x509 no longer reads conf->proxy_certs"
        assert 'has_x509 ? " x509/GSI-proxy" : ""' in squashed


# --------------------------------------------------------------------------- #
# §F — the parse tier                                                         #
# --------------------------------------------------------------------------- #

def _parse(tmp_path, **slots):
    """`nginx -t` on file 14's scaffold with the named slots filled.

    Every slot defaults to empty so a case names only what it is about; the
    scaffold's probe location writes nothing about proxy certificates, so a
    negative is never answered by a duplicate diagnostic first.
    """
    data = tmp_path / "parse-data"
    data.mkdir(exist_ok=True)
    values = {"PORT": PARSE_PLACEHOLDER_PORT,
              "STREAM_PORT": PARSE_PLACEHOLDER_PORT + 1,
              "LOG_DIR": str(tmp_path),
              "DATA": str(data),
              "LOC_KNOBS": "", "SRV_KNOBS": "", "HTTP_KNOBS": "",
              "OUTER": "", "STREAM_KNOBS": "", "STREAM_MAIN": "",
              "EXTRA_LOC": ""}
    values.update(slots)
    result = nginx_t("nginx_audit16nparse.conf", str(tmp_path), **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


# The two scopes this declaration names — one fewer than file 15's subjects, and
# the difference is the whole of §D.
RIGHT_SCOPES = ("SRV_KNOBS", "LOC_KNOBS")
# Every placement it does not name.  HTTP_KNOBS is here and not above:
# NGX_HTTP_MAIN_CONF is absent from the mask, so http{} must refuse even though
# NGX_HTTP_LOC_CONF_OFFSET would give it somewhere to store a value.
WRONG_SCOPES = ("HTTP_KNOBS", "OUTER", "STREAM_KNOBS", "STREAM_MAIN")


@_needs_nginx
class TestTheParseTier:
    """Values, arity, duplicates and the placement matrix, asked with nothing
    else in the file that could answer instead."""

    @pytest.mark.parametrize("scope", RIGHT_SCOPES)
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_both_arms_are_accepted_in_both_declared_scopes(self, tmp_path,
                                                            arm, scope):
        """The audit's step-1 question at both legal scopes.  Two of these four
        cases are the ``off`` arm the corpus never wrote, and the
        location-scoped pair is the placement §D shows to be inert — accepted
        here, which is exactly the problem."""
        rc, out = _parse(tmp_path, **{scope: f"        {DIRECTIVE} {arm};\n"})
        assert rc == 0, out

    @pytest.mark.parametrize("scope", RIGHT_SCOPES)
    def test_the_off_arm_advises_nothing(self, tmp_path, scope):
        """An operator who turns proxy acceptance off is not misconfiguring
        anything, in either scope."""
        rc, out = _parse(tmp_path, **{scope: f"        {DIRECTIVE} off;\n"})
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    def test_the_location_scoped_write_is_not_diagnosed(self, tmp_path):
        """The parse-tier half of #91, stated as a measurement: the placement
        that does nothing at runtime is accepted in silence — no warning, no
        note, nothing an operator could act on.  When the fix lands, THIS is the
        test that should change."""
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=f"            {DIRECTIVE} on;\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    def test_a_server_on_with_a_location_off_parses_clean(self, tmp_path):
        """The template's own shape: ``on`` in the server, ``off`` in a location
        beneath it.  An ordinary configuration to the parser, and (§D) an
        ineffective one to the SSL context."""
        rc, out = _parse(tmp_path,
                         SRV_KNOBS=f"        {DIRECTIVE} on;\n",
                         LOC_KNOBS=f"            {DIRECTIVE} off;\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    @pytest.mark.parametrize("value", ("1", "0", "yes", "enabled", "true"))
    def test_only_on_and_off_are_accepted(self, tmp_path, value):
        """``ngx_conf_set_flag_slot`` compares against exactly two tokens, so
        every other spelling of a boolean is refused rather than guessed at — a
        flag that silently read ``0`` as true would arm a listener its operator
        meant to leave alone."""
        rc, out = _parse(tmp_path, SRV_KNOBS=f"        {DIRECTIVE} {value};\n")
        assert rc != 0, out
        assert 'invalid value "%s"' % value in out, out

    def test_no_argument_is_refused(self, tmp_path):
        rc, out = _parse(tmp_path, SRV_KNOBS=f"        {DIRECTIVE};\n")
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    def test_two_arguments_are_refused(self, tmp_path):
        """NGX_CONF_FLAG is NGX_CONF_TAKE1 plus a value check; a second argument
        is an arity error and not a silently ignored token."""
        rc, out = _parse(tmp_path, SRV_KNOBS=f"        {DIRECTIVE} on off;\n")
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("scope", RIGHT_SCOPES)
    def test_a_second_write_in_one_scope_is_a_duplicate(self, tmp_path, scope):
        """Two values in one scope is a duplicate, which is what makes the
        server/location pair the only way to write both arms of this flag in one
        configuration — and the reason §D's mirror needed a second location."""
        rc, out = _parse(tmp_path, **{scope: f"        {DIRECTIVE} on;\n"
                                             f"        {DIRECTIVE} off;\n"})
        assert rc != 0, out
        assert "duplicate" in out, out

    @pytest.mark.parametrize("scope", WRONG_SCOPES)
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_no_other_placement_is_allowed(self, tmp_path, arm, scope):
        """http{}, the main context and the stream plane must refuse, and the
        refusal must be about the CONTEXT: nginx searches every module's command
        table before it checks scope, so "unknown directive" here would mean the
        directive had been dropped from the table rather than misplaced."""
        rc, out = _parse(tmp_path, **{scope: f"    {DIRECTIVE} {arm};\n"})
        assert rc != 0, out
        assert "is not allowed here" in out, out
        assert "unknown directive" not in out, out


# --------------------------------------------------------------------------- #
# §G — the declarations and the corpus                                        #
# --------------------------------------------------------------------------- #

class TestTheDeclarationsAndTheCorpus:
    """Every reading above is an inference from a handful of lines of C and from
    what the corpus does not contain.  If either changes, the tests would keep
    passing while measuring something else."""

    def test_the_setter_and_the_offset_are_the_flag_slot(self):
        """Two scopes, ``ngx_conf_set_flag_slot``, and
        ``NGX_HTTP_LOC_CONF_OFFSET`` — which is why a value written in
        ``server{}`` lands in that scope's loc_conf and becomes the parent of
        every location below it (and why §E's first block inherits it)."""
        text = MODULE_COMMANDS_C.read_text()
        marker = f'{{ ngx_string("{DIRECTIVE}"),'
        assert marker in text, DIRECTIVE
        # splitlines()[0] is the tail of the marker's own line, which is empty.
        lines = [ln.strip() for ln in text.split(marker, 1)[1].splitlines()[1:5]]
        assert lines[0] == ("NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | "
                            "NGX_CONF_FLAG,"), lines
        assert lines[1] == "ngx_conf_set_flag_slot,", lines
        assert lines[2] == "NGX_HTTP_LOC_CONF_OFFSET,", lines
        assert ("offsetof(ngx_http_brix_webdav_loc_conf_t, proxy_certs)"
                in lines[3]), lines

    def test_it_merges_to_zero(self):
        """The bare arm reads this 0.  A merge default of 1 would make ``on`` the
        redundant arm instead — the case for ``brix_upload_resume`` two
        files over, so the direction is not a given."""
        squashed = " ".join(CONFIG_MERGE_C.read_text().split())
        assert ("ngx_conf_merge_value(conf->proxy_certs, prev->proxy_certs, 0);"
                in squashed)

    def test_the_initialiser_is_unset(self):
        """And the other half of §C: ``off`` and absent arrive at the merge as 0
        and NGX_CONF_UNSET, which is why the two routes had to be measured
        rather than assumed identical."""
        squashed = " ".join(CONFIG_C.read_text().split())
        assert "conf->proxy_certs = NGX_CONF_UNSET;" in squashed

    def test_the_whole_effect_is_one_openssl_call(self):
        """§A's reading depends on there being nothing else: the flag sets one
        verify parameter on one SSL context and logs it.  A second consumer would
        make "the flag decides the handshake" an incomplete description."""
        text = POSTCONFIG_C.read_text()
        assert text.count("wdcf->proxy_certs") == 1, "a second consumer appeared"
        guard = text.index("if (wdcf->proxy_certs) {")
        block = text[guard:text.index("\n    }\n", guard)]
        assert "SSL_CTX_get0_param(sslcf->ssl.ctx)" in block, block
        assert ("X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_ALLOW_PROXY_"
                "CERTS);") in block, block
        # The INFO line §D's census reads, and the server_name that makes it a
        # census rather than a count.
        assert "enabled X509_V_FLAG_ALLOW_PROXY_CERTS" in block, block
        assert "&cscf->server_name" in block, block

    def test_the_sibling_shares_the_declaration_and_the_hook(self):
        """The capath sibling became bare ``brix_client_ca_store`` on the
        COMMON module (W2-105), still srv/loc-scoped and still consumed by the
        same server-level SSL_CTX hook — so #91 stays a property of the hook
        and not of this one directive."""
        text = (MODULE_COMMANDS_C.parent.parent.parent
                / "core/config/http_directives_ops.h").read_text()
        entry = " ".join(
            text.split('{ ngx_string("brix_client_ca_store"),', 1)[1]
            .split("},")[0].split())
        assert "NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1," \
            in entry, entry
        post = POSTCONFIG_C.read_text()
        head = post.index("webdav_postconf_setup_ssl_ctx(ngx_conf_t *cf,")
        body = post[head:post.index("\n}\n", head)]
        assert "client_ca_store" in body, body

    def test_the_corpus_writes_the_on_arm_widely(self):
        """Step 1 of the audit's own measurement, as the file found it: the arm
        that IS written is written everywhere, which is what makes the other arm
        a gap rather than an untested feature."""
        writes = [p.name for p in CONFIGS_DIR.rglob("*.conf")
                  if f"{DIRECTIVE} on;" in _squashed(p)]
        assert len(writes) >= 20, writes

    def test_this_files_template_is_the_only_off_arm_in_the_configs(self):
        """Step 2, and the reason the file exists.  If another config starts
        writing ``off``, this fails — and the audit's gap table should be re-run
        rather than this assertion relaxed."""
        writing_off = sorted(p.name for p in CONFIGS_DIR.rglob("*.conf")
                             if f"{DIRECTIVE} off;" in _squashed(p))
        assert writing_off == [TEMPLATE], writing_off

    def test_the_template_writes_the_arms_this_file_measures(self):
        """The template and the fixture have to agree: two server-scope slots the
        test fills, and one literal location-scoped ``on`` that is the finding.
        A template edit that moved the third write to server scope would turn §D
        into a duplicate of §A."""
        path = CONFIGS_DIR / TEMPLATE
        text = path.read_text()
        squashed = _squashed(path)
        assert "{SRV_ARM}" in text and "{OFF_ARM}" in text, text
        assert squashed.count(f"{DIRECTIVE} on;") == 1, squashed
        assert squashed.count(f"{DIRECTIVE} off;") == 1, squashed
        assert DIRECTIVE in _server_block(text, "loc-on"), text
        for name in SERVER_NAMES.values():
            assert f"server_name {name};" in text, name

    def test_the_ledger_owns_one_port_per_arm(self):
        """Three sockets, three ledger allocations, all distinct.  Two arms
        sharing a port would not be a slower test — an SSL_CTX belongs to a
        listener, so it would be a different measurement."""
        slot = LIFECYCLE_SHARED_PORTS[NAME]
        assert slot["port"] == PORT
        assert set(slot["extra"]) == {"OFF_PORT", "LOC_PORT"}, slot
        assert len({PORT, *slot["extra"].values()}) == 3, slot
