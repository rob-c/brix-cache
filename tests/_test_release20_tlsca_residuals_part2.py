# Continuation of test_release20_tlsca_residuals.py (§10.2 split; loaded through
# split_continuation so the two files are ONE module and share its fixtures).
#
# §E is what happens when the CRL feed itself is broken — the register's "error"
# tier, including the 2.0 F22 fix for the fail-open this row found — and §F/§G
# are the parse tier and the two-plane spelling pin.


# --------------------------------------------------------------------------- #
# Parse-tier helpers (shared by §E and §F)                                     #
# --------------------------------------------------------------------------- #

def _gsi_block(pki, *lines):
    """A complete stream GSI server body plus whatever the case adds."""
    body = ["brix_auth gsi;",
            f"brix_certificate     {pki['cert']};",
            f"brix_certificate_key {pki['key']};",
            f"brix_trusted_ca      {pki['ca']};"]
    body.extend(lines)
    return "".join(f"        {line}\n" for line in body)


def _parse_stream(tmp_path, knobs="", stream_extra=""):
    """The stream-only scaffold, REUSED from the audit-15u row: it writes no
    ``brix_auth`` line of its own, so a case can supply a whole GSI block
    without colliding with a fixed one.

    Every diagnostic the config parse emits arrives on stderr, not in the
    rendered ``error_log``: ``nginx -t`` has not opened the new log file by the
    time the GSI block is loaded, so the returned text is the whole record.
    """
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit15u_crlparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, DATA_ROOT=str(data),
                     LOG_DIR=str(tmp_path), KNOBS=knobs,
                     STREAM_EXTRA=stream_extra)
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


def _parse_both_planes(root, **slots):
    """The six-slot scaffold, REUSED from audit-16h: its placement slots are
    exactly the ones a BRIX_HTTP_ALL_CONF + NGX_STREAM_SRV_CONF pair needs."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(exist_ok=True)
    data = root / "data"
    data.mkdir(exist_ok=True)
    values = {"OUTER": "", "HTTP_KNOBS": "", "SRV_KNOBS": "", "KNOBS": "",
              "STREAM_KNOBS": "", "STREAM_MAIN": "", "SUBJECT": ""}
    values.update(slots)
    result = nginx_t("nginx_audit16hparse.conf", root,
                     PORT=PARSE_PLACEHOLDER_PORT,
                     SUBJ_PORT=PARSE_PLACEHOLDER_PORT + 1,
                     STREAM_PORT=PARSE_PLACEHOLDER_PORT + 2,
                     LOG_DIR=str(root / "logs"), DATA=str(data), **values)
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


# --------------------------------------------------------------------------- #
# §E — a broken CRL feed                                                       #
# --------------------------------------------------------------------------- #

class TestABrokenCrlFeedUnderRequire:
    """``require`` arms the CRL flags whatever ``crl_count`` says, so a feed
    that loads nothing refuses everything (``store_policy_store.c:414``).  That
    is the property an operator is buying when they write ``require``, and it
    is the only thing standing between a silently-emptied CRL directory and an
    open door."""

    def test_a_malformed_crl_fails_the_handshake_closed(self, tlsca, pki):
        """The bad directory holds a file that matches the loader's ``.r0``
        name predicate and is opened, but is not a CRL — ``PEM_read_X509_CRL``
        yields nothing and ``crl_count`` is 0.  The credential offered is the
        one every other plane accepts, so the refusal is about the feed."""
        ok, result = _accepted(tlsca, BADCRL, pki, "full")
        assert not ok, ("a malformed CRL under brix_crl_mode require admitted "
                        f"a login\n{result.stdout}")

    def test_narrowing_the_scope_does_not_rescue_a_broken_feed(self, tlsca,
                                                               pki):
        """The malformed-CRL plane deliberately writes ``brix_crl_scope last``.
        ``last`` tolerates a CRL-class verdict ABOVE the end entity — never one
        ON it — so a feed that cannot cover the user's own certificate still
        fails closed.  Both other credentials, so the refusal is not a property
        of one chain."""
        ok, result = _accepted(tlsca, BADCRL, pki, "revoked")
        assert not ok, result.stdout
        ok, result = _accepted(tlsca, BADCRL, pki, "gap")
        assert not ok, ("brix_crl_scope last turned an unusable CRL feed into "
                        f"an accepted login\n{result.stdout}")

    def test_the_malformed_directory_reports_that_it_loaded_nothing(
            self, tlsca, pki):
        """Attribution for the two above: without this line the refusals could
        be a broken chain.  ``brix_rebuild_gsi_store`` logs the count it got
        (``auth/gsi/config.c:57``), once per configured CRL path."""
        log = _since(tlsca, 0)
        assert f'brix: loaded 0 CRL(s) from "{pki["bad"]}"' in log, \
            f"the malformed CRL directory did not report an empty load\n" \
            f"{log[-3000:]}"


class TestAPermissiveModeOverAReadableDirectory:
    """The 2.0 F22 control, and the only ``try`` arm of the running instance.

    F22 made an unreadable entry in a CRL directory a hard load failure, and a
    fix in that shape is one wrong branch away from making EVERY directory load
    fail.  These two say the permissive mode is still permissive in the way it
    is meant to be — a CRL that is genuinely absent is downgraded — and still
    armed in the way it is meant to be: the same directory, read successfully,
    still refuses the user its CRL revokes."""

    def test_try_still_refuses_a_revoked_credential(self, tlsca, pki):
        """(security) ``try`` is not "off".  The directory loads three CRLs, so
        ``crl_count > 0`` arms ``CRL_CHECK|CRL_CHECK_ALL|USE_DELTAS``
        (``store_policy_store.c:414``) and the revocation still bites."""
        ok, result = _accepted(tlsca, TRY, pki, "revoked")
        assert not ok, ("brix_crl_mode try admitted a revoked credential over "
                        f"a CRL directory that revokes it\n{result.stdout}")

    def test_try_downgrades_a_crl_that_is_genuinely_absent(self, tlsca, pki):
        """The gap chain's root publishes no CRL at all.  ``all`` refuses it on
        {PORT}; ``try`` accepts it here.  Same credential, same directory, same
        scope — the mode is the only variable, which is what makes this a
        control for the F22 change rather than a restatement of §B."""
        ok, result = _accepted(tlsca, TRY, pki, "gap")
        assert ok, ("brix_crl_mode try refused a chain whose only fault is a "
                    f"missing CRL — F22 over-tightened the loader\n"
                    f"{result.stderr}")
        assert _accepted(tlsca, ALL, pki, "gap")[0] is False


class TestAnUnreadableCrlAnywhereRefusesToStart:
    """THE SECOND FINDING, now fixed as 2.0 F22 — these tests are the inverted
    form of the three that pinned it as a fail-open.

    ``brix_crl`` naming a FILE was always ``access(R_OK)``-checked at config
    time (``brix_conf_check_path``/``src/core/config/helpers.c:57``).  Naming
    that file's DIRECTORY passed the same check — ``access`` is asked about the
    directory, never about what is in it — and the loader then mapped the failed
    ``fopen`` to "0 CRLs here", which under ``try`` disarmed revocation for the
    whole server.  ``pki_load_crls_from_dirent`` now returns -1,
    ``pki_load_crls_from_dir`` propagates it, and the GSI store builder refuses
    the configuration.

    Both spellings refuse; the messages differ, and both are pinned, because an
    operator who sees only one of them has to be able to act on it."""

    def test_naming_the_unreadable_crl_directly_is_a_config_error(
            self, tmp_path, pki):
        """(error) The config-time path check, unchanged by F22."""
        rc, out = _parse_stream(tmp_path, _gsi_block(
            pki, f"brix_crl {pki['unread_file']};", "brix_crl_mode require;"))
        assert rc != 0, f"an unreadable CRL file was accepted at startup\n{out}"
        assert "failed permission check" in out, out

    def test_naming_its_directory_is_now_a_config_error_too(self, tmp_path,
                                                            pki):
        """(error) The F22 half.  Same file, same mode bits, named through its
        parent: the loader reports which file it could not open and the store
        builder names both the trusted_ca and the CRL path, because "the
        trust store would not build" is useless without those two paths."""
        rc, out = _parse_stream(tmp_path, _gsi_block(
            pki, f"brix_crl {pki['unread']};", "brix_crl_mode require;"))
        assert rc != 0, ("an unreadable CRL inside a CRL directory was "
                         f"accepted at startup — F22 has reverted\n{out}")
        for needle in (f'brix_pki: cannot open CRL file "{pki["unread_file"]}"',
                       "cannot build the GSI trust store",
                       f'trusted_ca "{pki["ca"]}"',
                       f'CRL path "{pki["unread"]}"'):
            assert needle in out, f"missing from the refusal: {needle}\n{out}"

    def test_the_permissive_mode_cannot_talk_the_loader_out_of_it(
            self, tmp_path, pki):
        """(security-negative) The pre-F22 fail-open was reachable ONLY under
        ``try``: ``require`` armed the flags whatever the count was, so it
        failed closed on its own.  The refusal must therefore not be a property
        of ``require`` — writing ``try``, or writing no mode at all, must not
        buy back the empty store."""
        for knob in ("brix_crl_mode try;", "brix_crl_mode off;", ""):
            lines = (f"brix_crl {pki['unread']};",) + ((knob,) if knob else ())
            rc, out = _parse_stream(tmp_path, _gsi_block(pki, *lines))
            assert rc != 0, (f"brix_crl_mode {knob or '<default>'} started a"
                             f" server whose CRL dir it cannot read\n{out}")
            assert "cannot build the GSI trust store" in out, out

    def test_the_http_plane_refuses_it_too(self, tmp_path, pki):
        """(error) The same loader builds the WebDAV store
        (``webdav_build_ca_store_once``/``config_merge.c:371``), so F22 is a
        both-planes fix or it is a hole an operator reaches by moving one
        export to https.  The message is the WebDAV one — different words, same
        refusal — and the ``brix_pki`` line naming the file is shared.

        It goes in the scaffold's SUBJECT slot, as a whole extra server: the
        stock ``/probe/`` location already writes ``brix_webdav_auth none``,
        and a second one there is diagnosed as a duplicate directive before the
        store is ever built.  The anchors go in ``brix_trusted_ca_dir``: the
        http plane splits the bundle file from the hashed directory across two
        directives where the stream plane's ``brix_trusted_ca`` takes either,
        so a hashed directory written into the http ``brix_trusted_ca`` is
        refused as "must be a regular file" long before any CRL is read."""
        subject = (
            "    server {\n"
            f"        listen {PARSE_PLACEHOLDER_PORT + 1};\n"
            "        location /crl/ {\n"
            "            brix_webdav          on;\n"
            f"            brix_storage_backend posix:{tmp_path};\n"
            "            brix_webdav_auth     required;\n"
            f"            brix_trusted_ca_dir  {pki['ca']};\n"
            f"            brix_crl             {pki['unread']};\n"
            "        }\n"
            "    }\n")
        rc, out = _parse_both_planes(tmp_path, SUBJECT=subject)
        assert rc != 0, ("the http plane started with a CRL directory it "
                         f"cannot read\n{out}")
        assert f'cannot open CRL file "{pki["unread_file"]}"' in out, out
        assert "failed to build cached CA store" in out, out

    def test_a_readable_directory_alongside_it_is_unaffected(self, tmp_path,
                                                             pki):
        """(success) The other side of the same predicate: F22 refuses "present
        but unreadable", never "opened and yielded no CRL".  The good directory
        holds three CRLs and one file (``gapint.r0``'s hierarchy aside) that the
        name predicate accepts; it parses."""
        rc, out = _parse_stream(tmp_path, _gsi_block(
            pki, f"brix_crl {pki['crls']};", "brix_crl_mode require;"))
        assert rc == 0, out
        assert "cannot build the GSI trust store" not in out, out


# --------------------------------------------------------------------------- #
# §F — the parse tier, on both planes                                          #
# --------------------------------------------------------------------------- #

SCOPE_TOKENS = ("all", "last")
VERIFY_LOG_TOKENS = ("off", "failure", "all")
BOTH = [("brix_crl_scope", t) for t in SCOPE_TOKENS] \
     + [("brix_tls_verify_log", t) for t in VERIFY_LOG_TOKENS]


class TestEveryTokenParsesOnEveryLegalPlacement:
    """Both directives are NGX_STREAM_SRV_CONF on the root:// plane and
    BRIX_HTTP_ALL_CONF (main|srv|loc) on the http one.  Four placements, five
    tokens — measured, because a directive that registers in a table nobody can
    write is a directive nobody can use."""

    @pytest.mark.parametrize("name, token", BOTH)
    @pytest.mark.parametrize("slot", ["KNOBS", "SRV_KNOBS", "HTTP_KNOBS",
                                      "STREAM_KNOBS"])
    def test_the_token_is_accepted(self, tmp_path, name, token, slot):
        rc, out = _parse_both_planes(tmp_path,
                                     **{slot: f"        {name} {token};\n"})
        assert rc == 0, f"{name} {token} was refused in {slot}:\n{out}"

    @pytest.mark.parametrize("name, token", [("brix_crl_scope", "LAST"),
                                             ("brix_crl_scope", "All"),
                                             ("brix_tls_verify_log", "Failure"),
                                             ("brix_tls_verify_log", "OFF")])
    def test_the_token_is_matched_case_insensitively(self, tmp_path, name,
                                                     token):
        """``ngx_conf_set_enum_slot`` compares with ``ngx_strcasecmp``, so the
        tokens are case-folded names and not literals.  Written down because an
        operator's ``Last`` parses today and a hand-rolled setter using
        ``ngx_strcmp`` would silently start rejecting it."""
        rc, out = _parse_both_planes(tmp_path,
                                     KNOBS=f"        {name} {token};\n")
        assert rc == 0, f"{name} {token} was refused:\n{out}"


class TestTheParseTierRefusesEverythingElse:

    @pytest.mark.parametrize("name, token", [
        ("brix_crl_scope", "on"), ("brix_crl_scope", "leaf"),
        ("brix_crl_scope", "1"), ("brix_crl_scope", "none"),
        ("brix_tls_verify_log", "on"), ("brix_tls_verify_log", "verbose"),
        ("brix_tls_verify_log", "2"), ("brix_tls_verify_log", "error"),
    ])
    def test_a_value_outside_the_table_is_refused(self, tmp_path, name, token):
        """``leaf``, ``none``, ``verbose`` and ``error`` are the words an
        operator reaches for that are not in the tables; ``1``/``2`` are the raw
        values behind ``BRIX_CRL_SCOPE_LAST`` and ``BRIX_TLS_VERIFY_LOG_ALL``.
        None may parse into a silent default — a ``brix_crl_scope leaf`` that
        quietly meant ``all`` would be a surprise in the safe direction and a
        ``brix_tls_verify_log error`` that quietly meant ``off`` one in the
        unsafe direction."""
        rc, out = _parse_both_planes(tmp_path,
                                     KNOBS=f"        {name} {token};\n")
        assert rc != 0, f"{name} {token} parsed:\n{out}"
        assert "invalid value" in out, out

    @pytest.mark.parametrize("line", ["brix_crl_scope;",
                                      "brix_crl_scope all last;",
                                      "brix_tls_verify_log;",
                                      "brix_tls_verify_log off all;"])
    def test_each_directive_takes_exactly_one_argument(self, tmp_path, line):
        rc, out = _parse_both_planes(tmp_path, KNOBS=f"        {line}\n")
        assert rc != 0, f"{line} parsed:\n{out}"
        assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("name", ["brix_crl_scope", "brix_tls_verify_log"])
    @pytest.mark.parametrize("slot", ["STREAM_MAIN", "OUTER"])
    def test_neither_directive_is_allowed_outside_its_contexts(
            self, tmp_path, name, slot):
        """``stream {}`` itself and the main context are both illegal.  It
        matters because the merge default for scope is the STRICT value: an
        operator who wrote a stream-wide ``brix_crl_scope last`` and was not
        told would believe they had relaxed something they had not — and would
        write it once and stop looking."""
        rc, out = _parse_both_planes(tmp_path,
                                     **{slot: f"    {name} all;\n"})
        assert rc != 0, f"{name} was accepted in {slot}:\n{out}"
        assert "directive is not allowed here" in out, out


# --------------------------------------------------------------------------- #
# §G — one spelling means one thing on both planes                             #
# --------------------------------------------------------------------------- #

class TestTheTwoPlanesShareOneVocabulary:
    """The stream tables live in ``module_enums.c`` and the http ones in
    ``http_common.c``: two arrays per directive that must stay identical.  A
    token added to one and not the other would parse on one plane and be
    refused on the other under the same name, which is the worst outcome for an
    operator copying a line between two server blocks."""

    @staticmethod
    def _tokens(source, table):
        text = (SRC / source).read_text(encoding="utf-8")
        body = text.split(f"{table}[] = {{", 1)[1].split("};", 1)[0]
        return re.findall(r'ngx_string\("([a-z_]+)"\)', body)

    @pytest.mark.parametrize("stream_table, http_table", [
        ("brix_crl_scopes", "brix_http_crl_scopes"),
        ("brix_tls_verify_logs", "brix_http_tls_verify_logs"),
    ])
    def test_the_tables_carry_the_same_tokens_in_the_same_order(
            self, stream_table, http_table):
        stream = self._tokens("protocols/root/stream/module_enums.c",
                              stream_table)
        http = self._tokens("core/config/http_common.c", http_table)
        assert stream and stream == http, (stream, http)

    def test_the_tokens_are_the_ones_this_file_tests(self):
        """Closes the loop: §F drives a hard-coded list, so a token added to
        both C tables and to neither test would still be untested."""
        assert self._tokens("protocols/root/stream/module_enums.c",
                            "brix_crl_scopes") == list(SCOPE_TOKENS)
        assert self._tokens("protocols/root/stream/module_enums.c",
                            "brix_tls_verify_logs") == list(VERIFY_LOG_TOKENS)
