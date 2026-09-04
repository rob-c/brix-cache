"""Test cases for audit16q_acc_engine_flag_arms — preamble (fixtures/helpers/mocks) lives in
_test_audit16q_acc_engine_flag_arms_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16q_acc_engine_flag_arms_helpers")


class TestThePgoArms:
    """One engine, on listener A alone.  B and C carry no authdb, so they never
    reach the installer and cannot answer for A — which §D shows is a real risk
    and not a precaution."""

    def test_the_absent_arm_resolves_the_full_gidlist(self, engine):
        """The control every arm below is read against: with no arm written the
        merge default is 0, the engine resolves the whole gidlist, and BOTH the
        primary-group and the supplementary-group rule grant."""
        acc = engine("audit-16q pgo absent", a=())
        assert acc.verdicts("A") == BASELINE

    def test_the_written_off_arm_is_the_absent_arm(self, engine):
        """The arm the corpus never wrote.  ``off`` reaches the merge as 0 and
        absence reaches it as NGX_CONF_UNSET, so the two routes are measured
        rather than assumed to meet — the whole table, not just the row this
        flag owns."""
        acc = engine("audit-16q pgo off", a=(PGO_OFF,))
        assert acc.verdicts("A") == BASELINE

    def test_the_on_arm_drops_every_supplementary_group(self, engine):
        """What the flag is for: the gidlist becomes the passwd entry's primary
        gid alone, so a rule keyed on a supplementary group stops applying while
        the primary one still grants.  A narrowing, not a loss of group
        resolution."""
        acc = engine("audit-16q pgo on", a=(PGO_ON,))
        assert acc.verdicts("A") == PGO_ON_VERDICTS

    def test_the_two_arms_differ_in_exactly_one_rule(self, engine):
        """Both arms in one process and one prefix, swapped in place.  The
        difference is the whole reading: one row, in one direction."""
        acc = engine("audit-16q pgo off then on", a=(PGO_OFF,))
        before = acc.verdicts("A")
        after = acc.swap(A_ACC=engine.block((PGO_ON,))).verdicts("A")
        moved = {rule for rule in RULE_PATHS if before[rule] != after[rule]}
        assert moved == {"g-supp"}, (before, after)

    def test_turning_it_back_off_restores_the_supplementary_rule(self, engine):
        """The mirror, and the reason it is not redundant: it says the row
        follows the TOKEN and not the age of the process.  ``off`` is the arm an
        operator reaches for after trying ``on``, and it is the arm nothing in
        the corpus had ever executed."""
        acc = engine("audit-16q pgo on then off", a=(PGO_ON,))
        assert acc.verdict("A", "g-supp") == KXR_NOT_AUTHORIZED
        assert acc.swap(A_ACC=engine.block((PGO_OFF,))).verdicts("A") == BASELINE

    def test_the_narrowed_rule_is_refused_and_not_missing(self, engine):
        """security-negative: the refusal must be an authorization verdict.
        kXR_NotFound here would mean the seeding failed and the whole section
        was reading an empty export."""
        acc = engine("audit-16q pgo denial code", a=(PGO_ON,))
        assert acc.verdict("A", "g-supp") == KXR_NOT_AUTHORIZED
        assert acc.verdict("A", "g-none") == KXR_NOT_AUTHORIZED
        # The same open on a path the identity DOES hold proves the file, the
        # export and the login are all in place.
        assert acc.verdict("A", "u-own") == GRANTED
        assert KXR_NOT_FOUND not in acc.verdicts("A").values()


# --------------------------------------------------------------------------- #
# §B — brix_acc_resolve_hosts, three arms in one process                      #
# --------------------------------------------------------------------------- #

@_needs_ptr
class TestTheResolveHostsArms:
    """A: written ``off``.  B: written ``on``.  C: nothing.  One process — which
    is only legitimate because this flag is read per server on every
    consultation, and §D's control is what says so."""

    @pytest.fixture
    def three(self, engine):
        return engine("audit-16q resolve_hosts three arms",
                      a=(RESOLVE_OFF,), b=(RESOLVE_ON,), c=())

    def test_the_arms_disagree_within_one_process(self, three):
        """The per-server reading, stated as the disagreement: the same rule,
        the same authdb, the same peer address, three listeners, two answers."""
        assert three.verdict("A", "host") == KXR_NOT_AUTHORIZED
        assert three.verdict("B", "host") == GRANTED
        assert three.verdict("C", "host") == KXR_NOT_AUTHORIZED

    def test_the_written_off_arm_is_the_absent_arm(self, three):
        """The arm the corpus never wrote, measured against the arm it writes by
        omission — every rule, not just the host one."""
        assert three.verdicts("A") == three.verdicts("C") == BASELINE

    def test_the_on_arm_moves_only_the_host_rule(self, three):
        """And the attribution control: turning reverse resolution on must not
        change what the identity or the group rules decide."""
        assert three.verdicts("B") == RESOLVE_ON_VERDICTS

    def test_a_host_rule_grants_nothing_until_the_flag_is_written(self, three):
        """security-negative, and the operator-visible half of §B: an ACL keyed
        on a hostname is INERT in the arm nothing had executed.  Writing
        ``h <name> /pub rl`` and leaving the flag alone produces no grant and no
        diagnostic — the authdb parses, the rule loads, and the entity it is
        matched against carries an address where the rule expects a name."""
        assert three.verdict("A", "host") == KXR_NOT_AUTHORIZED
        assert three.verdict("C", "host") == KXR_NOT_AUTHORIZED
        assert "emerg" not in three.errlog()


# --------------------------------------------------------------------------- #
# §C — brix_acc_encoding, three arms in one process                           #
# --------------------------------------------------------------------------- #

class TestTheEncodingArms:
    """A: written ``off``.  B: written ``on``.  C: nothing.  Both candidate paths
    exist on disk, so every verdict below is an authorization decision."""

    @pytest.fixture
    def three(self, engine):
        return engine("audit-16q encoding three arms",
                      a=(ENCODING_OFF,), b=(ENCODING_ON,), c=())

    def test_the_arms_disagree_within_one_process(self, three):
        assert three.verdict("A", "space") == KXR_NOT_AUTHORIZED
        assert three.verdict("B", "space") == GRANTED
        assert three.verdict("C", "space") == KXR_NOT_AUTHORIZED

    def test_the_written_off_arm_is_the_absent_arm(self, three):
        assert three.verdicts("A") == three.verdicts("C") == BASELINE

    def test_the_on_arm_decodes_the_rule(self, three):
        """``u * /a%20b rl`` becomes a rule about ``/a b``."""
        assert three.verdicts("B") == ENCODING_ON_VERDICTS

    def test_the_flag_swaps_which_path_the_rule_covers(self, three):
        """security-negative, and the reason ``off`` is not "the feature turned
        off": the escaped path is GRANTED in the arms that do not decode and
        REFUSED in the arm that does.  The rule always covers exactly one path;
        the flag chooses which."""
        assert three.verdict("A", "escaped") == GRANTED
        assert three.verdict("C", "escaped") == GRANTED
        assert three.verdict("B", "escaped") == KXR_NOT_AUTHORIZED

    def test_an_operator_turning_it_on_loses_the_escaped_path(self, three):
        """The same swap read as the migration it would be: every path the
        ``off`` arm granted through this rule, the ``on`` arm refuses, and the
        exchange is silent."""
        off_granted = {rule for rule, verdict in three.verdicts("A").items()
                       if verdict == GRANTED}
        on_granted = {rule for rule, verdict in three.verdicts("B").items()
                      if verdict == GRANTED}
        def _assert_test_an_operator_turning_it_on_loses_the_escaped_path_3():
            assert off_granted - on_granted == {"escaped"}
            assert on_granted - off_granted == {"space"}

        _assert_test_an_operator_turning_it_on_loses_the_escaped_path_3()


# --------------------------------------------------------------------------- #
# §D — the finding: a per-server declaration that is not per-server            #
# --------------------------------------------------------------------------- #

class TestThePgoScopeIsNotTheDeclaredOne:
    """DEFECT CANDIDATE #92.  Each case below writes an arm on ONE listener and
    reads it on that same listener; what the other listeners carry is the only
    thing that changes."""

    def test_a_later_engine_without_the_flag_undoes_this_servers_on(self,
                                                                    engine):
        """security-negative, the headline: A writes ``brix_acc_pgo on`` and
        gets no narrowing at all, because B — which merely runs the engine and
        says nothing about pgo — installs its merged 0 into the process global
        afterwards.  The server that ASKED to be narrowed is the one that is
        widened, and nothing is logged."""
        acc = engine("audit-16q pgo lost to a later engine",
                     a=(PGO_ON,), b=())
        assert acc.verdict("A", "g-supp") == GRANTED
        assert acc.verdicts("A") == BASELINE

    def test_a_later_engines_on_reaches_the_server_that_wrote_off(self, engine):
        """The mirror, and the one an operator is likelier to hit: A writes
        ``off``, B writes ``on``, and A is narrowed anyway.  Two servers in one
        worker cannot hold two values of a flag their declaration says is
        per-server."""
        acc = engine("audit-16q pgo reaches the off server",
                     a=(PGO_OFF,), b=(PGO_ON,))
        assert acc.verdict("A", "g-supp") == KXR_NOT_AUTHORIZED
        assert acc.verdicts("A") == PGO_ON_VERDICTS

    def test_the_last_engine_in_configuration_order_decides(self, engine):
        """Three servers, two of them writing ``off``, and all three answer with
        the third one's ``on``.  It is not a majority and not the first writer:
        ``brix_acc_init_server`` runs once per server in configuration order and
        the last call wins."""
        acc = engine("audit-16q pgo last writer wins",
                     a=(PGO_OFF,), b=(PGO_OFF,), c=(PGO_ON,))
        for server in ("A", "B", "C"):
            assert acc.verdict(server, "g-supp") == KXR_NOT_AUTHORIZED, server

    def test_the_mirror_confirms_order_and_not_precedence(self, engine):
        """The same three servers with the values exchanged: two ``on`` and a
        trailing ``off`` widen ALL of them.  So ``on`` has no precedence — the
        install is a plain assignment, and position is the whole rule."""
        acc = engine("audit-16q pgo last writer wins, mirrored",
                     a=(PGO_ON,), b=(PGO_ON,), c=(PGO_OFF,))
        for server in ("A", "B", "C"):
            assert acc.verdict(server, "g-supp") == GRANTED, server

    def test_the_encoding_flag_does_not_travel(self, engine):
        """The attribution control.  Same file, same fixture, same two
        listeners, a flag from the same header and the same declaration shape —
        and A keeps its own value.  Whatever is happening to pgo is not a
        property of the harness."""
        acc = engine("audit-16q encoding stays per-server",
                     a=(ENCODING_OFF,), b=(ENCODING_ON,))
        assert acc.verdict("A", "space") == KXR_NOT_AUTHORIZED
        assert acc.verdict("B", "space") == GRANTED

    @_needs_ptr
    def test_the_resolve_hosts_flag_does_not_travel(self, engine):
        """The second control, for the third subject: two servers, two values,
        both honoured.  Two of the three flags in this header are read out of
        the per-server conf at every consultation; one is not."""
        acc = engine("audit-16q resolve_hosts stays per-server",
                     a=(RESOLVE_OFF,), b=(RESOLVE_ON,))
        assert acc.verdict("A", "host") == KXR_NOT_AUTHORIZED
        assert acc.verdict("B", "host") == GRANTED

    def test_the_value_is_installed_into_a_process_global(self):
        """The C behind §D: the per-server value is passed to a setter that
        assigns a file-scope static.  There is no per-server copy to read back,
        which is why the last writer decides."""
        squashed = " ".join(ACC_CONFIG_C.read_text().split())
        assert "brix_acc_groups_set_primary_only(pgo);" in squashed
        groups = " ".join(ACC_GROUPS_C.read_text().split())
        assert "static int acc_primary_only = 0;" in groups
        assert ("void brix_acc_groups_set_primary_only(ngx_int_t on) "
                "{ acc_primary_only = on ? 1 : 0; }") in groups
        # And the reader: one global consulted at resolution time, with no
        # server in scope to ask instead.
        assert "if (acc_primary_only) {" in groups

    def test_every_engine_carrying_server_runs_the_installer(self):
        """Why "the last one" is a rule and not an accident: worker init walks
        cmcf->servers in configuration order and each pass calls
        brix_acc_init_server, which calls brix_acc_build for every server that
        selected the engine and named an authdb."""
        process = " ".join(PROCESS_C.read_text().split())
        assert "for (i = 0; i < cmcf->servers.nelts; i++) {" in process
        init = " ".join(SERVER_INIT_C.read_text().split())
        assert "if (brix_acc_init_server(xcf, cycle) != NGX_OK) {" in init
        acc = " ".join(ACC_CONFIG_C.read_text().split())
        # The early return is what lets §A isolate an arm: no authdb, no install.
        assert "brix_acc_http_t *acc = &xcf->common.acc;" in acc
        assert ("if (acc->format != BRIX_AUTHDB_FORMAT_XRDACC "
                "|| acc->authdb.len == 0) { return NGX_OK; }") in acc
        assert "acc->tables = brix_acc_http_build(" in acc

    def test_the_same_call_installs_three_more_process_wide_tunables(self):
        """#92 is a family and not a directive: gidlifetime, nisdomain and
        gidretran ride the same call into the same file-scope statics, so
        test_audit15f_acc_group_resolution.py's gidretran arms inherit the
        finding — its every arm is its own process for exactly this reason."""
        squashed = " ".join(ACC_CONFIG_C.read_text().split())
        for setter in ("brix_acc_groups_set_gidlifetime((time_t) gidlifetime);",
                       "brix_acc_groups_set_nisdomain(nisdomain);",
                       "brix_acc_groups_set_gidretran(gidretran);"):
            assert setter in squashed, setter


# --------------------------------------------------------------------------- #
# §E — the runtime channel, and the cache that hides it                       #
# --------------------------------------------------------------------------- #

class TestTheRequestTriggeredInstall:
    """The http plane declares the same three names and builds its tables on
    first use, so the install is reachable from the network."""

    def test_an_anonymous_request_installs_the_flag_for_the_root_servers(
            self, engine):
        """security-negative, and the sharpest form of #92: A writes
        ``brix_acc_pgo off`` and honours it — until one HTTP GET arrives at a
        location on a different port, whose own ``on`` is installed process-wide
        while the request that carried it is being refused.  A configuration
        that was correct at worker start is narrowed by traffic."""
        acc = engine("audit-16q http request installs pgo",
                     a=(PGO_OFF,), http=(PGO_ON,))
        assert acc.verdict("A", "g-supp") == GRANTED
        assert acc.http_get().status_code == 403
        assert acc.await_verdict("A", "g-supp",
                                 KXR_NOT_AUTHORIZED) == KXR_NOT_AUTHORIZED
        # The rest of A's table is untouched: this is the pgo row moving, not
        # the export or the login breaking.
        assert acc.verdicts("A") == PGO_ON_VERDICTS

    def test_the_request_that_installs_it_is_itself_refused(self, engine):
        """The request needs no credential and no success: it is refused by the
        very tables its arrival built.  Removing the location's acc block and
        restarting serves the same GET 200, so the 403 is the engine's verdict
        and not a WebDAV or export failure."""
        acc = engine("audit-16q the installing request is refused",
                     a=(PGO_OFF,), http=(PGO_ON,))
        refused = acc.http_get()
        assert refused.status_code == 403
        assert SEED not in refused.content
        served = acc.swap(HTTP_ACC="").http_get()
        assert served.status_code == 200
        assert served.content == SEED
        # And with the location's engine gone, A's own `off` stands.
        assert acc.verdict("A", "g-supp") == GRANTED

    def test_the_default_group_cache_hides_the_change_for_twelve_hours(
            self, engine):
        """The third channel: the same configuration, minus the one-second
        ``brix_acc_gidlifetime`` every other case writes.  The resolved gidlist
        is cached process-wide per user for 43200 seconds, so the flip §E's
        first case measures in a second is INVISIBLE here — a server that has
        answered one request keeps answering the old way until the entry
        expires, and one that has not starts answering the new way at once."""
        acc = engine("audit-16q the gid cache hides the install",
                     a=(PGO_OFF,), http=(PGO_ON,), gidlifetime=None)
        assert acc.verdict("A", "g-supp") == GRANTED       # populates the cache
        assert acc.http_get().status_code == 403
        time.sleep(2.0)
        assert acc.verdict("A", "g-supp") == GRANTED
        groups = " ".join(ACC_GROUPS_C.read_text().split())
        assert "static time_t acc_gidlifetime = 43200;" in groups
        assert "e->expiry = now + acc_gidlifetime;" in groups

    def test_the_http_tables_are_built_on_the_first_request(self):
        """Why a REQUEST can install anything at all: the http plane has no
        per-location init hook, so the build is lazy and its trigger is
        traffic."""
        squashed = " ".join(ACC_CONFIG_C.read_text().split())
        assert "if (acc->tables == NULL) {" in squashed
        assert "acc->tables = brix_acc_http_build(acc, log);" in squashed

    def test_the_http_plane_installs_through_the_same_builder(self):
        """And why the install is the same install: brix_acc_http_build passes
        the location's pgo into brix_acc_build, which is the function that
        assigns the global."""
        squashed = " ".join(ACC_CONFIG_C.read_text().split())
        assert ("return brix_acc_build((const char *) acc->authdb.data, "
                "acc->gidlifetime, acc->pgo,") in squashed


# --------------------------------------------------------------------------- #
# §F — the parse tier                                                         #
# --------------------------------------------------------------------------- #

def _parse(tmp_path, **slots):
    """`nginx -t` on file 14's scaffold with the named slots filled.

    Every slot defaults to empty so a case names only what it is about: the
    scaffold's probe location and stream server write nothing about the acc
    engine, so a negative is never answered by a duplicate diagnostic first.
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


# The scopes these three names are declared at.  The stream declaration is a
# server (NGX_STREAM_SRV_CONF); the http declaration, unified onto the shared
# HTTP-common table (phase-101 W2), carries BRIX_HTTP_ALL_CONF =
# MAIN|SRV|LOC — so it is legal at http{}, server{} AND location{}, not just a
# location as the pre-unification hand-written twin was.
RIGHT_SCOPES = {"STREAM_KNOBS": "        ", "LOC_KNOBS": "            ",
                "SRV_KNOBS": "        ", "HTTP_KNOBS": "    "}
# Every placement neither declaration names: OUTER is the top-level main config
# (outside both http{} and stream{}), STREAM_MAIN the stream main scope (the
# stream declaration's mask is NGX_STREAM_SRV_CONF alone).
WRONG_SCOPES = ("OUTER", "STREAM_MAIN")


@_needs_nginx
class TestTheParseTier:
    """Values, arity, duplicates and the placement matrix, asked with nothing
    else in the file that could answer instead."""

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_both_arms_are_accepted_in_a_stream_server(self, tmp_path, arm,
                                                       directive):
        """The audit's step-1 question at the declared stream scope.  Three of
        these six cases are the arm the corpus never wrote, and none of them
        advises anything: turning an engine knob off is not a
        misconfiguration."""
        rc, out = _parse(tmp_path,
                         STREAM_KNOBS=f"        {directive} {arm};\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_both_arms_are_accepted_in_an_http_location(self, tmp_path, arm,
                                                        directive):
        """The other plane's declaration of the same three names, unified onto
        the shared HTTP-common flag slot (phase-101 W2) — still measured
        separately from the stream plane, not a corollary of the ones above."""
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=f"            {directive} {arm};\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    @pytest.mark.parametrize("scope", WRONG_SCOPES)
    def test_no_other_placement_is_allowed(self, tmp_path, scope, directive):
        """Every placement the two masks leave out must refuse, and the refusal
        must be about the CONTEXT: nginx searches every module's command table
        before it checks scope, so "unknown directive" here would mean the name
        had been dropped from both tables rather than misplaced.  With two
        modules declaring the same name in different planes, this is also what
        says neither declaration is quietly covering for the other."""
        rc, out = _parse(tmp_path, **{scope: f"    {directive} on;\n"})
        assert rc != 0, out
        assert "is not allowed here" in out, out
        assert "unknown directive" not in out, out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_an_unknown_value_is_refused_on_the_stream_plane(self, tmp_path,
                                                             directive):
        """``ngx_conf_set_flag_slot`` compares against exactly two tokens; a
        flag that silently read anything else as true would arm an
        authorization change its operator never wrote."""
        rc, out = _parse(tmp_path,
                         STREAM_KNOBS=f"        {directive} maybe;\n")
        assert rc != 0, out
        assert f'invalid value "maybe" in "{directive}" directive' in out, out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_an_unknown_value_is_refused_on_the_http_plane(self, tmp_path,
                                                           directive):
        """The shared flag slot validates too — with nginx's own on|off message
        (phase-101 W2 retired the hand-written setter and its bespoke message)."""
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=f"            {directive} maybe;\n")
        assert rc != 0, out
        assert 'it must be "on" or "off"' in out, out

    def test_the_http_refusal_now_names_the_directive(self, tmp_path):
        """Convergence, not divergence: phase-101 W2 unified the http-plane arms
        onto nginx's ngx_conf_set_flag_slot, whose message names the directive
        (`in "brix_acc_pgo" directive`) exactly as the stream plane does — so a
        location carrying several acc knobs now reports which line the typo is
        on.  Before the unification the hand-written http setter did not."""
        rc, out = _parse(tmp_path,
                         LOC_KNOBS="            brix_acc_pgo maybe;\n")
        assert rc != 0, out
        assert "brix_acc_pgo" in out.split("invalid value", 1)[1], out

    @pytest.mark.parametrize("scope,indent", sorted(RIGHT_SCOPES.items()))
    @pytest.mark.parametrize("token", ("ON", "OFF"))
    def test_case_is_not_significant_on_either_plane(self, tmp_path, token,
                                                     scope, indent):
        """Both planes compare case-insensitively — they are both nginx flag
        slots now (phase-101 W2 unified the http arms onto ngx_conf_set_flag_slot),
        so ON/OFF are accepted exactly as on/off on either plane."""
        rc, out = _parse(tmp_path,
                         **{scope: f"{indent}brix_acc_pgo {token};\n"})
        assert rc == 0, out

    @pytest.mark.parametrize("scope,indent", sorted(RIGHT_SCOPES.items()))
    def test_no_argument_is_refused(self, tmp_path, scope, indent):
        rc, out = _parse(tmp_path, **{scope: f"{indent}brix_acc_pgo;\n"})
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("scope,indent", sorted(RIGHT_SCOPES.items()))
    def test_two_arguments_are_refused(self, tmp_path, scope, indent):
        """NGX_CONF_FLAG is NGX_CONF_TAKE1 plus a value check, and the http twin
        is a TAKE1 outright, so a second argument is an arity error on both
        planes rather than a silently ignored token."""
        rc, out = _parse(tmp_path, **{scope: f"{indent}brix_acc_pgo on off;\n"})
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    def test_a_repeated_write_is_a_duplicate_on_the_stream_plane(self,
                                                                 tmp_path):
        """``ngx_conf_set_flag_slot`` refuses a second write to the same slot,
        which is why §A's two arms needed a reconfigure rather than two lines."""
        rc, out = _parse(tmp_path,
                         STREAM_KNOBS="        brix_acc_pgo on;\n"
                                      "        brix_acc_pgo off;\n")
        assert rc != 0, out
        assert "is duplicate" in out, out

    def test_a_repeated_write_is_refused_on_the_http_plane(self, tmp_path):
        """Convergence again: phase-101 W2 put the http arms on nginx's
        ngx_conf_set_flag_slot, which carries a duplicate check (the slot field
        is NGX_CONF_UNSET until first written) — so two contradictory lines in
        one location are refused with `"brix_acc_pgo" directive is duplicate`,
        exactly like the stream plane, instead of the old hand-written setter's
        silent last-one-wins.  An operator can no longer half-arm the engine."""
        rc, out = _parse(tmp_path,
                         LOC_KNOBS="            brix_acc_pgo on;\n"
                                   "            brix_acc_pgo off;\n")
        assert rc != 0, out
        assert '"brix_acc_pgo" directive is duplicate' in out, out


# --------------------------------------------------------------------------- #
# §G — the declarations, the merges and the corpus                            #
# --------------------------------------------------------------------------- #

def _squashed(path):
    return " ".join(path.read_text().split())


# Where the audit's step-1/step-2 grep looks, and the suffixes it counts.  These
# three directives are configured from test sources and documented in prose;
# unlike files 14-16's subjects, no rendered template writes them at all, so a
# census restricted to configs/ would report a gap that is not there and miss the
# one that is.
CORPUS_ROOTS = (ROOT / "tests", ROOT / "docs", ROOT / "k8s-tests")
CORPUS_SUFFIXES = (".py", ".conf", ".md")


# This test's own source: the arm literals it closes over live here — the main
# file AND its split-off helper (split for the 600-line cap, testsuite §10.2),
# which is logically part of the same file and so is excluded from the census
# alongside it.
_OWN_FILES = frozenset({
    Path(__file__).resolve(),
    (Path(__file__).resolve().parent
     / "_test_audit16q_acc_engine_flag_arms_helpers.py"),
})


def _corpus_root_writes(root, token, own):
    hits = []
    for path in root.rglob("*"):
        if _expression_1(path) or path.resolve() in own:
            continue
        try:
            _guard_corpus_writes_1(token, path, hits)
        except OSError:
            continue
    return hits


def _corpus_writes(token):
    """Every file OUTSIDE this test's own source that spells `token` literally."""
    hits = []
    for root in CORPUS_ROOTS:
        hits.extend(_corpus_root_writes(root, token, _OWN_FILES))
    return sorted(hits)


class TestTheDeclarationsAndTheCorpus:
    """Every reading above is an inference from a handful of lines of C and from
    what the corpus does not contain.  If either changes, the tests would keep
    passing while measuring something else."""

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_the_stream_declaration_is_a_server_scoped_flag_slot(self,
                                                                 directive):
        """One scope, ``ngx_conf_set_flag_slot``, NGX_STREAM_SRV_CONF_OFFSET —
        the declaration that promises §D what §D does not get."""
        text = DIRECTIVES_H.read_text()
        marker = f'{{ ngx_string("{directive}"),'
        assert marker in text, directive
        # splitlines()[0] is the tail of the marker's own line, which is empty.
        lines = [ln.strip() for ln in text.split(marker, 1)[1].splitlines()[1:5]]
        assert lines[0] == "NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,", lines
        assert lines[1] == "ngx_conf_set_flag_slot,", lines
        assert lines[2] == "NGX_STREAM_SRV_CONF_OFFSET,", lines
        assert lines[3] == ("offsetof(ngx_stream_brix_srv_conf_t, common."
                            f"{SUBJECTS[directive]}),"), lines

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_it_merges_to_zero(self, directive):
        """The bare arm reads this 0, which is what makes ``off`` the arm nobody
        needed to write and ``on`` the arm everybody did.  A merge default of 1
        would have made the corpus census come out the other way round."""
        field = SUBJECTS[directive].removeprefix("acc.")
        assert (f"ngx_conf_merge_value(conf->{field}, prev->{field}, 0);"
                in _squashed(MERGE_C))

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_the_http_twin_is_a_shared_flag_slot_on_common(self, directive):
        """The same name on the HTTP plane, unified (phase-101 W2) onto ONE bare
        registration on the shared HTTP-common table.

        The hand-written per-directive setters (and their whole
        module_acc_directives.c home) are gone: one name is now declared
        BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG behind nginx's own ngx_conf_set_flag_slot,
        landing its value in common.acc.<field> via offsetof — so it works on
        every HTTP protocol (webdav, s3, cvmfs) from a single row.  The field
        each directive arms is still its own (that is what §F measures per-plane),
        only the registration is shared and generic now."""
        text = HTTP_AUTH_H.read_text()
        marker = f'{{ ngx_string("{directive}"),'
        assert marker in text, directive
        # Normalise whitespace across the whole entry (up to its closing `},`)
        # rather than pinning fixed line offsets.
        entry = " ".join(text.split(marker, 1)[1].split("},", 1)[0].split())
        assert "BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG," in entry, entry
        assert "ngx_conf_set_flag_slot," in entry, entry
        field = SUBJECTS[directive]                       # e.g. "acc.pgo"
        assert (f"offsetof(ngx_http_brix_common_conf_t, common.{field})"
                in entry), entry

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_the_corpus_writes_the_on_arm_and_never_the_off_arm(self,
                                                               directive):
        """Steps 1 and 2 of the audit's own measurement, as this file found
        them: the ``on`` arm is written — in test sources and in the
        authorization docs — and the ``off`` arm was written nowhere.  If
        another file starts writing ``off``, re-run the gap table rather than
        relaxing this."""
        assert _corpus_writes(f"{directive} on;"), \
            f"{directive} is written nowhere at all"
        assert _corpus_writes(f"{directive} off;") == []

    @pytest.mark.parametrize("arm", OFF_ARMS)
    def test_this_file_writes_every_off_arm_literally(self, arm):
        """The closure itself.  The audit greps the tree for
        ``<directive> <value>;``, so an arm assembled at runtime from a name and
        a token would leave the gap open while the tests passed.  The literals
        live in this test's own source — the main file or its split-off helper
        (both are excluded from the corpus census as one logical file)."""
        own = "".join(p.read_text() for p in _OWN_FILES)
        assert arm in own

    def test_the_template_carries_four_engine_slots_and_writes_no_arm(self):
        """The template offers a whole acc block per listener and takes no
        position on any subject: three root:// servers, one http location, and
        not one of the six arms written in the file itself."""
        text = (CONFIGS_DIR / TEMPLATE).read_text()
        for slot in ("{A_ACC}", "{B_ACC}", "{C_ACC}", "{HTTP_ACC}"):
            assert slot in text, slot
        squashed = " ".join(text.split())
        for directive in SUBJECTS:
            def _assert_test_the_template_carries_four_engine_slots_and_writes_no_arm_2():
                assert f"{directive} on;" not in squashed, directive
                assert f"{directive} off;" not in squashed, directive

            _assert_test_the_template_carries_four_engine_slots_and_writes_no_arm_2()
        def _assert_test_the_template_carries_four_engine_slots_and_writes_no_arm_1():
            assert squashed.count("brix_root on;") == 3
            assert squashed.count("brix_auth unix;") == 3

        _assert_test_the_template_carries_four_engine_slots_and_writes_no_arm_1()

    def test_the_ledger_owns_one_port_per_listener(self):
        """Four sockets, four ledger allocations, all distinct.  Two root://
        servers sharing a port would not be a slower test: holding three arms
        side by side in one process is what §B, §C and §D each measure."""
        slot = LIFECYCLE_SHARED_PORTS[NAME]
        ports = [slot["port"], *slot["extra"].values()]
        assert sorted(slot["extra"]) == ["B_PORT", "C_PORT", "HTTP_PORT"]
        assert len(set(ports)) == 4, ports
