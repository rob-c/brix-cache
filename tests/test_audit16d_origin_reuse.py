"""Test cases for audit16d_origin_reuse — preamble (fixtures/helpers/mocks) lives in
_test_audit16d_origin_reuse_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16d_origin_reuse_helpers")


class TestTheFlagOnOneLocation:
    """The two values, each written out, in the one configuration shape where
    an operator's reading of the directive cannot be wrong."""

    def test_reuse_on_serves_the_whole_batch_over_one_connection(
            self, lifecycle, tmp_path, mock):
        """success: the ON arm, which until now was reachable only as the merge
        default and was therefore never distinguished from it.

        One fill thread keeps one curl handle, the handle keeps its connection
        pool across ``curl_easy_reset()``, and the origin is HTTP/1.1 — so every
        request after the first rides the connection the first one opened.
        """
        endpoint = _start(lifecycle, tmp_path, policy_a=_policy(ON))
        _warm(endpoint, mock, REPO_A)
        reading = _measure(endpoint, mock, REPO_A)
        _served(reading, mock)
        assert reading.accepts == 0, (
            f"reuse is on but the origin accepted {reading.accepts} new "
            f"connections for {reading.requests} requests: {reading}\n"
            f"{reading.errlog}")

    def test_reuse_off_opens_a_fresh_connection_for_every_request(
            self, lifecycle, tmp_path, mock):
        """success: the OFF arm — the value nothing in the corpus had ever
        written, and the one an operator reaches for when a middlebox is
        reaping their idle connections.

        CURLOPT_FORBID_REUSE keeps the finished connection out of the pool and
        CURLOPT_FRESH_CONNECT refuses to draw from it, so the count is exactly
        the request count: no more (nothing is opened speculatively) and no
        fewer (nothing is kept).
        """
        endpoint = _start(lifecycle, tmp_path, policy_a=_policy(OFF))
        _warm(endpoint, mock, REPO_A)
        reading = _measure(endpoint, mock, REPO_A)
        _served(reading, mock)
        assert reading.accepts == reading.requests, (
            f"reuse is off but the origin accepted {reading.accepts} "
            f"connections for {reading.requests} requests: {reading}\n"
            f"{reading.errlog}")

    def test_nothing_in_the_log_names_the_policy_in_force(self, lifecycle,
                                                          tmp_path, mock):
        """DEFECT CANDIDATE #69, the run-time half of "nothing is said".

        The instance runs at ``error_log info``, the most verbose level an
        operator would ever deploy, on the arm that is NOT the default — and
        there is no line saying which reuse policy is in force.  That is what
        makes §C's clobber undiagnosable in production as well as at parse time:
        the operator whose ``off`` was taken away by a sibling location has
        nowhere to look and nothing to grep for.

        Byte-identity across the arms is not asserted here; it is asserted on
        every batch in the file, by ``_served`` against the origin's own copy.
        """
        endpoint = _start(lifecycle, tmp_path, policy_a=_policy(OFF))
        _warm(endpoint, mock, REPO_A)
        reading = _measure(endpoint, mock, REPO_A)
        _served(reading, mock)
        assert reading.accepts == reading.requests, (
            f"the OFF arm is not in force after all: {reading}")
        named = [line for line in reading.errlog.splitlines()
                 if any(word in line.lower()
                        for word in ("reuse", "keep-alive to origin",
                                     "fresh connect"))]
        assert named == [], (
            "the reuse policy is now named in the log — pin the new line here "
            f"and narrow #69 to the parse tier:\n" + "\n".join(named))


# --------------------------------------------------------------------------- #
# B. The merge default                                                         #
# --------------------------------------------------------------------------- #

class TestTheMergeDefault:
    """``ngx_conf_merge_value(conf->cvmfs.origin_reuse_conn,
    prev->cvmfs.origin_reuse_conn, 1)`` — cvmfs_module_merge.c:209-210."""

    def test_the_directive_absent_behaves_as_on(self, lifecycle, tmp_path,
                                                mock):
        """success: the default is reuse, asserted rather than assumed.

        Every cvmfs config in the corpus is this one, so this is the arm the
        whole suite has been exercising by accident.  Pinning it is what makes
        the ON case above a measurement of the DIRECTIVE instead of a second
        measurement of the default.
        """
        endpoint = _start(lifecycle, tmp_path, policy_a="")
        _warm(endpoint, mock, REPO_A)
        reading = _measure(endpoint, mock, REPO_A)
        _served(reading, mock)
        assert reading.accepts == 0, (
            f"the merge default is no longer reuse: {reading}\n"
            f"{reading.errlog}")


# --------------------------------------------------------------------------- #
# C. DEFECT CANDIDATE #69 — the location-level flag that is not per-location   #
# --------------------------------------------------------------------------- #

class TestTheFlagIsProcessGlobal:
    """Each test reads the SAME batch through the SAME location; the only thing
    that changes between them is what a sibling location wrote."""

    def test_a_sibling_location_takes_the_operators_off_away(
            self, lifecycle, tmp_path, mock):
        """DEFECT CANDIDATE #69(a).

        Location A writes ``off`` — proven above to give one connection per
        request when it is the only location.  Location B, a different
        repository, writes ``on`` and is merged after it.  A's fills go back to
        reusing.  Nothing about A changed, and nothing anywhere says so.
        """
        endpoint = _start(lifecycle, tmp_path, policy_a=_policy(OFF),
                          policy_b=_policy(ON))
        _warm(endpoint, mock, REPO_A)
        reading = _measure(endpoint, mock, REPO_A)
        _served(reading, mock)
        assert reading.accepts == 0, (
            "a sibling location no longer overrides this one's reuse policy — "
            f"#69(a) may be fixed: {reading}\n{reading.errlog}")

    def test_a_silent_sibling_location_takes_it_away_too(
            self, lifecycle, tmp_path, mock):
        """DEFECT CANDIDATE #69(b) — the row an operator actually hits.

        Location B says NOTHING about connection reuse.  It is a second
        repository export, added months later, by someone who has never heard
        of this directive.  Its unset flag merges to 1 and is written to the
        process global exactly like a chosen value, so location A's ``off`` —
        the workaround for the middlebox that made A unusable — is gone.
        """
        endpoint = _start(lifecycle, tmp_path, policy_a=_policy(OFF),
                          policy_b="")
        _warm(endpoint, mock, REPO_A)
        reading = _measure(endpoint, mock, REPO_A)
        _served(reading, mock)
        assert reading.accepts == 0, (
            "an opinion-less sibling location no longer reverts this one's "
            f"reuse policy — #69(b) may be fixed: {reading}\n{reading.errlog}")

    def test_a_sibling_off_costs_this_location_its_keepalive(
            self, lifecycle, tmp_path, mock):
        """DEFECT CANDIDATE #69(c).

        The reverse direction, and the expensive one: location A asked for
        nothing unusual (``on``), and one sibling that needs ``off`` puts A back
        on a cold TCP connection and a cold congestion window for every single
        object it fills.  On the high-latency link the reuse path was written
        for, that is the whole cost the path exists to avoid.
        """
        endpoint = _start(lifecycle, tmp_path, policy_a=_policy(ON),
                          policy_b=_policy(OFF))
        _warm(endpoint, mock, REPO_A)
        reading = _measure(endpoint, mock, REPO_A)
        _served(reading, mock)
        assert reading.accepts == reading.requests, (
            "a sibling location no longer imposes its no-reuse policy on this "
            f"one — #69(c) may be fixed: {reading}\n{reading.errlog}")

    def test_both_locations_get_the_same_answer(self, lifecycle, tmp_path,
                                                mock):
        """DEFECT CANDIDATE #69, stated as an identity rather than as a clobber.

        A says ``on``, B says ``off``, and the two locations are measured in the
        same process against the same origin.  If the directive were
        per-location the readings would differ; they are equal, which is the
        finding said once without reference to merge order.
        """
        endpoint = _start(lifecycle, tmp_path, policy_a=_policy(ON),
                          policy_b=_policy(OFF))
        _warm(endpoint, mock, REPO_A)
        _warm(endpoint, mock, REPO_B)
        through_a = _measure(endpoint, mock, REPO_A)
        through_b = _measure(endpoint, mock, REPO_B)
        _served(through_a, mock)
        _served(through_b, mock)
        assert through_a.accepts == through_a.requests, (
            f"location A: {through_a}\n{through_a.errlog}")
        assert through_b.accepts == through_b.requests, (
            f"location B: {through_b}\n{through_b.errlog}")


# --------------------------------------------------------------------------- #
# D. The blast radius — the flag is not per-FEATURE either                     #
# --------------------------------------------------------------------------- #

def _source(path):
    return path.read_text()


class TestTheReusePolicyIsNotConfinedToCvmfs:
    """DEFECT CANDIDATE #69(d), taken from the C.

    Demonstrating this on the wire needs a second protocol face (sd_http is
    reached from a root:// listener), which is a whole second instrument for a
    fact the source states plainly.  What is pinned here is each link of the
    chain, so a fix anywhere along it fails a test here rather than passing
    silently.
    """

    def test_the_transport_applies_the_policy_unconditionally(self):
        """The reuse policy is applied by the request path itself, with no
        condition on which feature asked for the request."""
        text = _source(SETUP_C)
        assert "    s3o_apply_reuse(curl);\n" in text, (
            "s3o_apply_reuse is no longer called unconditionally from the "
            "transport — re-read the chain and re-state #69(d)")
        assert text.count("s3o_apply_reuse(curl);") == 1, (
            "more than one call site: the single unconditional application is "
            "what makes the policy reach every caller of the transport")

    def test_the_plain_http_backend_drives_the_same_transport(self):
        """sd_http is the ``http://`` storage backend, and it shares the vtable
        the reuse policy is applied inside."""
        text = _source(SD_HTTP_C)
        assert "brix_s3_transport_t" in text, (
            "sd_http no longer names the shared transport vtable — the "
            "cross-feature half of #69(d) needs re-deriving")

    def test_only_a_cvmfs_location_can_ever_set_the_policy(self):
        """And the other end of the asymmetry: the ONLY way to write the global
        is a cvmfs-enabled location, so an sd_http tier can be re-policied by a
        cvmfs location but can never state a policy of its own."""
        text = _source(MERGE_C)
        setter = "brix_s3_origin_reuse_set("
        assert text.count(setter) == 1, (
            f"{setter} no longer has exactly one call site in the merge")
        gate = text.index("if (conf->cvmfs.enable) {")
        call = text.index(setter)
        assert gate < call < text.index("return NGX_CONF_OK;", gate), (
            "the setter call left the `if (conf->cvmfs.enable)` block — the "
            "asymmetry #69(d) describes has changed shape")


# --------------------------------------------------------------------------- #
# E. The parse tier                                                            #
# --------------------------------------------------------------------------- #

def _knobs(*lines):
    return "".join(f"            {line}\n" for line in lines)


def _second_location(*lines):
    """A whole second cvmfs location for the parse scaffold — the shape §C
    measured, asked of ``nginx -t`` instead of of a request."""
    body = "".join(f"            {line}\n" for line in lines)
    return (f"\n        location /cvmfs2/ {{\n"
            f"            brix_cvmfs           on;\n"
            f"            brix_cache_store     posix:{{CACHE2}};\n"
            f"{body}        }}\n")


def _diagnostics(out):
    """The lines of an ``nginx -t`` transcript that would tell an operator
    something is wrong.  Matching on the transcript as a whole cannot work: the
    prefix is a tmp_path named after the test, and the tokens this file tests
    ("on", "off") appear inside directory names."""
    return [line for line in out.splitlines()
            if any(sev in line for sev in ("[warn]", "[error]", "[crit]",
                                           "[emerg]"))]


def _parse(tmp_path, knobs="", loc_extra="", http_extra="", outer=""):
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    cache2 = tmp_path / "cache2"
    cache2.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit16dparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, LOG_DIR=str(tmp_path),
                     CACHE=str(cache), BACKEND=BACKEND, KNOBS=knobs,
                     LOC_EXTRA=loc_extra.replace("{CACHE2}", str(cache2)),
                     HTTP_EXTRA=http_extra, OUTER=outer)
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


DIRECTIVE = "brix_cvmfs_origin_reuse_conn"


class TestTheParseTier:
    """What the flag accepts and refuses.  Nothing here starts a server, and
    every case damages only its own tmp_path copy of the scaffold."""

    @pytest.mark.parametrize("value", ["on", "off"])
    def test_both_values_parse(self, tmp_path, value):
        """success: the two arms of the pair, at the tier that costs nothing —
        and the reason a value-granularity sweep exists, since neither had ever
        been written anywhere in the corpus."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} {value};"))
        assert rc == 0, f"{DIRECTIVE} {value} was rejected\n{out}"

    @pytest.mark.parametrize("value", ["On", "OFF", "oN"])
    def test_the_values_are_case_insensitive(self, tmp_path, value):
        """ngx_conf_set_flag_slot compares with ngx_strcasecmp after checking
        the length, so the config language is case-insensitive here while the
        audit's own grep for written values is not — which is why the sweep has
        to read the setter rather than the configs alone."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} {value};"))
        assert rc == 0, f"the flag slot rejected {value!r}\n{out}"

    @pytest.mark.parametrize("value", ["1", "0", "true", "yes", "enabled"])
    def test_a_plausible_synonym_is_refused(self, tmp_path, value):
        """error: every one of these is what an operator writes for a boolean
        in some other configuration language, and the flag slot takes exactly
        two spellings.  Refusing loudly is the whole protection here — silently
        keeping the default would hand the operator the policy they were trying
        to change, process-wide."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} {value};"))
        assert rc != 0 and f'invalid value "{value}"' in out, out

    def test_an_empty_value_is_refused(self, tmp_path):
        """security-negative: an unset shell variable expanding to "" must not
        quietly become the default.  An operator templating this per site would
        silently re-enable reuse for every export in the process — including the
        ones whose configuration they never touched."""
        rc, out = _parse(tmp_path, _knobs(f'{DIRECTIVE} "";'))
        assert rc != 0 and 'invalid value ""' in out, out

    @pytest.mark.parametrize("line", [f"{DIRECTIVE};",
                                      f"{DIRECTIVE} on off;",
                                      f"{DIRECTIVE} off on;"])
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, line):
        """error: NGX_CONF_FLAG is TAKE1.  "on off" is the shape an operator
        reaches for when they want a preference order, and it must not parse as
        either value."""
        rc, out = _parse(tmp_path, _knobs(line))
        assert rc != 0, f"{line!r} parsed\n{out}"
        assert "invalid number of arguments" in out, out

    def test_a_duplicate_directive_is_refused(self, tmp_path):
        """security-negative: two values in ONE location would leave which one
        wins to the parser's ordering.  nginx refuses that — which is exactly
        the check §C shows the directive does not get ACROSS locations."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} on;",
                                          f"{DIRECTIVE} off;"))
        assert rc != 0 and f'"{DIRECTIVE}" directive is duplicate' in out, out

    def test_the_directive_is_accepted_at_http_level(self, tmp_path):
        """success: MAIN|SRV|LOC within http.  A site-wide default is the
        legitimate way to write this one — it is the only placement whose
        meaning matches what the C actually does."""
        rc, out = _parse(tmp_path, http_extra=f"    {DIRECTIVE} off;\n")
        assert rc == 0, f"an http-level {DIRECTIVE} was rejected\n{out}"

    def test_the_directive_is_refused_outside_http(self, tmp_path):
        """security-negative: written at the top of the file it reads like a
        global default — which is what it effectively is.  nginx must still
        refuse it rather than silently ignore it."""
        rc, out = _parse(tmp_path, outer=f"{DIRECTIVE} off;\n")
        assert rc != 0, f"a main-context {DIRECTIVE} parsed\n{out}"
        assert f'"{DIRECTIVE}" directive is not allowed here' in out, out

    def test_two_locations_disagreeing_parse_in_silence(self, tmp_path):
        """DEFECT CANDIDATE #69, parse-time half.

        Config parse is the last moment the clobber is diagnosable: both values
        are known, the merge is about to discard one of them, and which one
        survives depends on nothing an operator can see.  Nothing is said — no
        warning, no notice, nothing naming either location — so their only
        feedback is a Stratum-1 link that got slow, or a middlebox workaround
        that stopped working, on an export they did not edit.
        """
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} off;"),
                         loc_extra=_second_location(f"{DIRECTIVE} on;"))
        assert rc == 0, f"the two-location config stopped parsing\n{out}"
        assert _diagnostics(out) == [], (
            "the discarded reuse policy is now diagnosed at parse time — pin "
            f"the new diagnostic here and close #69\n{out}")


# --------------------------------------------------------------------------- #
# F. Source pins for the mechanism                                             #
# --------------------------------------------------------------------------- #

class TestTheMechanismIsWhereTheFileSaysItIs:
    """Everything above reads the flag through a socket.  These read it in the
    C, so that a refactor which moves the mechanism fails here — where the
    message names the new shape — instead of failing as an unexplained
    connection count."""

    def test_the_global_has_exactly_one_writer_and_one_reader(self):
        """The single-writer/single-reader shape is what makes "the last
        location merged decides" a complete description of the behaviour."""
        text = _source(SETUP_C)
        assert text.count("g_origin_no_reuse = ") == 1, (
            "g_origin_no_reuse has more than one writer")
        assert text.count("if (g_origin_no_reuse)") == 1, (
            "g_origin_no_reuse has more than one reader")

    def test_the_off_arm_is_forbid_reuse_plus_fresh_connect(self):
        """Both options, not either: FORBID_REUSE keeps the finished connection
        out of the pool and FRESH_CONNECT refuses to draw from it.  One without
        the other would still reuse in one direction, and the accept counts §A
        asserts would be off by one."""
        text = _source(SETUP_C)
        for option in ("CURLOPT_FORBID_REUSE, 1L", "CURLOPT_FRESH_CONNECT, 1L"):
            assert option in text, f"{option} is gone from the no-reuse arm"

    def test_the_pool_survives_between_requests(self):
        """The ON arm is only meaningful because the handle is kept and reset
        rather than re-created; ``curl_easy_reset()`` preserves the connection
        pool, ``curl_easy_init()`` would not."""
        text = _source(SETUP_C)
        assert "curl_easy_reset(handle)" in text, (
            "the per-thread handle is no longer reset-and-reused — the ON arm "
            "would then be indistinguishable from the OFF arm")

    def test_the_merge_default_is_reuse(self):
        """§B measured it; this names the line, so that a change to the default
        fails with the reason rather than with a connection count."""
        text = _source(MERGE_C)
        assert ("ngx_conf_merge_value(conf->cvmfs.origin_reuse_conn,\n"
                "                         prev->cvmfs.origin_reuse_conn, 1);"
                ) in text, "the origin_reuse_conn merge default is no longer 1"
