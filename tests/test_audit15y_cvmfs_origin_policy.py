"""Test cases for audit15y_cvmfs_origin_policy — preamble (fixtures/helpers/mocks) lives in
_test_audit15y_cvmfs_origin_policy_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit15y_cvmfs_origin_policy_helpers")


class TestTheOriginHttpVersionIsProcessGlobal:
    """A location-level directive whose value is decided by another location.

    Each test reads the SAME request through the SAME location; the only thing
    that changes between them is what a sibling location wrote.
    """

    def test_version_11_fills_over_http1(self, lifecycle, tmp_path, mock):
        """success: the token no config in the suite writes.

        ``1.1`` is what an operator pins when their Stratum-1 is behind
        something that mishandles h2c Upgrade, and until now nothing measured
        that it works.  The mock answers as HTTP/1.0 (BaseHTTPRequestHandler's
        default), so 1.0 is the honest negotiated token for a 1.x policy.
        """
        endpoint = _start(lifecycle, tmp_path,
                          policy_a=_policy("brix_cvmfs_origin_http_version 1.1;"))
        status, body = _fetch(endpoint, REPO_A)
        _settle()
        assert status == 200, _errlog(endpoint)
        assert body, "an empty manifest is not a fill"
        protos = _protos(endpoint)
        assert protos and set(protos) <= {"1.0", "1.1"}, (
            f"1.1 negotiated something else: {protos}\n{_errlog(endpoint)}")

    def test_2direct_alone_cannot_fill_from_an_http1_origin(self, lifecycle,
                                                            tmp_path, mock):
        """error: h2c prior knowledge has no fallback, by design.

        This is the reading every other case in the class is taken against —
        the value is unambiguously wrong for this origin, and one location
        writing it fails one location.
        """
        endpoint = _start(
            lifecycle, tmp_path,
            policy_a=_policy("brix_cvmfs_origin_http_version 2-direct;"))
        status, _ = _fetch(endpoint, REPO_A)
        _settle()
        assert status == 504, f"expected a gateway timeout, got {status}"
        assert _protos(endpoint) == [], (
            "a proto was negotiated after all — the origin is no longer "
            f"HTTP/1.x-only\n{_errlog(endpoint)}")

    def test_a_sibling_location_takes_a_working_version_away(self, lifecycle,
                                                             tmp_path, mock):
        """DEFECT CANDIDATE #57(a).

        Location A writes ``1.1`` — the value that works here, proven by the
        first test in this class.  Location B, a different repository, writes
        ``2-direct``.  A stops serving.  Nothing about A changed.
        """
        endpoint = _start(
            lifecycle, tmp_path,
            policy_a=_policy("brix_cvmfs_origin_http_version 1.1;"),
            policy_b=_policy("brix_cvmfs_origin_http_version 2-direct;"))
        status_a, _ = _fetch(endpoint, REPO_A)
        status_b, _ = _fetch(endpoint, REPO_B)
        _settle()
        assert (status_a, status_b) == (504, 504), (
            "the locations no longer share one process-global HTTP version — "
            f"A={status_a} B={status_b}; #57 may be fixed\n{_errlog(endpoint)}")
        assert _protos(endpoint) == [], _errlog(endpoint)

    def test_the_last_location_merged_decides_for_both(self, lifecycle,
                                                       tmp_path, mock):
        """DEFECT CANDIDATE #57(a), the other order.

        The same two values, swapped.  Now BOTH locations serve — including the
        one that asked for h2c prior knowledge and was quietly given HTTP/1.x
        instead.  Config order, not location, is what selected the version.
        """
        endpoint = _start(
            lifecycle, tmp_path,
            policy_a=_policy("brix_cvmfs_origin_http_version 2-direct;"),
            policy_b=_policy("brix_cvmfs_origin_http_version 1.1;"))
        status_a, body_a = _fetch(endpoint, REPO_A)
        status_b, body_b = _fetch(endpoint, REPO_B)
        _settle()
        assert (status_a, status_b) == (200, 200), (
            f"A={status_a} B={status_b}\n{_errlog(endpoint)}")
        assert body_a and body_b
        protos = _protos(endpoint)
        assert protos and set(protos) <= {"1.0", "1.1"}, (
            "the 2-direct location was served over h2c after all — the global "
            f"is no longer last-merge-wins: {protos}")

    def test_a_location_that_says_nothing_overrides_one_that_does(self, lifecycle,
                                                                  tmp_path, mock):
        """DEFECT CANDIDATE #57(b): silence is not neutral.

        Location A pins ``2-direct``; location B mentions no version at all.
        B's unset value merges to 0 and is written to the global exactly like a
        chosen one, so A is served over HTTP/1.x — the policy it wrote is
        discarded by a location that expressed no policy.
        """
        endpoint = _start(
            lifecycle, tmp_path,
            policy_a=_policy("brix_cvmfs_origin_http_version 2-direct;"),
            policy_b="")
        status_a, _ = _fetch(endpoint, REPO_A)
        status_b, _ = _fetch(endpoint, REPO_B)
        _settle()
        assert (status_a, status_b) == (200, 200), (
            "the silent location no longer clobbers the explicit one — "
            f"A={status_a} B={status_b}; #57(b) may be fixed\n{_errlog(endpoint)}")
        protos = _protos(endpoint)
        assert protos and set(protos) <= {"1.0", "1.1"}, protos

    def test_a_location_that_says_nothing_is_forced_onto_h2c(self, lifecycle,
                                                             tmp_path, mock):
        """security-negative / DEFECT CANDIDATE #57(c): the blast radius.

        The same two locations in the other order.  Location A never mentions
        the directive — it is an existing, working repository export — and
        adding location B for a new repository that needs ``2-direct`` takes A
        down with it.  The export that stops serving is not the export that was
        edited, and nothing in the config names A.
        """
        endpoint = _start(
            lifecycle, tmp_path, policy_a="",
            policy_b=_policy("brix_cvmfs_origin_http_version 2-direct;"))
        status_a, _ = _fetch(endpoint, REPO_A)
        status_b, _ = _fetch(endpoint, REPO_B)
        _settle()
        assert (status_a, status_b) == (504, 504), (
            "an unrelated location no longer forces its version onto a silent "
            f"one — A={status_a} B={status_b}; #57(c) may be fixed\n"
            f"{_errlog(endpoint)}")
        assert _protos(endpoint) == [], _errlog(endpoint)


# --------------------------------------------------------------------------- #
# B. brix_cvmfs_geo_answer — the control                                       #
# --------------------------------------------------------------------------- #

class TestGeoAnswerIsHonestlyPerLocation:
    """The same trio's third directive, read at request time instead of merged.

    Every assertion here is what §A's assertions would have been if the version
    directive were per-location, which is the point of measuring it in the same
    file with the same origin.
    """

    def test_off_relays_the_geo_request_to_the_origin(self, lifecycle, tmp_path,
                                                      mock):
        """success: the token no config in the suite writes.

        ``off`` means "this cache does not answer geo itself" — the request is
        relayed to the Stratum-1, whose answer is returned verbatim.  The
        status alone cannot show that (``rtt`` answers 200 too), so the witness
        is the origin's own request log.
        """
        endpoint = _start(lifecycle, tmp_path,
                          policy_a=_policy("brix_cvmfs_geo_answer off;"))
        mock.reset()
        status, body = _fetch(endpoint, REPO_A, GEO_PATH)
        _settle(0.3)
        assert (status, body) == (200, GEO_BODY), _errlog(endpoint)
        assert len(mock.geo_hits()) == 1, (
            f"`off` did not relay to the origin: {mock.paths()}")

    def test_rtt_answers_locally_and_never_touches_the_origin(self, lifecycle,
                                                              tmp_path, mock):
        """The written half of the pair, measured the same way so the two
        readings are comparable: identical status, identical body, and the
        origin never hears about it."""
        endpoint = _start(lifecycle, tmp_path,
                          policy_a=_policy("brix_cvmfs_geo_answer rtt;"))
        mock.reset()
        status, body = _fetch(endpoint, REPO_A, GEO_PATH)
        _settle(0.3)
        assert (status, body) == (200, GEO_BODY), _errlog(endpoint)
        assert mock.geo_hits() == [], (
            f"`rtt` reached the origin: {mock.paths()}")

    def test_each_location_keeps_its_own_answer_mode(self, lifecycle, tmp_path,
                                                     mock):
        """The contrast with §A, stated in one config.

        Two locations, two different tokens, one worker: A relays and B does
        not.  Nothing here depends on which was merged last, because
        gate.c:422 reads the location's own value on the request.
        """
        endpoint = _start(lifecycle, tmp_path,
                          policy_a=_policy("brix_cvmfs_geo_answer off;"),
                          policy_b=_policy("brix_cvmfs_geo_answer rtt;"))
        mock.reset()
        status_a, body_a = _fetch(endpoint, REPO_A, GEO_PATH)
        _settle(0.3)
        relayed = len(mock.geo_hits())

        mock.reset()
        status_b, body_b = _fetch(endpoint, REPO_B, GEO_PATH)
        _settle(0.3)
        local = mock.geo_hits()

        assert (status_a, body_a) == (200, GEO_BODY), _errlog(endpoint)
        assert (status_b, body_b) == (200, GEO_BODY), _errlog(endpoint)
        assert relayed == 1, "the `off` location stopped relaying"
        assert local == [], f"the `rtt` location relayed: {local}"

    def test_the_order_does_not_change_either_location(self, lifecycle, tmp_path,
                                                       mock):
        """error arm + the order control.

        The same two tokens swapped.  ``rtt`` still answers locally and ``off``
        still relays — and because ``off`` relays, location B's geo request
        reaches an origin that serves geo for REPO_A only, so the operator sees
        the Stratum-1's own 404 rather than a locally-invented answer.  That
        pass-through of a failure is the behaviour ``off`` exists for.
        """
        endpoint = _start(lifecycle, tmp_path,
                          policy_a=_policy("brix_cvmfs_geo_answer rtt;"),
                          policy_b=_policy("brix_cvmfs_geo_answer off;"))
        mock.reset()
        status_a, body_a = _fetch(endpoint, REPO_A, GEO_PATH)
        _settle(0.3)
        quiet = mock.geo_hits()

        mock.reset()
        status_b, _ = _fetch(endpoint, REPO_B, GEO_PATH)
        _settle(0.3)
        relayed = len(mock.geo_hits())

        assert (status_a, body_a) == (200, GEO_BODY), _errlog(endpoint)
        assert quiet == [], (
            f"`rtt` relayed once a sibling wrote `off`: {quiet}")
        assert status_b == 404, (
            f"the relayed geo request did not carry the origin's verdict: "
            f"{status_b}\n{_errlog(endpoint)}")
        assert relayed == 1, "the `off` location stopped relaying"


# --------------------------------------------------------------------------- #
# C. brix_cvmfs_fill_retry_policy — DEFECT CANDIDATE #58                       #
# --------------------------------------------------------------------------- #

class TestTheFillRetryPolicy:
    """What ``failover`` is, and what stops it being that.

    Every case reads the manifest through location A over the SAME
    DEAD|LIVE origin set; the observable is the sd_http line that says a read
    ran out of endpoints, counted in the instance's own log.
    """

    def test_the_directive_absent_never_exhausts_the_endpoint_set(self, lifecycle,
                                                                  tmp_path, mock):
        """The default: a dead primary is failed over from, quietly.  This is
        the reading ``failover`` has to match to be a no-op."""
        endpoint = _start(lifecycle, tmp_path, backend=DEAD_THEN_LIVE,
                          policy_a=_retry_policy())
        status, body = _fetch(endpoint, REPO_A)
        _settle()
        assert status == 200 and body, _errlog(endpoint)
        assert _count(endpoint, EXHAUSTED) == 0, _errlog(endpoint)

    def test_failover_is_indistinguishable_from_omitting_the_directive(
            self, lifecycle, tmp_path, mock):
        """success: the token no config in the suite writes.

        ``failover`` is the enum's 0 and the merge default, so writing it must
        be exactly writing nothing — the same 200, from the same alternate,
        with the same silent log.  An operator who writes it to document intent
        must not be changing behaviour.
        """
        endpoint = _start(lifecycle, tmp_path, backend=DEAD_THEN_LIVE,
                          policy_a=_retry_policy("failover"))
        status, body = _fetch(endpoint, REPO_A)
        _settle()
        assert status == 200 and body, _errlog(endpoint)
        assert _count(endpoint, EXHAUSTED) == 0, (
            "`failover` exhausted the endpoint set — it is no longer the "
            f"default's twin\n{_errlog(endpoint)}")

    def test_force_primary_exhausts_the_set_and_returns_hold_expiry(
            self, lifecycle, tmp_path, mock):
        """force-primary never opens the configured alternate.

        sd_http.h:100-104 says force-primary "never fails over to an alternate
        on a transport failure".  With the static selector, the configured
        dead endpoint is rank-preferred for every retry, so the bounded hold
        returns 504 rather than silently serving the alternate.
        """
        endpoint = _start(
            lifecycle, tmp_path, backend=DEAD_THEN_LIVE,
            policy_a=_retry_policy("force-primary"))
        status, body = _fetch(endpoint, REPO_A)
        _settle()
        log = _errlog(endpoint)
        assert status == 504, f"force-primary served an alternate ({status})\n{log}"
        assert _count(endpoint, EXHAUSTED) > 0, (
            f"force-primary did not exhaust its configured primary\n{log}")
        assert FILL_RETRY in log, (
            f"force-primary did not retry its configured primary\n{log}")

    def test_a_silent_sibling_leaves_a_failover_location_alone(self, lifecycle,
                                                               tmp_path, mock):
        """The control for the next test: a second location, by itself, changes
        nothing.  Without this the latch below could be read as "two cvmfs
        locations behave differently from one"."""
        endpoint = _start(lifecycle, tmp_path, backend=DEAD_THEN_LIVE,
                          policy_a=_retry_policy("failover"), policy_b="")
        status, body = _fetch(endpoint, REPO_A)
        _settle()
        assert status == 200 and body, _errlog(endpoint)
        assert _count(endpoint, EXHAUSTED) == 0, _errlog(endpoint)

    def test_a_force_primary_sibling_latches_a_failover_location(self, lifecycle,
                                                                 tmp_path, mock):
        """security-negative: the process-global force-primary latch wins.

        Location A writes ``failover``.  Location B, a different repository,
        writes ``force-primary``.  A now follows the same force-primary route:
        it exhausts the configured primary until its short hold expires.  The
        merge has no clearing call, so the process-wide setter wins over A's
        local ``failover`` value.
        """
        endpoint = _start(
            lifecycle, tmp_path, backend=DEAD_THEN_LIVE,
            policy_a=_retry_policy("failover"),
            policy_b=_retry_policy("force-primary"))
        status, body = _fetch(endpoint, REPO_A)
        _settle()
        log = _errlog(endpoint)
        assert status == 504, log
        assert _count(endpoint, EXHAUSTED) > 0, (
            "the force-primary latch no longer reaches a `failover` location\n"
            + log)

    def test_nothing_in_the_tree_can_clear_the_force_primary_latch(self):
        """The source arm of the same finding, so a fix cannot land silently.

        A runtime test can only show that ``failover`` does not clear the latch
        in the orders it tried.  The tree can say something stronger: there is
        one caller, and it passes 1.
        """
        calls = subprocess.run(
            ["grep", "-rnE", r"sd_http_force_primary_set\([01]\)", "src/"],
            cwd=ROOT, capture_output=True, text=True).stdout.splitlines()
        assert calls, ("the setter has no literal call sites left — re-read "
                       "cvmfs_module_merge.c before trusting this class")
        assert all(line.endswith("sd_http_force_primary_set(1);")
                   for line in calls), (
            "something now passes a value other than 1 — the latch may be "
            "clearable, so re-measure "
            f"test_a_force_primary_sibling_latches_a_failover_location:\n"
            + "\n".join(calls))


# --------------------------------------------------------------------------- #
# D. The parse tier                                                            #
# --------------------------------------------------------------------------- #

def _knobs(*lines):
    return "".join(f"            {line}\n" for line in lines)


def _second_location(*lines):
    """A whole second cvmfs location for the parse scaffold — the shape §A
    measured, asked of `nginx -t` instead of of a request.

    The cache store is left as a CACHE2 marker for `_parse` to fill in: the
    caller is a test method that has no reason to know where the scaffold puts
    its second store.
    """
    body = "".join(f"            {line}\n" for line in lines)
    return (f"\n        location /cvmfs2/ {{\n"
            f"            brix_cvmfs           on;\n"
            f"            brix_cache_store     posix:{{CACHE2}};\n"
            f"{body}        }}\n")


def _diagnostics(out):
    """The lines of an `nginx -t` transcript that would tell an operator
    something is wrong.  Matching on the transcript as a whole cannot work: the
    prefix is a tmp_path named after the test, so tokens this file tests
    ("off", "2", "1") appear in the output as part of a directory."""
    return [line for line in out.splitlines()
            if any(sev in line for sev in ("[warn]", "[error]", "[crit]",
                                           "[emerg]"))]


def _parse(tmp_path, knobs="", loc_extra="", http_extra="", outer=""):
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    cache2 = tmp_path / "cache2"
    cache2.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit15y_cvparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, LOG_DIR=str(tmp_path),
                     CACHE=str(cache), BACKEND=LIVE, KNOBS=knobs,
                     LOC_EXTRA=loc_extra.replace("{CACHE2}", str(cache2)),
                     HTTP_EXTRA=http_extra, OUTER=outer)
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


ALL_TOKENS = ([("brix_cvmfs_fill_retry_policy", t) for t in RETRY_TOKENS]
              + [("brix_cvmfs_geo_answer", t) for t in GEO_TOKENS]
              + [("brix_cvmfs_origin_http_version", t) for t in HTTPV_TOKENS])


class TestTheParseTier:
    """What the three enums accept and refuse.  Nothing here starts a server,
    and every case damages only its own tmp_path copy of the scaffold."""

    @pytest.mark.parametrize("directive,token", ALL_TOKENS,
                             ids=[f"{d.split('_', 2)[-1]}-{t}"
                                  for d, t in ALL_TOKENS])
    def test_every_token_in_the_table_parses(self, tmp_path, directive, token):
        """success: the enum tables (protocols/cvmfs/module.c:338-356) and the
        documentation agree on the spelling of all of them, including the three
        no config in the suite writes."""
        rc, out = _parse(tmp_path, _knobs(f"{directive} {token};"))
        assert rc == 0, f"{directive} {token} was rejected\n{out}"

    @pytest.mark.parametrize("directive,token", [
        ("brix_cvmfs_fill_retry_policy", "Force-Primary"),
        ("brix_cvmfs_geo_answer", "RTT"),
        ("brix_cvmfs_origin_http_version", "2-Direct")])
    def test_the_tokens_are_case_insensitive(self, tmp_path, directive, token):
        """ngx_conf_set_enum_slot compares with ngx_strcasecmp, so the config
        language is case-insensitive here while the audit's own grep for
        written values is not — which is why a value-granularity sweep has to
        read the enum table rather than the configs alone."""
        rc, out = _parse(tmp_path, _knobs(f"{directive} {token};"))
        assert rc == 0, f"the enum rejected {token!r}\n{out}"

    @pytest.mark.parametrize("directive,token", [
        ("brix_cvmfs_fill_retry_policy", "primary"),
        ("brix_cvmfs_geo_answer", "on"),
        ("brix_cvmfs_origin_http_version", "1.0")])
    def test_a_near_miss_token_is_refused(self, tmp_path, directive, token):
        """error: each of these is what an operator plausibly writes for the
        real token, and each must fail loudly rather than leave the default in
        place — for two of the three, silently keeping the default is a
        different origin policy for the whole worker."""
        rc, out = _parse(tmp_path, _knobs(f"{directive} {token};"))
        assert rc != 0 and f'invalid value "{token}"' in out, out

    @pytest.mark.parametrize("directive", ["brix_cvmfs_fill_retry_policy",
                                           "brix_cvmfs_geo_answer",
                                           "brix_cvmfs_origin_http_version"])
    def test_the_enum_number_is_not_a_token(self, tmp_path, directive):
        """error: all three are small integers internally (and the version's
        are 11/20/21/30, which read like plausible values). The enums take
        names only."""
        rc, out = _parse(tmp_path, _knobs(f"{directive} 0;"))
        assert rc != 0 and 'invalid value "0"' in out, out

    @pytest.mark.parametrize("directive", ["brix_cvmfs_fill_retry_policy",
                                           "brix_cvmfs_geo_answer",
                                           "brix_cvmfs_origin_http_version"])
    def test_an_empty_value_is_refused(self, tmp_path, directive):
        """security-negative: an unset shell variable expanding to "" must not
        quietly become the default — an operator templating origin policy per
        site would silently un-pin every export, and for two of the three that
        change lands on every OTHER export in the process too."""
        rc, out = _parse(tmp_path, _knobs(f'{directive} "";'))
        assert rc != 0 and 'invalid value ""' in out, out

    @pytest.mark.parametrize("line", [
        "brix_cvmfs_fill_retry_policy;",
        "brix_cvmfs_fill_retry_policy failover force-primary;",
        "brix_cvmfs_geo_answer;",
        "brix_cvmfs_origin_http_version 2 2-direct;"])
    def test_each_directive_takes_exactly_one_argument(self, tmp_path, line):
        """error: NGX_CONF_TAKE1.  "failover force-primary" and "2 2-direct"
        are the shapes an operator reaches for when they want a preference
        order, and neither must parse as either value."""
        rc, out = _parse(tmp_path, _knobs(line))
        assert rc != 0, f"{line!r} parsed\n{out}"
        assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("directive,first,second", [
        ("brix_cvmfs_fill_retry_policy", "failover", "force-primary"),
        ("brix_cvmfs_geo_answer", "off", "rtt"),
        ("brix_cvmfs_origin_http_version", "1.1", "2-direct")])
    def test_a_duplicate_directive_is_refused(self, tmp_path, directive, first,
                                              second):
        """security-negative: two values in ONE location would leave which one
        wins to the parser's ordering.  nginx refuses that — which is exactly
        the check the two directives in §A do not get across locations."""
        rc, out = _parse(tmp_path, _knobs(f"{directive} {first};",
                                          f"{directive} {second};"))
        assert rc != 0 and f'"{directive}" directive is duplicate' in out, out

    @pytest.mark.parametrize("directive,token", [
        ("brix_cvmfs_fill_retry_policy", "force-primary"),
        ("brix_cvmfs_geo_answer", "off"),
        ("brix_cvmfs_origin_http_version", "1.1")])
    def test_each_directive_is_accepted_at_http_level(self, tmp_path, directive,
                                                      token):
        """success: MAIN|SRV|LOC within http.  A site-wide default is the
        legitimate way to write the two process-global ones — it is the only
        placement whose meaning matches what the C actually does."""
        rc, out = _parse(tmp_path, http_extra=f"    {directive} {token};\n")
        assert rc == 0, f"an http-level {directive} was rejected\n{out}"

    @pytest.mark.parametrize("directive,token", [
        ("brix_cvmfs_fill_retry_policy", "force-primary"),
        ("brix_cvmfs_geo_answer", "off"),
        ("brix_cvmfs_origin_http_version", "1.1")])
    def test_each_directive_is_refused_outside_http(self, tmp_path, directive,
                                                    token):
        """security-negative: written at the top of the file it reads like a
        global default — which, for two of the three, is what it effectively
        is.  nginx must still refuse it rather than silently ignore it."""
        rc, out = _parse(tmp_path, outer=f"{directive} {token};\n")
        assert rc != 0, f"a main-context {directive} parsed\n{out}"
        assert f'"{directive}" directive is not allowed here' in out, out

    def test_two_locations_disagreeing_about_the_version_parse_in_silence(
            self, tmp_path):
        """DEFECT CANDIDATE #57, parse-time half.

        Config parse is the last moment the clobber is diagnosable: both values
        are known, the merge is about to discard one of them, and which one
        survives depends on nothing an operator can see.  Nothing is said — no
        warning, no notice, nothing naming either location — so their only
        feedback is §A's 504 on an export they did not edit.
        """
        rc, out = _parse(
            tmp_path,
            _knobs("brix_cvmfs_origin_http_version 1.1;"),
            loc_extra=_second_location("brix_cvmfs_origin_http_version 2-direct;"))
        assert rc == 0, f"the two-location config stopped parsing\n{out}"
        assert _diagnostics(out) == [], (
            "the discarded origin HTTP version is now diagnosed at parse time "
            f"— pin the new diagnostic here and close #57\n{out}")

    def test_two_locations_disagreeing_about_the_retry_policy_parse_in_silence(
            self, tmp_path):
        """DEFECT CANDIDATE #58, parse-time half.

        The same silence on the directive where it is worse: here the losing
        location is not merely overridden, it is overridden in one direction
        only, and there is no ordering of these two locations that lets
        ``failover`` mean failover.
        """
        rc, out = _parse(
            tmp_path,
            _knobs("brix_cvmfs_fill_retry_policy failover;"),
            loc_extra=_second_location(
                "brix_cvmfs_fill_retry_policy force-primary;"))
        assert rc == 0, f"the two-location config stopped parsing\n{out}"
        assert _diagnostics(out) == [], (
            "the one-way retry-policy latch is now diagnosed at parse time — "
            f"pin the new diagnostic here and close #58\n{out}")
