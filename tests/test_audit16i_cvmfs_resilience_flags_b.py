"""Test cases for audit16i_cvmfs_resilience_flags — preamble (fixtures/helpers/mocks) lives in
_test_audit16i_cvmfs_resilience_flags_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16i_cvmfs_resilience_flags_helpers")


def _inherit_probe(flag, endpoint, tmp_path):
    """The flag's own observable, reduced to True = "the feature ran here"."""
    if flag == "brix_cvmfs_bundle":
        rels = _base_rels(REPO_A)[:2]
        _warm(endpoint, REPO_A, rels)
        response = _fetch(endpoint, REPO_A, BUNDLE_PATH, method="POST",
                          data=_want(rels))
        return response.status_code == 200
    if flag == "brix_cvmfs_dict":
        _warm(endpoint, REPO_A, [_cas_rel(b) for b in DICT_BODIES])
        return _fetch(endpoint, REPO_A, DICT_CURRENT).status_code == 200
    if flag == "brix_cvmfs_delta":
        return _delta_probe(endpoint).headers.get(
            "Content-Encoding") == "zstd-delta"
    if flag == "brix_cvmfs_scrub":
        rels = _base_rels(REPO_A)
        _warm(endpoint, REPO_A, rels)
        victim = _resident(tmp_path, REPO_A, rels[0])
        assert victim is not None, f"nothing was cached\n{_errlog(endpoint)}"
        _corrupt(victim)
        return _await_gone(victim, timeout=12.0)
    if flag == "brix_cvmfs_learn":
        first, second = _base_rels(REPO_A)[:2]
        slot = _train_then_evict(endpoint, tmp_path, first, second)
        conn = _session(endpoint)
        try:
            _session_get(conn, REPO_A, first)
        finally:
            conn.close()
        return _await_present(slot, timeout=10.0)
    if flag == "brix_cvmfs_swarm":
        _fetch(endpoint, REPO_A)
        _settle(2.5)
        return _roster(endpoint).status_code == 200
    if flag == "brix_cvmfs_unified_origin":
        _fetch(endpoint, REPO_A)
        status, _, _ = _absolute_form(endpoint, f"{HOST}:{DEAD_PORT}", REPO_A,
                                      _base_rels(REPO_A)[1])
        return status == 200
    raise AssertionError(f"no probe for {flag}")


# brix_cvmfs_trace is deliberately not in this list: it is the one flag whose
# probe does not reduce to a single boolean, because its two faces disagree.
INHERITED_FLAGS = ("brix_cvmfs_bundle", "brix_cvmfs_dict", "brix_cvmfs_delta",
                   "brix_cvmfs_scrub", "brix_cvmfs_learn", "brix_cvmfs_swarm",
                   "brix_cvmfs_unified_origin")


def _inherit_start(lifecycle, tmp_path, flag, child):
    support = INHERIT_SUPPORT.get(flag)
    if flag == "brix_cvmfs_swarm":
        support = _swarm_support()
    srv_arm = _arm(f"{flag} on;", *(support or ()), indent=8)
    loc_arm = _arm(f"{flag} off;") if child == "off" else ""
    return _start(lifecycle, tmp_path, srv_arm=srv_arm, loc_arm=loc_arm)


class TestWhatAChildLocationCanTakeBack:
    """All eight of the MAIN|SRV|LOC flags are documented the same way, and one
    of them does not behave the same way."""

    @pytest.mark.parametrize("flag", INHERITED_FLAGS)
    @pytest.mark.parametrize("child", ("bare", "off"))
    def test_the_child_decides(self, lifecycle, tmp_path, mock, flag, child):
        """success + error in one parametrised pair.

        The `bare` arm is not decoration: without it, "the location's `off` won"
        is indistinguishable from "the server-level `on` never reached the
        location at all", and for seven of these eight flags it is the second
        reading that would be wrong.
        """
        endpoint = _inherit_start(lifecycle, tmp_path, flag, child)
        ran = _inherit_probe(flag, endpoint, tmp_path)
        if child == "bare":
            assert ran, (
                f"a server-level `{flag} on` did not reach the location — the "
                f"`off` arm below cannot be read against this\n"
                f"{_errlog(endpoint)}")
        else:
            assert not ran, (
                f"the location's `{flag} off` did not take back the server's "
                f"`on`\n{_errlog(endpoint)}")


class TestTheTraceLatch:
    """DEFECT CANDIDATE #80 — the eighth flag, and the one whose `off` is not a
    retraction.

    ``brix_cvmfs_trace`` has two faces.  The per-request one
    (handler_finalize.c:88,100) writes ``cvmfs-trace: client …`` off the
    location's own merged value and is honest.  The origin one
    (s3_transport_setup.c:208) writes ``cvmfs-trace: upstream …`` at INFO or
    DEBUG according to a process-wide latch that only ever gets set.  One
    config, one request, two answers.
    """

    UPSTREAM = "cvmfs-trace: upstream"
    CLIENT = "cvmfs-trace: client"

    def _read(self, endpoint):
        _warm(endpoint, REPO_A, [_base_rels(REPO_A)[0]])
        _settle(1.0)
        return (_count(endpoint, self.UPSTREAM), _count(endpoint, self.CLIENT))

    def test_a_server_level_on_reaches_a_silent_child(self, lifecycle, tmp_path,
                                                      mock):
        """success: the control.  Both faces speak when nobody retracts."""
        endpoint = _start(lifecycle, tmp_path,
                          srv_arm=_arm("brix_cvmfs_trace on;", indent=8))
        upstream, client = self._read(endpoint)
        assert upstream >= 1, f"the origin face is silent\n{_errlog(endpoint)}"
        assert client >= 1, f"the request face is silent\n{_errlog(endpoint)}"

    def test_the_child_can_take_back_only_one_of_the_two_faces(
            self, lifecycle, tmp_path, mock):
        """DEFECT CANDIDATE #80.

        The location writes `off`.  The per-request face obeys.  The origin
        face — the one whose lines carry the full origin URL — keeps writing at
        INFO, because ``brix_origin_trace_set(1)`` has no counterpart and the
        merge that called it has no else (cvmfs_module_merge.c:167-172).
        """
        endpoint = _start(lifecycle, tmp_path,
                          srv_arm=_arm("brix_cvmfs_trace on;", indent=8),
                          loc_arm=_arm("brix_cvmfs_trace off;"))
        upstream, client = self._read(endpoint)
        assert client == 0, (
            "the per-request face ignored the location's `off` too — this "
            f"section's honest control is gone\n{_errlog(endpoint)}")
        assert upstream >= 1, (
            "the origin face went quiet — the process-wide trace latch now has "
            "a way back, so #80 may be fixed: replace this with the new "
            f"behaviour\n{_errlog(endpoint)}")

    def test_a_config_that_never_says_on_writes_neither_face(self, lifecycle,
                                                             tmp_path, mock):
        """error / the second control.  The latch is per-process, so "nobody
        wrote `on`" has to be silent or the reading above would just be the
        default."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_arm("brix_cvmfs_trace off;"))
        upstream, client = self._read(endpoint)
        assert (upstream, client) == (0, 0), (
            f"upstream={upstream} client={client}\n{_errlog(endpoint)}")

    def test_the_latch_has_no_caller_that_can_clear_it(self):
        """The source arm of the same finding, so a fix cannot land silently.

        A runtime test can only say the latch did not clear in the orders it
        tried.  The tree can say something stronger: nothing passes 0.
        """
        calls = subprocess.run(
            ["grep", "-rn", "brix_origin_trace_set(", "src/"],
            cwd=ROOT, capture_output=True, text=True).stdout.splitlines()
        setters = [line for line in calls if "brix_origin_trace_set(0)" in line]
        assert calls, ("the setter has no call sites left — re-read "
                       "cvmfs_module_merge.c before trusting this class")
        assert setters == [], (
            "something now clears the origin trace latch — re-measure "
            f"test_the_child_can_take_back_only_one_of_the_two_faces:\n"
            + "\n".join(calls))


# --------------------------------------------------------------------------- #
# J. Two exports are one export — DEFECT CANDIDATES #81 and #82                #
# --------------------------------------------------------------------------- #

class TestTwoCacheLocationsShareOneExport:
    """A cvmfs cache location declares no root, so it is anchored at "/"
    (cvmfs_module_build.c:215-217) and every per-export registration is keyed on
    that.  Two locations, one export — which decides both what a sibling's `on`
    can reach and whose backend the export ends up using."""

    def _corrupt_a(self, lifecycle, tmp_path, arm_a, arm_b):
        endpoint = _start_pair(lifecycle, tmp_path, arm_a=arm_a, arm_b=arm_b)
        rels = _base_rels(REPO_A)
        _warm(endpoint, REPO_A, rels[:1])
        victim = _resident(tmp_path, REPO_A, rels[0])
        assert victim is not None, (
            f"location A's fill was not cached anywhere\n{_errlog(endpoint)}")
        _corrupt(victim)
        return endpoint, victim

    def test_a_siblings_scrub_evicts_the_objects_of_a_location_that_said_off(
            self, lifecycle, tmp_path, mock):
        """DEFECT CANDIDATE #82.

        Location A writes ``brix_cvmfs_scrub off``.  Location B, a different
        repository, writes ``on``.  A's cached object is checksummed and
        evicted anyway: the scrub is registered against the export, and both
        locations are the same export.
        """
        endpoint, victim = self._corrupt_a(
            lifecycle, tmp_path,
            arm_a=_flag("brix_cvmfs_scrub", "written-off", *SCRUB_SUPPORT),
            arm_b=_flag("brix_cvmfs_scrub", "on", *SCRUB_SUPPORT))
        assert _await_gone(victim), (
            "the sibling's scrub no longer reaches this location's objects — "
            f"#82 may be fixed\n{_errlog(endpoint)}")

    def test_the_both_off_control_keeps_the_object(self, lifecycle, tmp_path,
                                                   mock):
        """error / the control that makes the previous test the flag.

        The identical config with B also `off`.  Nothing is evicted, so what
        reached A's objects above was B's `on` and not the scrub running
        regardless.
        """
        endpoint, victim = self._corrupt_a(
            lifecycle, tmp_path,
            arm_a=_flag("brix_cvmfs_scrub", "written-off", *SCRUB_SUPPORT),
            arm_b=_flag("brix_cvmfs_scrub", "written-off", *SCRUB_SUPPORT))
        assert not _await_gone(victim, timeout=8.0), (
            f"an object was evicted with every scrub off\n{_errlog(endpoint)}")

    def test_the_reach_does_not_depend_on_which_location_said_on(
            self, lifecycle, tmp_path, mock):
        """DEFECT CANDIDATE #82, the other order — the export is shared, not
        inherited, so declaration order changes nothing."""
        endpoint, victim = self._corrupt_a(
            lifecycle, tmp_path,
            arm_a=_flag("brix_cvmfs_scrub", "on", *SCRUB_SUPPORT),
            arm_b=_flag("brix_cvmfs_scrub", "written-off", *SCRUB_SUPPORT))
        assert _await_gone(victim), (
            f"the export's scrub did not run\n{_errlog(endpoint)}")

    def test_the_last_location_merged_owns_the_store(self, lifecycle, tmp_path,
                                                     mock):
        """DEFECT CANDIDATE #81, the cache half.

        Both locations name their own ``brix_cache_store``.  A request through
        the FIRST one is cached under the SECOND one's path, because
        ``brix_vfs_backend_entry_get_or_create()`` overwrites the entry it finds
        for the shared canonical root.
        """
        endpoint = _start_pair(lifecycle, tmp_path)
        rels = _base_rels(REPO_A)
        _warm(endpoint, REPO_A, rels[:2])
        _settle()
        first = list((tmp_path / "cache-a").rglob("*"))
        second = list((tmp_path / "cache-b").rglob("*"))
        assert [p for p in second if p.is_file()], (
            "nothing landed in the second location's store — re-measure, the "
            f"export collapse may be fixed\n{_errlog(endpoint)}")
        assert [p for p in first if p.is_file()] == [], (
            "the first location's own store is in use again — #81 may be "
            f"fixed; re-read the section\n{_errlog(endpoint)}")

    def test_a_new_export_with_a_dead_origin_takes_the_working_one_down(
            self, lifecycle, tmp_path, mock):
        """DEFECT CANDIDATE #81, the blast radius — and the row an operator
        actually hits.

        Location A is an existing, working export pointed at a live Stratum-1.
        Location B is added for a new repository whose Stratum-1 is not up yet.
        A stops serving: its requests are sent to B's origin, retried until the
        client hold expires, and the live Stratum-1 that A's own
        ``brix_storage_backend`` names is never contacted at all.  Nothing in the
        config names A, and nothing was said at parse time (§K).

        The status is whichever bound expires first — the fill's retry ladder
        outlives the client hold, so it is 504 here and would be 502 with a
        longer hold.  The reading is therefore WHERE the request went, which the
        mock's own request log answers without ambiguity.
        """
        # Written identically in both locations: origin_connect_timeout reaches a
        # process-wide setter, so two different values would not be two bounds.
        bounds = ("brix_cvmfs_origin_connect_timeout 1;",
                  "brix_cvmfs_client_hold 4;")
        endpoint = _start_pair(lifecycle, tmp_path, backend_a=LIVE,
                              backend_b=DEAD, arm_a=_arm(*bounds),
                              arm_b=_arm(*bounds))
        mock.reset()
        response = _fetch(endpoint, REPO_A, timeout=120)
        assert response.status_code in (502, 504), (
            "the first export still serves — the origin half of the collapse "
            f"may be fixed: {response.status_code}\n{_errlog(endpoint)}")
        assert mock.paths() == [], (
            "the live Stratum-1 location A names was contacted after all, so "
            "the export kept A's backend: re-read #81\n"
            f"{_errlog(endpoint)}")
        assert _count(endpoint, f"http origin {HOST}:{DEAD_PORT} failed") >= 1, (
            "location A's fill did not go to the SECOND location's origin — "
            f"the collapse this section pins has moved\n{_errlog(endpoint)}")

    def test_the_reverse_order_serves_the_first_export_from_the_seconds_origin(
            self, lifecycle, tmp_path, mock):
        """DEFECT CANDIDATE #81, the same config in the other order.

        Now the DEAD origin is the one declared first, and the export takes the
        second location's live one — so location A serves 200 from a Stratum-1
        its own ``brix_storage_backend`` never named.  Config order, not
        location, is what selected the origin.
        """
        endpoint = _start_pair(lifecycle, tmp_path, backend_a=DEAD,
                              backend_b=LIVE)
        response = _fetch(endpoint, REPO_A, timeout=120)
        assert response.status_code == 200, (
            f"{response.status_code}\n{_errlog(endpoint)}")
        assert response.content, "an empty body is not a fill"


# --------------------------------------------------------------------------- #
# K. The parse tier                                                            #
# --------------------------------------------------------------------------- #

def _knobs(*lines):
    return "".join(f"            {line}\n" for line in lines)


def _extra_location(prefix, *lines, cvmfs=False):
    """A whole second location for the parse scaffold.  Its cache store is left
    as a CACHE2 marker for `_parse` to fill in: a test method has no reason to
    know where the scaffold puts its second store."""
    body = "".join(f"            {line}\n" for line in lines)
    head = ("            brix_cvmfs           on;\n"
            "            brix_cache_store     posix:{CACHE2};\n"
            if cvmfs else "")
    return f"\n        location {prefix} {{\n{head}{body}        }}\n"


def _diagnostics(out):
    """The lines of an `nginx -t` transcript that would tell an operator
    something is wrong.  Matching on the transcript as a whole cannot work: the
    prefix is a tmp_path named after the test, so tokens this file tests ("on",
    "off") appear in the output as part of a directory name."""
    return [line for line in out.splitlines()
            if any(sev in line for sev in ("[warn]", "[error]", "[crit]",
                                           "[emerg]"))]


def _parse(tmp_path, knobs="", srv_knobs="", http_knobs="", outer="", extra="",
           backend=LIVE):
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    cache2 = tmp_path / "cache2"
    cache2.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit16iparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, LOG_DIR=str(tmp_path),
                     CACHE=str(cache), BACKEND=backend, KNOBS=knobs,
                     SRV_KNOBS=srv_knobs, HTTP_KNOBS=http_knobs, OUTER=outer,
                     EXTRA=extra.replace("{CACHE2}", str(cache2)))
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


SCOPE_SLOT = {"location": "knobs", "server": "srv_knobs", "http": "http_knobs"}
SCOPE_INDENT = {"location": 12, "server": 8, "http": 4}


def _at(scope, *lines):
    """One directive placed in one scope, as the kwargs `_parse` wants."""
    indent = SCOPE_INDENT[scope]
    return {SCOPE_SLOT[scope]:
            "".join(" " * indent + line + "\n" for line in lines)}


class TestTheParseTier:
    """What the nine accept and refuse.  Nothing here starts a server, and every
    case damages only its own tmp_path copy of the scaffold."""

    @pytest.mark.parametrize("value", ("on", "off"))
    @pytest.mark.parametrize("scope", ("location", "server", "http"))
    @pytest.mark.parametrize("flag", SCOPED_FLAGS)
    def test_both_arms_parse_in_all_three_http_scopes(self, tmp_path, flag,
                                                      scope, value):
        """success: eight of the nine are MAIN|SRV|LOC
        (directives_resilience.h), so `off` is speakable everywhere `on` is —
        including at http level, which is the only placement whose meaning
        matches what the per-export ones actually do."""
        lines = [f"{flag} {value};"]
        if flag == "brix_cvmfs_swarm" and value == "on":
            lines.append(f"brix_cache_peers self={HOST}:1 {HOST}:2;")
        rc, out = _parse(tmp_path, **_at(scope, *lines))
        assert rc == 0, f"{flag} {value} at {scope} was rejected\n{out}"

    @pytest.mark.parametrize("value", ("on", "off"))
    def test_the_secure_layer_is_a_location_directive_only(self, tmp_path,
                                                           value):
        """The ninth is not like the other eight.

        ``brix_scvmfs`` is NGX_HTTP_LOC_CONF alone, so a site-wide default — the
        obvious way to turn a whole server's exports secure, and the way the
        other eight accept — is refused.  An operator who writes it beside them
        gets a config that does not load, on both arms.
        """
        rc, out = _parse(tmp_path, **_at("location", f"brix_scvmfs {value};"))
        assert rc == 0, f"a location-level brix_scvmfs {value} was rejected\n{out}"
        for scope in ("server", "http"):
            rc, out = _parse(tmp_path, **_at(scope, f"brix_scvmfs {value};"))
            assert rc != 0, f"brix_scvmfs {value} parsed at {scope}\n{out}"
            assert '"brix_scvmfs" directive is not allowed here' in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_each_flag_is_refused_in_the_main_context(self, tmp_path, flag):
        """security-negative: written at the top of the file each of these
        reads like a global default — and for the per-export ones that is
        effectively what a location-level value already is.  nginx must still
        refuse the placement rather than silently ignore it."""
        rc, out = _parse(tmp_path, outer=f"{flag} on;\n")
        assert rc != 0, f"a main-context {flag} parsed\n{out}"
        assert f'"{flag}" directive is not allowed here' in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_a_non_boolean_value_is_refused(self, tmp_path, flag):
        """error: ngx_conf_set_flag_slot takes on|off and nothing else.  "1" is
        what an operator templating from a boolean variable writes, and it must
        not quietly leave the default in place."""
        rc, out = _parse(tmp_path, **_at("location", f"{flag} 1;"))
        assert rc != 0 and 'invalid value "1"' in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_an_empty_value_is_refused(self, tmp_path, flag):
        """security-negative: an unset shell variable expanding to "" must not
        become `off` by accident — for brix_scvmfs that would silently drop a
        whole authorization layer off an export."""
        rc, out = _parse(tmp_path, **_at("location", f'{flag} "";'))
        assert rc != 0 and 'invalid value ""' in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_arity_is_exactly_one(self, tmp_path, flag):
        """error: NGX_CONF_FLAG is TAKE1.  "on off" is the shape someone
        reaches for when editing an arm in place and not finishing."""
        for line in (f"{flag};", f"{flag} on off;"):
            rc, out = _parse(tmp_path, **_at("location", line))
            assert rc != 0, f"{line!r} parsed\n{out}"
            assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_a_second_occurrence_in_one_location_is_a_duplicate(self, tmp_path,
                                                                flag):
        """security-negative: two values in ONE location would leave which one
        wins to the parser's ordering.  nginx refuses that — which is exactly
        the check the per-export flags do not get ACROSS locations (§J)."""
        rc, out = _parse(tmp_path,
                         **_at("location", f"{flag} on;", f"{flag} off;"))
        assert rc != 0 and f'"{flag}" directive is duplicate' in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_value_is_case_insensitive(self, tmp_path, flag):
        """ngx_conf_set_flag_slot compares with ngx_strcasecmp, so ``OFF`` is
        the same token as ``off`` while the audit's own grep for written values
        is case-sensitive — which is why a value-granularity sweep has to read
        the flag table rather than the configs alone."""
        rc, out = _parse(tmp_path, **_at("location", f"{flag} OFF;"))
        assert rc == 0, f"the flag rejected 'OFF'\n{out}"


class TestTheCrossChecksTheOffArmSkips:
    """Three of the nine gate a block of config-time validation.  Each pair is
    the IDENTICAL broken block under `on` and under `off`: the flag is the only
    thing that decides whether the reload survives it."""

    SWARM_EMERG = ("brix_cvmfs_swarm requires brix_cache_peers "
                   "(the seed ring naming this node's own \"self=\" slot)")
    UNIFIED_EMERG = ("brix_cvmfs_unified_origin on requires brix_storage_backend "
                     "to name an http(s) origin set")
    SCVMFS_EMERG = "brix_scvmfs requires brix_cvmfs on"

    def test_swarm_on_without_a_seed_ring_is_a_reload_breaker(self, tmp_path):
        """error: cvmfs_module_build.c:299-312."""
        rc, out = _parse(tmp_path, **_at("location", "brix_cvmfs_swarm on;"))
        assert rc != 0, f"a swarm with no peers parsed\n{out}"
        assert self.SWARM_EMERG in out, out

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_swarm_off_never_looks_for_the_seed_ring(self, tmp_path, arm):
        """success, and the point of the pair: an operator turning the ring off
        may delete ``brix_cache_peers`` — but is never told they now MAY, and is
        never told the check stopped running."""
        knobs = ("" if arm == "absent"
                 else _knobs("brix_cvmfs_swarm off;"))
        rc, out = _parse(tmp_path, knobs=knobs)
        assert rc == 0, f"a peerless config was refused with the swarm {arm}\n{out}"

    def test_unified_origin_on_without_an_http_backend_is_a_reload_breaker(
            self, tmp_path):
        """error: cvmfs_module_merge.c:228-247.  The proxy face serves every
        request from the location's own backend, so a posix backend would 500
        per request instead."""
        rc, out = _parse(tmp_path,
                         **_at("location", "brix_cvmfs_unified_origin on;"),
                         backend="posix:/tmp")
        assert rc != 0, f"a posix-backed unified origin parsed\n{out}"
        assert self.UNIFIED_EMERG in out, out

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_unified_origin_off_never_looks_at_the_backend(self, tmp_path, arm):
        """success: the same posix backend, accepted.  Which is correct — and
        which is also why flipping the flag on months later fails the reload for
        a reason that has nothing to do with the edit."""
        knobs = ("" if arm == "absent"
                 else _knobs("brix_cvmfs_unified_origin off;"))
        rc, out = _parse(tmp_path, knobs=knobs, backend="posix:/tmp")
        assert rc == 0, (
            f"a posix backend was refused with unified_origin {arm}\n{out}")

    # Each row is a whole scvmfs block that breaks the reload the moment the
    # flag says `on`, and is inert the moment it says `off` — the early return
    # at cvmfs_module_merge.c:281 is before all of them.
    BROKEN_SCVMFS = (
        ("bearer-without-issuers", ("brix_scvmfs_authz bearer;",),
         "brix_scvmfs_authz bearer requires brix_scvmfs_token_issuers"),
        ("voms-without-trust-dirs", ("brix_scvmfs_authz voms;",),
         "brix_scvmfs_authz voms requires brix_scvmfs_vomsdir"),
        ("an-issuer-file-that-is-not-there",
         ("brix_scvmfs_authz bearer;",
          "brix_scvmfs_token_issuers /nonexistent/scitokens.cfg;"),
         "brix_token_config: open /nonexistent/scitokens.cfg"),
    )

    @pytest.mark.parametrize("tag,lines,needle", BROKEN_SCVMFS,
                             ids=[row[0] for row in BROKEN_SCVMFS])
    def test_a_broken_authz_block_breaks_the_reload_only_when_the_layer_is_on(
            self, tmp_path, tag, lines, needle):
        """error: the three EMERGs behind the early return, each with the
        identical block under `off` accepted in the same test — a pair rather
        than two cases, because the whole claim is that only the flag differs.
        """
        rc, out = _parse(tmp_path, **_at("location", "brix_scvmfs on;", *lines))
        assert rc != 0, f"{tag} parsed with brix_scvmfs on\n{out}"
        assert needle in out, out
        for arm in ("brix_scvmfs off;", None):
            body = list(lines) if arm is None else [arm, *lines]
            rc, out = _parse(tmp_path, **_at("location", *body))
            assert rc == 0, (
                f"{tag} was refused with the layer "
                f"{'off' if arm else 'absent'}\n{out}")

    def test_the_layer_is_refused_on_a_location_that_is_not_a_cvmfs_export(
            self, tmp_path):
        """security-negative: ``brix_scvmfs on`` on a location with no
        ``brix_cvmfs`` is an authorization layer over nothing, and it is the
        shape of a copy-paste into the wrong block.  It must break the reload
        rather than sit there looking enabled."""
        rc, out = _parse(tmp_path,
                         extra=_extra_location("/bare/", "brix_scvmfs on;"))
        assert rc != 0, f"brix_scvmfs on a non-cvmfs location parsed\n{out}"
        assert self.SCVMFS_EMERG in out, out

    def test_the_same_misplacement_is_silent_when_the_layer_is_off(self,
                                                                   tmp_path):
        """The other half of the pair: `off` on a non-cvmfs location parses,
        because the check is behind the flag.  A location that will never be an
        export can therefore carry a disabled security layer indefinitely
        without anyone being told the two do not go together."""
        rc, out = _parse(tmp_path,
                         extra=_extra_location("/bare/", "brix_scvmfs off;"))
        assert rc == 0, f"a disabled layer was refused\n{out}"


class TestTwoExportsParseInSilence:
    """DEFECT CANDIDATES #81 and #82, parse-time half.

    Config parse is the last moment either collapse is diagnosable: both stores
    are known, both origins are known, both arms of the flag are known, and the
    merge is about to discard one of each.
    """

    @pytest.mark.parametrize("flag", ("brix_cvmfs_scrub", "brix_cvmfs_learn"))
    def test_two_exports_disagreeing_about_a_per_export_flag_say_nothing(
            self, tmp_path, flag):
        """#82: one location says `off`, the other says `on`, and they are the
        same export.  No warning names either location, so the operator's only
        feedback is §J's eviction of objects they excluded."""
        rc, out = _parse(tmp_path, **_at("location", f"{flag} on;"),
                         extra=_extra_location("/cvmfs2/", f"{flag} off;",
                                               cvmfs=True))
        assert rc == 0, f"the two-location config stopped parsing\n{out}"
        assert _diagnostics(out) == [], (
            "a disagreement between two exports is now diagnosed at parse time "
            f"— pin the new diagnostic here and close #82\n{out}")

    def test_two_exports_naming_different_origins_say_nothing(self, tmp_path):
        """#81: two stores and two origins, one export, and the file already
        knows how to warn about a coherent-but-useless combination
        (cvmfs_module_build.c:315+ warns about origin coords with no geo
        answering).  Here it says nothing at all."""
        rc, out = _parse(
            tmp_path, backend=LIVE,
            extra=_extra_location("/cvmfs2/",
                                  f'brix_storage_backend "{DEAD}";',
                                  cvmfs=True))
        assert rc == 0, f"the two-location config stopped parsing\n{out}"
        assert _diagnostics(out) == [], (
            "the discarded store/origin is now diagnosed at parse time — pin "
            f"the new diagnostic here and close #81\n{out}")
