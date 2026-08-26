"""Test cases for audit16j_root_caps_flags — preamble (fixtures/helpers/mocks) lives in
_test_audit16j_root_caps_flags_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16j_root_caps_flags_helpers")


class TestTheDocumentedShapeCannotReachTheCache:
    """DEFECT CANDIDATE #84.  `nginx_collapse_redir.conf` is the suite's only
    config that enables the flag: a static `brix_manager_map`, no
    `brix_manager_mode`.  Every open there is answered by the static-map branch
    (open_manager.c:207-215), which neither inserts into the cache nor reads it.

    MAP_PORT has that shape, so the answer is measured there; the tracked config
    is only READ, to check that the premise still holds.
    """

    def test_the_static_map_shape_answers_from_the_map_not_the_cache(self, caps):
        """Two opens of one path on a static-map node, and neither is a cache
        hit — the detail is the static branch's own word, `redirect`."""
        for _ in range(2):
            status, body = _open_read(MAP_PORT, "/mapped.bin")
            assert status == KXR_REDIRECT, (status, body, caps.errlog())
        details = _open_details(caps, "map", "/mapped.bin", 2)
        assert details == ["redirect", "redirect"], (
            f"the two opens were answered from {details}; a static-map node "
            f"cannot reach open_manager.c:117/:164 at all, so neither "
            f"`registry` nor `redir-cache` is available to it")

    def test_the_shape_that_enables_the_flag_has_no_manager_mode(self, caps):
        """The premise, read off the tracked config rather than asserted.

        If this fails the finding is stale — the config gained the directive that
        makes its cache reachable — and #84 should be retired rather than the
        assertion loosened.
        """
        tracked = (Path(__file__).resolve().parent / "configs"
                   / "nginx_collapse_redir.conf").read_text()
        assert "brix_collapse_redir" in tracked, tracked
        assert "brix_manager_mode" not in tracked, (
            "nginx_collapse_redir.conf now sets brix_manager_mode — #84's "
            "premise has changed")

    def test_the_shape_still_advertises_the_collapse_bit(self, caps):
        """The half that makes #84 a defect rather than a dead branch: the
        advertisement does not depend on the cache being reachable, because the
        flags word reads `caps.collapse_redir` and nothing else
        (session/protocol.c:121).

        COLLON_PORT proves the bit follows the flag; MAP_PORT proves the answer
        does not.  Together they say a static-map node with the flag promises a
        client something no code path in it can deliver.
        """
        assert _flags(COLLON_PORT) & KXR_COLLAPSEREDIR
        assert _open_read(MAP_PORT, "/promised.bin")[0] == KXR_REDIRECT
        assert _open_read(MAP_PORT, "/promised.bin")[0] == KXR_REDIRECT
        assert _open_details(caps, "map", "/promised.bin", 2) \
            == ["redirect", "redirect"], caps.access("map")


# --------------------------------------------------------------------------- #
# §F — brix_metadata_only's other conjunct                                     #
# --------------------------------------------------------------------------- #

class TestTheMetadataOnlyRefusalIsConditional:
    """`caps.metadata_only && manager_map == NULL` (open_request.c:69).
    `test_protocol_flags.py` covers the refusal, which is the left conjunct with
    the right one true.  MAP_PORT is the same flag with a map, where the branch
    is skipped and the open is redirected instead.
    """

    def test_the_flag_with_a_map_redirects_instead_of_refusing(self, caps):
        """The untested half of the conjunction: metadata-only stops meaning
        "no file I/O here" the moment the node has somewhere to send you."""
        status, body = _open_read(MAP_PORT, "/mapped-meta.bin")
        assert status == KXR_REDIRECT, (
            f"status {status}, body {body!r} — a metadata_only node WITH a "
            f"manager_map is supposed to skip the refusal at open_request.c:69 "
            f"and redirect")

    def test_the_flag_still_advertises_the_metadata_role(self, caps):
        """The advertisement does not follow the conjunction: attrMeta is set
        from `caps.metadata_only` alone, so a client is told "metadata only" by a
        node that will happily redirect it to data."""
        flags = _flags(MAP_PORT)
        assert flags & KXR_ATTRMETA, (
            f"word {flags:#010x} lacks kXR_attrMeta with the flag on")

    def test_the_off_arm_neither_refuses_nor_advertises(self, caps):
        """The arm nobody had written, on the server with no map — where the
        refusal WOULD fire if the flag were on."""
        assert _flags(OFF_PORT) & KXR_ATTRMETA == 0
        status, body = _open_read(OFF_PORT)
        assert status == kXR_ok, (status, body, caps.errlog())


# --------------------------------------------------------------------------- #
# §G — the two spellings of "supervisor"                                       #
# --------------------------------------------------------------------------- #

class TestTheOtherSpellingOfSupervisor:
    """`brix_supervisor` writes `caps.supervisor`; `brix_cms_role supervisor`
    writes `cms.role`.  Nothing in `src/` assigns one from the other — the
    readers of `caps.supervisor` are session/protocol.c, runtime_server.c,
    net/cms/server_handler.c and net/cms/send.c, and none of them consults
    `cms.role`.  ROLE_PORT writes the token and not the flag.
    """

    def test_the_token_does_not_advertise_the_supervisor_bit(self, caps):
        """An operator who wrote `brix_cms_role supervisor` has not told any
        root:// client that this node is a supervisor."""
        flags = _flags(ROLE_PORT)
        assert flags & KXR_ATTRSUPER == 0, (
            f"word {flags:#010x} sets kXR_attrSuper from brix_cms_role alone; "
            f"the two spellings would then be linked and this section is moot")

    def test_the_token_leaves_the_export_alone(self, caps):
        """The sharp half: the flag deletes the export (§B) and the token does
        not, so the two spellings differ in whether the node holds files."""
        status, data = _read_back(ROLE_PORT, "/seed.bin", len(SEED))
        assert status == kXR_ok and data == SEED, (
            f"a brix_cms_role supervisor node could not read its own export "
            f"({status}, {data!r}); only caps.supervisor is supposed to reach "
            f"brix_server_has_runtime_export()\n{caps.errlog()}")

    def test_the_flag_arm_is_the_contrast(self, caps):
        """Both halves of the pair in one assertion, so the difference is not
        assembled out of two tests that could drift apart."""
        role, flag = _flags(ROLE_PORT), _flags(SUPER_PORT)
        assert flag & KXR_ATTRSUPER and role & KXR_ATTRSUPER == 0, (
            f"brix_supervisor gives {flag:#010x} and brix_cms_role supervisor "
            f"gives {role:#010x}; the pair is the finding")


# --------------------------------------------------------------------------- #
# §H — the parse tier                                                          #
# --------------------------------------------------------------------------- #





class TestTheParseTier:
    """Values, arity, duplicates and — the part that carries a finding — the
    placement matrix that says the merge's inheritance arm is unreachable."""

    @pytest.mark.parametrize("arm", ("on", "off"))
    @pytest.mark.parametrize("flag", FLAGS)
    def test_both_arms_are_accepted_in_a_stream_server(self, tmp_path, flag,
                                                       arm):
        """The audit's step-1 question for all ten pairs, asked where the
        directive is legal."""
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} {arm};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("token", ("ON", "Off", "oN"))
    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_arms_are_case_insensitive(self, tmp_path, flag, token):
        """`ngx_conf_set_flag_slot` compares with ngx_strcasecmp, which is what
        makes the audit's step-2 grep for `flag on` / `flag off` sound only
        because no config in the corpus spells it any other way."""
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} {token};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("value", ("yes", "1", "true", "enabled", ""))
    @pytest.mark.parametrize("flag", FLAGS)
    def test_a_value_outside_the_two_arms_is_refused(self, tmp_path, flag,
                                                     value):
        """A flag has exactly two tokens; "1" and "true" are the spellings an
        operator brings from other config languages."""
        line = f"        {flag} {value};\n" if value else f"        {flag};\n"
        rc, out = _parse(tmp_path, KNOBS=line)
        assert rc != 0, f"{flag} {value!r} was accepted: {out}"

    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, flag):
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} on off;\n")
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_a_duplicate_is_refused(self, tmp_path, flag):
        rc, out = _parse(tmp_path,
                         KNOBS=f"        {flag} on;\n        {flag} off;\n")
        assert rc != 0, out
        assert "duplicate" in out, out

    @pytest.mark.parametrize("slot", ("STREAM_KNOBS", "HTTP_KNOBS",
                                      "LOC_KNOBS", "OUTER"))
    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_directive_is_refused_everywhere_but_a_stream_server(
            self, tmp_path, flag, slot):
        """The matrix that makes the merge's inheritance arm unreachable rather
        than untested: `stream{}` is a refusal, so `prev` can never hold a
        written value for any of the five.

        The refusal must be a placement one.  `unknown directive` would mean the
        stream module was not loaded and the case measured nothing.
        """
        rc, out = _parse(tmp_path, **{slot: f"    {flag} on;\n"})
        assert rc != 0, out
        assert "is not allowed here" in out, out
        assert "unknown directive" not in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_one_server_arm_does_not_reach_a_sibling(self, tmp_path, flag):
        """Two stream servers, one carrying the flag: the config loads, which is
        the parse-tier half of "the scope is per-server"."""
        extra = ("    server {\n"
                 f"        listen {PARSE_PLACEHOLDER_PORT + 2};\n"
                 "        brix_root on;\n"
                 "        brix_auth none;\n"
                 "    }\n")
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} on;\n", EXTRA=extra)
        assert rc == 0, out

    def test_all_five_off_arms_load_together(self, tmp_path):
        """The config §A runs, at parse level: five `off` lines in one server is
        not a combination the parser objects to."""
        knobs = "".join(f"        {flag} off;\n" for flag in FLAGS)
        rc, out = _parse(tmp_path, KNOBS=knobs)
        assert rc == 0, out

    def test_no_off_arm_is_diagnosed_at_all(self, tmp_path):
        """Silence is part of the subject: writing `off` on a flag that merges
        to 0 must not produce an advisory, or the audit's "never written" would
        have been noticed as noise long ago."""
        knobs = "".join(f"        {flag} off;\n" for flag in FLAGS)
        rc, out = _parse(tmp_path, KNOBS=knobs)
        assert _diagnostics(out) == [], out
        assert rc == 0, out


# A syntactically valid remote origin, and the same URL with the trailing slash
# the parser rejects (vfs_backend_config_s3.c:260-275 splits on the last colon
# and requires the tail to be a port).  `nginx -t` never connects to either.
REMOTE_OK = f"root://{HOST}:{DS_PORT}"
REMOTE_BAD = f"root://{HOST}:{DS_PORT}/"

# One authorization rule, in the spelling that needs no auth mode and no file:
# brix_authdb parses its file at config time and brix_require_vo demands
# `brix_auth gsi|token|both`, either of which would put a second directive's
# diagnostic ahead of the one being measured.
GROUP_RULE = "        brix_inherit_parent_group /cms;\n"


class TestTheSupervisorFlagSkipsBackendValidation:
    """DEFECT CANDIDATE #86.  `brix_supervisor on` makes
    `brix_server_has_runtime_export()` false (runtime_server.c:27), and the
    backend URL is parsed inside the export setup that predicate gates — so the
    flag does not merely ignore `brix_storage_backend` at runtime (§B), it
    switches OFF that directive's config-time syntax check.  A typo in the
    origin URL is an `nginx -t` failure on a data server and silence on a
    supervisor.

    This is the sharpest reading in the file for the audit's own question,
    because the `off` arm — the token nobody had ever written — is the arm that
    RESTORES a validation the `on` arm removes.
    """

    def test_the_invalid_origin_is_refused_without_the_flag(self, tmp_path):
        """The control: the parser does have an opinion about this URL."""
        rc, out = _parse(tmp_path, BACKEND=REMOTE_BAD)
        assert rc != 0, out
        assert "invalid remote origin host:port" in out, out

    def test_the_flag_makes_the_same_invalid_origin_load(self, tmp_path):
        """The finding.  One flag, and a URL nginx rejects becomes a URL nginx
        accepts."""
        rc, out = _parse(tmp_path, BACKEND=REMOTE_BAD,
                         KNOBS="        brix_supervisor on;\n")
        assert rc == 0, (
            f"the invalid origin is now refused with brix_supervisor on — #86 is "
            f"fixed and this class should be retired: {out}")

    def test_the_off_arm_restores_the_validation(self, tmp_path):
        """The arm nobody had written, doing the only thing it can do here:
        putting the config-time check back."""
        rc, out = _parse(tmp_path, BACKEND=REMOTE_BAD,
                         KNOBS="        brix_supervisor off;\n")
        assert rc != 0, out
        assert "invalid remote origin host:port" in out, out

    def test_the_accepted_config_never_mentions_the_backend_it_ignored(
            self, tmp_path):
        """Why #86 is a defect and not a documented mode: the accepted run says
        nothing about the directive whose value it stopped reading.

        A warning naming the ignored backend is the fix; if this fails, retire
        the claim rather than loosening it.
        """
        rc, out = _parse(tmp_path, BACKEND=REMOTE_BAD,
                         KNOBS="        brix_supervisor on;\n")
        assert rc == 0, out
        assert REMOTE_BAD not in out, (
            f"the accepted run now names the ignored backend — the silence this "
            f"test pins may be fixed: {out}")


class TestTheRemoteAuthzGuardOnlyArmsWithTheFlag:
    """`brix_server_guard_remote_authz()` (runtime_server.c:66-98) refuses the
    combination of a remote-origin backend, authorization rules, and a server
    mode with no runtime export — and `caps.supervisor` is one of the four ways
    into that mode.  So writing the flag turns a config that loads into one that
    is refused, and the `off` arm skips the guard entirely.

    Both facts about the guard are read as a triple with the flag as the only
    variable, and the last case bounds it: the guard needs BOTH conditions, so a
    posix backend keeps the same rules legal.
    """

    def test_the_combination_loads_without_the_flag(self, tmp_path):
        """The control.  A data server may pair a remote origin with authz rules
        because its export setup runs and aligns both sides of the path join."""
        rc, out = _parse(tmp_path, BACKEND=REMOTE_OK, KNOBS=GROUP_RULE)
        assert rc == 0, out

    def test_the_flag_turns_the_same_config_into_a_refusal(self, tmp_path):
        """One line added, and a config that loaded no longer does."""
        rc, out = _parse(tmp_path, BACKEND=REMOTE_OK,
                         KNOBS=GROUP_RULE + "        brix_supervisor on;\n")
        assert rc != 0, (
            "brix_supervisor on over a remote backend with authz rules was "
            f"accepted; runtime_server.c:72-97 is supposed to refuse it: {out}")

    def test_the_refusal_explains_the_mechanism_and_names_the_mode(
            self, tmp_path):
        """The message is the reason this is a guardrail rather than a trap: it
        names the mode class, the `//path` vs `/path` mismatch and the fix."""
        _rc, out = _parse(tmp_path, BACKEND=REMOTE_OK,
                          KNOBS=GROUP_RULE + "        brix_supervisor on;\n")
        for needle in ("requires a runtime export", "supervisor", "brix_export"):
            assert needle in out, (needle, out)

    def test_the_off_arm_skips_the_guard(self, tmp_path):
        """The arm nobody had written: `off` restores the runtime export, and
        with it the exemption."""
        rc, out = _parse(tmp_path, BACKEND=REMOTE_OK,
                         KNOBS=GROUP_RULE + "        brix_supervisor off;\n")
        assert rc == 0, out

    def test_a_local_backend_keeps_the_same_rules_legal(self, tmp_path):
        """The bound: the guard is about the pair, so the flag alone does not
        make authorization rules illegal."""
        rc, out = _parse(tmp_path,
                         KNOBS=GROUP_RULE + "        brix_supervisor on;\n")
        assert rc == 0, out
