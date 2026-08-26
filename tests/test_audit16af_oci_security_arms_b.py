"""Test cases for audit16af_oci_security_arms — preamble (fixtures/helpers/mocks) lives in
_test_audit16af_oci_security_arms_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16af_oci_security_arms_helpers")


class TestTheChallengeCannotBeFollowed:
    """DEFECT #118 — oci_authz.c:85-88 builds the realm from
    `r->headers_in.server`, which nginx parses out of the Host header WITHOUT
    the port.  A registry on any port but 80 therefore advertises a realm on
    the wrong one, and the endpoint it names is not implemented at all.

    The module says this matters in its own words: "`podman login` only works
    against a registry that answers an unauthenticated request with a challenge
    it can follow, so the header is part of the contract, not decoration."
    """

    def _challenge(self, port):
        _, headers, _ = _plain(port)("POST", "/v2/lab/app/blobs/uploads/")
        return headers.get("WWW-Authenticate", "")

    @pytest.mark.parametrize("arm,port", AUTHENTICATING)
    def test_the_realm_drops_the_port_the_request_arrived_on(self, arms, arm,
                                                             port):
        challenge = self._challenge(port)

        assert "Bearer realm=" in challenge
        assert f":{port}" not in challenge, challenge

    @pytest.mark.parametrize("arm,port", AUTHENTICATING)
    def test_the_service_drops_it_as_well(self, arms, arm, port):
        """Both fields come from the same span, so a client that reconstructed
        the endpoint from `service` instead lands in the same place."""
        challenge = self._challenge(port)

        service = challenge.split('service="', 1)[1].rstrip('"')
        assert service == BIND_HOST, service

    def test_the_advertised_endpoint_is_not_implemented(self, arms):
        """Following the realm — port and all — reaches the registry's own
        grammar, which reads `token` as a repository name."""
        status, _, body = _plain(R_OFF)("GET", "/v2/token")

        assert status == 404
        assert _err(body) == "NAME_UNKNOWN"

    def test_the_challenge_is_otherwise_well_formed(self, arms):
        """The bound: the header is a syntactically valid Bearer challenge and
        every client will parse it.  It parses to the wrong place, which is the
        harder failure to notice."""
        challenge = self._challenge(R_OFF)

        assert challenge.startswith('Bearer realm="')
        assert '",service="' in challenge
        assert challenge.count('"') == 4


# --------------------------------------------------------------------------- #
# §G  Nobody is recorded  (DEFECT #119)                                        #
# --------------------------------------------------------------------------- #

class TestNoLogNamesWhoPushed:
    """DEFECT #119 — brix_oci_registry_authz() fills `principal` and its only
    caller (oci_registry.c:290,318) declares it on the stack, passes it in, and
    never reads it back.  The anonymous branch's own comment says the identity
    is "Recorded as such in the identity so the access log distinguishes
    'nobody authenticated' from 'somebody did, and it was anonymous'"
    (oci_authz.c:222-224).  Neither string reaches any log.

    This template turns `access_log` ON at http level, which no other OCI
    config does, so that the absence measured here is the module's and not the
    fixture's."""

    def test_the_instance_does_write_an_access_log(self, arms):
        """The precondition, asserted rather than assumed: an absence proved
        against a log that was never written proves nothing."""
        _plain(R_ANON)("GET", "/v2/")

        assert "GET /v2/" in arms.logs()

    def test_an_authenticated_push_names_nobody_in_the_access_log(self, arms):
        call = _plain(R_OFF, {"Authorization": "Bearer " + arms.token()})
        assert _push_image(call, "who/authed", "v1")[0] == 201

        access = arms.await_log("access.log", "who/authed/manifests")
        assert PUSHER not in access, [ln for ln in access.splitlines()
                                      if PUSHER in ln]

    def test_an_anonymous_push_is_never_called_anonymous(self, arms):
        """The half the comment is explicitly about.  The string does not occur
        anywhere in anything the instance wrote."""
        assert _push_image(_plain(R_ANON), "who/anon", "v1")[0] == 201

        assert "anonymous" not in arms.logs()

    def test_the_two_pushes_are_indistinguishable_in_the_access_log(self,
                                                                    arms):
        """Which is what "no identity is recorded" costs: the manifest PUT that
        a scoped token authorised and the one nobody authorised are the same
        line but for the port."""
        token = {"Authorization": "Bearer " + arms.token()}
        assert _push_image(_plain(R_OFF, token), "who/pair-a", "v1")[0] == 201
        assert _push_image(_plain(R_ANON), "who/pair-b", "v1")[0] == 201

        access = arms.await_log("access.log", "who/pair-b/manifests")

        def shape(needle):
            line = [ln for ln in access.splitlines() if needle in ln][-1]
            return line.split(" - ")[0], line.split('"')[1].split()[0]

        assert shape("who/pair-a/manifests") == shape("who/pair-b/manifests")

    def test_the_subject_only_survives_where_the_token_layer_logged_it(self,
                                                                       arms):
        """The bound, and the reason this is a defect about the registry rather
        than about tokens: the `sub` IS in the error log — put there by
        brix_token's own validation line, at info level, with no mention of
        what it was then allowed to do.  The registry contributes nothing."""
        call = _plain(R_ABS, {"Authorization": "Bearer " + arms.token()})
        assert _push_image(call, "who/traced", "v1")[0] == 201

        named = [ln for ln in arms.errlog().splitlines() if PUSHER in ln]
        def _assert_test_the_subject_only_survives_where_the_token_layer_logged_it_1():
            assert named, "the token layer logged nothing either"
            assert all("brix_token:" in ln for ln in named), named

        _assert_test_the_subject_only_survives_where_the_token_layer_logged_it_1()
        assert not any("who/traced" in ln and "principal" in ln
                       for ln in named)


# --------------------------------------------------------------------------- #
# §H  The parse tier, and the flag with no runtime at all                      #
# --------------------------------------------------------------------------- #

ANON = "brix_oci_registry_allow_anonymous"
INSECURE = "brix_oci_mirror_insecure"

_REGISTRY = ("            brix_oci_registry      on;\n"
             "            brix_oci_registry_root {STORE};\n"
             "            brix_allow_write       on;\n")


def _tls_server(mode):
    return (f"        ssl_certificate        {SERVER_CERT};\n"
            f"        ssl_certificate_key    {SERVER_KEY};\n"
            f"        ssl_client_certificate {CA_CERT};\n"
            f"        ssl_verify_client      {mode};\n")


def _mirror(url, arm=None):
    line = "" if arm is None else f"            {INSECURE} {arm};\n"
    return (f"            brix_oci_mirror  {url};\n"
            f"{line}"
            "            brix_cache_store posix:{STORE};\n")


def _parse(tmp_path, **slots):
    """`nginx -t` on the shared parse scaffold.

    configs/nginx_audit16jparse.conf is reused rather than copied, for the
    reason files 29-31 give: it writes neither flag itself, so a duplicate
    negative can be sure the duplicate it is shown is the one it wrote.  Its
    LOC_KNOBS slot is an http location, which is the only context either
    directive declares."""
    tmp_path = Path(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    data = tmp_path / "parse-data"
    data.mkdir(exist_ok=True)
    store = tmp_path / "parse-store"
    store.mkdir(exist_ok=True)
    values = {"PORT": PARSE_PLACEHOLDER_PORT,
              "PORT2": PARSE_PLACEHOLDER_PORT + 1,
              "LOG_DIR": str(tmp_path),
              "BACKEND": f"posix:{data}",
              "KNOBS": "", "STREAM_KNOBS": "", "HTTP_KNOBS": "",
              "LOC_KNOBS": "", "OUTER": "", "EXTRA": ""}
    values.update({k: v.replace("{STORE}", str(store)) if isinstance(v, str)
                   else v for k, v in slots.items()})
    result = nginx_t("nginx_audit16jparse.conf", str(tmp_path), **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _diagnostics(out):
    """Only the lines nginx itself flagged: a tmp_path name can contain the
    token under test, so a substring search over the whole output would match
    the temp directory rather than a diagnostic."""
    return [ln for ln in out.splitlines()
            if any(tag in ln for tag in ("[warn]", "[error]", "[crit]",
                                         "[emerg]"))]


class TestBothArmsOfBothFlagsParse:

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_an_arm_is_accepted_in_an_http_location(self, tmp_path, flag, arm):
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} {arm};\n")

        assert rc == 0, out

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_an_arm_draws_no_diagnostic(self, tmp_path, flag, arm):
        """Accepted is not enough — §A's claim is that a written `off` is a
        normal thing to write, and a NOTICE saying the line is redundant would
        be a different (and better) world."""
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} {arm};\n")

        assert rc == 0 and _diagnostics(out) == [], _diagnostics(out)

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    def test_an_arm_alone_needs_no_surface_to_belong_to(self, tmp_path, flag):
        """Neither flag is cross-validated against the surface it configures,
        so both are accepted in a location that has neither a registry nor a
        mirror — the arm merges and is never consulted."""
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} off;\n")

        assert rc == 0, out


class TestTheAnonymityFlagIsTheRegistrysOnlyWayToSayOpen:

    def test_the_written_off_is_refused_exactly_as_its_omission_is(self,
                                                                   tmp_path):
        """The parse half of §A, and the one that matters most: a registry with
        `off` and a registry with nothing must fail the same way, or the corpus
        has been asserting a refusal it never provoked."""
        off = _parse(tmp_path / "off", LOC_KNOBS=_REGISTRY + f"            {ANON} off;\n")
        absent = _parse(tmp_path / "abs", LOC_KNOBS=_REGISTRY)

        assert off[0] == absent[0] != 0
        assert _diagnostics(off[1])[0].split(": ", 1)[1].split(" in ")[0] == \
            _diagnostics(absent[1])[0].split(": ", 1)[1].split(" in ")[0]

    def test_the_refusal_names_all_three_ways_out(self, tmp_path):
        rc, out = _parse(tmp_path, LOC_KNOBS=_REGISTRY)

        assert rc != 0
        for way in ("brix_oci_token_issuers", "ssl_verify_client",
                    "brix_oci_registry_allow_anonymous on"):
            assert way in out, way

    def test_the_written_on_is_what_makes_it_load(self, tmp_path):
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=_REGISTRY + f"            {ANON} on;\n")

        assert rc == 0, out

    def test_an_issuer_table_makes_it_load_without_the_flag(self, tmp_path,
                                                            arms):
        """The second route, which is the one registry_lane's authenticating
        leg takes."""
        rc, out = _parse(
            tmp_path,
            LOC_KNOBS=_REGISTRY
            + f"            brix_oci_token_issuers {arms.issuers};\n")

        assert rc == 0, out


class TestTheMirrorFlagIsOnlyEverAboutCleartext:
    """DEFECT #120 — `up->insecure` (oci_merge.c:312) is the only thing the
    merged value is copied to and nothing reads it again, so the flag's entire
    effect is the cleartext permit at oci_merge.c:117.  The black-box shadow of
    that dead field is here: once the upstream is `https://`, both arms and the
    omission are the same configuration."""

    @pytest.mark.parametrize("arm", ("off", None), ids=("off", "absent"))
    def test_a_cleartext_upstream_is_refused_by_the_written_off_and_by_its_omission(
            self, tmp_path, arm):
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=_mirror("http://mirror.invalid", arm))

        assert rc != 0
        assert "a cleartext upstream would hand every pulled token" in out

    def test_the_written_on_is_what_permits_it(self, tmp_path):
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=_mirror("http://mirror.invalid", "on"))

        assert rc == 0, out

    @pytest.mark.parametrize("arm", ("on", "off", None),
                             ids=("on", "off", "absent"))
    def test_an_https_upstream_loads_under_every_arm(self, tmp_path, arm):
        """#120 as a measurement.  If the flag meant what its name says it
        would have something to do here, and it does not: all three are one
        configuration."""
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=_mirror("https://registry.invalid", arm))

        assert rc == 0, out
        assert _diagnostics(out) == [], _diagnostics(out)

    def test_the_flag_cannot_open_a_registry_instead(self, tmp_path):
        """The bound: it is a mirror-only permit and the two surfaces stay
        refused as a pair, so #120 is about a dead field and not about a
        confusable one."""
        rc, out = _parse(
            tmp_path,
            LOC_KNOBS=_REGISTRY + f"            {INSECURE} on;\n")

        assert rc != 0
        assert "without an authenticated context" in out


class TestTheFlagsRefuseWhatIsNotAFlag:

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    @pytest.mark.parametrize("value", ("yes", "true", "1", "of", "0",
                                       "enabled"))
    def test_a_value_that_is_not_an_arm_is_refused(self, tmp_path, flag,
                                                   value):
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} {value};\n")

        assert rc != 0
        assert 'it must be "on" or "off"' in out or \
            "invalid number of arguments" in out, out

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    @pytest.mark.parametrize("spelling", ("ON", "On", '"on"', "'on'"))
    def test_the_arm_is_case_insensitive_and_quote_transparent(self, tmp_path,
                                                               flag,
                                                               spelling):
        """Not a defect and not a nicety either: `brix_oci_registry_allow_
        anonymous ON` opens a registry to the world, and an operator grepping
        the corpus for the lower-case token would not find it.  Both flags
        inherit this from ngx_conf_set_flag_slot's ngx_strcasecmp and from the
        parser stripping quotes before the setter sees the value, so it is the
        spelling surface an audit of either flag actually has."""
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=f"            {flag} {spelling};\n")

        assert rc == 0, out

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    @pytest.mark.parametrize("line", ("{flag};", "{flag} on off;",
                                      "{flag} on on;"))
    def test_an_arity_other_than_one_is_refused(self, tmp_path, flag, line):
        rc, out = _parse(tmp_path,
                         LOC_KNOBS="            " + line.format(flag=flag)
                         + "\n")

        assert rc != 0
        assert "invalid number of arguments" in out

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    def test_writing_it_twice_is_refused(self, tmp_path, flag):
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=f"            {flag} on;\n"
                                   f"            {flag} off;\n")

        assert rc != 0
        assert "directive is duplicate" in out


class TestTheFlagsAreHttpLocationOnly:
    """Both are declared NGX_HTTP_LOC_CONF and nothing else
    (directives_registry.h:36-42, directives_mirror.h:56-62), which is a
    narrower scope than most of the module — brix_oci_max_blob_size and
    brix_oci_token_issuers are MAIN|SRV|LOC.  A flag that cannot be written in
    a parent has no parent value to inherit, so the merge's inheritance arm for
    both (oci_merge.c:72,75) is unreachable rather than untested."""

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    @pytest.mark.parametrize("slot,indent", [("HTTP_KNOBS", "        "),
                                             ("STREAM_KNOBS", "    "),
                                             ("KNOBS", "        "),
                                             ("OUTER", "")])
    def test_every_other_placement_is_refused(self, tmp_path, flag, slot,
                                              indent):
        rc, out = _parse(tmp_path, **{slot: f"{indent}{flag} on;\n"})

        assert rc != 0
        assert f'"{flag}" directive is not allowed here' in out, out

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    def test_a_sibling_location_does_not_reach_this_one(self, tmp_path, flag):
        """Two locations in one server, one flag written: the scaffold's own
        EXTRA slot is a stream server, so the sibling question is asked with a
        second location instead."""
        rc, out = _parse(
            tmp_path,
            LOC_KNOBS=f"            {flag} on;\n"
                      "        }\n"
                      "        location /other/ {\n")

        assert rc == 0, out
