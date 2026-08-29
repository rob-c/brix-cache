"""Test cases for audit16ae_gridftp_gate_off_arms — preamble (fixtures/helpers/mocks) lives in
_test_audit16ae_gridftp_gate_off_arms_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16ae_gridftp_gate_off_arms_helpers")


class TestTheArmedGsiPlaneDiffersExactlyThere:
    """The other side of the equality: G_ON is G_OFF plus one line, and these
    are all the observable consequences of it before a login."""

    def test_feat_advertises_the_security_extensions(self, gates):
        feat = " ".join(_dialogue(G_ON, ["FEAT"])[0])
        for token in ("AUTH GSSAPI", "PBSZ", "PROT", "DCAU"):
            assert token in feat, (token, feat)

    def test_auth_gssapi_is_accepted(self, gates):
        assert _reply(_dialogue(G_ON, ["AUTH GSSAPI"])[0]).startswith("334")

    def test_an_unknown_mechanism_is_504_rather_than_534(self, gates):
        """The armed plane HAS a mechanism list, so it answers "unknown
        mechanism"; the disarmed planes have none and answer "not available".
        The two codes are how a client tells the arms apart, and `AUTH TLS` is
        the sharpest case — a real mechanism name, refused for two different
        reasons by two servers that differ by one line."""
        for mechanism in ("TLS", "XYZ"):
            armed = _reply(_dialogue(G_ON, [f"AUTH {mechanism}"])[0])
            disarmed = _reply(_dialogue(G_OFF, [f"AUTH {mechanism}"])[0])
            assert armed.startswith("504"), (mechanism, armed)
            assert disarmed.startswith("534"), (mechanism, disarmed)

    def test_a_garbage_adat_token_never_authenticates(self, gates):
        """The security negative of the arm: a well-formed base64 blob that is
        not a GSSAPI token draws a 335 continuation and then 535, and the
        session is no more logged in than before — PWD and PASV still answer
        530."""
        replies = _dialogue(G_ON, ["AUTH GSSAPI", "ADAT AAAA", "ADAT AAAA",
                                   "PWD", "PASV"])
        assert _reply(replies[0]).startswith("334"), replies[0]
        assert _reply(replies[2]).startswith("535"), replies[2]
        assert _reply(replies[3]).startswith("530"), replies[3]
        assert _reply(replies[4]).startswith("530"), replies[4]

    def test_a_malformed_adat_token_is_rejected_as_malformed(self, gates):
        """Not base64 at all → 501 rather than 535: the decoder refuses before
        the mechanism sees anything, which is the boundary that keeps arbitrary
        client bytes out of the GSSAPI accept path."""
        replies = _dialogue(G_ON, ["AUTH GSSAPI", "ADAT !!!not-base64!!!"])
        assert _reply(replies[1]).startswith("501"), replies[1]

    def test_pbsz_answers_200_on_a_plane_that_refuses_every_auth(self, gates):
        """Worth stating on its own.  `PBSZ 0` is answered `200 PBSZ=0` by all
        three planes — including the two that have just refused every AUTH with
        534.  A client probing PBSZ to decide whether the server speaks RFC 2228
        is told yes by a server that does not."""
        for label, port in ALL_GSI:
            assert _reply(_dialogue(port, ["PBSZ 0"])[0]).startswith("200"), \
                label

    def test_prot_p_is_refused_on_every_plane_including_the_armed_one(self,
                                                                      gates):
        """PROT P needs a security context, and none of these three sessions has
        one — the armed plane offers GSSAPI but this cell never completes it.
        All three answer 536, which is the arm-independent half of the data
        channel surface."""
        for label, port in ALL_GSI:
            assert _reply(_dialogue(port, ["PROT P"])[0]).startswith("536"), \
                label
            assert _reply(_dialogue(port, ["PROT C"])[0]).startswith("200"), \
                label


class TestArmingGsiDoesNotRequireIt:
    """DEFECT CANDIDATE #111.

    G_ON is the operator doc's §3 config: `brix_gridftp_gsi on` with a host
    certificate, key and CA, presented as "the production form: an RFC 2228 GSI
    control channel authenticated by an X.509 (proxy) certificate".  Every cell
    below runs against that plane with no certificate, no proxy, and no AUTH at
    all.

    ev_grp_login (ftp_ev_dispatch.c:226-233) sets `fc->authed = 1` on any PASS
    and does not look at `fc->conf->gsi`.  Nothing in the gridftp command table
    requires the security layer, and `brix_gridftp_require_vo` — the only
    directive that could — is a per-PATH ACL evaluated after resolution
    (ftp_ev_path.c:117-125) which is allow-all when no rule covers the path.
    """

    def test_an_anonymous_cleartext_login_succeeds_on_the_armed_plane(self,
                                                                      gates):
        replies = _dialogue(G_ON, ["USER anonymous", "PASS x@example.org",
                                   "PWD"])
        assert _reply(replies[0]).startswith("331"), replies[0]
        assert _reply(replies[1]).startswith("230"), replies[1]
        assert _reply(replies[2]).startswith("257"), replies[2]

    def test_any_password_at_all_is_accepted(self, gates):
        """PASS is not checked against anything — the point is not that
        anonymous is allowed but that the branch which sets `authed` has no
        condition on it."""
        for password in ("", "wrong", "../../etc/shadow", "x" * 200):
            replies = _dialogue(G_ON, ["USER someone", f"PASS {password}"])
            assert _reply(replies[1]).startswith("230"), (password, replies)

    def test_the_cleartext_session_can_write_through_the_armed_plane(self,
                                                                     gates,
                                                                     request):
        """The consequence, and the reason this is a security finding and not a
        curiosity: the unauthenticated session gets the export's full
        read-write surface."""
        payload = os.urandom(777)
        name = f"{_uid(request)}.bin"
        assert _stor(G_ON, name, payload) == 226
        assert gates.disk(name).read_bytes() == payload
        code, body = _retr(G_ON, name)
        assert code == 226 and body == payload

    def test_the_armed_plane_is_indistinguishable_from_the_disarmed_ones_here(
            self, gates, request):
        """The equality that makes the size of the finding legible: for a client
        that simply never sends AUTH, all three GSI planes are the same server.
        Arming GSI adds a mechanism; it removes nothing."""
        payload = os.urandom(512)
        for label, port in ALL_GSI:
            name = f"{_uid(request)}-{label}.bin"
            assert _stor(port, name, payload) == 226, label
            assert gates.disk(name).read_bytes() == payload, label

    def test_the_path_confinement_still_holds_for_the_cleartext_session(
            self, gates):
        """What DOES still gate the anonymous session, stated so the finding is
        bounded: invariant 4's resolve_path is upstream of authentication, so an
        escape above the export is refused whether or not anyone logged in
        meaningfully."""
        for escape in ("../../../../etc/passwd", "/etc/passwd",
                       "..%2f..%2f..%2fetc%2fpasswd", "....//etc/passwd"):
            code, body = _retr(G_ON, escape)
            assert code in (550, 553), (escape, code)
            assert b"root:x:" not in body, escape


# --------------------------------------------------------------------------- #
# G. Parse tier                                                                #
# --------------------------------------------------------------------------- #

FLAGS = ("brix_verify_write",
         "brix_gridftp_require_allo_size",
         "brix_gridftp_gsi")


def _parse(tmp_path, **slots):
    """`nginx -t` on the shared parse scaffold.

    configs/nginx_audit16jparse.conf is reused rather than copied, for the
    reason files 29 and 30 give: it writes none of the three flags itself, so a
    duplicate negative can be sure the duplicate it is shown is the one it
    wrote.
    """
    data = tmp_path / "parse-data"
    data.mkdir(exist_ok=True)
    values = {"PORT": PARSE_PLACEHOLDER_PORT,
              "PORT2": PARSE_PLACEHOLDER_PORT + 1,
              "LOG_DIR": str(tmp_path),
              "BACKEND": f"posix:{data}",
              "KNOBS": "", "STREAM_KNOBS": "", "HTTP_KNOBS": "",
              "LOC_KNOBS": "", "OUTER": "", "EXTRA": ""}
    values.update(slots)
    result = nginx_t("nginx_audit16jparse.conf", str(tmp_path), **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _diagnostics(out):
    """Only the lines nginx itself flagged: a tmp_path name can contain the
    token under test, so a substring search over the whole output would match
    the temp directory rather than a diagnostic."""
    return [ln for ln in out.splitlines()
            if any(tag in ln for tag in ("[warn]", "[error]", "[crit]",
                                         "[emerg]"))]


class TestBothArmsOfAllThreeFlagsParse:
    """The parse half of the same claim, in the scope the directives declare."""

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_an_arm_is_accepted_in_a_stream_server(self, tmp_path, flag, arm):
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} {arm};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_an_arm_draws_no_diagnostic(self, tmp_path, flag, arm):
        """Accepted is not enough — the claim in §A/§B is that a written `off`
        is a normal thing to write, and a NOTICE saying the line is redundant
        would be a different (and better) world."""
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} {arm};\n")
        assert rc == 0 and _diagnostics(out) == [], _diagnostics(out)

    @pytest.mark.parametrize("flag", FLAGS)
    def test_all_three_disarming_tokens_together_are_accepted(self, tmp_path,
                                                              flag):
        """The W_OFF plane's shape, at parse time: nothing cross-validates the
        three against each other or against `brix_gridftp` being off."""
        rc, out = _parse(tmp_path, KNOBS="".join(
            f"        {f} off;\n" for f in FLAGS))
        assert rc == 0, out
        assert _diagnostics(out) == [], _diagnostics(out)


class TestTheFlagsRefuseWhatIsNotAFlag:
    """Arity and value, per flag.  `ngx_conf_set_flag_slot` produces both
    messages, and the negatives are what neither existing gridftp file has —
    both only ever render well-formed arms."""

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("value", ("yes", "no", "1", "0", "ON", "OFF",
                                       "true", '""'))
    def test_a_non_flag_value_is_refused_and_named(self, tmp_path, flag, value):
        """`ON`/`OFF` are in the list because ngx_conf_set_flag_slot's match is
        case-INSENSITIVE, unlike the parameter tokens file 30 found in the
        open-file-cache setter — the same codebase does both, and only a test
        that writes them says which is which."""
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} {value};\n")
        if value in ("ON", "OFF"):
            assert rc == 0, out
            return
        assert rc != 0, out
        assert any(f'invalid value "{value.strip(chr(34))}" in "{flag}"' in ln
                   for ln in _diagnostics(out)), _diagnostics(out)

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("args", ("", "on off", "on on on"))
    def test_a_wrong_argument_count_is_refused(self, tmp_path, flag, args):
        line = f"        {flag}{' ' + args if args else ''};\n"
        rc, out = _parse(tmp_path, KNOBS=line)
        assert rc != 0, out
        assert any(f'invalid number of arguments in "{flag}"' in ln
                   for ln in _diagnostics(out)), _diagnostics(out)

    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_same_flag_twice_in_one_server_is_a_duplicate(self, tmp_path,
                                                              flag):
        rc, out = _parse(tmp_path,
                         KNOBS=f"        {flag} on;\n        {flag} off;\n")
        assert rc != 0, out
        assert any(f'"{flag}" directive is duplicate' in ln
                   for ln in _diagnostics(out)), _diagnostics(out)


class TestTheFlagsAreStreamServerOnly:
    """All three are declared NGX_STREAM_SRV_CONF and nothing else
    (ftp_module.c:258,279,286), so every other placement must be refused —
    including `stream{}` itself, where a reader might expect a site-wide
    default to be writable.  brix_ftp_merge_conf implements parent inheritance
    for all three (ftp_module_merge.c:160,161,164); this class is what says
    that inheritance arm is unreachable rather than untested.
    """

    #: bare brix_verify_write is the ONE shared write-integrity flag (W3):
    #: the http plane registers it too, so those placements are legal there.
    HTTP_SHARED = {"brix_verify_write"}

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("slot", ("STREAM_KNOBS", "HTTP_KNOBS",
                                      "LOC_KNOBS", "OUTER"))
    def test_the_flag_is_refused_outside_a_stream_server(self, tmp_path, flag,
                                                         slot):
        rc, out = _parse(tmp_path, **{slot: f"    {flag} on;\n"})
        if flag in self.HTTP_SHARED and slot in ("HTTP_KNOBS", "LOC_KNOBS"):
            assert rc == 0, out
            return
        assert rc != 0, out
        assert any(f'"{flag}" directive is not allowed here' in ln
                   for ln in _diagnostics(out)), _diagnostics(out)

    @pytest.mark.parametrize("flag", FLAGS)
    def test_a_sibling_server_may_write_its_own_arm(self, tmp_path, flag):
        """Scope: the arms are per-block, so two servers in one stream{} may
        disagree — which is what the eight-plane instance above depends on."""
        extra = ("    server {\n"
                 f"        listen {PARSE_PLACEHOLDER_PORT + 2};\n"
                 "        brix_root on;\n"
                 "        brix_auth none;\n"
                 f"        {flag} off;\n"
                 "    }\n")
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} on;\n", EXTRA=extra)
        assert rc == 0, out


class TestTheGsiFlagIsTheOnlyOneWithAPrerequisite:
    """`brix_gridftp_gsi on` demands a certificate, key and CA
    (ftp_module_gsi.c:47-54) — and only when the gateway is enabled, because
    brix_ftp_merge_tls (ftp_module_merge.c:142) guards the build with
    `enable && gsi`.  Both halves matter: the second is why G_ABS can carry PKI
    material with no flag, and why a stray `brix_gridftp_gsi on` in a block that
    is not a gateway is silently harmless.
    """

    def _gateway(self, tmp_path, extra):
        data = tmp_path / "ftp-export"
        data.mkdir(exist_ok=True)
        return ("        brix_gridftp        on;\n"
                f"        brix_export {data};\n" + extra)

    def test_gsi_on_without_a_certificate_is_refused(self, tmp_path):
        rc, out = _parse(tmp_path, KNOBS=self._gateway(
            tmp_path, "        brix_gridftp_gsi on;\n"))
        assert rc != 0, out
        assert any("brix_gridftp_gsi requires brix_certificate" in ln
                   for ln in _diagnostics(out)), _diagnostics(out)

    @pytest.mark.parametrize("arm", ("        brix_gridftp_gsi off;\n", ""))
    def test_the_disarmed_gateway_needs_no_certificate(self, tmp_path, arm):
        """The written `off` and its omission agree at parse time too — and
        this is the cell that shows the prerequisite is attached to the flag
        rather than to the gateway."""
        rc, out = _parse(tmp_path, KNOBS=self._gateway(tmp_path, arm))
        assert rc == 0, out

    def test_gsi_on_in_a_block_that_is_not_a_gateway_is_accepted(self,
                                                                 tmp_path):
        """`brix_gridftp` off (the default), so `enable && gsi` is false and the
        context is never built — the flag is inert rather than refused.  Worth
        a cell because it is the one way to write `brix_gridftp_gsi on` and get
        no GSI and no complaint."""
        rc, out = _parse(tmp_path, KNOBS="        brix_gridftp_gsi on;\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], _diagnostics(out)

    def test_a_partial_certificate_set_is_refused(self, tmp_path):
        """One of the three is not enough, and the message names all three —
        an operator who set the certificate and forgot the CA gets told what is
        missing rather than a TLS failure at runtime."""
        rc, out = _parse(tmp_path, KNOBS=self._gateway(
            tmp_path,
            "        brix_gridftp_gsi on;\n"
            f"        brix_certificate {SERVER_CERT};\n"))
        assert rc != 0, out
        assert any("brix_trusted_ca" in ln
                   for ln in _diagnostics(out)), _diagnostics(out)


# --------------------------------------------------------------------------- #
# H. The instance said nothing about any of it                                 #
# --------------------------------------------------------------------------- #

class TestNothingIsLoggedAboutTheDisarmedGates:
    """Eight gateways, five of them writing a disarming token, and the startup
    log names none of the three directives.

    An operator who wrote `brix_verify_write off` on a plane that also
    accepts REST (§D), or `brix_gridftp_gsi on` on a plane that still takes
    anonymous logins (§F), gets no line saying so.  That silence is what makes
    #111 and #112 findings rather than documented trade-offs.
    """

    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_startup_log_never_names_the_flag(self, gates, flag):
        offenders = [ln for ln in gates.errlog().splitlines() if flag in ln]
        assert offenders == [], offenders

    def test_the_armed_gsi_plane_logs_no_warning_about_cleartext_logins(
            self, gates):
        """The specific silence behind #111: nothing anywhere says the GSI
        gateway also accepts USER/PASS."""
        log = gates.errlog().lower()
        for token in ("cleartext login", "unauthenticated", "gsi not required"):
            assert token not in log, token

    def test_the_instance_started_clean(self, gates):
        """Eight gateways is a configuration a real deployment could hold, and
        "the disarming arms are accepted" means accepted without complaint.

        Request-scoped lines are excluded by their `client:` field rather than
        by a whitelist of texts — §E and §F deliberately ask for refusals, and
        an [error] per refused transfer is the server working.
        """
        bad = [ln for ln in gates.errlog().splitlines()
               if any(tag in ln for tag in ("[emerg]", "[alert]", "[error]"))
               and "client:" not in ln]
        assert bad == [], bad


# --------------------------------------------------------------------------- #
# I. DEFECT CANDIDATE #114 — %ll handed to nginx's own formatter                #
# --------------------------------------------------------------------------- #

class TestTheRestReplyIsMalformed:
    """`brix_ftp_ev_reply` formats through ngx_vslprintf (ftp_ev_reply.c:107),
    which implements `%L` and `%O` and has no `%lld`.  ftp_ev_dispatch.c:173
    writes

        "350 Restart position accepted (%lld)\\r\\n"

    so the value comes out right on LP64 — `%l` consumes the argument as a long
    — and the trailing `ld` is emitted as literal text.  This is the one of the
    four sites that reaches a client.

    The other three are log lines and are named here rather than measured,
    because a WARN nobody can provoke on demand is not a cell:
      * protocols/root/session/signing.c:43   `%llu` × 2, sigver replay WARN
      * protocols/root/query/set.c:78         `%llu` × 3, cms.space INFO
      * fs/cache/directives.c:231             `%llu`, config-time NOTICE

    The hazard is latent rather than live: on an ILP32 or LLP64 target `%l`
    would consume the wrong width and the values would be wrong too.
    """

    @pytest.mark.parametrize("offset", ("0", "10", "4294967296"))
    def test_the_reply_carries_a_literal_ld(self, gates, offset):
        reply = _reply(_dialogue(W_ON, [f"REST {offset}"], login=True)[0])
        assert reply == f"350 Restart position accepted ({offset}ld)", reply

    @pytest.mark.parametrize("label,port", ALL_WRITE + ALL_GSI)
    def test_every_plane_emits_the_same_malformed_reply(self, gates, label,
                                                        port):
        """It is the formatter and not the configuration: all eight gateways
        answer identically, so no arm of any of the three flags is involved."""
        reply = _reply(_dialogue(port, ["REST 10"], login=True)[0])
        assert reply == "350 Restart position accepted (10ld)", (label, reply)

    def test_the_value_itself_is_correct(self, gates):
        """The half that keeps this a formatting defect rather than a
        correctness one: the offset is echoed exactly, so a client that parses
        the number and ignores the tail is unharmed — which is why it has
        survived."""
        for offset in ("0", "1", "10", "4294967296", "9223372036854775807"):
            reply = _reply(_dialogue(W_ON, [f"REST {offset}"], login=True)[0])
            assert reply.startswith(f"350 Restart position accepted ({offset}"), \
                reply
