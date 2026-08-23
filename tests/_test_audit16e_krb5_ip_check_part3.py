# --------------------------------------------------------------------------- #
# C. DEFECT CANDIDATE #70 — the check the ticket can opt out of                #
# --------------------------------------------------------------------------- #

class TestTheCheckIsInertForAnAddresslessTicket:
    """What ``on`` is worth against the credential every real client presents."""

    def test_a_stock_kinit_produces_an_addressless_ticket(self, planes):
        """The premise: ``kdc_helpers.up()`` kinits through the generated
        profile with no ``noaddresses`` line at all, and MIT's default for it is
        true.  Nothing in this suite, and nothing in a normal deployment, asks
        for anything else."""
        assert _addressless_ticket().addresses == set(), (
            "the stock credential cache now carries addresses — #70 needs "
            "re-deriving, and so does the profile in kdc_helpers")

    def test_the_enabled_check_accepts_it_from_a_foreign_address(self, planes):
        """security-negative, and the finding: the AP-REQ arrives from an
        address no ticket ever named, against a server whose operator switched
        the address check ON, and it authenticates.  ``krb5_rd_req`` compares
        nothing when there is nothing to compare."""
        ticket = _addressless_ticket()
        result = _relayed(planes, planes.on, ticket, "stat", READ_FILE)
        assert result.returncode == 0, (
            "an addressless ticket is now refused from a foreign address — the "
            "check gained teeth, so re-state #70\n"
            f"{result.stdout}{result.stderr}")

    def test_neither_arm_can_be_told_from_the_other(self, planes):
        """The observability half of #70.  Same credential, same source, both
        planes: same verdict, and no line anywhere names the check, says it was
        skipped, or distinguishes a checked login from an unchecked one."""
        ticket = _addressless_ticket()
        assert _relayed(planes, planes.on, ticket,
                        "stat", READ_FILE).returncode == 0
        assert _relayed(planes, planes.off, ticket,
                        "stat", READ_FILE).returncode == 0

        text = planes.errlog()
        for phrase in ("ip_check=on", "ip_check=off"):
            # The config-time NOTICE is allowed to say it once per parse; what
            # must not exist is a RUNTIME line, and those are the ones carrying
            # a connection number.
            for line in text.splitlines():
                if phrase in line:
                    assert "krb5 auth configured" in line, (
                        f"a runtime line now names the check: {line}")
        for phrase in ("address check", "ip check", "peer address"):
            assert phrase not in text.lower(), (
                f"the acceptor now says something about {phrase!r} at run time "
                "— close #70's observability half against the new line")

    def test_the_unchecked_login_is_counted_like_any_other(self, planes):
        """And the metric cannot tell them apart either: an addressless login
        through the enabled plane moves no failure counter and is recorded as an
        ordinary krb5 success."""
        ticket = _addressless_ticket()
        before = planes.auth_failures()
        assert _relayed(planes, planes.on, ticket,
                        "stat", READ_FILE).returncode == 0
        assert planes.auth_failures() == before, (
            "an accepted login moved the failure counter")


# --------------------------------------------------------------------------- #
# D. The shape of the denial                                                   #
# --------------------------------------------------------------------------- #

class TestTheDenial:
    """A refused login must refuse everything that follows it."""

    def test_the_refused_session_reads_nothing(self, planes):
        """security-negative: the denial happens before the session is marked
        authenticated (auth.c:296-310 returns before brix_krb5_session_grant),
        so a read attempted on the same connection must come back empty rather
        than partially served."""
        ticket = _addressed_ticket(planes.tmp_path)
        result = _relayed(planes, planes.on, ticket, "cat", READ_FILE)
        assert result.returncode != 0, (
            f"a refused session read the file\n{result.stdout}")
        assert READ_BODY.decode() not in result.stdout, (
            "file content reached a client whose AP-REQ was refused")

    def test_the_other_planes_are_unaffected_by_the_refusal(self, planes):
        """The flag is per-server, which is the contrast with the tranche's
        previous subject: a refusal on the enabled plane leaves the other two
        serving the same credential in the same worker."""
        ticket = _addressed_ticket(planes.tmp_path)
        assert _refused(_relayed(planes, planes.on, ticket, "stat", READ_FILE))
        for port, plane in ((planes.off, "off"), (planes.absent, "absent")):
            result = _relayed(planes, port, ticket, "stat", READ_FILE)
            assert result.returncode == 0, (
                f"the {plane} plane broke after a refusal on the on plane\n"
                f"{result.stdout}{result.stderr}")


# --------------------------------------------------------------------------- #
# E. The parse tier                                                            #
# --------------------------------------------------------------------------- #

def _knobs(*lines):
    return "".join(f"        {line}\n" for line in lines)


def _second_server(*lines):
    """A whole second stream server for the parse scaffold.

    Its listen port is the OTHER placeholder: ngx_stream_core_listen refuses a
    repeated address/port pair, and that error would arrive before whatever the
    case is actually asking about.
    """
    body = "".join(f"        {line}\n" for line in lines)
    return (f"\n    server {{\n"
            f"        listen {SHARED_PARSE_PLACEHOLDER_PORT};\n"
            f"        brix_root on;\n"
            f"{body}    }}\n")


def _diagnostics(out):
    """The lines of an ``nginx -t`` transcript that would tell an operator
    something is wrong.  Matching on the transcript as a whole cannot work: the
    prefix is a tmp_path named after the test, and the tokens this file tests
    ("on", "off") appear inside directory names."""
    return [line for line in out.splitlines()
            if any(sev in line for sev in ("[warn]", "[error]", "[crit]",
                                           "[emerg]"))]


def _parse(tmp_path, knobs="", srv_extra="", stream_extra="", http_knobs="",
           outer=""):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit16eparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT,
                     HTTP_PORT=PARSE_PLACEHOLDER_PORT,
                     LOG_DIR=str(tmp_path), DATA=str(data), KNOBS=knobs,
                     SRV_EXTRA=srv_extra, STREAM_EXTRA=stream_extra,
                     HTTP_KNOBS=http_knobs, OUTER=outer)
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


class TestTheParseTier:
    """What the flag accepts and refuses.  Nothing here starts a server, needs
    a realm, or touches anything outside its own tmp_path copy of the
    scaffold."""

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
        two spellings.  Refusing loudly is the whole protection: a silently
        ignored `brix_krb5_ip_check 1` would leave the check off on a server
        whose operator believes they turned it on."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} {value};"))
        assert rc != 0 and f'invalid value "{value}"' in out, out

    def test_an_empty_value_is_refused(self, tmp_path):
        """security-negative: an unset shell variable expanding to "" must not
        quietly become the default — and the default here is the permissive
        arm."""
        rc, out = _parse(tmp_path, _knobs(f'{DIRECTIVE} "";'))
        assert rc != 0 and 'invalid value ""' in out, out

    @pytest.mark.parametrize("line", [f"{DIRECTIVE};",
                                      f"{DIRECTIVE} on off;",
                                      f"{DIRECTIVE} off on;"])
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, line):
        """error: NGX_CONF_FLAG is TAKE1."""
        rc, out = _parse(tmp_path, _knobs(line))
        assert rc != 0, f"{line!r} parsed\n{out}"
        assert "invalid number of arguments" in out, out

    def test_a_duplicate_directive_is_refused(self, tmp_path):
        """security-negative: two values in ONE server would leave which one
        wins to the parser's ordering, on a directive whose whole subject is
        whether a credential is checked."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} on;",
                                          f"{DIRECTIVE} off;"))
        assert rc != 0 and f'"{DIRECTIVE}" directive is duplicate' in out, out

    def test_the_directive_is_refused_at_stream_level(self, tmp_path):
        """security-negative: NGX_STREAM_SRV_CONF alone.  Written once at the
        top of the stream block it reads like a site-wide default, and adopting
        it silently for every server — or ignoring it silently — would both be
        worse than refusing."""
        rc, out = _parse(tmp_path, stream_extra=f"    {DIRECTIVE} on;\n")
        assert rc != 0, f"a stream-level {DIRECTIVE} parsed\n{out}"
        assert f'"{DIRECTIVE}" directive is not allowed here' in out, out

    def test_the_directive_is_refused_in_an_http_server(self, tmp_path):
        """security-negative: the WebDAV face has its own auth directives, and
        this one has no meaning there.  An operator who writes it into http
        must be told, not quietly left with an unauthenticated face."""
        rc, out = _parse(tmp_path, http_knobs=f"        {DIRECTIVE} on;\n")
        assert rc != 0, f"an http-level {DIRECTIVE} parsed\n{out}"
        assert f'"{DIRECTIVE}" directive is not allowed here' in out, out

    def test_the_directive_is_refused_at_main_context(self, tmp_path):
        """security-negative: outside stream {} entirely."""
        rc, out = _parse(tmp_path, outer=f"{DIRECTIVE} on;\n")
        assert rc != 0, f"a main-context {DIRECTIVE} parsed\n{out}"
        assert f'"{DIRECTIVE}" directive is not allowed here' in out, out

    def test_it_parses_on_a_server_that_has_no_krb5_auth(self, tmp_path):
        """The scaffold configures no `brix_auth krb5` at all, so the flag lands
        on a server that can never read it — and nothing says so.  That is not
        a defect (a flag slot has no way to know), but it is why §A's NOTICE is
        the only feedback that exists: it is printed by the krb5 config stage,
        which a non-krb5 server never runs."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} on;"))
        assert rc == 0, out
        assert _diagnostics(out) == [], (
            f"the parse now diagnoses an unreadable {DIRECTIVE}\n{out}")

    def test_two_servers_may_disagree(self, tmp_path):
        """success, and the contrast with DEFECT #69 two files ago: this value
        is per-server, so two servers holding two values is a legitimate
        configuration rather than a silent clobber — §B measures both at once
        in one worker."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} on;"),
                         srv_extra=_second_server(f"{DIRECTIVE} off;"))
        assert rc == 0, f"two servers disagreeing stopped parsing\n{out}"
        assert _diagnostics(out) == [], out


# --------------------------------------------------------------------------- #
# F. Source pins for the mechanism                                             #
# --------------------------------------------------------------------------- #

def _source(path):
    return path.read_text()


def _code_lines(path, token):
    """Lines naming ``token`` that are code rather than prose.

    auth.c documents the flag three times in WHAT/WHY blocks before reading it
    once, and a pin that counted those would be a pin on the comments."""
    return [line for line in _source(path).splitlines()
            if token in line and not line.lstrip().startswith(("*", "/*", "//"))]


class TestTheMechanismIsWhereTheFileSaysItIs:
    """Everything above reads the flag through a socket.  These read it in the
    C, so that a refactor which moves the mechanism fails here — where the
    message names the new shape — instead of failing as an unexplained login."""

    def test_the_flag_has_exactly_one_reader(self):
        """One early return is the whole of the `off` arm.  A second reader
        would mean the value decides something else as well, and every claim in
        this file about "the only thing that changes" would need re-deriving."""
        readers = _code_lines(AUTH_C, "conf->krb5.ip_check")
        assert len(readers) == 1, (
            f"krb5.ip_check is read in more than one place: {readers}")
        assert "    if (!conf->krb5.ip_check) {\n        return NGX_OK;\n" in \
            _source(AUTH_C), "the off arm is no longer a plain early return"

    def test_the_merge_default_is_off(self):
        """§B measured it; this names the line, so a change to the default fails
        with the reason rather than as a login that stopped being refused."""
        lines = _code_lines(MERGE_C, "conf->krb5.ip_check")
        assert len(lines) == 1, f"expected one merge line, got {lines}"
        merge = " ".join(lines[0].split())          # the column alignment varies
        assert merge == ("ngx_conf_merge_value(conf->krb5.ip_check, "
                         "prev->krb5.ip_check, 0);"), (
            f"the merge default is no longer 0: {merge}")

    def test_the_notice_prints_the_value(self):
        """§A reads this line out of a log; this pins the line that writes it,
        because it is the only operator-visible statement of the value that
        exists anywhere."""
        text = _source(CONFIG_C)
        assert 'keytab=%s ip_check=%s' in text, (
            "the config NOTICE no longer states ip_check")
        assert 'xcf->krb5.ip_check ? "on" : "off"' in text, (
            "the NOTICE no longer renders the flag as on/off")

    def test_only_ipv4_and_ipv6_peers_can_be_bound(self):
        """The README calls the check best-effort because of exactly this:
        brix_krb5_peer_addr handles AF_INET and AF_INET6 and declines anything
        else, and an enabled check turns a decline into a denial (auth.c:228-
        239).  A unix-socket peer on an enabled server is therefore refused —
        which is a real consequence of the `on` arm and is pinned here rather
        than measured, since this listener has no AF_UNIX face."""
        text = _source(AUTH_C)
        for token in ("ADDRTYPE_INET;", "ADDRTYPE_INET6;"):
            assert token in text, f"{token} is gone from brix_krb5_peer_addr"
        assert "cannot bind krb5 peer address" in text, (
            "the unbindable-peer denial is gone — an enabled check now falls "
            "through to krb5_rd_req with no address bound")
