"""Test cases for audit16ai_gridftp_write_gate — preamble (fixtures/helpers/mocks) lives in
_test_audit16ai_gridftp_write_gate_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16ai_gridftp_write_gate_helpers")


class TestThePermissionVerdictPrecedesTheDataChannelCheck:
    """ev_xfer_guards tests `allow_write` first and `fc->active || pasv_fd` second,
    so a STOR with no data channel is answered 550 on a read-only export and 425
    on a writable one.

    Worth pinning: the order is what stops a probe from distinguishing "no data
    channel" from "no permission", and reversing it would leak the export's
    writability to a client that never opened a data connection.
    """

    def test_a_storless_data_channel_is_refused_on_permission(self, gw, request):
        ftp = _connect(G_OFF)
        try:
            reply = _cmd(ftp, "STOR /" + _uid(request) + ".bin")
        finally:
            ftp.close()
        assert reply.startswith("550 Permission denied (read-only export)"), reply

    def test_the_armed_face_answers_425_to_the_same_command(self, gw, request):
        """The control, and the reason the cell above is about ordering rather
        than about STOR: with the gate open the SECOND check is what fires."""
        ftp = _connect(G_ON)
        try:
            reply = _cmd(ftp, "STOR /" + _uid(request) + ".bin")
        finally:
            ftp.close()
        assert reply.startswith("425 Use PASV or PORT first"), reply

    @pytest.mark.parametrize("verb", ("PASV", "EPSV"))
    def test_a_read_only_export_still_opens_a_data_listener(self, gw, verb):
        """PASV is not gated — a read-only export binds a listener for a client
        that has no verb to use it for.  Not a defect (RETR needs it), but it is
        the reason the ordering above is load-bearing: the listener's existence
        says nothing about writability, and the 550 must not either."""
        ftp = _connect(G_OFF)
        try:
            reply = _cmd(ftp, verb)
        finally:
            ftp.close()
        assert reply[:3] in ("227", "229"), reply


# --------------------------------------------------------------------------- #
# H. What the gate does not cover                                              #
# --------------------------------------------------------------------------- #

class TestTheUngatedVerbsAnswerTheSameOnBothFaces:
    """The read side and the transfer-parameter verbs are outside the gate, and
    must be: a read-only export that could not be read would be useless.

    Stated explicitly so that a future change which put one of them behind the
    flag is a failure here rather than a surprise in the field.
    """

    def test_retr_serves_a_file_from_a_read_only_export(self, gw, request):
        name = _uid(request)
        payload = b"readable\n" * 16
        _seed_file(gw, "off", name, payload)
        code, body = _retr(G_OFF, "/" + name)
        assert code == 226, code
        assert body == payload

    def test_size_and_mdtm_answer(self, gw, request):
        name = _uid(request)
        _seed_file(gw, "off", name, b"1234567890")
        replies = _sequence(G_OFF, [f"SIZE /{name}", f"MDTM /{name}"])
        assert replies[0] == "213 10", replies
        assert replies[1].startswith("213 "), replies

    @pytest.mark.parametrize("command,prefix", (("ALLO 1048576", "200"),
                                                ("REST 5", "350"),
                                                ("MODE E", "200"),
                                                ("TYPE I", "200"),
                                                ("SYST", "215"),
                                                ("NOOP", "200"),
                                                ("PWD", "257")))
    def test_a_transfer_parameter_verb_is_ungated(self, gw, command, prefix):
        assert _one(G_OFF, command).startswith(prefix), command

    def test_cksm_is_ungated(self, gw, request):
        """A checksum is a read, and the gate does not cover it — which also
        means it is available on the face whose `verify_write` can never fire."""
        name = _uid(request)
        _seed_file(gw, "off", name, b"checksum me\n")
        reply = _one(G_OFF, f"CKSM ADLER32 0 -1 /{name}")
        assert reply.startswith("213 "), reply

    def test_feat_does_not_advertise_writability(self, gw):
        """FEAT is identical on both faces, so a client cannot learn from the
        capability list whether the export will accept a STOR — it has to try,
        and trying is what #134 says nobody records."""
        on = _one(G_ON, "FEAT")
        off = _one(G_OFF, "FEAT")
        assert on == off, (on, off)


class TestSiteAnswersOkToEverything:
    """DEFECT CANDIDATE #136 — ev_grp_session's SITE arm
    (ftp_ev_dispatch.c:259) is a bare `200 OK` with the argument never read.

    The gate is not bypassed: nothing happens.  What is wrong is the reply — a
    client that issues `SITE CHMOD 000` against a read-only export is told the
    mutation succeeded.
    """

    def test_site_chmod_is_answered_ok_on_a_read_only_export(self, gw, request):
        name = _uid(request)
        _seed_file(gw, "off", name)
        assert _one(G_OFF, f"SITE CHMOD 000 /{name}") == "200 OK"

    def test_and_the_mode_is_unchanged(self, gw, request):
        """The second half, and the one that makes it a reply bug rather than a
        gate bypass."""
        name = _uid(request)
        path = _seed_file(gw, "off", name)
        _one(G_OFF, f"SITE CHMOD 000 /{name}")
        assert (path.stat().st_mode & 0o777) == 0o644

    def test_the_armed_face_answers_ok_and_changes_nothing_either(self, gw,
                                                                  request):
        """SITE is unimplemented, not gated — so the finding is about the reply
        on every face, and an operator cannot use `allow_write on` to make
        `SITE CHMOD` work."""
        name = _uid(request)
        path = _seed_file(gw, "on", name)
        assert _one(G_ON, f"SITE CHMOD 000 /{name}") == "200 OK"
        assert (path.stat().st_mode & 0o777) == 0o644

    @pytest.mark.parametrize("argument", ("HELP", "UMASK 022", "EXEC /bin/sh",
                                          "NONSENSE", ""))
    def test_every_site_argument_gets_the_same_answer(self, gw, argument):
        """Including ones no server should accept.  `SITE EXEC` is the classic
        wu-ftpd remote-execution verb; answering it `200 OK` executes nothing
        here, but it tells a scanner the verb is supported."""
        assert _one(G_OFF, ("SITE " + argument).strip()) == "200 OK", argument


# --------------------------------------------------------------------------- #
# I. Security-negative                                                         #
# --------------------------------------------------------------------------- #

class TestAReadOnlyExportIsNotEscapable:
    """Invariant 4's resolve_path runs before every open, and the gate runs
    before resolve_path — so a traversal aimed at a mutation is refused by the
    gate and one aimed at a read is refused by the resolver.

    Both need saying: a reader who knows only §A might conclude that a
    read-only face is safe because nothing can be written, which says nothing
    about what can be read.
    """

    @pytest.mark.parametrize("escape", ("../../../../etc/passwd",
                                        "/etc/passwd",
                                        "..%2f..%2f..%2fetc%2fpasswd",
                                        "....//etc/passwd"))
    def test_a_traversal_read_is_refused(self, gw, escape):
        code, body = _retr(G_OFF, escape)
        assert code in (550, 553), (escape, code)
        assert b"root:x:" not in body, escape

    @pytest.mark.parametrize("escape", ("../../../../tmp",
                                        "/tmp",
                                        "..%2f..%2f..%2ftmp"))
    def test_a_traversal_mutation_is_refused_by_the_gate_first(self, gw, escape):
        """The gate is upstream of the resolver, so the refusal an escape gets
        is the PERMISSION one — the path is never resolved and the attempt is
        indistinguishable, on the wire, from a well-formed one."""
        reply = _one(G_OFF, f"MKD {escape}")
        assert reply.startswith("550 Permission denied (read-only)"), reply

    def test_a_traversal_mutation_on_the_armed_face_is_refused_by_the_resolver(
            self, gw, request):
        """The control: with the gate open the resolver is what refuses, and it
        does.  Without this cell §A could be satisfied by a build whose resolver
        had stopped working, since the gate would hide it."""
        reply = _one(G_ON, "MKD ../../../../tmp/" + _uid(request))
        assert reply[:3] in ("550", "553"), reply
        assert not Path("/tmp", _uid(request)).exists()

    def test_a_disarmed_export_cannot_be_written_through_a_symlink(self, gw,
                                                                   request):
        """A symlink inside the export pointing out of it — the shape that
        defeats a purely lexical path check.  The gate refuses before the link
        is ever followed, which is the right order."""
        name = _uid(request)
        target = gw.export("off") / (name + "-link")
        target.symlink_to("/tmp")
        reply = _one(G_OFF, f"MKD /{name}-link/{name}")
        assert reply.startswith("550 Permission denied (read-only)"), reply
        assert not Path("/tmp", name).exists()


# --------------------------------------------------------------------------- #
# J. Parse tier                                                                #
# --------------------------------------------------------------------------- #

FLAG = "brix_gridftp_allow_write"


def _parse(tmp_path, **slots):
    """`nginx -t` on the shared parse scaffold.

    configs/nginx_audit16jparse.conf is reused rather than copied, for the reason
    files 29-34 give: it writes the flag nowhere itself, so a duplicate negative
    can be sure the duplicate it is shown is the one it wrote.
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
    """Only the lines nginx itself flagged: a tmp_path name can contain the token
    under test, so a substring search over the whole output would match the
    temp directory rather than a diagnostic."""
    return [ln for ln in out.splitlines()
            if any(tag in ln for tag in ("[warn]", "[error]", "[crit]",
                                         "[emerg]"))]


class TestBothArmsParse:
    """The parse half of §A's claim, in the scope the directive declares."""

    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_an_arm_is_accepted_in_a_stream_server(self, tmp_path, arm):
        rc, out = _parse(tmp_path, KNOBS=f"        {FLAG} {arm};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_an_arm_draws_no_diagnostic(self, tmp_path, arm):
        """Accepted is not enough — §A's premise is that a written `off` is a
        normal thing to write, and a notice saying the line is redundant would
        be a different (and better) world."""
        rc, out = _parse(tmp_path, KNOBS=f"        {FLAG} {arm};\n")
        assert rc == 0 and _diagnostics(out) == [], _diagnostics(out)

    @pytest.mark.parametrize("arm", ("ON", "Off", '"on"'))
    def test_the_setter_is_case_insensitive_and_unquotes(self, tmp_path, arm):
        """ngx_conf_set_flag_slot compares case-insensitively and the tokenizer
        strips quotes, so all three are the same line.  Pinned because a config
        in the wild will eventually be written one of these ways."""
        rc, out = _parse(tmp_path, KNOBS=f"        {FLAG} {arm};\n")
        assert rc == 0, out

    def test_a_sibling_server_may_write_the_other_arm(self, tmp_path):
        """The whole config's shape: four gateways in one process, each with its
        own arm.  The scaffold's EXTRA slot is a whole second stream server, so
        this is the sibling question and not the scope one — nothing at parse
        time cross-validates two servers' arms against each other."""
        extra = ("    server {\n"
                 f"        listen {PARSE_PLACEHOLDER_PORT + 2};\n"
                 "        brix_root on;\n"
                 "        brix_auth none;\n"
                 f"        {FLAG} off;\n"
                 "    }\n")
        rc, out = _parse(tmp_path, KNOBS=f"        {FLAG} on;\n", EXTRA=extra)
        assert rc == 0, out
        assert _diagnostics(out) == [], _diagnostics(out)


class TestTheFlagRefusesWhatIsNotAFlag:
    """Arity and value.  `ngx_conf_set_flag_slot` produces both messages, and it
    names the DIRECTIVE as well as the value — unlike the enum setter, which
    names only the value.  Both halves are asserted, because the directive name
    is the whole of what makes the diagnostic actionable on a server carrying a
    dozen gridftp lines.
    """

    @pytest.mark.parametrize("value", ("1", "0", "yes", "no", "true", "false",
                                       "enable", '""'))
    def test_a_non_flag_value_is_refused_by_name(self, tmp_path, value):
        rc, out = _parse(tmp_path, KNOBS=f"        {FLAG} {value};\n")
        assert rc != 0, out
        assert f'in "{FLAG}" directive' in out, out
        assert 'it must be "on" or "off"' in out, out

    @pytest.mark.parametrize("line", (f"{FLAG};", f"{FLAG} on off;",
                                      f"{FLAG} on on;"))
    def test_a_wrong_arity_is_refused(self, tmp_path, line):
        rc, out = _parse(tmp_path, KNOBS=f"        {line}\n")
        assert rc != 0, out
        assert "invalid number of arguments" in out, out
        assert FLAG in out, out

    @pytest.mark.parametrize("pair", (("on", "on"), ("off", "off"),
                                      ("on", "off")))
    def test_a_duplicate_is_refused_even_when_the_arms_agree(self, tmp_path,
                                                             pair):
        """Including the opposed pair, which is the one an operator would most
        want a diagnostic for — and gets the same generic one."""
        rc, out = _parse(tmp_path, KNOBS="".join(
            f"        {FLAG} {arm};\n" for arm in pair))
        assert rc != 0, out
        assert "is duplicate" in out, out


class TestTheFlagIsRefusedOutsideItsScope:
    """NGX_STREAM_SRV_CONF only: not `main`, not `events`, not the stream block
    itself, not an http location.

    A flag accepted in a scope that never reads it is the silently-ignored shape
    this tranche has found repeatedly; here the parser refuses all four.
    """

    @pytest.mark.parametrize("slot", ("OUTER", "STREAM_KNOBS", "HTTP_KNOBS",
                                      "LOC_KNOBS"))
    def test_a_foreign_scope_is_refused(self, tmp_path, slot):
        rc, out = _parse(tmp_path, **{slot: f"    {FLAG} on;\n"})
        assert rc != 0, out
        assert f'"{FLAG}" directive is not allowed here' in out, out


class TestTheCompanionKnobsAreNotCrossValidated:
    """DEFECT CANDIDATE #137 and its neighbours: three gridftp knobs that only
    have meaning on a writable export are accepted, without a word, beside
    `allow_write off`.

    The merge has every fact it needs to say so — all four flags are merged in
    the same function, ftp_module_merge.c:159-164 — and says nothing.
    """

    @pytest.mark.parametrize("companion", ("brix_gridftp_verify_write",
                                           "brix_gridftp_require_allo_size"))
    def test_a_write_only_knob_is_accepted_beside_a_closed_gate(self, tmp_path,
                                                               companion):
        rc, out = _parse(tmp_path, KNOBS=(f"        {FLAG} off;\n"
                                          f"        {companion} on;\n"))
        assert rc == 0, out
        assert _diagnostics(out) == [], _diagnostics(out)

    def test_both_companions_at_once_are_accepted_too(self, tmp_path):
        """The G_VER plane's shape, plus one — the composition is not merely
        unvalidated pairwise."""
        rc, out = _parse(tmp_path, KNOBS=(
            f"        {FLAG} off;\n"
            "        brix_gridftp_verify_write on;\n"
            "        brix_gridftp_require_allo_size on;\n"))
        assert rc == 0, out
        assert _diagnostics(out) == [], _diagnostics(out)

    def test_a_bogus_companion_value_is_still_refused_by_name(self, tmp_path):
        """The companion's own setter runs regardless, so the composition being
        unvalidated is about MEANING and not about parsing — a malformed
        companion is caught, an inert one is not."""
        rc, out = _parse(tmp_path, KNOBS=(
            f"        {FLAG} off;\n"
            "        brix_gridftp_verify_write bogus;\n"))
        assert rc != 0, out
        assert 'in "brix_gridftp_verify_write" directive' in out, out


# --------------------------------------------------------------------------- #
# K. DEFECT CANDIDATE #133 — the corpus's own claim about itself               #
# --------------------------------------------------------------------------- #

CONFIGS = Path(__file__).resolve().parent / "configs"


def _balanced_server_block(body, match):
    depth, index = 0, match.end() - 1
    while index < len(body):
        if body[index] == "{":
            depth += 1
        elif body[index] == "}":
            depth -= 1
            if depth == 0:
                break
        index += 1
    return body[match.start():index + 1]


def _server_block(body, needle):
    """The `server { ... }` whose text contains `needle`, brace-counted.

    A regex cannot do it: the template's own placeholders are braced, so
    `[^}]*` stops at `{RO_PORT}` rather than at the block's end.
    """
    for match in re.finditer(r"\bserver\s*\{", body):
        block = _balanced_server_block(body, match)
        if needle in block:
            return block
    return None


class TestTheCorpusDoesNotWriteTheTokenItDocuments:
    """Read off the tree rather than argued: which configs write the flag, and
    what the two read-only ones actually contain.

    A guard rather than a finding once it is fixed — the cells state the current
    truth and will fail the moment someone writes the token, which is the point.
    """

    def _bodies(self):
        return {p.name: p.read_text(errors="replace")
                for p in CONFIGS.glob("*.conf")}

    def test_no_config_but_this_file_s_own_writes_the_disarming_token(self):
        """The census that opened the file.  The template this suite renders is
        the exception, and is excluded by name so the cell keeps measuring the
        rest of the corpus."""
        mine = "nginx_audit16ai_gridftp_write_gate.conf"
        writers = sorted(
            name for name, body in self._bodies().items()
            if name != mine
            and re.search(rf"^\s*{FLAG}\s+off\s*;", body, re.MULTILINE))
        assert writers == [], writers

    def test_the_arming_token_is_written_widely(self):
        """The other half, so the cell above is a statement about the DISARMING
        arm and not about the directive being unused."""
        writers = [name for name, body in self._bodies().items()
                   if re.search(rf"^\s*{FLAG}\s+on\s*;", body, re.MULTILINE)]
        assert len(writers) >= 20, writers

    def test_the_metrics_config_documents_a_line_its_server_does_not_carry(self):
        """#133.  The header names the directive; the RO_PORT server block does
        not contain it.  The gateway is read-only by merge, so the suite that
        rests on it passes — which is how the mismatch survived."""
        body = (CONFIGS / "nginx_gridftp_metrics.conf").read_text()
        assert f"{FLAG} off" in body, "header no longer claims it"

        block = _server_block(body, "{RO_PORT}")
        assert block, body
        assert FLAG not in block, block

    def test_the_other_read_only_config_says_what_it_does(self):
        """The control: nginx_gridftp_plain_ev_ro.conf is read-only by omission
        too, and its header says so rather than claiming a line.  The two
        together are why #133 is about the comment and not about the
        omission."""
        body = (CONFIGS / "nginx_gridftp_plain_ev_ro.conf").read_text()
        assert not re.search(rf"^\s*{FLAG}", body, re.MULTILINE), body
        assert "allow_write" in body, "the header no longer explains itself"
