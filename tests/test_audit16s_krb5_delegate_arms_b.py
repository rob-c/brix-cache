"""Test cases for audit16s_krb5_delegate_arms — preamble (fixtures/helpers/mocks) lives in
_test_audit16s_krb5_delegate_arms_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16s_krb5_delegate_arms_helpers")


class _Session:
    """A logged-in xrdfs held open, so the per-connection ccache can be looked
    at while it exists."""

    def __init__(self, port, ccache):
        self.proc = subprocess.Popen(
            [SYS_XRDFS, f"root://{url_host(HOST)}:{port}"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=_env(ccache))

    def stat(self):
        self.proc.stdin.write(f"stat {READ_FILE}\n")
        self.proc.stdin.flush()

    def close(self):
        try:
            self.proc.stdin.write("exit\n")
            self.proc.stdin.flush()
            self.proc.wait(timeout=30)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            self.proc.kill()


# How long to wait for a capture to appear.  `_Session.stat()` only WRITES a
# command to an interactive xrdfs — it does not read the reply — so the
# subprocess spawn, the TCP connect and the whole Kerberos handshake all still
# lie ahead of the first poll, against a server that itself started moments
# ago.  The original 4s (80 x 0.05) budget covered that on an idle box and
# nothing else: under load the capture lands after the poll has given up, and
# the file the server did write is never seen.  Measured against the server's
# own log, the handshake completed ~10s after the instance came up, so the
# budget is now 30s — this bounds a WAIT, and a healthy run still returns on
# the first tick after the capture.
_CAPTURE_TIMEOUT = 30.0
_CAPTURE_TICK = 0.05


def _wait_for_auth(planes, port, timeout=_CAPTURE_TIMEOUT):
    """Block until the server logs a completed krb5 auth on `port`.

    An absence assertion needs the same evidence a presence one does: that the
    session actually got as far as authenticating.  Without it a security-neg
    case is answered before the handshake it is judging has even happened.
    """
    needle = f"server: 0.0.0.0:{port}"  # net-literal-allow: matches the server-logged bind address in error.log, not a dial target
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for line in planes.errlog().splitlines():
            if "krb5 auth OK" in line and needle in line:
                return True
        time.sleep(_CAPTURE_TICK)
    return False


def _capture_while_open(port, ccache, directory=DEFAULT_CAPTURE_DIR):
    """Open a session, wait for its capture file, return (path, session)."""
    before = set(_captures(directory))
    session = _Session(port, ccache)
    session.stat()
    deadline = time.monotonic() + _CAPTURE_TIMEOUT
    while time.monotonic() < deadline:
        time.sleep(_CAPTURE_TICK)
        new = set(_captures(directory)) - before
        if new:
            return new.pop(), session
    return None, session


class TestWhereTheCapturedTicketLands:
    """FINDING #96, resolved by phase-108 C11 — the private staging dir, and
    no knob at all."""

    def test_the_capture_lands_in_the_private_staging_dir(self, planes):
        """The only rendering there is now: every capture is staged under the
        per-uid tmpfs dir the VOLATILE arm owns, with no environment input."""
        path, session = _capture_while_open(planes.on, planes.forwardable)
        try:
            assert path is not None, (
                f"no capture file appeared under {DEFAULT_CAPTURE_DIR}\n"
                f"{planes.errlog()}")
        finally:
            session.close()

    def test_it_is_private_to_the_worker(self, planes):
        """security-negative: the engine's O_EXCL 0600 create (plus its
        defensive fchmod) survives libkrb5 rewriting the file by name, and
        the file is owned by the worker's own uid."""
        path, session = _capture_while_open(planes.on, planes.forwardable)
        try:
            assert path is not None
            info = path.stat()
            assert oct(info.st_mode & 0o777) == "0o600", oct(info.st_mode)
            assert info.st_uid == os.getuid()
        finally:
            session.close()

    def test_what_sits_there_is_a_usable_tgt(self, planes):
        """Why the location is worth a finding at all: the file is not an
        opaque blob but a credential cache holding the user's ticket-granting
        ticket, readable as one by anything running as that uid."""
        path, session = _capture_while_open(planes.on, planes.forwardable)
        try:
            assert path is not None
            out = subprocess.run([SYS_KLIST, "-c", "FILE:" + str(path)],
                                 env={**os.environ, "KRB5_CONFIG": KRB5_CONF},
                                 capture_output=True, text=True, timeout=30)
            assert out.returncode == 0, _text(out)
            assert "alice@" in out.stdout, out.stdout
            assert "krbtgt/" in out.stdout, out.stdout
        finally:
            session.close()

    def test_it_is_unlinked_when_the_connection_closes(self, planes):
        """The pool cleanup at deleg_capture.c:163-172, measured: the ccache is
        per-connection and does not outlive it."""
        path, session = _capture_while_open(planes.on, planes.forwardable)
        assert path is not None
        session.close()
        for _ in range(40):
            time.sleep(0.05)
            if not path.exists():
                break
        assert not path.exists(), f"{path} outlived its connection"

    def test_the_off_plane_writes_nothing_anywhere(self, planes):
        """security-negative: the arm nobody wrote never puts a user's TGT on
        disk at all, which is the other half of what the pair buys."""
        before = set(_captures())
        session = _Session(planes.off, planes.forwardable)
        session.stat()
        try:
            # Wait for the handshake to COMPLETE before judging it.  A flat
            # 1s sleep answered this case long before the ~10s Kerberos
            # handshake finished, so it passed whatever the off arm did — a
            # security-negative that had stopped testing anything.
            assert _wait_for_auth(planes, planes.off), (
                "the off plane never authenticated, so this case proved "
                f"nothing:\n{planes.errlog()}")
            assert set(_captures()) - before == set(), (
                "the off arm wrote a ccache into the staging dir")
        finally:
            session.close()

    def test_krb5_deleg_ccache_not_in_world_dir(self, planes):
        """security-negative (phase-108 C11): the forwarded TGT's ccache is
        never created under a world-writable directory — the CWE-377
        regression test for brix_krb5_deleg_mkccache.  The capture's parent
        must be the per-uid staging dir, owned by this uid, 0700, and no
        capture may appear under /tmp at the same moment."""
        tmp_before = set(Path("/tmp").glob(CAPTURE_GLOB))
        path, session = _capture_while_open(planes.on, planes.forwardable)
        try:
            assert path is not None, (
                f"no capture file appeared under {DEFAULT_CAPTURE_DIR}\n"
                f"{planes.errlog()}")
            parent = path.parent
            assert parent == DEFAULT_CAPTURE_DIR
            info = parent.stat()
            assert info.st_uid == os.getuid()
            assert oct(info.st_mode & 0o777) == "0o700", oct(info.st_mode)
            assert set(Path("/tmp").glob(CAPTURE_GLOB)) - tmp_before == set(), (
                "a capture appeared under world-writable /tmp — CWE-377 is back")
        finally:
            session.close()

    def test_no_env_directive_can_move_it_anymore(self, relocated):
        """FINDING #96 inverted by phase-108 C11: the rendering that used to
        relocate the capture (`env TMPDIR;` plus a handed-in directory) now
        changes nothing — the VOLATILE arm never consults the environment, so
        the capture still lands in the staging dir and the handed-in
        directory stays empty."""
        endpoint, ticket, ccdir = relocated
        assert "env TMPDIR;" in _read(endpoint.config)
        path, session = _capture_while_open(endpoint.port, ticket)
        try:
            assert path is not None, (
                f"no capture file appeared under {DEFAULT_CAPTURE_DIR} — the "
                f"TMPDIR rendering broke the capture outright\n"
                f"{_read(os.path.join(endpoint.prefix, 'logs', 'error.log'))}")
            assert path.parent == DEFAULT_CAPTURE_DIR
            assert oct(path.stat().st_mode & 0o777) == "0o600"
            assert sorted(ccdir.glob(CAPTURE_GLOB)) == [], (
                "the capture followed $TMPDIR again — the #96 knob is back")
        finally:
            session.close()

    def test_the_verb_is_pinned_at_the_source(self):
        """Pinned at the source, so a change away from the shared credential
        verb (or a regrown $TMPDIR/mkstemp fallback) has to come past this
        file."""
        source = _read(CAPTURE_C)
        assert "brix_cred_write(&req" in source
        assert "BRIX_CRED_ARM_VOLATILE" in source
        assert "BRIX_CRED_KIND_CCACHE" in source
        assert '"brix-krb5-fwd-"' in source
        # The calls, not the words: the file's own comment records the #96
        # history and may name $TMPDIR in prose.
        assert "getenv(" not in source
        assert "mkstemp(" not in source

    def test_no_config_in_the_corpus_writes_that_env_directive(self):
        """And the census half of #96: nothing in the coverage corpus except
        this file's own §G rendering asks nginx to pass TMPDIR to a worker, so
        no deployment modelled by the suite has ever moved a capture."""
        writers = sorted(path.name for path in CONFIGS.glob("*.conf")
                         if re.search(r"^\s*env\s+TMPDIR\s*;", _read(path),
                                      re.MULTILINE))
        assert writers == [], (
            f"a config now writes `env TMPDIR;`: {writers} — fold it into #96")


# --------------------------------------------------------------------------- #
# I. The parse tier                                                            #
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


def _parse(tmp_path, knobs="", srv_extra="", stream_extra="", http_knobs="",
           outer=""):
    """`nginx -t` over file 5's scaffold, which writes no directive of its own.

    Shared rather than copied: the scaffold's shape — one stream server, a
    second one on the other placeholder, and the three placement slots — is
    exactly what a stream-srv flag needs, and a second copy of it would be a
    config whose only difference is the name in its header.
    """
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
    a realm or a KDC, or touches anything outside its own tmp_path."""

    @pytest.mark.parametrize("value", ["on", "off"])
    def test_both_values_parse(self, tmp_path, value):
        """success: the two arms at the tier that costs nothing — and the
        reason a value-granularity sweep exists, since `off` had never been
        written anywhere in the corpus in any form."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} {value};"))
        assert rc == 0, f"{DIRECTIVE} {value} was rejected\n{out}"

    @pytest.mark.parametrize("value", ["On", "OFF", "oFf"])
    def test_the_values_are_case_insensitive(self, tmp_path, value):
        """ngx_conf_set_flag_slot compares case-insensitively, which is worth a
        row because a config that spells it `Off` is the same config."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} {value};"))
        assert rc == 0, f"the flag slot rejected {value!r}\n{out}"

    @pytest.mark.parametrize("value", ["1", "0", "true", "yes", "disabled"])
    def test_a_plausible_synonym_is_refused(self, tmp_path, value):
        """security-negative: a spelling that looks like it disables delegation
        must not parse into the enabled arm.  `0` is the dangerous direction —
        it reads as off and is not."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} {value};"))
        assert rc != 0 and f'invalid value "{value}"' in out, out

    def test_an_empty_value_is_refused(self, tmp_path):
        """security-negative: an unset shell variable expanding to "" must not
        silently become an arm."""
        rc, out = _parse(tmp_path, _knobs(f'{DIRECTIVE} "";'))
        assert rc != 0 and 'invalid value ""' in out, out

    @pytest.mark.parametrize("line", [f"{DIRECTIVE};",
                                      f"{DIRECTIVE} on off;"])
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, line):
        rc, out = _parse(tmp_path, _knobs(line))
        assert rc != 0, f"{line!r} parsed\n{out}"
        assert "invalid number of arguments" in out, out

    def test_a_duplicate_directive_is_refused(self, tmp_path):
        """security-negative: two arms in one server must be an error rather
        than a last-one-wins, or a config could carry both and mean either."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} on;",
                                          f"{DIRECTIVE} off;"))
        assert rc != 0 and "is duplicate" in out, out

    def test_the_directive_is_refused_at_stream_level(self, tmp_path):
        """NGX_STREAM_SRV_CONF and nothing else: a site-wide default is exactly
        what an operator would try, and it must not parse."""
        rc, out = _parse(tmp_path, stream_extra=f"    {DIRECTIVE} on;\n")
        assert rc != 0 and "directive is not allowed here" in out, out

    def test_the_directive_is_refused_in_an_http_server(self, tmp_path):
        """The WebDAV face has its own auth and no delegation round at all."""
        rc, out = _parse(tmp_path, http_knobs=_knobs(f"{DIRECTIVE} on;"))
        assert rc != 0 and "directive is not allowed here" in out, out

    def test_the_directive_is_refused_at_main_context(self, tmp_path):
        rc, out = _parse(tmp_path, outer=f"{DIRECTIVE} on;\n")
        assert rc != 0 and "directive is not allowed here" in out, out

    def test_it_parses_on_a_server_that_has_no_krb5_auth(self, tmp_path):
        """A flag slot has no view of the auth method, so a server that can
        never reach the gate accepts the directive silently.  Recorded rather
        than filed: the same is true of every auth-specific flag in the table,
        and diagnosing it would need a merge-time check this module does not
        have for any of them."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} on;"))
        assert rc == 0, out
        assert "delegate" not in out, (
            f"the parse now says something about a delegation nobody can "
            f"reach\n{out}")

    def test_two_servers_may_disagree(self, tmp_path):
        """The parse-tier statement of §E's runtime measurement: a per-server
        flag with two values in one config is not a conflict."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} on;"),
                         srv_extra=_second_server(f"{DIRECTIVE} off;"))
        assert rc == 0, out


# --------------------------------------------------------------------------- #
# J. The mechanism is where this file says it is                               #
# --------------------------------------------------------------------------- #

class TestTheMechanismIsWhereTheFileSaysItIs:
    """Source pins for the claims above that no runtime case can make."""

    def test_the_declaration_is_a_stream_server_flag(self):
        declaration = _read(DIRECTIVES_H)
        block = declaration.split(f'ngx_string("{DIRECTIVE}")', 1)[1][:300]
        assert "NGX_STREAM_SRV_CONF | NGX_CONF_FLAG" in block, block
        assert "ngx_conf_set_flag_slot" in block, block
        assert "offsetof(ngx_stream_brix_srv_conf_t, krb5.delegate)" in block

    def test_the_flag_has_exactly_one_reader(self):
        """Everything else in the delegation path keys off ctx->krb5.round, so
        the gate is read once per connection and never again.  Two sites touch
        the field across src/: the merge that gives it its default, and the
        predicate §C-§E measure."""
        sites = {path.relative_to(ROOT).as_posix()
                 for path in (ROOT / "src").rglob("*.c")
                 if "conf->krb5.delegate" in _read(path)}
        assert sites == {"src/core/config/server_conf_merge_security.c",
                         "src/auth/krb5/deleg_capture.c"}, sites
        assert "return conf != NULL && conf->krb5.delegate == 1;" in _read(
            CAPTURE_C)

    def test_round_two_is_dispatched_on_the_parked_state(self):
        """Why the second message does not need the gate: a connection that has
        been challenged is already in round 1, and that is what routes it."""
        source = _read(AUTH_C)
        assert "if (ctx->krb5.round == 1) {" in source
        assert "return brix_krb5_finish_delegation(&rq);" in source

    def test_the_capture_lands_in_memory_before_it_reaches_a_file(self):
        """The order matters for #96: the forwarded credential is parked in a
        private MEMORY ccache (capture.c) and only then exported to the 0600
        temp file, so what lands in /tmp is a copy the acceptor makes for the
        origin leg rather than the working credential itself."""
        assert 'krb5_cc_new_unique(kctx, "MEMORY", NULL, &cc);' in _read(
            MEMORY_C)
        capture = _read(CAPTURE_C)
        assert capture.index("brix_krb5_deleg_mkccache(c, path, pathlen)") \
            < capture.index("brix_krb5_cred_to_ccache(*gss_cred, path,"), (
                "the export no longer follows the temp-file creation")

    def test_the_notice_carries_no_delegation_word(self):
        """#95's config-time half, pinned where it is emitted."""
        source = _read(CONFIG_C)
        notice = source.split(NOTICE, 1)[1][:400]
        assert "ip_check=" in notice
        assert "delegate" not in notice, notice

    def test_the_corpus_wrote_the_on_arm_twice_and_the_off_arm_here(self):
        """The census this file closes, re-measured so it cannot rot: `on` in
        the two configs the audit names, `off` only in this file's own."""
        on_writers = sorted(path.name for path in CONFIGS.glob("*.conf")
                            if _writes(_read(path), "on"))
        off_writers = sorted(path.name for path in CONFIGS.glob("*.conf")
                             if _writes(_read(path), "off"))
        def _assert_test_the_corpus_wrote_the_on_arm_twice_and_the_off_arm_here_1():
            assert on_writers == ["nginx_audit16s_krb5_delegate.conf",
                                  "nginx_lc_krb5_cache_origin.conf",
                                  "nginx_lc_native_krb5_delegate.conf"], on_writers
            assert off_writers == ["nginx_audit16s_krb5_delegate.conf"], off_writers

        _assert_test_the_corpus_wrote_the_on_arm_twice_and_the_off_arm_here_1()

    def test_the_two_existing_delegation_tests_write_only_the_on_arm(self):
        """Why this file is not a duplicate of either: neither writes `off`,
        and neither has a second plane to compare against."""
        here = Path(__file__).resolve().parent
        for name in ("test_krb5_delegation_e2e.py", "test_krb5_delegate_load.py"):
            text = _read(here / name)
            assert not _writes(text, "off"), (
                f"{name} now writes the off arm; the pair has a second closer")
