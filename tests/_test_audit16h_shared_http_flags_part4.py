# --------------------------------------------------------------------------- #
# §G — the parse matrix                                                        #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheParseMatrix:
    """Where each of the six may be written, and what it may be written as."""

    @pytest.mark.parametrize("name", FLAG_NAMES)
    @pytest.mark.parametrize("where", ["knobs", "srv", "http"])
    @pytest.mark.parametrize("value", ["on", "off"])
    def test_both_arms_parse_in_all_three_http_scopes(self, tmp_path, name,
                                                      where, value):
        """BRIX_HTTP_ALL_CONF spelled out on the wire of the parser: three
        scopes, both values, six directives."""
        result = _parse(tmp_path, **{where: f"{name} {value};"})
        assert result.returncode == 0, \
            f"{name} {value} was refused in {where}:\n{result.stderr}"

    @pytest.mark.parametrize("name", FLAG_NAMES)
    def test_none_is_accepted_in_the_main_context(self, tmp_path, name):
        result = _parse(tmp_path, outer=f"{name} on;")
        assert result.returncode != 0, f"{name} was accepted outside http{{}}"
        assert f'"{name}" directive is not allowed here' in result.stderr, \
            result.stderr

    @pytest.mark.parametrize("name", STREAM_FLAGS)
    def test_the_four_shared_names_are_accepted_in_a_stream_server(
            self, tmp_path, name):
        """The stream plane declares its own entries for these four
        (root/stream/directives_tpc.h:228,249 and root/stream/module.c:366,429),
        so the same word is legal in two grammars with two backing structs."""
        result = _parse(tmp_path, stream=f"{name} on;")
        assert result.returncode == 0, result.stderr

    @pytest.mark.parametrize("name", HTTP_ONLY_FLAGS)
    def test_the_two_http_only_names_are_refused_in_a_stream_server(
            self, tmp_path, name):
        result = _parse(tmp_path, stream=f"{name} on;")
        assert result.returncode != 0, f"{name} was accepted in stream{{}}"
        assert f'"{name}" directive is not allowed here' in result.stderr, \
            result.stderr

    @pytest.mark.parametrize("name", FLAG_NAMES)
    def test_none_is_accepted_at_stream_level(self, tmp_path, name):
        """Even the four are server-scoped there — NGX_STREAM_SRV_CONF only."""
        result = _parse(tmp_path, stream_main=f"{name} on;")
        assert result.returncode != 0, f"{name} was accepted at stream level"
        assert f'"{name}" directive is not allowed here' in result.stderr, \
            result.stderr

    @pytest.mark.parametrize("name", FLAG_NAMES)
    def test_a_misplaced_name_is_never_reported_as_unknown(self, tmp_path, name):
        """The diagnostic an operator actually reads.  nginx searches every
        module's command table before it checks the context, so a stream-only
        placement of an http-only flag is a scope error, not a typo — and a
        future move between planes must not silently turn one into the other."""
        result = _parse(tmp_path, outer=f"{name} off;")
        assert "unknown directive" not in result.stderr, result.stderr

    @pytest.mark.parametrize("name", FLAG_NAMES)
    @pytest.mark.parametrize("value", ["ON", "OFF", "On", "oFf"])
    def test_the_value_is_case_insensitive(self, tmp_path, name, value):
        result = _parse(tmp_path, knobs=f"{name} {value};")
        assert result.returncode == 0, \
            f"{name} refused {value}:\n{result.stderr}"

    @pytest.mark.parametrize("name", FLAG_NAMES)
    @pytest.mark.parametrize("value", ["maybe", "1", "0", "yes", "true", '""'],
                             ids=["word", "one", "zero", "yes", "true", "empty"])
    def test_a_non_boolean_value_is_refused(self, tmp_path, name, value):
        """``1`` and ``0`` included: the flag setter takes the two words and
        nothing else, and an operator who writes the C value is told."""
        result = _parse(tmp_path, knobs=f"{name} {value};")
        assert result.returncode != 0, f"{name} accepted {value}"
        assert "invalid value" in result.stderr and 'it must be "on" or "off"' \
            in result.stderr, result.stderr

    @pytest.mark.parametrize("name", FLAG_NAMES)
    @pytest.mark.parametrize("line", ["{name};", "{name} on off;"],
                             ids=["no-argument", "two-arguments"])
    def test_the_arity_is_exactly_one(self, tmp_path, name, line):
        result = _parse(tmp_path, knobs=line.format(name=name))
        assert result.returncode != 0, f"{name} accepted the wrong arity"
        assert "invalid number of arguments" in result.stderr, result.stderr

    @pytest.mark.parametrize("name", FLAG_NAMES)
    def test_a_second_occurrence_is_a_duplicate(self, tmp_path, name):
        """The two arms in one scope are refused rather than last-one-wins, so
        an operator who writes both is told instead of silently resolved."""
        result = _parse(tmp_path, knobs=f"{name} on;\n{name} off;")
        assert result.returncode != 0 and "is duplicate" in result.stderr, \
            result.stderr

    @pytest.mark.parametrize("where", ["knobs", "srv", "http"])
    def test_the_access_log_slot_takes_a_path_or_the_off_sentinel(
            self, tmp_path, where):
        """The str-slot the session log depends on, in the same three scopes.
        ``off`` is a VALUE of the path, not a flag — which is why it is the one
        extra row this file carries."""
        for text in (f"brix_access_log {tmp_path}/audit.log;",
                     "brix_access_log off;"):
            result = _parse(tmp_path, **{where: text})
            assert result.returncode == 0, result.stderr

    @pytest.mark.parametrize("line", ["brix_access_log;", "brix_access_log a b;"],
                             ids=["no-argument", "two-arguments"])
    def test_the_access_log_arity_is_exactly_one(self, tmp_path, line):
        result = _parse(tmp_path, knobs=line)
        assert result.returncode != 0, "brix_access_log accepted a bad arity"
        assert "invalid number of arguments" in result.stderr, result.stderr


# --------------------------------------------------------------------------- #
# §H — the C the tables above are a reading of                                 #
# --------------------------------------------------------------------------- #

def _command_entry(text, name):
    """The one command-table entry for `name`, from its ngx_string to the
    NULL that closes it."""
    start = text.index(f'{{ ngx_string("{name}")')
    return text[start:text.index("},", start)]


def _squashed(text):
    return " ".join(text.split())


class TestTheDeclarationsAndTheMerge:
    """Source pins for the claims the wire cannot make: what the six share,
    what they merge to, and in which order the two layers run."""

    @pytest.mark.parametrize("name,field", FLAGS,
                             ids=[name for name, _ in FLAGS])
    def test_the_six_share_one_declaration_shape(self, name, field):
        entry = _command_entry(_http_common_commands_text(), name)
        assert "BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG" in entry, entry
        assert "ngx_conf_set_flag_slot" in entry, entry
        assert "NGX_HTTP_LOC_CONF_OFFSET" in entry, entry
        assert f"common.{field})" in entry, entry

    def test_the_scope_macro_is_the_three_http_contexts(self):
        """The parse matrix in §G is a reading of this one line."""
        assert _squashed("#define BRIX_HTTP_ALL_CONF \\\n"
                         "    (NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|"
                         "NGX_HTTP_LOC_CONF)") \
            in _squashed(HTTP_COMMON_C.read_text())

    @pytest.mark.parametrize("field,default", [
        ("verify_write", 0), ("read_only", 0), ("compress", 0),
        ("strict_security", 0), ("session_log", 1),
        ("backend_krb5_forwardable", 0)])
    def test_the_merge_defaults_are_what_the_absent_arm_measures(
            self, field, default):
        """``session_log`` is the one that defaults ON, which is why its absent
        arm logs and every other absent arm is inert."""
        assert (f"ngx_conf_merge_value(conf->{field}, prev->{field}, "
                f"{default});") in _squashed(_shared_text())

    def test_the_access_log_path_is_compared_against_the_word_off(self):
        """Not a flag: the sentinel is a path value that is never opened, which
        is why §E can silence a location without turning the session log off."""
        squashed = _squashed(_shared_text())
        assert 'ngx_conf_merge_str_value(conf->access_log, prev->access_log, "");' \
            in squashed
        assert 'ngx_strcmp(conf->access_log.data, (u_char *) "off") != 0' \
            in squashed
        assert "conf->access_log_file = NULL;" in squashed

    def test_the_common_module_adopts_and_leaves_enforcement_to_the_protocols(self):
        """The ordering behind §A's opt-out: the common module's merge does
        nothing but fill unset fields from the parent, and
        ``brix_shared_apply_read_only`` runs later, per location, inside each
        protocol's own shared merge — by which time an inherited
        ``allow_write`` is already the child's own."""
        merge = HTTP_COMMON_C.read_text()
        # The definition, not the forward declaration: the return type sits on
        # its own line only where the function is defined.
        body_start = merge.index(
            "static char *\nbrix_http_common_merge_loc_conf(")
        body = merge[body_start:merge.index("\n}", body_start)]
        assert "brix_shared_adopt_unified(&conf->common, &prev->common);" in body
        assert "apply_read_only" not in body
        assert "brix_shared_apply_read_only(conf, cf->log);" \
            in _squashed(_shared_text())

    def test_apply_read_only_is_silent_unless_it_takes_a_grant_away(self):
        """Which is why §A's log assertions count exactly one sentence: the
        NOTICE is emitted where a write grant is being overridden — and, since
        phase-104, where ``read_only_public`` implies ``read_only`` — and
        nowhere else.  §A's live count stays at one because its configs set
        ``read_only`` directly, never via the public posture."""
        text = SHARED_H.read_text()
        body = text[text.index("brix_shared_apply_read_only(ngx_http_brix"):]
        body = body[:body.index("\n}")]
        assert "if (common->read_only != 1) {" in body
        assert "common->allow_write = 0;" in body
        # The sentences §A reads off the log, reassembled from the C literals
        # they are split across — so a reword in either place is caught in
        # both.
        implies_notice = ("brix: read_only_public on - implies read_only; the "
                          "export is read-only and server-introspection "
                          "queries are refused")
        assert "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', body)) \
            == implies_notice + READ_ONLY_NOTICE, body

    def test_the_security_gate_has_exactly_three_callers(self):
        """§B's three subjects are not a sample — they are the whole set of
        configurations ``brix_strict_security`` can refuse."""
        callers = []
        for path in sorted(SRC_DIR.rglob("*.c")):
            text = path.read_text(errors="replace")
            if "brix_shared_security_gate(" in text:
                callers.append(str(path.relative_to(ROOT)))
        assert callers == ["src/observability/dashboard/module.c",
                           "src/protocols/s3/module.c",
                           "src/protocols/webdav/config_merge.c"], callers
        assert 'strict ? " (refused: brix_strict_security on)" : ""' \
            in SHARED_H.read_text()

    def test_the_compress_flag_gates_the_negotiator(self):
        assert "if (!opts->compress) {" in FILE_SERVE_C.read_text()
        assert ("if (is_range || r->header_only || "
                "file_size < BRIX_COMPRESS_MIN_SIZE) {") \
            in COMPRESS_C.read_text()
        assert "#define BRIX_COMPRESS_MIN_SIZE  256" in COMPRESS_H.read_text()

    def test_the_session_record_is_cached_per_connection(self):
        """DEFECT #79 in the C: the lookup and its early return come BEFORE the
        conf is read for an access-log fd, so a second location on the same
        connection never gets its own decision."""
        text = SESSLOG_CONN_C.read_text()
        body = text[text.index("brix_http_sess(ngx_http_request_t *r,"):]
        body = body[:body.index("\n}")]
        lookup = body.index("record = brix_http_sess_lookup(c);")
        early = body.index("return record->sess;")
        reads_conf = body.index("brix_http_shared_access_log_fd(conf)")
        begins = body.index("brix_sess_begin(conf->session_log")
        assert lookup < early < reads_conf < begins, body
        assert "if (!enabled || log_fd == NGX_INVALID_FILE) {" \
            in SESSLOG_NGX_C.read_text()

    def test_the_put_path_hands_verify_write_to_the_writer(self):
        """The one http reader the flag has — which is exactly why §C's three
        arms being identical is a finding and not a tautology."""
        assert _squashed("brix_vfs_writer_open(vctx, BRIX_VFS_O_ATOMIC,\n"
                         "                                    "
                         "conf->common.verify_write, &staged_err);") \
            in _squashed(PUT_SETUP_C.read_text())

    def test_exactly_four_of_the_six_are_declared_on_the_stream_plane(self):
        """The asymmetry §G's stream rows are a reading of.  The stream
        plane's registrations live in the root stream module AND the stream
        common module (core/config/stream_common.c — where the W3 unification
        moved brix_verify_write and its bare-storage siblings)."""
        stream_sources = (sorted(STREAM_DIR.rglob("*.c"))
                          + sorted(STREAM_DIR.rglob("*.h"))
                          + [ROOT / "src/core/config/stream_common.c"])
        declared = set()
        for path in stream_sources:
            text = path.read_text(errors="replace")
            for name in FLAG_NAMES:
                if f'ngx_string("{name}")' in text:
                    declared.add(name)
        assert declared == set(STREAM_FLAGS), sorted(declared)
        assert not declared & set(HTTP_ONLY_FLAGS)
