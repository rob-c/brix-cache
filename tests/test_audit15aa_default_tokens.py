"""Test cases for audit15aa_default_tokens — preamble (fixtures/helpers/mocks) lives in
_test_audit15aa_default_tokens_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit15aa_default_tokens_helpers")


class TestTheTokensParse:
    """The cheapest thing that had never been established: that writing the
    default token at all is legal.  A directive whose default spelling is
    refused would be a defect nothing in the tree could have caught, because
    nothing in the tree wrote one."""

    STREAM_ONLY = ("brix_health_check_type", "brix_ssi_cta_executor")

    @pytest.mark.parametrize("directive,token", [(t[0], t[1]) for t in TOKENS],
                             ids=TOKEN_IDS)
    def test_the_token_parses_in_its_own_context(self, tmp_path, directive,
                                                 token):
        if directive in self.STREAM_ONLY:
            result = _parse(tmp_path, stream=_line(directive, token))
        elif directive == "brix_backend_s3_sts_flavor":
            # Declared on BOTH planes; the stream one is the copy under §C.
            result = _parse(tmp_path, stream=_line(directive, token),
                            loc=_line(directive, token, indent=12))
        else:
            result = _parse(tmp_path, loc=_line(directive, token, indent=12))
        assert result.returncode == 0, _output(result)

    @pytest.mark.parametrize("directive,token", [(t[0], t[1]) for t in TOKENS],
                             ids=TOKEN_IDS)
    def test_an_unknown_token_is_refused(self, tmp_path, directive, token):
        """error: an enum directive must reject what it does not know rather
        than fall through to its default — otherwise a typo in the token silently
        selects the very behaviour this file is about."""
        where = ("stream" if directive in self.STREAM_ONLY
                 or directive == "brix_backend_s3_sts_flavor" else "loc")
        indent = 8 if where == "stream" else 12
        result = _parse(tmp_path,
                        **{where: _line(directive, "nosuchtoken", indent)})
        _check_test_an_unknown_token_is_refused_1(result, directive)
        out = _output(result).lower()
        _check_test_an_unknown_token_is_refused_2(result, out, directive)

    @pytest.mark.parametrize("directive,token", [(t[0], t[1]) for t in TOKENS],
                             ids=TOKEN_IDS)
    def test_a_prefix_of_the_token_is_refused(self, tmp_path, directive, token):
        """security-negative: ngx_conf_set_enum_slot compares the whole name
        (name.len is tested before the bytes), so a truncated token must be an
        error.  A prefix match would make `brix_webdav_redirect_scheme http`
        and `... https` the same line, which is precisely the pair this file
        distinguishes."""
        where = ("stream" if directive in self.STREAM_ONLY
                 or directive == "brix_backend_s3_sts_flavor" else "loc")
        indent = 8 if where == "stream" else 12
        result = _parse(tmp_path,
                        **{where: _line(directive, token[:-1], indent)})
        assert result.returncode != 0, \
            f"{directive} accepted '{token[:-1]}', a prefix of '{token}'"

    @pytest.mark.parametrize("directive,token", [(t[0], t[1]) for t in TOKENS],
                             ids=TOKEN_IDS)
    def test_the_token_is_case_insensitive(self, tmp_path, directive, token):
        """ngx_conf_set_enum_slot matches with ngx_strcasecmp, so `AWS` and
        `aws` are one pair and not two.  The tranche's §Method counts pairs off
        the enum table for exactly this reason — counting spellings instead
        would inflate the denominator without adding a single behaviour."""
        where = ("stream" if directive in self.STREAM_ONLY
                 or directive == "brix_backend_s3_sts_flavor" else "loc")
        indent = 8 if where == "stream" else 12
        result = _parse(tmp_path,
                        **{where: _line(directive, token.upper(), indent)})
        assert result.returncode == 0, _output(result)

    def test_a_stream_token_is_refused_in_a_location(self, tmp_path):
        """error: brix_health_check_type is NGX_STREAM_SRV_CONF only."""
        result = _parse(tmp_path,
                        loc=_line("brix_health_check_type", "ping", 12))
        assert result.returncode != 0, \
            "brix_health_check_type was accepted in an http location"

    def test_the_redirect_scheme_is_refused_above_a_location(self, tmp_path):
        """error: brix_webdav_redirect_scheme is NGX_HTTP_LOC_CONF only, unlike
        brix_webdav_checksum_xattr_format three tables away, which is declared
        main|srv|loc.  The asymmetry is real and worth pinning: it is the reason
        the redirect arm below can only be built out of locations."""
        result = _parse(tmp_path,
                        http_main=_line("brix_webdav_redirect_scheme", "http", 4))
        assert result.returncode != 0, \
            "brix_webdav_redirect_scheme was accepted in the http main context"

    def test_the_xattr_format_parses_above_a_location(self, tmp_path):
        """success: the same directive that DEFECT CANDIDATE #62 shows to be
        inert is nonetheless accepted at the http main context, which is what
        makes the finding a contradiction rather than a limitation."""
        result = _parse(
            tmp_path,
            http_main=_line("brix_webdav_checksum_xattr_format", "text", 4))
        assert result.returncode == 0, _output(result)

    def test_a_token_at_the_top_level_is_refused(self, tmp_path):
        """security-negative: outside stream{} and http{} nginx knows none of
        these directives, and an unknown directive at the top level must be a
        parse error, never a silent no-op."""
        result = _parse(tmp_path,
                        outer=_line("brix_ssi_cta_executor", "prod", 0))
        assert result.returncode != 0, \
            "brix_ssi_cta_executor was accepted at the top level"


# --------------------------------------------------------------------------- #
# B. Where the default is, and which tokens restate it.                        #
# --------------------------------------------------------------------------- #

class TestWhereTheDefaultIs:

    @pytest.mark.parametrize("row", TOKENS, ids=TOKEN_IDS)
    def test_the_token_agrees_with_the_merge(self, row):
        directive, token, field, unit, spelling, table = row
        default = _constant(_merge_default(unit, field))
        value = _enum_table(*table)[token]
        if RESTATES_THE_DEFAULT[directive]:
            assert value == default, (
                f"{directive} {token} = {value} but the merge in {unit} "
                f"defaults conf->{field} to {spelling} = {default}; this file's "
                f"premise is that writing the token changes nothing")
        else:
            assert value != default, (
                f"{directive} {token} = {value} now equals the merge default "
                f"{spelling} = {default}; it was the one token in this set that "
                f"asked for a change, and it is this file's control")

    @pytest.mark.parametrize("row", TOKENS, ids=TOKEN_IDS)
    def test_the_merge_default_is_spelled_as_the_source_says(self, row):
        """The spelling, not just the value.  Two of the five merge to a bare
        `0` where the enum has a name for it (BRIX_STS_FLAVOR_AWS, and the SSI
        table has no names at all), so the default and the token agree only by
        the coincidence of two literals.  Pinning the spelling is what makes a
        future renumbering visible here instead of at a WLCG site."""
        _directive, _token, field, unit, spelling, _table = row
        assert _merge_default(unit, field) == spelling

    @pytest.mark.parametrize("row", TOKENS, ids=TOKEN_IDS)
    def test_the_table_carries_exactly_the_tokens_audited(self, row):
        """The tranche counts (directive, value) pairs off the enum table.  A
        sixth token in any table below means the audit's denominator moved and
        this file no longer closes the directive."""
        directive, _token, _field, _unit, _spelling, table = row
        assert tuple(_enum_table(*table)) == EXPECTED_TOKENS[directive]

    def test_the_ssi_reader_agrees_with_the_ssi_table(self):
        """brix_ssi_executor_enum spells its values as bare 0 and 1, and ssi.c
        compares against a bare 1.  Nothing links the two, so assert the link."""
        assert _enum_table("src/protocols/root/stream/module.c",
                           "brix_ssi_executor_enum")["prod"] == 1
        assert re.search(r"conf->ssi_cta_executor == 1", _source(
            "src/protocols/ssi/ssi.c")), \
            "ssi.c no longer selects the executor with `== 1`"


# --------------------------------------------------------------------------- #
# C. One directive name, two enum tables.                                      #
# --------------------------------------------------------------------------- #

class TestTheTwoStsTables:
    """brix_backend_s3_sts_flavor is declared on the http plane off
    brix_sts_flavor_enum and on the stream plane off a deliberate copy
    (module.c:69 says so in as many words, because the http table is
    file-static).  Two tables for one directive name is a sync hazard with no
    compiler behind it — these are the assertions that stand in for one."""

    def test_both_planes_carry_the_same_tokens(self):
        tables = {plane: _enum_table(path, name)
                  for plane, path, name in STS_TABLES}
        assert tables["http"] == tables["stream"], (
            "the stream copy of brix_backend_s3_sts_flavor has drifted from "
            f"the http original: {tables}")

    def test_the_tokens_resolve_to_the_documented_enum(self):
        table = _enum_table(*STS_TABLES[0][1:])
        assert table["aws"] == _constant("BRIX_STS_FLAVOR_AWS")
        assert table["minio"] == _constant("BRIX_STS_FLAVOR_MINIO")

    def test_the_post_merge_fallback_agrees_with_the_merge(self):
        """deleg_wire.c:40 re-tests backend_sts_flavor against
        NGX_CONF_UNSET_UINT after the shared merge has already folded it, and
        falls back to BRIX_STS_FLAVOR_AWS.  The branch is unreachable while the
        merge runs, which makes it harmless and invisible — right up to the day
        the merge default changes and the two disagree.  Assert they agree."""
        default = _constant(_merge_default("src/core/config/shared_conf_merge.h",
                                           "backend_sts_flavor"))
        flat = _flat(_source("src/protocols/shared/deleg_wire.c"))
        hit = re.search(r"cf->flavor = \(cc->backend_sts_flavor != "
                        r"NGX_CONF_UNSET_UINT\) \? \(int\) "
                        r"cc->backend_sts_flavor : ([A-Za-z0-9_]+);", flat)
        assert hit, "deleg_wire.c no longer picks the flavor with that ternary"
        assert _constant(hit.group(1)) == default, (
            f"deleg_wire.c falls back to {hit.group(1)} but the merge defaults "
            f"to {default}")


# --------------------------------------------------------------------------- #
# D. DEFECT CANDIDATE #63 — the CTA executor is decided by the last open.      #
# --------------------------------------------------------------------------- #

class TestTheCtaExecutorAliases:

    def test_the_test_face_completes_an_archive(self, cluster):
        """control: with only its own face opened, `executor test` runs the
        simulated executor and the archive completes.  Without this row the
        failures below could be the CTA service being broken."""
        rsp, alerts = _archive(cluster["ssi"])
        assert rsp == CTA_RSP_SUCCESS, (rsp, alerts)
        assert ALERT_TAPE in alerts, alerts

    def test_the_prod_face_fails_without_a_backend(self, cluster):
        """control: `executor prod` selects cta_exec.c's prod_vtbl, which in a
        build with no nearline backend fails cleanly.  This is the token under
        test reaching its own code for the first time in the tree."""
        rsp, alerts = _archive(cluster["ssi2"])
        assert rsp == CTA_RSP_ERR_CTA, (rsp, alerts)
        assert ALERT_NO_BACKEND in alerts, alerts

    def test_a_prod_open_breaks_the_test_faces_request(self, cluster):
        """DEFECT CANDIDATE #63, first direction: the request is submitted on
        the `executor test` face and answered by the production executor,
        because an open on the other face landed in between."""
        rsp, alerts = _archive(cluster["ssi"], alias_open=cluster["ssi2"])
        assert rsp == CTA_RSP_ERR_CTA, (
            "the prod face no longer retargets the test face — if "
            "brix_ssi_cta_configure() has moved off the open path, delete "
            "DEFECT CANDIDATE #63 from this module's docstring", rsp, alerts)
        assert ALERT_NO_BACKEND in alerts, alerts

    def test_a_test_open_fabricates_success_on_the_prod_face(self, cluster):
        """DEFECT CANDIDATE #63, the direction that matters: the request is
        submitted on the face an operator configured for real tape, and it is
        answered CTA_RSP_SUCCESS — "writing to tape" — by the simulated
        executor.  A durability guarantee, fabricated by an unrelated client's
        open on a different listener."""
        rsp, alerts = _archive(cluster["ssi2"], alias_open=cluster["ssi"])
        assert rsp == CTA_RSP_SUCCESS, (
            "the test face no longer retargets the prod face — if "
            "brix_ssi_cta_configure() has moved off the open path, delete "
            "DEFECT CANDIDATE #63 from this module's docstring", rsp, alerts)
        assert ALERT_TAPE in alerts, alerts

    def test_the_journal_aliases_through_the_same_call(self, cluster):
        """The journal path rides the same brix_ssi_cta_configure() call, so it
        aliases identically: the prod face writes no brix_ssi_cta_journal, and
        its open therefore clears the path the other face configured.  The
        journal is here because the executor's fix has to carry it."""
        assert cluster["journal"].exists(), \
            "the test face never opened its journal at all"
        flat = _flat(_source("src/protocols/ssi/ssi.c"))
        assert "brix_ssi_cta_configure(jbuf, conf->ssi_cta_executor == 1);" \
            in flat, "ssi.c no longer configures the service from the open path"

    def test_the_executor_lives_in_a_process_global(self, cluster):
        """The static half of #63: g_cta_use_prod is file-static per worker and
        is read at completion, not carried on the request."""
        text = _source("src/protocols/ssi/svc_cta/cta_service.c")
        assert re.search(r"^static int\s+g_cta_use_prod;", text, re.MULTILINE), \
            "g_cta_use_prod is no longer a file-static global"
        assert re.search(r"return g_cta_use_prod \? cta_exec_prod_vtbl\(\)",
                         text), "the vtbl is no longer chosen from the global"


# --------------------------------------------------------------------------- #
# E. DEFECT CANDIDATE #62 — `text` cannot be restored.                         #
# --------------------------------------------------------------------------- #

def _require_xattr(cluster):
    if cluster["control_xattr"] is None:
        pytest.skip("no user.* xattr support on this filesystem: the control "
                    "PUT left no user.XrdCks.adler32 to compare against")


class TestTheXattrFormatCannotBeRestored:

    def test_the_control_process_writes_the_text_record(self, cluster):
        """control: in a process where `text` is the only format anyone asks
        for, `text` is what lands — the text record is
        "<hex> <mtime_sec> <mtime_nsec> <size>" (integrity_info.h:122)."""
        _require_xattr(cluster)
        raw = cluster["control_xattr"]
        want = format(zlib.adler32(cluster["control_payload"]) & 0xffffffff,
                      "08x")
        assert raw.decode().split()[0] == want, raw
        assert raw.count(b" ") == 3, ("not the text record", raw)

    def test_the_xrdcks_location_writes_the_binary_record(self, cluster):
        """control: the sibling that DOES ask for a change gets it.  The record
        is the stock XrdCksData struct — test_checksum_on_write.py owns its
        field layout, so this only establishes that it is not text."""
        _require_xattr(cluster)
        name = f"bin_{uuid.uuid4().hex[:8]}.bin"
        payload = os.urandom(2048)
        _put(cluster["port"], f"/bin/{name}", payload)
        raw = _xattr(cluster["data"] / "bin" / name)
        assert raw is not None, "no checksum xattr on the xrdcks location"
        assert raw[:16].split(b"\x00", 1)[0] == b"adler32", raw[:16]
        assert b" " not in raw[:16], ("looks like the text record", raw)

    def test_the_text_location_writes_the_binary_record_anyway(self, cluster):
        """DEFECT CANDIDATE #62: the location writes `text`, and gets the
        binary record, because a location twelve lines away in the same file
        wrote `xrdcks` and config_merge.c:107 has no else."""
        _require_xattr(cluster)
        name = f"txt_{uuid.uuid4().hex[:8]}.bin"
        payload = os.urandom(2048)
        _put(cluster["port"], f"/txt/{name}", payload)
        raw = _xattr(cluster["data"] / "txt" / name)
        assert raw is not None, "no checksum xattr on the text location"
        assert b" " not in raw[:16], (
            "brix_webdav_checksum_xattr_format text now produces the text "
            "record even beside an xrdcks location — delete DEFECT CANDIDATE "
            "#62 from this module's docstring", raw)
        assert raw[:16].split(b"\x00", 1)[0] == b"adler32", raw[:16]

    def test_the_two_locations_are_byte_identical(self, cluster):
        """The sharpest statement of #62: PUT the SAME bytes through the
        location that asks for text and the location that asks for xrdcks, and
        the two xattrs are the same record.  The directive selects nothing."""
        _require_xattr(cluster)
        payload = os.urandom(2048)
        records = []
        for where in ("txt", "bin"):
            name = f"pair_{where}_{uuid.uuid4().hex[:8]}.bin"
            _put(cluster["port"], f"/{where}/{name}", payload)
            raw = _xattr(cluster["data"] / where / name)
            assert raw is not None, where
            records.append(raw)
        assert records[0] == records[1], (
            "the text and xrdcks locations now differ, which is what they "
            "should always have done — delete DEFECT CANDIDATE #62")

    def test_the_setter_accepts_text_but_the_caller_never_passes_it(self):
        """The static half of #62, and the reason it reads as an oversight
        rather than a design: brix_integrity_set_xattr_format() validates and
        accepts BRIX_CKS_FMT_TEXT.  Only the call site excludes it."""
        setter = _flat(_source("src/core/compat/integrity_info.c"))
        assert "if (fmt == BRIX_CKS_FMT_TEXT || fmt == BRIX_CKS_FMT_XRDCKS)" \
            in setter, "the setter no longer accepts BRIX_CKS_FMT_TEXT"

        merge = _flat(_source("src/protocols/webdav/config_merge.c"))
        guard = ("if (conf->checksum_xattr_format != BRIX_CKS_FMT_TEXT) { "
                 "/* §8.x: stock-interoperable binary XrdCksData write format "
                 "(process-wide). */ brix_integrity_set_xattr_format("
                 "conf->checksum_xattr_format); }")
        assert guard in merge, (
            "the guard around brix_integrity_set_xattr_format has changed — "
            "re-measure DEFECT CANDIDATE #62 before trusting this file")
        tail = merge[merge.index(guard) + len(guard):].lstrip()
        assert not tail.startswith("else"), (
            "config_merge.c has grown an else on the xattr-format guard, which "
            "is the fix — delete DEFECT CANDIDATE #62 from this docstring")

    def _field_hits(self, path):
        hits = []
        for line in path.read_text(errors="replace").splitlines():
            if "checksum_xattr_format" not in line:
                continue
            stripped = line.lstrip()
            if stripped.startswith(("*", "/*", "//")):
                continue
            if not _expression_1(stripped):
                hits.append(stripped)
        return hits

    def test_nothing_else_reads_the_merged_field(self):
        """conf->checksum_xattr_format is initialised, merged, addressed by a
        directive table — and read by exactly one statement, the one that
        throws it away.  Line numbers are deliberately not asserted; the claim
        is about which files can possibly consult the merged value, and it must
        survive an unrelated edit above it."""
        hits = {}
        for path in ROOT.joinpath("src").rglob("*.[ch]"):
            found = self._field_hits(path)
            if found:
                hits[str(path.relative_to(ROOT))] = found
        assert sorted(hits) == ["src/protocols/webdav/config_merge.c",
                                "src/protocols/webdav/webdav_loc_conf.h"], hits
        assert len(hits["src/protocols/webdav/webdav_loc_conf.h"]) == 1, hits
        # The merge macro (two lines), the guard, and the setter call.
        _check_test_nothing_else_reads_the_merged_field_3(hits)


# --------------------------------------------------------------------------- #
# F. The redirect scheme — the same merge, done correctly.                     #
# --------------------------------------------------------------------------- #

class TestTheRedirectSchemeIsPerLocation:
    """The contrast that makes #62 a defect and not a house style.
    brix_webdav_redirect_scheme is merged in the SAME function, twelve lines
    below the checksum format, and it is read off conf-> at request time — so
    three locations in one process give three answers."""

    @pytest.mark.parametrize("where,scheme", [
        ("rdr-none", "http"),     # no directive: the merge default
        ("rdr-http", "http"),     # the token under test
        ("rdr-https", "https"),   # the control
    ])
    def test_each_location_decides_its_own_scheme(self, cluster, where, scheme):
        status, headers, _body = _req("GET", cluster["port"],
                                      f"/{where}/probe.dat")
        assert status == 307, (status, headers)
        location = headers.get("Location", "")
        assert location.startswith(f"{scheme}://"), (where, location)
        assert f"/{where}/probe.dat" in location, location

    def test_writing_http_is_the_same_as_writing_nothing(self, cluster):
        """The file's thesis, in its one uncomplicated instance: the token and
        its absence produce the same Location but for the path."""
        _s, none_headers, _b = _req("GET", cluster["port"],
                                    "/rdr-none/probe.dat")
        _s, http_headers, _b = _req("GET", cluster["port"],
                                    "/rdr-http/probe.dat")
        none_loc = none_headers.get("Location", "").replace("/rdr-none/", "/X/")
        http_loc = http_headers.get("Location", "").replace("/rdr-http/", "/X/")
        assert none_loc == http_loc, (none_loc, http_loc)

    def test_the_scheme_is_read_from_the_conf_at_request_time(self):
        """Static: no global anywhere on this path — the ternary reads conf->
        inside the Location builder."""
        flat = _flat(_source("src/protocols/webdav/redirect.c"))
        assert ('conf->redirect_scheme == BRIX_WEBDAV_RDR_HTTPS ? "https" '
                ': "http"') in flat, \
            "redirect.c no longer chooses the scheme from the merged conf"
        assert _merge_default("src/protocols/webdav/config_merge.c",
                              "redirect_scheme") == "BRIX_WEBDAV_RDR_HTTP"


# --------------------------------------------------------------------------- #
# G. The health-check probe type.                                             #
# --------------------------------------------------------------------------- #

class TestTheHealthCheckProbeType:
    """`ping` is unusual in this set: it is not merely the default, it is the
    else-branch.  Nothing in src/ ever compares probe_type to BRIX_HC_TYPE_PING,
    so `ping`, the absent directive and any future third token that is not
    `stat` are one code path — which is why the parse tier in §A is the whole of
    what a token-level test can add, and the wire-level split belongs beside the
    live probe harness in test_phase22_health_check.py."""

    def test_ping_is_the_else_branch(self):
        probe = _source("src/net/manager/health_check_probe.c")
        assert "if (hc->probe_type == BRIX_HC_TYPE_STAT) {" in probe
        assert "BRIX_HC_TYPE_PING" not in probe, (
            "health_check_probe.c now names BRIX_HC_TYPE_PING — `ping` has "
            "stopped being the else-branch and deserves a wire-level test")

    def test_the_only_comparison_in_the_tree_is_against_stat(self):
        hits = [f"{path.relative_to(ROOT)}"
                for path in ROOT.joinpath("src").rglob("*.[ch]")
                if re.search(r"probe_type\s*==", path.read_text(errors="replace"))]
        assert hits == ["src/net/manager/health_check_probe.c"], hits

    def test_the_merge_default_is_the_ping_token(self):
        default = _constant(_merge_default(
            "src/core/config/server_conf_merge_cluster.c", "hc.type"))
        table = _enum_table("src/protocols/root/stream/module_enums.c",
                            "brix_hc_types")
        assert table["ping"] == default
        assert table["stat"] != default
