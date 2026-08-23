# --------------------------------------------------------------------------- #
# §D — DEFECT CANDIDATE #94: the mismatch never reaches the wire as one       #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheMismatchErrorCode:
    """At-rest corruption is reported as a disk error, not a checksum error.

    The distinction is not cosmetic.  kXR_IOError tells a client the server had
    trouble reading; kXR_ChkSumErr tells it this replica's bytes are wrong.  A
    federation client retries the first elsewhere and can be told to quarantine
    the second — and the scrub metric that would otherwise surface it
    (``brix_csi_scrub_mismatch_total``) counts only the background scrub, never
    a read.
    """

    def test_a_verify_mismatch_reports_ioerror(self, farm):
        """The measurement.  Same file, same byte, two acceptors that both
        verify — both say 3007."""
        f = farm("audit-16r §D the code on the wire", **TRUST_LAYOUT)
        f.put("A", "clean.bin")
        f.corrupt("clean.bin")
        for server in ("A", "C"):
            verdict, message = f.read(server, "clean.bin")
            assert verdict == KXR_IO_ERROR, \
                ("DEFECT CANDIDATE #94 has been FIXED: a CSI verify mismatch "
                 "now reports kXR_ChkSumErr.  Flip this expectation and strike "
                 f"#94 from the audit.  Got {verdict}: {message}")
            assert message == "Input/output error", message

    def test_the_same_feature_reports_a_missing_record_as_chksumerr(self, farm):
        """The inconsistency, in one process.  'No record at all' is a checksum
        error; 'the record says these bytes are wrong' is a disk error.  If
        either code is right, it is not this way round."""
        f = farm("audit-16r §D the two codes side by side", **TRUST_LAYOUT)
        f.put("A", "clean.bin")
        f.corrupt("clean.bin")
        f.seed_untagged("untagged.bin")
        assert f.read("A", "clean.bin")[0] == KXR_IO_ERROR
        assert f.read("D", "untagged.bin")[0] == KXR_CHKSUM_ERR

    def test_the_out_bit_that_would_have_carried_it_is_set(self):
        """The job struct does carry the distinction — one bit, declared for
        exactly this, and written on every mismatch."""
        assert ("unsigned csi_mismatch:1; "
                "/* OUT: a page failed CSI verify (W2) */") in \
            _squashed(VFS_IO_CORE_H)
        squashed = _squashed(VFS_IO_CORE_C)
        assert "job->csi_mismatch = 1;" in squashed
        assert ("maps it to kXR_ChkSumErr instead of serving corrupt data.") \
            in squashed

    def test_and_nothing_in_src_ever_reads_it(self):
        """The defect itself: one write, zero reads, in the whole of ``src/``.
        The bit is set, documented as the mechanism for a specific mapping, and
        dropped on the floor."""
        writes, reads = _csi_mismatch_accesses()
        assert writes == ["src/fs/vfs/vfs_io_core.c:155"], writes
        assert reads == [], \
            ("DEFECT CANDIDATE #94 has been FIXED: something now reads "
             f"csi_mismatch.  Re-read §D and strike #94.  Readers: {reads}")

    def test_the_hard_coded_code_is_the_one_on_the_wire(self):
        """And the site that answers instead, which is why the reading above
        surfaces as 3007: a literal, on the path both the warm-hit and the
        synchronous fill converge on."""
        squashed = _squashed(READ_BUFFERED_C)
        assert "kXR_IOError, strerror(errno));" in squashed
        assert "mismatch surfaces here as EIO (job.csi_mismatch set);" in squashed
        assert "kXR_ChkSumErr" not in squashed

    def test_an_integrity_checked_handle_never_takes_the_sendfile_path(self):
        """The control on the two findings above: neither is "the read skipped
        the engine".  A handle with a CSI engine is excluded from zero-copy by
        the gate itself, so every verifying read really does run through the
        buffered path that §D measures."""
        assert "&& ctx->files[idx].csi == NULL" in _squashed(READ_SENDFILE_C)


def _csi_mismatch_accesses():
    writes, reads = [], []
    paths = (path for path in sorted(SRC_DIR.rglob("*"))
             if path.suffix in (".c", ".h") and path.is_file())
    for path in paths:
        path_writes, path_reads = _csi_mismatch_accesses_in(path)
        writes.extend(path_writes)
        reads.extend(path_reads)
    return writes, reads


def _csi_mismatch_accesses_in(path):
    writes, reads = [], []
    lines = path.read_text(errors="replace").splitlines()
    for number, line in enumerate(lines, 1):
        kind = _csi_mismatch_access_kind(line)
        if kind:
            target = writes if kind == "write" else reads
            target.append(f"{path.relative_to(ROOT)}:{number}")
    return writes, reads


def _csi_mismatch_access_kind(line):
    stripped = line.strip()
    if "csi_mismatch" not in stripped:
        return None
    if stripped.startswith(("*", "/*")) or "csi_mismatch:1;" in stripped:
        return None
    return "write" if "csi_mismatch = 1" in stripped else "read"


# --------------------------------------------------------------------------- #
# §E — what verification covers, and what it does not                         #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheCoverageRule:
    """Verification is per BLOCK and only for blocks the read buffer fully
    spans.  That is a deliberate fail-open on coverage (csi_verify.c), and it
    bounds what ``trust_fs off`` can be said to guarantee."""

    def test_a_read_of_the_damaged_block_fails(self, farm):
        f = farm("audit-16r §E aligned block reads", **TRUST_LAYOUT)
        f.put("A", "big.bin")
        f.corrupt("big.bin")
        assert f.read("A", "big.bin", 1 * BLOCK, BLOCK)[0] == KXR_IO_ERROR

    @pytest.mark.parametrize("block", (0, 2))
    def test_a_read_of_an_undamaged_block_succeeds(self, farm, block):
        """The other two blocks of the same file are unaffected — the granule
        is the unit, so damage does not poison the whole object."""
        f = farm("audit-16r §E intact blocks", **TRUST_LAYOUT)
        f.put("A", "big.bin")
        f.corrupt("big.bin")
        verdict, body = f.read("A", "big.bin", block * BLOCK, BLOCK)
        assert verdict == GRANTED, (verdict, body)
        assert body == PAYLOAD[block * BLOCK:(block + 1) * BLOCK]

    def test_a_straddling_read_serves_the_corrupt_byte(self, farm):
        """The limitation, measured rather than inferred.  A read of
        [2048, 6144) contains the flipped byte at 5000 and covers NO block
        fully — block 0 starts before it and block 1 ends after it — so the loop
        verifies nothing and the corruption is served, under ``trust_fs off``,
        with kXR_ok.  An operator who writes ``off`` gets per-block detection,
        not per-byte detection, and nothing in the configuration says so."""
        f = farm("audit-16r §E straddling read", **TRUST_LAYOUT)
        f.put("A", "big.bin")
        damaged = f.corrupt("big.bin")
        verdict, body = f.read("C", "big.bin", 2048, BLOCK)
        assert verdict == GRANTED, (verdict, body)
        assert body == damaged[2048:2048 + BLOCK]
        assert body != PAYLOAD[2048:2048 + BLOCK]

    def test_the_coverage_rule_is_where_the_source_says(self):
        """Pinned so the reading above cannot quietly become wrong: the loop
        breaks out on the first block the buffer does not fully span."""
        squashed = _squashed(CSI_VERIFY_C)
        assert "break; /* not fully covered by this read */" in squashed
        assert "if (len == 0 || c->trust_fs) { return BRIX_CSI_OK;" in squashed


# --------------------------------------------------------------------------- #
# §F — the parse tier                                                         #
# --------------------------------------------------------------------------- #

def _parse(tmp_path, **slots):
    """`nginx -t` on file 14's scaffold with the named slots filled.

    Every slot defaults to empty so a case names only what it is about: the
    scaffold writes nothing about CSI, so a negative is never answered by a
    duplicate diagnostic first.
    """
    data = tmp_path / "parse-data"
    data.mkdir(exist_ok=True)
    values = {"PORT": PARSE_PLACEHOLDER_PORT,
              "STREAM_PORT": PARSE_PLACEHOLDER_PORT + 1,
              "LOG_DIR": str(tmp_path),
              "DATA": str(data),
              "LOC_KNOBS": "", "SRV_KNOBS": "", "HTTP_KNOBS": "",
              "OUTER": "", "STREAM_KNOBS": "", "STREAM_MAIN": "",
              "EXTRA_LOC": ""}
    values.update(slots)
    result = nginx_t("nginx_audit16nparse.conf", str(tmp_path), **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


# The one scope the mask names, and every placement it does not.  Unlike file
# 17's subjects these two names exist on the stream plane only — there is no
# http twin to measure, which is itself worth pinning (§G).
WRONG_SCOPES = ("SRV_KNOBS", "HTTP_KNOBS", "LOC_KNOBS", "OUTER", "STREAM_MAIN")


@_needs_nginx
class TestTheParseTier:
    """Values, arity, duplicates and the placement matrix, asked with nothing
    else in the file that could answer instead."""

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_both_arms_are_accepted_in_a_stream_server(self, tmp_path, arm,
                                                       directive):
        """The audit's step-1 question at the declared scope.  Two of these four
        cases are the arm the corpus never wrote, and none of them advises
        anything: turning an integrity knob off is a decision, not a
        misconfiguration — which is exactly why §C's silence is a defect and
        this silence is not."""
        rc, out = _parse(tmp_path, STREAM_KNOBS=f"        {directive} {arm};\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    @pytest.mark.parametrize("arm", ("ON", "Off"))
    def test_the_arms_are_case_insensitive(self, tmp_path, arm, directive):
        """``ngx_conf_set_flag_slot`` compares case-insensitively, so a config
        that shouts is the same configuration.  Pinned because §G's corpus
        census greps for the lower-case spelling and would miss a shouted arm."""
        rc, out = _parse(tmp_path, STREAM_KNOBS=f"        {directive} {arm};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    @pytest.mark.parametrize("value", ("1", "0", "yes", "true", "enabled"))
    def test_anything_else_is_refused_by_name(self, tmp_path, value, directive):
        """The refusal names the directive and both legal arms — the one piece
        of config-time feedback these two directives do give."""
        rc, out = _parse(tmp_path, STREAM_KNOBS=f"        {directive} {value};\n")
        assert rc != 0, out
        assert (f'invalid value "{value}" in "{directive}" directive, '
                'it must be "on" or "off"') in out, out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    @pytest.mark.parametrize("body", ("", " on off"))
    def test_the_arity_is_exactly_one(self, tmp_path, body, directive):
        rc, out = _parse(tmp_path, STREAM_KNOBS=f"        {directive}{body};\n")
        assert rc != 0, out
        assert (f'invalid number of arguments in "{directive}" directive') \
            in out, out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_a_second_write_in_one_server_is_refused(self, tmp_path, directive):
        """``ngx_conf_set_flag_slot`` refuses a repeated write, so an operator
        cannot end up with two arms in one server and no idea which won."""
        rc, out = _parse(tmp_path,
                         STREAM_KNOBS=f"        {directive} on;\n"
                                      f"        {directive} off;\n")
        assert rc != 0, out
        assert f'"{directive}" directive is duplicate' in out, out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    @pytest.mark.parametrize("slot", WRONG_SCOPES)
    def test_every_other_placement_is_refused(self, tmp_path, slot, directive):
        """NGX_STREAM_SRV_CONF alone — not http, not a location, not stream
        main, not the top level.  ``is not allowed here`` and never ``unknown
        directive``: the name is always known, and only the placement is
        wrong."""
        rc, out = _parse(tmp_path, **{slot: f"    {directive} off;\n"})
        assert rc != 0, out
        assert f'"{directive}" directive is not allowed here' in out, out
        assert "unknown directive" not in out, out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_both_arms_parse_without_the_master_switch(self, tmp_path,
                                                       directive):
        """``brix_csi off`` plus a written arm is accepted in silence too: the
        flag has no effect at all with the engine off, and nothing says so.
        The same shape as §C, one level up."""
        rc, out = _parse(tmp_path,
                         STREAM_KNOBS=f"        brix_csi off;\n"
                                      f"        {directive} on;\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out
