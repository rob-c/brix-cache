# --------------------------------------------------------------------------- #
# §A — brix_csi_trust_fs, three arms in one worker                            #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheTrustFsArms:
    """What the flag decides is not how fast a read is; it is whether a read of
    known-corrupt bytes succeeds."""

    def test_a_clean_file_reads_byte_exact_through_every_arm(self, farm):
        """The floor.  Before any arm can be said to change a verdict, all four
        acceptors have to agree about an undamaged file — otherwise §A would be
        measuring the export, the granule or the write path."""
        f = farm("audit-16r §A clean baseline", **TRUST_LAYOUT)
        assert f.put("A", "clean.bin") == kXR_ok, f.errlog()
        assert f.tagged("clean.bin"), "the write left no integrity record"
        for server in "ABCD":
            verdict, body = f.read(server, "clean.bin")
            assert verdict == GRANTED, f"{server}: {verdict} {body}"
            assert body == PAYLOAD, f"{server} served different bytes"

    def test_the_absent_arm_refuses_a_corrupt_read(self, farm):
        """Acceptor A writes neither flag.  The merge default is 0, so the
        engine attaches on reads and the damaged block fails — this is the
        behaviour the two `off` arms below have to reproduce."""
        f = farm("audit-16r §A absent vs corrupt", **TRUST_LAYOUT)
        f.put("A", "clean.bin")
        f.corrupt("clean.bin")
        verdict, message = f.read("A", "clean.bin")
        assert verdict != GRANTED, "corrupt bytes were served"
        assert verdict == KXR_IO_ERROR, (verdict, message)

    def test_the_off_arm_refuses_the_same_read(self, farm):
        """The arm the corpus never wrote, reaching the merge as 0 through the
        other route.  Absence and ``off`` are the same configuration measured
        two ways, and this is the case that says so rather than assuming it."""
        f = farm("audit-16r §A off vs corrupt", **TRUST_LAYOUT)
        f.put("A", "clean.bin")
        f.corrupt("clean.bin")
        assert f.read("C", "clean.bin")[0] == KXR_IO_ERROR

    def test_the_on_arm_serves_the_corrupt_bytes(self, farm):
        """Not a no-op in the other direction: the trusting acceptor hands back
        exactly what is on disk, including the flipped byte, with kXR_ok.  A
        client cannot tell this read from a good one."""
        f = farm("audit-16r §A on vs corrupt", **TRUST_LAYOUT)
        f.put("A", "clean.bin")
        damaged = f.corrupt("clean.bin")
        verdict, body = f.read("B", "clean.bin")
        assert verdict == GRANTED, (verdict, body)
        assert body == damaged
        assert body != PAYLOAD, "the fixture did not actually damage the file"

    def test_the_three_arms_disagree_in_one_worker(self, farm):
        """The attribution control.  One process, one export, one file, three
        verdicts — so the flag is read per server on every open, and none of §A
        is an artefact of restarting nginx between arms.  (File 17's
        ``brix_acc_pgo``, declared at the same scope in the same header, fails
        exactly this test; #92.)"""
        f = farm("audit-16r §A per-server control", **TRUST_LAYOUT)
        f.put("A", "clean.bin")
        f.corrupt("clean.bin")
        verdicts = {s: f.read(s, "clean.bin")[0] for s in "ABC"}
        assert verdicts == {"A": KXR_IO_ERROR,
                            "B": GRANTED,
                            "C": KXR_IO_ERROR}, verdicts

    def test_a_trusting_acceptor_still_writes_the_record(self, farm):
        """``on`` skips the engine for READS only — the branch is
        ``!(trust_fs && !is_write)``.  A trusted export therefore keeps
        producing records for everyone else to verify against, which is what
        makes the flag a read-side policy rather than an opt-out."""
        f = farm("audit-16r §A trusted write still tags", **TRUST_LAYOUT)
        assert f.put("B", "viaTrust.bin") == kXR_ok
        assert f.tagged("viaTrust.bin")
        # And a verifying acceptor accepts what the trusting one wrote.
        assert f.read("A", "viaTrust.bin") == (GRANTED, PAYLOAD)

    def test_the_engine_master_switch_is_a_different_thing(self, farm):
        """``brix_csi off`` and ``brix_csi_trust_fs on`` reach the same read
        verdict by different routes, and are not interchangeable: the first
        stops recording, the second keeps recording and stops checking.  An
        operator who reads them as synonyms silently stops producing the records
        every other acceptor depends on."""
        f = farm("audit-16r §A master switch", **REQUIRE_LAYOUT)
        f.put("A", "clean.bin")
        damaged = f.corrupt("clean.bin")
        assert f.read("D", "clean.bin") == (GRANTED, damaged)
        assert f.put("D", "viaOff.bin") == kXR_ok
        assert not f.tagged("viaOff.bin"), "brix_csi off still recorded"


# --------------------------------------------------------------------------- #
# §B — brix_csi_require, three arms in one worker                             #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheRequireArms:
    """What the flag decides is whether an UNTAGGED file may be read at all."""

    def test_the_absent_arm_serves_an_untagged_file(self, farm):
        """The merge default is 0 and the code calls it fail-open: an
        unrecorded read proceeds without CSI.  Every export that predates the
        feature depends on this."""
        f = farm("audit-16r §B absent vs untagged", **TRUST_LAYOUT)
        f.seed_untagged("untagged.bin")
        assert not f.tagged("untagged.bin")
        assert f.read("A", "untagged.bin") == (GRANTED, PAYLOAD)

    def test_the_off_arm_serves_it_too(self, farm):
        """The arm the corpus never wrote, reaching the same 0 explicitly."""
        f = farm("audit-16r §B off vs untagged", **REQUIRE_LAYOUT)
        f.seed_untagged("untagged.bin")
        assert f.read("A", "untagged.bin") == (GRANTED, PAYLOAD)

    def test_the_on_arm_refuses_it_with_chksumerr(self, farm):
        """The refusal, and its wording.  This is the ONE place on the read path
        that produces kXR_ChkSumErr — §D is about the place that does not."""
        f = farm("audit-16r §B on vs untagged", **TRUST_LAYOUT)
        f.seed_untagged("untagged.bin")
        verdict, message = f.read("D", "untagged.bin")
        assert verdict == KXR_CHKSUM_ERR, (verdict, message)
        assert message == "integrity record missing", message

    def test_the_refusal_is_not_a_missing_file(self, farm):
        """The attribution control for §B.  An export with no record and an
        export with no file must not be the same reading, or every row above
        could be a seeding slip."""
        f = farm("audit-16r §B refusal vs not-found", **TRUST_LAYOUT)
        f.seed_untagged("untagged.bin")
        assert f.read("D", "untagged.bin")[0] == KXR_CHKSUM_ERR
        assert f.read("D", "nosuch.bin")[0] == KXR_NOT_FOUND
        assert f.read("D", "untagged.bin")[0] != KXR_NOT_AUTHORIZED

    def test_a_tagged_file_passes_the_requirement(self, farm):
        """``require on`` is a requirement about the RECORD, not a refusal of
        the export: the same acceptor serves a file that has one."""
        f = farm("audit-16r §B on vs tagged", **TRUST_LAYOUT)
        f.put("A", "clean.bin")
        assert f.read("D", "clean.bin") == (GRANTED, PAYLOAD)

    def test_it_gates_reads_only(self, farm):
        """``!is_write`` in the condition.  An open-for-write of an untagged
        file is granted — otherwise a require-on export could never be brought
        into compliance, since only a write creates the record it demands."""
        f = farm("audit-16r §B write open of an untagged file", **TRUST_LAYOUT)
        f.seed_untagged("untagged.bin")
        assert f.read("D", "untagged.bin")[0] == KXR_CHKSUM_ERR
        assert f.open_for_write("D", "untagged.bin") == (GRANTED, "")
        assert f.put("D", "untagged.bin") == kXR_ok
        assert f.tagged("untagged.bin")
        assert f.read("D", "untagged.bin") == (GRANTED, PAYLOAD)

    def test_the_three_arms_disagree_in_one_worker(self, farm):
        """The per-server control for §B: one untagged file, three verdicts, one
        process."""
        f = farm("audit-16r §B per-server control", **REQUIRE_LAYOUT)
        f.seed_untagged("untagged.bin")
        verdicts = {s: f.read(s, "untagged.bin")[0] for s in "ACD"}
        assert verdicts == {"A": GRANTED,          # require off
                            "C": KXR_CHKSUM_ERR,   # require on, trust off
                            "D": GRANTED}, verdicts  # no engine


# --------------------------------------------------------------------------- #
# §C — DEFECT CANDIDATE #93: the two flags are not independent                #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheArmsCompose:
    """``brix_csi_require on`` is silently inert under ``brix_csi_trust_fs on``.

    Both are declared as plain per-server flags with nothing to suggest an
    ordering between them, and an operator writing both is asking for the strict
    reading of both: record every file, refuse anything unrecorded, and skip the
    per-read CRC because the filesystem already checksums.  What they get is the
    skip and not the refusal — the ``require`` test is nested inside the branch
    that ``trust_fs`` turns off.
    """

    def test_require_on_is_inert_under_trust_on(self, farm):
        """The finding.  Acceptor B writes both arms and serves the file that
        acceptor C — the same two directives, one of them ``off`` — refuses."""
        f = farm("audit-16r §C require under trust", **REQUIRE_LAYOUT)
        f.seed_untagged("untagged.bin")
        assert f.read("B", "untagged.bin") == (GRANTED, PAYLOAD), \
            "DEFECT CANDIDATE #93 has been FIXED: require now survives " \
            "trust_fs.  Flip this expectation to kXR_ChkSumErr and strike #93."
        assert f.read("C", "untagged.bin")[0] == KXR_CHKSUM_ERR

    def test_it_also_loses_the_corruption_check(self, farm):
        """Both halves at once, so the loss is not read as a trade.  The same
        acceptor that stopped requiring a record also stopped checking the
        records it has: B serves corrupt bytes AND unrecorded bytes."""
        f = farm("audit-16r §C both halves", **REQUIRE_LAYOUT)
        f.put("C", "clean.bin")
        damaged = f.corrupt("clean.bin")
        f.seed_untagged("untagged.bin")
        assert f.read("B", "clean.bin") == (GRANTED, damaged)
        assert f.read("B", "untagged.bin") == (GRANTED, PAYLOAD)
        assert f.read("C", "clean.bin")[0] == KXR_IO_ERROR
        assert f.read("C", "untagged.bin")[0] == KXR_CHKSUM_ERR

    def test_nothing_at_config_time_says_so(self, farm):
        """The half that makes this a defect rather than a documented
        interaction.  ``nginx -t`` accepts the pair without a word, and the
        worker's startup log — which does announce the export, the mode and the
        auth scheme — never mentions CSI at all."""
        f = farm("audit-16r §C silence", **REQUIRE_LAYOUT)
        log = f.errlog()
        assert "endpoint ready" in log, log[-2000:]
        offending = [line for line in log.splitlines()
                     if "csi" in line.lower()
                     and ("[warn]" in line or "[error]" in line
                          or "[emerg]" in line)]
        assert offending == [], offending

    def test_nginx_t_accepts_the_pair_in_silence(self, tmp_path):
        """The same silence at the parse tier, where a merge-time diagnostic
        would live.  Written as a parse case so it stays true for a
        configuration that never starts."""
        rc, out = _parse(tmp_path,
                         STREAM_KNOBS=f"        brix_csi on;\n"
                                      f"        {REQUIRE_ON}\n"
                                      f"        {TRUST_ON}\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    def test_the_gate_in_the_source_is_the_reason(self, farm):
        """The one line of C the whole section rests on: the ``require`` test is
        inside the ``if`` that ``trust_fs`` short-circuits, so no ordering of
        the two directives in a config can change the outcome."""
        squashed = _squashed(OPEN_FINALIZE_C)
        assert ("if (conf->csi.enable && S_ISREG(st->st_mode) "
                "&& !(conf->csi.trust_fs && !is_write))") in squashed
        assert ("if (!is_write && crc == BRIX_CSI_NOTAGS "
                "&& conf->csi.require)") in squashed
        gate = squashed.index("!(conf->csi.trust_fs && !is_write)")
        require = squashed.index("&& conf->csi.require)")
        assert gate < require, "the require test is no longer nested"
        # Reversing the order in the config cannot matter, and this is the
        # measurement that says the source reading is the operative one.
        f = farm("audit-16r §C order is irrelevant",
                 a=_csi_block(TRUST_ON, REQUIRE_ON),
                 b=_csi_block(REQUIRE_ON, TRUST_ON),
                 c=_csi_block(REQUIRE_ON),
                 d=_csi_block())
        f.seed_untagged("untagged.bin")
        assert f.read("A", "untagged.bin")[0] == GRANTED
        assert f.read("B", "untagged.bin")[0] == GRANTED
        assert f.read("C", "untagged.bin")[0] == KXR_CHKSUM_ERR
