"""Test cases for audit16j_root_caps_flags — preamble (fixtures/helpers/mocks) lives in
_test_audit16j_root_caps_flags_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16j_root_caps_flags_helpers")


class TestWritingOffChangesNothingTheClientCanSee:
    """The audit's literal subject: the token nobody had written.

    All five merge to 0, so this section can only ever confirm equality — and
    that is worth measuring rather than assuming, because it is the claim every
    other section's `absent` control silently rests on.  One server carrying all
    five `off` is a per-flag reading, not a combined one: the flags word is an OR
    of independent bits, so if any single `off` set its bit the word would differ
    and name it.
    """

    def test_the_reference_server_advertises_none_of_the_five_bits(self, caps):
        """The control.  Without it an equal pair of words proves only that two
        servers agree, not that they agree on the value the flags decide."""
        flags = _flags(PORT)
        assert flags & OWNED_BITS == 0, (
            f"a server writing none of the five advertises {flags & OWNED_BITS:#x} "
            f"of them (word {flags:#010x}) — the `absent` arm every section below "
            f"uses as its control is not clean")
        assert flags & KXR_ISSERVER, (
            f"the reference is not advertising kXR_isServer (word {flags:#010x}); "
            f"it is not the plain data server the rest of the file assumes")

    def test_written_off_is_byte_identical_to_absent(self, caps):
        """The whole word, not five bits: a flag that reached some OTHER bit
        would pass a five-bit check and fail this one."""
        off, ref = _flags(OFF_PORT), _flags(PORT)
        assert off == ref, (
            f"all five written `off` gives {off:#010x} where absent gives "
            f"{ref:#010x}; `off` and absent share a merged value "
            f"(conf_structs.h:537-548), so the words must be identical")

    @pytest.mark.parametrize("flag", FLAGS)
    def test_no_off_arm_sets_the_bit_its_flag_owns(self, caps, flag):
        """Per-flag attribution of the previous test's single word."""
        bit, flags = OWNED_BIT[flag], _flags(OFF_PORT)
        assert flags & bit == 0, (
            f"{flag} off sets {bit:#x}, the bit it owns (word {flags:#010x})")

    def test_the_off_server_still_serves_its_export(self, caps):
        """Five `off` lines must not cost the server its ordinary function —
        the reading that says the previous three measured a live server."""
        status, data = _read_back(OFF_PORT, "/seed.bin", len(SEED))
        assert status == kXR_ok and data == SEED, (status, data, caps.errlog())


# --------------------------------------------------------------------------- #
# §B — brix_supervisor, isolated from brix_manager_mode                        #
# --------------------------------------------------------------------------- #

def _banner_block(log, needle):
    """One server's `root:// endpoint ready` line plus its annotation lines.

    The banner is written once per process (master and worker both log it), and
    every copy is byte-identical apart from the pid — so the FIRST block naming
    an export is the whole reading.  A block ends at the next banner or at the
    first line that is not one of the indented `brix:   ` annotations.
    """
    lines = log.splitlines()
    for i, line in enumerate(lines):
        if "root:// endpoint ready" not in line or needle not in line:
            continue
        block = [line]
        for nxt in lines[i + 1:]:
            if "root:// endpoint ready" in nxt or "brix:   " not in nxt:
                break
            block.append(nxt)
        return block
    return []


class TestTheSupervisorFlagDeletesTheExport:
    """`brix_server_has_runtime_export()` is false when `caps.supervisor` is set
    (runtime_server.c:25-29), which skips the export setup (:190) — so
    `root_canon` stays empty and the export fd is never opened.  The suite's only
    other supervisor writes `brix_manager_mode` beside the flag, and manager_mode
    alone already makes that predicate false; this server writes the flag ALONE,
    over a `brix_storage_backend` it asks for by path.
    """

    def test_the_supervisor_advertises_the_role_it_claims(self, caps):
        """Not a new reading — the control that says this server really is the
        arm, before the rest of the section concludes things from what it
        refuses."""
        flags = _flags(SUPER_PORT)
        want = KXR_ISMANAGER | KXR_ATTRSUPER
        assert flags & want == want, (
            f"word {flags:#010x} is missing kXR_isManager|kXR_attrSuper; "
            f"brix_supervisor on did not take effect at all")

    def test_the_supervisor_cannot_serve_the_file_in_its_own_export(self, caps):
        """The finding this section exists for: the export directive is accepted,
        the tree exists, the file is there, and the open fails — because the
        flag removed the export before it was ever prepared."""
        status, body = _open_read(SUPER_PORT)
        assert status != kXR_ok, (
            f"a brix_supervisor server opened /seed.bin out of its configured "
            f"brix_storage_backend; brix_server_has_runtime_export() is supposed "
            f"to have skipped the export setup entirely (body={body!r})")

    def test_the_same_export_serves_when_the_flag_is_the_only_difference(
            self, caps):
        """Attribution.  REF and SUPER differ in one line and in two trees
        seeded with the same bytes, so the refusal above is the flag's."""
        status, data = _read_back(PORT, "/seed.bin", len(SEED))
        assert status == kXR_ok and data == SEED, (status, data, caps.errlog())

    def test_the_dropped_backend_is_never_named_in_the_error_log(self, caps):
        """What makes it a finding rather than a documented mode: the export the
        config asked for is not mentioned once — no warning, and no line in the
        startup banner that names every OTHER server's export.

        If this ever fails, the honest response is to retire the claim: a
        diagnostic naming brix_supervisor beside the path it ignored is the fix.
        """
        log = caps.errlog()
        assert f'export "{caps.tree("ref")}"' in log, (
            "the startup banner no longer names configured exports, so the "
            "silence measured below is not attributable to the flag")
        assert f'export "{caps.tree("super")}"' not in log, (
            "brix_supervisor's ignored backend is now named in the log — the "
            "silence this test pins may have been fixed")

    def test_the_supervisor_banner_claims_a_writable_root_export(self, caps):
        """The sharper half of the same finding: the banner does not go quiet,
        it says something else.  With no export prepared `root_canon` is empty
        and the line renders `export "/" (read-write)` — the one shape an
        operator reads as "the whole filesystem, writable" — and unlike the two
        manager_mode blocks it carries no `mode:` annotation naming the role
        that removed the export.

        Attribution without counting: SUPER is the only server here that writes
        `brix_allow_write on` and ends up with no export, so a read-WRITE banner
        for `/` can only be its own (MAP, COLLON and COLLOFF also report `/`,
        but read-only).
        """
        block = _banner_block(caps.errlog(), 'export "/" (read-write)')
        assert block, (
            "no writable `/` banner: the supervisor's empty export root no "
            f"longer renders as one\n{caps.errlog()}")
        assert not any("mode:" in ln or "supervisor" in ln for ln in block[1:]), (
            f"the supervisor banner now annotates its role: {block}")


# --------------------------------------------------------------------------- #
# §C — brix_recover_writes: the journal (DEFECT CANDIDATE #83)                  #
# --------------------------------------------------------------------------- #

def _rewrite_probe(port, path, sync_between=False):
    """Write A then B over the SAME (offset, length); return what the file holds.

    Both statuses are returned so a caller can tell "refused" from "accepted and
    discarded" — the whole distinction #83 rests on.
    """
    s = _session(port)
    try:
        handle = _open_handle(s, path, kXR_new | kXR_open_updt | kXR_delete)
        first = _write(s, handle, 0, b"AAAA")
        if sync_between:
            _sync(s, handle)
        second = _write(s, handle, 0, b"BBBB")
        _close(s, handle)
    finally:
        s.close()
    status, data = _read_back(port, path, 4)
    return first, second, status, data


class TestTheWriteRecoveryJournal:
    """The replay detector matches on (offset, length) alone — no content, no
    client-supplied generation — and the write path consults it on every write
    with no reconnect condition (write.c:120-134).  Both halves of that are
    measured here.
    """

    def test_the_journal_swallows_a_legitimate_rewrite(self, caps):
        """DEFECT CANDIDATE #83, first half.  Same offset, same length, DIFFERENT
        bytes, one handle, no disconnect: the server answers kXR_ok and keeps the
        first bytes."""
        first, second, status, data = _rewrite_probe(WRTS_PORT, "/rewrite.bin")
        assert first[0] == kXR_ok, (first, caps.errlog())
        assert second[0] == kXR_ok, (
            f"the second write was refused ({second}); the finding is that it is "
            f"ACCEPTED and discarded, so a refusal would be a different bug")
        assert status == kXR_ok, (status, data)
        assert data == b"AAAA", (
            f"read back {data!r}; if this is now b'BBBB' the replay detector has "
            f"gained a content or generation check and #83's first half is fixed")

    def test_the_same_rewrite_lands_when_the_flag_is_off(self, caps):
        """Attribution: the identical sequence against the all-`off` server,
        which differs from WRTS only in this flag."""
        first, second, status, data = _rewrite_probe(OFF_PORT, "/rewrite.bin")
        assert (first[0], second[0], status) == (kXR_ok, kXR_ok, kXR_ok), (
            first, second, status, caps.errlog())
        assert data == b"BBBB", (
            f"read back {data!r} from a server with brix_recover_writes off; "
            f"the journal is not supposed to exist there at all")

    def test_the_same_rewrite_lands_on_the_absent_arm(self, caps):
        """The third arm.  `off` and absent share a merged value, so a
        difference between this and the previous test would mean the merge is
        not what conf_structs.h says."""
        _first, _second, status, data = _rewrite_probe(PORT, "/rewrite.bin")
        assert status == kXR_ok and data == b"BBBB", (status, data)

    def test_a_sync_between_the_writes_restores_the_lost_one(self, caps):
        """The third mechanism: kXR_sync flushes the journal (sync.c:92), so the
        protection the flag advertises is exactly as durable as the client's
        habit of not syncing — and the write that vanishes without a sync lands
        with one."""
        _first, _second, status, data = _rewrite_probe(WRTS_PORT, "/synced.bin",
                                                       sync_between=True)
        assert status == kXR_ok, (status, data)
        assert data == b"BBBB", (
            f"read back {data!r} after a kXR_sync between the two writes; the "
            f"journal was supposed to have been flushed")

    def test_a_different_length_at_the_same_offset_is_not_a_replay(self, caps):
        """The bound on #83: the match is exact on both fields, so a 2-byte write
        over a 4-byte one lands.  The defect is the equal-length case, not "the
        journal swallows overwrites"."""
        s = _session(WRTS_PORT)
        try:
            handle = _open_handle(s, "/partial.bin",
                                  kXR_new | kXR_open_updt | kXR_delete)
            assert _write(s, handle, 0, b"AAAA")[0] == kXR_ok
            assert _write(s, handle, 0, b"BB")[0] == kXR_ok
            _close(s, handle)
        finally:
            s.close()
        status, data = _read_back(WRTS_PORT, "/partial.bin", 4)
        assert status == kXR_ok and data == b"BBAA", (
            f"read back {data!r}, want b'BBAA' — a shorter write at a journalled "
            f"offset must not be taken for a replay")

    def test_the_replay_the_journal_exists_for_is_executed_anyway(self, caps):
        """DEFECT CANDIDATE #83, second half.  The journal is per-handle and the
        recovery path is a REOPEN, so the replayed write arrives at an empty
        journal and is executed — the double write the feature exists to
        prevent.  Measured with different bytes, because identical bytes written
        twice to a POSIX file are indistinguishable from one write."""
        s = _session(WRTS_PORT)
        try:
            handle = _open_handle(s, "/replay.bin",
                                  kXR_new | kXR_open_updt | kXR_delete)
            assert _write(s, handle, 0, b"AAAA")[0] == kXR_ok
            _close(s, handle)
        finally:
            s.close()

        # The reopen a recovering client performs, then the "replay".
        s = _session(WRTS_PORT)
        try:
            handle = _open_handle(s, "/replay.bin", kXR_open_updt)
            assert _write(s, handle, 0, b"BBBB")[0] == kXR_ok
            _close(s, handle)
        finally:
            s.close()

        status, data = _read_back(WRTS_PORT, "/replay.bin", 4)
        assert status == kXR_ok and data == b"BBBB", (
            f"read back {data!r} — if this is now b'AAAA' the journal has learnt "
            f"to survive a reopen and #83's second half is fixed")

    def test_the_journalling_server_advertises_the_recovery_it_offers(self, caps):
        """The control the two halves are read against: this server does tell
        clients to replay, which is what makes the journal's behaviour a
        promise rather than an internal detail."""
        flags = _flags(WRTS_PORT)
        assert flags & KXR_RECOVERWRTS, (
            f"word {flags:#010x} lacks kXR_recoverWrts; the journal is armed but "
            f"no client is being told to replay into it")


# --------------------------------------------------------------------------- #
# §D — brix_virtual_redirector off (DEFECT CANDIDATE #85)                      #
# --------------------------------------------------------------------------- #

class TestTheRedirectorRoleTheFlagCannotDeny:
    """`caps.virtual_redirector || (manager_map != NULL && cms.addr == NULL)`
    (session/protocol.c:81-83).  MAP_PORT writes the flag `off` and carries a
    static map with no CMS, so the second disjunct holds.
    """

    def test_off_does_not_clear_the_bit_when_a_map_supplies_it(self, caps):
        """DEFECT CANDIDATE #85: the arm nobody had written turns out not to be
        an arm — this config denies the role and advertises it."""
        flags = _flags(MAP_PORT)
        assert flags & KXR_ATTRVIRTRDR, (
            f"word {flags:#010x} — if kXR_attrVirtRdr is now clear on a static-map "
            f"node that writes brix_virtual_redirector off, the disjunct has "
            f"gained a way to say no and #85 is fixed")

    def test_the_role_bit_brings_the_manager_bit_with_it(self, caps):
        """The disjunct sets kXR_isManager alongside, so an `off` flag also
        cannot stop the node being counted as a manager."""
        flags = _flags(MAP_PORT)
        assert flags & KXR_ISMANAGER, (
            f"word {flags:#010x} advertises attrVirtRdr without isManager, which "
            f"protocol.c:81-83 emits as one expression")

    def test_a_node_with_no_map_takes_the_flag_at_its_word(self, caps):
        """The bound: this is an unconditional disjunct, not a broken flag.  The
        all-`off` server has no map, and its bit is clear."""
        flags = _flags(OFF_PORT)
        assert flags & KXR_ATTRVIRTRDR == 0, (
            f"word {flags:#010x} sets attrVirtRdr with no manager_map and the flag "
            f"written off; #85 would then be a defect in the flag rather than in "
            f"the disjunct")


# --------------------------------------------------------------------------- #
# §E — brix_collapse_redir: the cache (DEFECT CANDIDATE #84)                    #
# --------------------------------------------------------------------------- #

def _await_registration(caps, timeout=25.0):
    """Wait until the data node has registered with the CMS listener.

    The manager registry is process-global and populated by the data node's own
    upward login on a `brix_cms_interval 2` timer — so §E's subject does not
    exist for the first seconds of the instance's life.  The readable proof that
    it does is a redirect: until the registry holds a server the dynamic path
    declines and the manager answers kXR_noserver (open_manager.c:226-230).

    The wait lives here rather than in the fixture so only §E pays for it.
    """
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        status, body = _open_read(COLLOFF_PORT, "/registered.bin")
        if status == KXR_REDIRECT:
            return
        last = (status, body)
        time.sleep(0.5)
    pytest.fail(f"no data server registered with the manager within {timeout}s; "
                f"last open answered {last} — the collapse-cache arms have no "
                f"registry to select out of.\n{caps.errlog()}")


# _open_details moved to _test_audit16j_root_caps_flags_helpers.py so the
# _b split (which reexports only the helpers) can read the access-log detail.



def _open_detail(caps, which, path, nth=1):
    """The DETAIL of the `nth` (1-based) logged open of `path` on one server."""
    hits = _open_details(caps, which, path, nth)
    return hits[nth - 1] if len(hits) >= nth else None


class TestTheCollapseRedirectCache:
    """The cache is consulted only inside `brix_open_manager_dynamic`, which the
    redirect entry point enters only under `conf->manager_mode`
    (open_manager.c:196-203).  Both arms here set manager_mode, so the only
    variable is the flag.

    The cache is process-global (`brix_redir_cache_insert` takes no conf), so
    each arm drives its own path — a path warmed by the `on` arm would be in the
    cache when the `off` arm asked, and the `off` arm's reading would be about
    the gate rather than about the cache.
    """

    def test_the_first_open_is_answered_from_the_registry(self, caps):
        """The control both arms start from: a cold path is a registry select on
        either arm, so the difference measured next is the SECOND open."""
        _await_registration(caps)
        status, body = _open_read(COLLON_PORT, "/cold-on.bin")
        assert status == KXR_REDIRECT, (status, body, caps.errlog())
        detail = _open_detail(caps, "collon", "/cold-on.bin")
        assert detail == "registry", (
            f"first open on the `on` arm was answered from {detail!r}, not the "
            f"registry")

    def test_the_second_open_is_answered_from_the_cache(self, caps):
        """The flag's actual effect, and the only reading in the suite that
        shows the cache being used: the same path again skips the registry."""
        _await_registration(caps)
        assert _open_read(COLLON_PORT, "/warm-on.bin")[0] == KXR_REDIRECT
        assert _open_read(COLLON_PORT, "/warm-on.bin")[0] == KXR_REDIRECT
        details = _open_details(caps, "collon", "/warm-on.bin", 2)
        assert details == ["registry", "redir-cache"], (
            f"the two opens were answered from {details}; the `on` arm inserts "
            f"at open_manager.c:117 and must read at :164")

    def test_the_off_arm_asks_the_registry_every_time(self, caps):
        """The `off` arm nobody had written: same manager_mode, same registry,
        same path twice, and the cache is never consulted."""
        _await_registration(caps)
        assert _open_read(COLLOFF_PORT, "/warm-off.bin")[0] == KXR_REDIRECT
        assert _open_read(COLLOFF_PORT, "/warm-off.bin")[0] == KXR_REDIRECT
        details = _open_details(caps, "colloff", "/warm-off.bin", 2)
        assert details == ["registry", "registry"], (
            f"the two opens were answered from {details}; with the flag off the "
            f"lookup at open_manager.c:164 must not run")

    def test_both_arms_redirect_to_the_registered_data_server(self, caps):
        """Attribution: the flag changes where the ANSWER came from, not what
        the answer is.  A client cannot tell the arms apart."""
        _await_registration(caps)
        _open_read(COLLON_PORT, "/target.bin")
        on_body = _open_read(COLLON_PORT, "/target.bin")[1]
        off_body = _open_read(COLLOFF_PORT, "/target-off.bin")[1]
        assert _redirect_target(on_body)[1] == DS_PORT, _redirect_target(on_body)
        assert _redirect_target(off_body)[1] == DS_PORT, \
            _redirect_target(off_body)

    def test_the_off_arm_does_not_advertise_the_collapse_bit(self, caps):
        """The wire half of the `off` arm, for the client that decides whether
        to trust a cached redirect."""
        flags = _flags(COLLOFF_PORT)
        assert flags & KXR_COLLAPSEREDIR == 0, (
            f"word {flags:#010x} advertises kXR_collapseRedir with the flag "
            f"written off")

    def test_the_on_arm_advertises_it(self, caps):
        flags = _flags(COLLON_PORT)
        assert flags & KXR_COLLAPSEREDIR, (
            f"word {flags:#010x} lacks kXR_collapseRedir with the flag on")

