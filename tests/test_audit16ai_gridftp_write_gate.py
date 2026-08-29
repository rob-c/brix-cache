"""Test cases for audit16ai_gridftp_write_gate — preamble (fixtures/helpers/mocks) lives in
_test_audit16ai_gridftp_write_gate_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16ai_gridftp_write_gate_helpers")


@pytest.mark.parametrize("verb,seed,template,refusal", NS_VERBS,
                         ids=[v[0] for v in NS_VERBS])
class TestTheWrittenOffEqualsItsOmission:
    """`brix_allow_write off` written out, against the same server with
    the line deleted, verb by verb.

    This is the claim the corpus has rested on without making it: every
    "read-only gateway" in the tree is read-only by omission, and the merge
    default is the only reason it is.  `ngx_conf_merge_value` is reached only
    with the slot still NGX_CONF_UNSET, so the two spellings are genuinely
    different paths through ftp_module_merge.c:159 — which is what makes the
    equality a measurement rather than a restatement.
    """

    def test_the_two_disarmed_planes_answer_identically(self, gw, request,
                                                        verb, seed, template,
                                                        refusal):
        name = _uid(request)
        replies = {}
        for label, port in DISARMED:
            _seed_for(gw, label, seed, name)
            replies[label] = _one(port, template.format(n=name))
        assert replies["off"] == replies["absent"], replies

    def test_the_refusal_is_the_string_the_c_carries(self, gw, request, verb,
                                                     seed, template, refusal):
        """Equality alone would be satisfied by two planes that both broke the
        same way, so the shared answer is pinned to the literal in the source."""
        name = _uid(request)
        for label, port in DISARMED:
            _seed_for(gw, label, seed, name)
            reply = _one(port, template.format(n=name))
            assert reply.startswith(refusal), (label, reply)

    def test_neither_disarmed_plane_touched_its_export(self, gw, request, verb,
                                                       seed, template, refusal):
        """The half a reply-code comparison cannot make: a plane that answered
        550 and mutated anyway would pass every cell above."""
        name = _uid(request)
        for label, port in DISARMED:
            _seed_for(gw, label, seed, name)
            before = sorted(p.name for p in gw.export(label).iterdir())
            _one(port, template.format(n=name))
            after = sorted(p.name for p in gw.export(label).iterdir())
            assert before == after, (label, before, after)


class TestTheWrittenOffEqualsItsOmissionForTheTransferVerbs:
    """STOR and APPE, which are refused at the OTHER call site
    (ev_xfer_guards) and carry the other refusal string.

    Split from the parametrized class above because a transfer verb needs a data
    channel and the namespace verbs do not — and because §D's whole subject is
    that these two are the only gated verbs that meter anything.
    """

    @pytest.mark.parametrize("verb", ("STOR", "APPE"))
    def test_the_two_disarmed_planes_refuse_identically(self, gw, request, verb):
        name = _uid(request) + ".bin"
        codes = {label: _stor(port, "/" + name, b"x" * 512, verb=verb)
                 for label, port in DISARMED}
        assert codes["off"] == codes["absent"] == 550, codes

    @pytest.mark.parametrize("verb", ("STOR", "APPE"))
    def test_no_object_appears_on_either_disarmed_export(self, gw, request,
                                                         verb):
        name = _uid(request) + ".bin"
        for label, port in DISARMED:
            _stor(port, "/" + name, b"x" * 512, verb=verb)
            assert not (gw.export(label) / name).exists(), label

    @pytest.mark.parametrize("verb", ("STOR", "APPE"))
    def test_the_refusal_names_the_export_and_not_the_path(self, gw, request,
                                                           verb):
        """ev_xfer_guards' string differs from ns_mutate's by one word —
        "(read-only export)" against "(read-only)" — and that word is the only
        thing on the wire that tells an operator which of the two call sites
        refused.  If they are ever unified, this cell says so."""
        name = _uid(request) + ".bin"
        ftp = _connect(G_OFF)
        try:
            ftp.putcmd("STOR /" + name)
            reply = ftp.getresp()
        except ftplib.Error as exc:
            reply = str(exc)
        finally:
            ftp.close()
        assert reply.startswith("550 Permission denied (read-only export)"), reply


class TestTheInertCompanionChangesNothing:
    """The G_VER face — `allow_write off` beside `verify_write on` — answers
    every gated verb exactly as the two plain disabled faces do.

    #137 is that the composition is accepted; this is that it is also inert.  A
    verify knob that changed a refusal would be a worse bug than a verify knob
    that does nothing, so the equality is stated three-wide rather than two.
    """

    @pytest.mark.parametrize("verb,seed,template,refusal", NS_VERBS,
                             ids=[v[0] for v in NS_VERBS])
    def test_all_three_disarmed_planes_answer_identically(self, gw, request,
                                                          verb, seed, template,
                                                          refusal):
        name = _uid(request)
        replies = {}
        for label, port in ALL_DISARMED:
            _seed_for(gw, label, seed, name)
            replies[label] = _one(port, template.format(n=name))
        assert len(set(replies.values())) == 1, replies
        assert replies["verify"].startswith(refusal), replies

    @pytest.mark.parametrize("verb", ("STOR", "APPE"))
    def test_the_verify_plane_refuses_transfers_too(self, gw, request, verb):
        name = _uid(request) + ".bin"
        assert _stor(G_VER, "/" + name, b"x" * 512, verb=verb) == 550
        assert not (gw.export("verify") / name).exists()


# --------------------------------------------------------------------------- #
# B. The armed control                                                         #
# --------------------------------------------------------------------------- #

class TestTheArmedGateLetsEveryGovernedVerbThrough:
    """The positive half, in the same process, so §A is a statement about the
    flag and not about the build.

    Without these cells a gateway that refused MKD for some unrelated reason
    would satisfy every equality above.
    """

    def test_mkd_creates_a_directory(self, gw, request):
        name = _uid(request)
        reply = _one(G_ON, f"MKD /{name}")
        assert reply.startswith("257"), reply
        assert (gw.export("on") / name).is_dir()

    def test_xmkd_creates_a_directory(self, gw, request):
        name = _uid(request)
        assert _code(_one(G_ON, f"XMKD /{name}")) == 257
        assert (gw.export("on") / name).is_dir()

    def test_dele_removes_a_file(self, gw, request):
        name = _uid(request)
        path = _seed_file(gw, "on", name)
        reply = _one(G_ON, f"DELE /{name}")
        assert reply.startswith("250"), reply
        assert not path.exists()

    @pytest.mark.parametrize("verb", ("RMD", "XRMD"))
    def test_rmd_removes_a_directory(self, gw, request, verb):
        name = _uid(request)
        path = _seed_dir(gw, "on", name)
        reply = _one(G_ON, f"{verb} /{name}")
        assert reply.startswith("250"), reply
        assert not path.exists()

    def test_rnfr_rnto_renames(self, gw, request):
        name = _uid(request)
        src = _seed_file(gw, "on", name, b"rename me\n")
        replies = _sequence(G_ON, [f"RNFR /{name}", f"RNTO /{name}-moved"])
        assert replies[0].startswith("350"), replies
        assert replies[1].startswith("250"), replies
        assert not src.exists()
        assert (gw.export("on") / f"{name}-moved").read_bytes() == b"rename me\n"

    @pytest.mark.parametrize("verb", ("STOR", "APPE"))
    def test_a_transfer_commits(self, gw, request, verb):
        name = _uid(request) + ".bin"
        payload = os.urandom(2048)
        assert _stor(G_ON, "/" + name, payload, verb=verb) == 226
        assert (gw.export("on") / name).read_bytes() == payload

    def test_the_control_writes_land_in_its_own_export(self, gw, request):
        """Four exports under one data root, and the gate is the only thing
        keeping a write on the writable one — so the neighbour check is part of
        the control, not decoration."""
        name = _uid(request) + ".bin"
        assert _stor(G_ON, "/" + name, b"y" * 64) == 226
        for face in ("off", "absent", "verify"):
            assert not (gw.export(face) / name).exists(), face


# --------------------------------------------------------------------------- #
# C. What the runtime says it merged                                           #
# --------------------------------------------------------------------------- #

class TestTheSessionLineReportsTheMergedFlag:
    """ftp_ev_io.c:292 logs `session start (export=%s write=%d)` — the ONE place
    in the whole system where the merged value of the flag is observable without
    provoking it.

    It is at `[info]`, which is a level no production deployment runs, so in
    practice an operator cannot tell a read-only gateway from a writable one
    except by trying to write to it.  That is a smaller finding than #134 and is
    stated here rather than numbered, because the line does exist and does carry
    the right value.
    """

    @pytest.mark.parametrize("face,port,expected", (("on", G_ON, 1),
                                                    ("off", G_OFF, 0),
                                                    ("absent", G_ABS, 0),
                                                    ("verify", G_VER, 0)))
    def test_the_line_carries_the_value_the_face_was_configured_with(
            self, gw, face, port, expected):
        offset = gw.errlog_size()
        ftp = _connect(port)
        ftp.close()
        text = gw.errlog_since(offset)
        lines = [ln for ln in text.splitlines() if "gateway session start" in ln]
        assert lines, text
        assert f"write={expected}" in lines[-1], lines[-1]

    def test_the_written_off_and_the_omission_log_the_same_value(self, gw):
        """The merge default, read off the runtime rather than off the source:
        `write=0` on both, which is the whole of §A's premise in one line."""
        values = {}
        for label, port in DISARMED:
            offset = gw.errlog_size()
            ftp = _connect(port)
            ftp.close()
            text = gw.errlog_since(offset)
            match = re.search(r"gateway session start \(export=\S+ write=(\d)\)",
                              text)
            assert match, text
            values[label] = match.group(1)
        assert values["off"] == values["absent"] == "0", values

    def test_the_line_names_the_export_the_face_serves(self, gw):
        """Four faces, four subtrees: the same line that carries the flag also
        proves the plane under test is the plane that answered."""
        offset = gw.errlog_size()
        ftp = _connect(G_OFF)
        ftp.close()
        text = gw.errlog_since(offset)
        assert f"export={gw.export('off')} write=0" in text, text


# --------------------------------------------------------------------------- #
# D. DEFECT CANDIDATE #134 — the metric asymmetry                              #
# --------------------------------------------------------------------------- #

class TestARefusedTransferIsMeteredAndARefusedMutationIsNot:
    """ev_xfer_guards meters its permission verdict; the other three call sites
    do not meter theirs.

    The comment above ev_xfer_guards explains what it does NOT meter and why —
    "protocol misuse ... the verb never became an operation" — which is a good
    reason that does not apply to MKD, DELE, RMD, RNFR or RNTO.  Each of those
    IS a requested operation with an authorization outcome, and each books
    nothing.
    """

    def test_a_refused_stor_books_a_forbidden_write(self, gw, request):
        before = gw.scrape()
        assert _stor(G_OFF, "/" + _uid(request) + ".bin", b"z" * 128) == 550
        after = gw.scrape()
        assert (gw.ops(after, "write", "forbidden")
                - gw.ops(before, "write", "forbidden")) == 1

    def test_a_refused_appe_books_one_too(self, gw, request):
        before = gw.scrape()
        assert _stor(G_OFF, "/" + _uid(request) + ".bin", b"z" * 128,
                     verb="APPE") == 550
        after = gw.scrape()
        assert (gw.ops(after, "write", "forbidden")
                - gw.ops(before, "write", "forbidden")) == 1

    @pytest.mark.parametrize("verb,seed,template,refusal", NS_VERBS,
                             ids=[v[0] for v in NS_VERBS])
    def test_a_refused_namespace_verb_books_nothing_at_all(self, gw, request,
                                                           verb, seed, template,
                                                           refusal):
        """Not `forbidden` under another op name, not `ok`, not `io` — nothing.

        The comparison is over the whole {proto="gridftp"} plane rather than a
        named series, because "the refusal was booked somewhere else" and "the
        refusal was not booked" are different worlds and only the second one is
        the finding.
        """
        name = _uid(request)
        _seed_for(gw, "off", seed, name)
        before = gw.gridftp_rows(gw.scrape())
        reply = _one(G_OFF, template.format(n=name))
        assert reply.startswith(refusal), reply
        after = gw.gridftp_rows(gw.scrape())

        moved = {k: (before.get(k), after.get(k))
                 for k in set(before) | set(after)
                 if before.get(k) != after.get(k)}
        # The login books an auth row; nothing else may move.
        moved.pop('brix_auth_total{proto="gridftp",method="none",status="ok"}',
                  None)
        assert moved == {}, moved

    def test_seven_refusals_in_one_session_book_two_rows(self, gw, request):
        """The finding in one cell: a client that tries every gated verb once
        leaves a trace of exactly the two the transfer path meters.

        This is what a metrics-based alert on a read-only export would see — two
        `write/forbidden` increments out of nine refusals — and it is why an
        operator watching {proto="gridftp"} cannot distinguish a client probing
        for a writable path from one that never tried.
        """
        name = _uid(request)
        _seed_file(gw, "off", name)
        _seed_dir(gw, "off", name + "-d")

        before = gw.scrape()
        replies = _sequence(G_OFF, [f"MKD /{name}-a", f"XMKD /{name}-b",
                                    f"DELE /{name}", f"RMD /{name}-d",
                                    f"XRMD /{name}-d", f"RNFR /{name}",
                                    f"RNTO /{name}-x"])
        assert all(r[:3] in ("550", "503") for r in replies), replies
        _stor(G_OFF, f"/{name}.bin", b"q" * 32)
        _stor(G_OFF, f"/{name}.bin", b"q" * 32, verb="APPE")
        after = gw.scrape()

        rows_before, rows_after = gw.gridftp_rows(before), gw.gridftp_rows(after)
        ops_moved = {k for k in set(rows_before) | set(rows_after)
                     if k.startswith("brix_io_ops_total")
                     and rows_before.get(k) != rows_after.get(k)}
        assert ops_moved == {
            'brix_io_ops_total{proto="gridftp",op="write",status="forbidden"}'
        }, ops_moved
        assert (gw.ops(after, "write", "forbidden")
                - gw.ops(before, "write", "forbidden")) == 2


# --------------------------------------------------------------------------- #
# E. DEFECT CANDIDATE #134, second half — the log says nothing either          #
# --------------------------------------------------------------------------- #

class TestNoRefusalIsLoggedAtAnyLevel:
    """The template sets `error_log ... info`, the most verbose level an
    operator can practically run, and a refusal produces no line at it.

    A metric that does not move and a log that says nothing are the same finding
    from two directions, and the second is the one that matters to an incident
    responder: after the fact, there is no record that the attempt happened.
    """

    @pytest.mark.parametrize("verb,seed,template,refusal", NS_VERBS,
                             ids=[v[0] for v in NS_VERBS])
    def test_a_refused_namespace_verb_leaves_no_line(self, gw, request, verb,
                                                     seed, template, refusal):
        name = _uid(request)
        _seed_for(gw, "off", seed, name)
        offset = gw.errlog_size()
        reply = _one(G_OFF, template.format(n=name))
        assert reply.startswith(refusal), reply

        text = gw.errlog_since(offset)
        session = ("connected to", "gateway session start",
                   "gateway session end")
        residue = [ln for ln in text.splitlines()
                   if ln.strip() and not any(tag in ln for tag in session)]
        assert residue == [], residue

    def test_a_refused_stor_leaves_no_line_either(self, gw, request):
        """The metered path is no better logged than the unmetered ones, so the
        two halves of #134 do not cancel: nothing anywhere names the refusal."""
        offset = gw.errlog_size()
        assert _stor(G_OFF, "/" + _uid(request) + ".bin", b"z" * 64) == 550
        text = gw.errlog_since(offset)
        assert "denied" not in text.lower(), text
        assert "forbidden" not in text.lower(), text
        assert "read-only" not in text.lower(), text

    def test_the_writable_face_does_log_its_mutations(self, gw, request):
        """The control that makes the silence a finding rather than a property
        of the log: a SUCCESSFUL mkdir on the armed face writes a
        brix_access_json line naming the op, the path and the status."""
        name = _uid(request)
        offset = gw.errlog_size()
        assert _code(_one(G_ON, f"MKD /{name}")) == 257
        text = gw.errlog_since(offset)
        assert "brix_access_json" in text, text
        assert '"op":"mkdir"' in text, text
        assert '"status":"ok"' in text, text

    def test_the_refused_mkdir_produces_no_access_json(self, gw, request):
        """Stated against the cell above: the access log is where a refusal
        would naturally go, and phase-97 §5's "success path only" rule for the
        CNS emitter has, in effect, been applied to the audit record too."""
        name = _uid(request)
        offset = gw.errlog_size()
        assert _one(G_OFF, f"MKD /{name}").startswith("550"), name
        assert "brix_access_json" not in gw.errlog_since(offset)


# --------------------------------------------------------------------------- #
# F. DEFECT CANDIDATE #135 — RNTO's permission branch is unreachable           #
# --------------------------------------------------------------------------- #

class TestRntoNeverReachesItsOwnPermissionCheck:
    """brix_ftp_ev_cmd_rnto tests `rnfr_set` and consumes it BEFORE it tests
    `allow_write`.  `rnfr_set` is set in one place — the tail of
    brix_ftp_ev_cmd_rnfr — which is behind the same gate.

    So on a read-only export the second check is dead: no dialogue can arrive at
    RNTO with a pairing armed.  The cells below try the three shapes a client
    could use to arm one and measure that none does.
    """

    def test_a_bare_rnto_is_503_and_not_550(self, gw, request):
        reply = _one(G_OFF, f"RNTO /{_uid(request)}")
        assert reply.startswith("503 RNFR required first"), reply

    def test_rnfr_then_rnto_is_still_503(self, gw, request):
        """The pairing a client would actually send.  RNFR is refused, so it
        never sets `rnfr_set`, so RNTO answers as though RNFR had not been sent
        — which is true, and is why the 550 below it is unreachable."""
        name = _uid(request)
        _seed_file(gw, "off", name)
        replies = _sequence(G_OFF, [f"RNFR /{name}", f"RNTO /{name}-moved"])
        assert replies[0].startswith("550 Permission denied (read-only)"), replies
        assert replies[1].startswith("503 RNFR required first"), replies
        assert (gw.export("off") / name).exists()
        assert not (gw.export("off") / f"{name}-moved").exists()

    def test_a_repeated_rnfr_rnto_pair_does_not_arm_it(self, gw, request):
        """The one shape that could in principle differ: state left by a first
        failed pairing changing the answer to a second.  It does not — the
        refusal is before every assignment to `rnfr_set`."""
        name = _uid(request)
        _seed_file(gw, "off", name)
        replies = _sequence(G_OFF, [f"RNFR /{name}", f"RNTO /{name}-1",
                                    f"RNFR /{name}", f"RNTO /{name}-2"])
        assert [r[:3] for r in replies] == ["550", "503", "550", "503"], replies

    def test_the_armed_face_proves_the_dead_line_is_the_only_difference(
            self, gw, request):
        """On the writable face the same dialogue reaches RNTO with the pairing
        armed and renames — so `rnfr_set` is reachable, and it is the GATE on
        RNFR, not a broken pairing, that makes the RNTO check dead."""
        name = _uid(request)
        _seed_file(gw, "on", name)
        replies = _sequence(G_ON, [f"RNFR /{name}", f"RNTO /{name}-moved"])
        assert replies[0].startswith("350"), replies
        assert replies[1].startswith("250"), replies

    def test_a_bare_rnto_on_the_armed_face_is_also_503(self, gw, request):
        """The pairing check itself is not the finding and behaves the same on
        both faces; without this cell the 503 in the first case could be read as
        a read-only artefact."""
        assert _one(G_ON, f"RNTO /{_uid(request)}").startswith("503"), "armed"


# --------------------------------------------------------------------------- #
# G. Ordering — the verdict is reached before the data channel is              #
# --------------------------------------------------------------------------- #

