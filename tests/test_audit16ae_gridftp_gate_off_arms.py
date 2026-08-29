"""Test cases for audit16ae_gridftp_gate_off_arms — preamble (fixtures/helpers/mocks) lives in
_test_audit16ae_gridftp_gate_off_arms_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16ae_gridftp_gate_off_arms_helpers")


@pytest.mark.parametrize("shape,allo,sent", ALLO_SHAPES)
class TestTheWrittenAlloOffEqualsItsOmission:
    """`brix_gridftp_require_allo_size off` written out, against the same server
    with the line deleted.

    This is the claim test_gridftp_allo_truncation.py's `gw_lenient` fixture
    rests on and does not make: it calls its control arm "off" and renders
    nothing.  Four ALLO shapes × two planes, and every cell must agree on the
    completion code AND on the bytes that reached the disk — a plane that
    accepted the transfer but committed something different would pass a
    code-only comparison.
    """

    def test_the_two_disarmed_planes_answer_identically(self, gates, request,
                                                        shape, allo, sent):
        codes = {}
        sizes = {}
        for label, port in DISARMED:
            name = f"{_uid(request)}-{label}.bin"
            codes[label] = _stor(port, name, os.urandom(sent), allo=allo)
            sizes[label] = gates.size(name)
        assert codes["off"] == codes["absent"], codes
        assert sizes["off"] == sizes["absent"] == sent, sizes

    def test_a_disarmed_plane_accepts_every_shape(self, gates, request,
                                                  shape, allo, sent):
        """The positive half, stated separately so a regression that made BOTH
        disarmed planes refuse would fail here rather than silently satisfying
        the equality above."""
        for label, port in DISARMED:
            name = f"{_uid(request)}-{label}.bin"
            code = _stor(port, name, os.urandom(sent), allo=allo)
            assert code == 226, f"{label}/{shape}: {code}"


class TestTheArmedAlloGateStillFires:
    """The armed arm, in the same process, so the equality above is a statement
    about the flag and not about the build.

    Overlaps test_gridftp_allo_truncation.py deliberately: that file proves the
    guard exists, this one proves the two disarmed spellings are the same thing
    the guard is being compared against.
    """

    @pytest.mark.parametrize("port,plane", ((W_ON, "both-on"),
                                            (W_AONLY, "allo-only")))
    @pytest.mark.parametrize("shape,allo,sent", (("short", 4000, 2500),
                                                 ("over", 4000, 5000)))
    def test_a_mismatched_length_is_refused(self, gates, request, port, plane,
                                            shape, allo, sent):
        name = f"{_uid(request)}.bin"
        assert _stor(port, name, os.urandom(sent), allo=allo) == 550

    @pytest.mark.parametrize("port,plane", ((W_ON, "both-on"),
                                            (W_AONLY, "allo-only")))
    def test_an_exact_length_still_commits(self, gates, request, port, plane):
        """No false positive, and the cell that makes the two refusals above
        mean something."""
        payload = os.urandom(4000)
        name = f"{_uid(request)}.bin"
        assert _stor(port, name, payload, allo=4000) == 226
        assert gates.disk(name).read_bytes() == payload

    @pytest.mark.parametrize("port,plane", ((W_ON, "both-on"),
                                            (W_AONLY, "allo-only")))
    def test_a_stor_with_no_allo_is_unaffected(self, gates, request, port,
                                               plane):
        """ftp_gateway.h:63-64 — "A STOR with no preceding ALLO is unaffected
        either way".  The armed planes are the only place that sentence can be
        measured, and it is the sentence that keeps the flag from being a
        blanket refusal of clients that do not send ALLO."""
        payload = os.urandom(2500)
        name = f"{_uid(request)}.bin"
        assert _stor(port, name, payload) == 226
        assert gates.disk(name).read_bytes() == payload


# --------------------------------------------------------------------------- #
# B. brix_verify_write — the written `off` against its omission         #
# --------------------------------------------------------------------------- #

class TestTheWrittenVerifyOffEqualsItsOmission:
    """The second never-written token, measured the same way.

    `verify_write` reads each STOR back through the driver and CRC-checks it
    (ftp_gateway.h:39-45), so on a clean transfer every arm must agree — the
    check passing is indistinguishable from the check not running, which is
    exactly why the interesting cells are §C and §D and not here.  What is here
    is the equality the corpus assumes.
    """

    @pytest.mark.parametrize("size", (0, 1, 1234, 200000))
    def test_a_clean_stor_round_trips_on_every_write_plane(self, gates, request,
                                                           size):
        """Including zero bytes, which is the shape a verifier is most likely to
        get wrong: an empty accumulator's CRC and an empty file's are both
        trivially equal, but the length comparison in brix_vfs_wverify_check is
        against a file that must exist at all."""
        payload = os.urandom(size)
        for label, port in ALL_WRITE:
            name = f"{_uid(request)}-{label}.bin"
            code = _stor(port, name, payload)
            assert code == 226, f"{label}: {code}"
            assert gates.disk(name).read_bytes() == payload, label

    def test_the_two_disarmed_planes_are_byte_identical(self, gates, request):
        payload = os.urandom(48000)
        stored = {}
        for label, port in DISARMED:
            name = f"{_uid(request)}-{label}.bin"
            assert _stor(port, name, payload) == 226
            stored[label] = gates.disk(name).read_bytes()
        assert stored["off"] == stored["absent"] == payload

    def test_an_overwrite_of_an_existing_object_agrees_across_the_arms(
            self, gates, request):
        """A STOR onto a name that already holds bytes: the verifier reopens the
        object it just wrote, so a stale-length or append-instead-of-truncate
        bug would show here and only here."""
        for label, port in ALL_WRITE:
            name = f"{_uid(request)}-{label}.bin"
            assert _stor(port, name, b"A" * 5000) == 226
            assert _stor(port, name, b"B" * 300) == 226
            assert gates.disk(name).read_bytes() == b"B" * 300, label


# --------------------------------------------------------------------------- #
# C. The composition — the flag named for verification is not the one that      #
#    catches a truncated write                                                  #
# --------------------------------------------------------------------------- #

class TestTheTwoGatesAnswerForDifferentFailures:
    """W_VONLY and W_AONLY differ from each other by exactly two lines, and are
    the two configurations an operator would reach for after reading the names.

    No defect number: ftp_gateway.h:39-45 says plainly that `verify_write` is a
    STORAGE-persistence check and not a wire check, so it declining to notice a
    short delivery is the documented behaviour.  It is recorded because the
    documentation that says so is a C header comment, and the two directive
    names alone point the other way.
    """

    def test_verify_only_accepts_a_truncated_upload(self, gates, request):
        """`verify_write on`, `require_allo_size off`: the client declared 4000
        bytes, delivered 2500, and got 226 with the short object committed
        under its final name.  The read-back verified what was written, which
        is not what was promised."""
        name = f"{_uid(request)}.bin"
        assert _stor(W_VONLY, name, os.urandom(2500), allo=4000) == 226
        assert gates.size(name) == 2500

    def test_allo_only_refuses_the_same_upload(self, gates, request):
        """The mirror image, two lines different: `verify_write off`,
        `require_allo_size on` → 550."""
        name = f"{_uid(request)}.bin"
        assert _stor(W_AONLY, name, os.urandom(2500), allo=4000) == 550

    def test_the_two_crosses_disagree_on_the_same_bytes(self, gates, request):
        """Both statements in one cell, on one payload, so the difference cannot
        be blamed on the data."""
        payload = os.urandom(2500)
        vonly = f"{_uid(request)}-vonly.bin"
        aonly = f"{_uid(request)}-aonly.bin"
        assert _stor(W_VONLY, vonly, payload, allo=4000) == 226
        assert _stor(W_AONLY, aonly, payload, allo=4000) == 550
        assert gates.disk(vonly).read_bytes() == payload

    def test_verify_only_matches_the_fully_disarmed_planes(self, gates,
                                                           request):
        """And the sharper form: on a truncated upload, the plane with the
        integrity check armed is indistinguishable from the plane with nothing
        armed at all."""
        codes = {}
        for label, port in (("verify-only", W_VONLY),) + DISARMED:
            name = f"{_uid(request)}-{label}.bin"
            codes[label] = _stor(port, name, os.urandom(2500), allo=4000)
        assert codes["verify-only"] == codes["off"] == codes["absent"] == 226, \
            codes


# --------------------------------------------------------------------------- #
# D. DEFECT CANDIDATE #112 — a client-chosen REST turns verify_write off        #
# --------------------------------------------------------------------------- #

class TestARestOffsetDisablesTheOperatorsVerification:
    """ftp_ev_xfer.c:374:

        *verify = (fc->conf->verify_write && *start == 0);

    `*start` is the REST offset the CLIENT sent.  The operator's directive is
    ANDed with a value under the peer's control, so `REST 1` before every STOR
    is a complete, silent opt-out of the integrity check on a server configured
    to require it.

    THE MEASUREMENT IS A POSITIVE, NOT AN ABSENCE.  A cell asserting "no verify
    happened" by asserting nothing went wrong would pass under any
    implementation.  This one is built so that a verifier which HAD run would
    have destroyed the evidence: brix_vfs_wverify_check compares the
    accumulator's total against `brix_vfs_file_size(rfh)` and returns NGX_ERROR
    on a mismatch, which unlinks the object and fails the transfer.  After
    `REST 10` and 20 delivered bytes the accumulator holds 20 while the file
    holds 100 — so the file still being there, still 100 bytes, still answering
    226, is proof the comparison never happened.
    """

    @pytest.mark.parametrize("label,port", ALL_WRITE)
    def test_a_rest_stor_is_accepted_and_leaves_the_object_intact(
            self, gates, request, label, port):
        name = f"{_uid(request)}.bin"
        assert _stor(port, name, b"X" * 100) == 226
        assert gates.size(name) == 100
        code = _stor(port, name, b"Y" * 20, rest=10)
        assert code == 226, f"{label}: {code}"
        assert gates.size(name) == 100, (
            f"{label}: the object changed size, so the write path is not the "
            f"one this cell reasons about")

    def test_the_verifying_plane_is_indistinguishable_from_the_disarmed_ones(
            self, gates, request):
        """The finding in one sentence: with `REST 10` in front of it, the plane
        with `verify_write on` behaves exactly like the plane with
        `verify_write off` and exactly like the plane that never wrote the
        line."""
        results = {}
        for label, port in ALL_WRITE:
            name = f"{_uid(request)}-{label}.bin"
            _stor(port, name, b"X" * 100)
            results[label] = (_stor(port, name, b"Y" * 20, rest=10),
                              gates.size(name))
        assert results["both-on"] == results["off"] == results["absent"] == \
            (226, 100), results

    @pytest.mark.parametrize("label,port", ALL_WRITE)
    def test_rest_zero_is_the_control_and_writes_from_the_start(
            self, gates, request, label, port):
        """`REST 0` satisfies `*start == 0`, so the verifier DOES run — and the
        write is an ordinary truncating STOR.  Without this control, "the file
        was unchanged" could be read as "REST always no-ops", which would make
        the cells above say nothing."""
        name = f"{_uid(request)}.bin"
        assert _stor(port, name, b"X" * 100) == 226
        assert _stor(port, name, b"Y" * 20, rest=0) == 226
        assert gates.size(name) == 20, label
        assert gates.disk(name).read_bytes() == b"Y" * 20

    @pytest.mark.parametrize("argument", ("-1", "abc", ""))
    def test_a_negative_or_unparseable_rest_is_refused(self, gates, argument):
        """The gate that keeps the offset a non-negative integer
        (ftp_ev_dispatch.c:168-171).  It holds for the cases it covers — the
        finding above is not that REST is unvalidated, it is that a VALID REST
        disables an unrelated control."""
        reply = _reply(_dialogue(W_ON, [f"REST {argument}".rstrip()],
                                 login=True)[0])
        assert reply.startswith("501"), (argument, reply)


class TestTheRestOffsetParserIsLax:
    """What the same three lines do NOT reject, measured because §D leans on
    them and because the shape is the one that hides an off-by-one.

        long long off = strtoll(arg, &endp, 10);
        if (arg[0] == '\0' || endp == arg || off < 0) ... 501

    `endp == arg` catches "no digits at all"; nothing catches "digits followed
    by something else", and nothing checks errno for ERANGE.  No defect number:
    RFC 959 does not say a server must refuse a trailing byte, every observed
    outcome is a refusal or a correct prefix, and the saturating case fails the
    transfer rather than committing anything.  It is recorded so that a future
    change to this parser is a change to a measured behaviour.
    """

    @pytest.mark.parametrize("argument,offset", (("9x", "9"),
                                                 ("10abc", "10"),
                                                 ("0x10", "0"),
                                                 ("+5", "5"),
                                                 ("-0", "0"),
                                                 ("-0.5", "0"),
                                                 (" 12", "12")))
    def test_a_trailing_or_signed_argument_is_accepted_as_its_prefix(
            self, gates, argument, offset):
        """`0x10` is the sharpest: a client that wrote a hex offset is told
        `350` and gets offset 0, which is a silent restart from the beginning
        rather than a refusal."""
        reply = _reply(_dialogue(W_ON, [f"REST {argument}"], login=True)[0])
        assert reply.startswith(f"350 Restart position accepted ({offset}"), \
            (argument, reply)

    def test_an_out_of_range_offset_saturates_rather_than_failing(self, gates):
        """strtoll clamps to LLONG_MAX and sets ERANGE; errno is not read, so
        the reply is a 350 for an offset the client never asked for."""
        reply = _reply(_dialogue(W_ON, ["REST 99999999999999999999999999"],
                                 login=True)[0])
        assert reply.startswith("350 Restart position accepted "
                                "(9223372036854775807"), reply

    def test_a_stor_at_the_saturated_offset_fails_but_leaves_an_empty_object(
            self, gates, request):
        """The one consequence worth stating: the transfer is refused 550, and
        the name is left holding a zero-byte file.  Same shape as §E — the
        refusal is on the control channel and the object is already gone."""
        name = f"{_uid(request)}.bin"
        assert _stor(W_ON, name, b"Z" * 10,
                     rest="99999999999999999999999999") == 550
        assert gates.size(name) == 0, gates.size(name)


# --------------------------------------------------------------------------- #
# E. DEFECT CANDIDATE #113 — the refused object is left readable                #
# --------------------------------------------------------------------------- #

class TestARefusedUploadStaysOnDiskAndServes:
    """A 550 from the ALLO gate is a refusal on the control channel only.

    The object keeps its final name, its bytes, and its readability: SIZE
    reports it, RETR serves it, and nothing about it says "partial".  The doc
    comment says the prefix is left in place deliberately, for a REST-resume,
    and that is a defensible choice — but a resume story needs a way to tell a
    resumable prefix from a complete file, and there is none.  The over-long
    case is worse than the short one: the object left behind is LONGER than the
    ALLO the refusal was based on.
    """

    @pytest.mark.parametrize("shape,allo,sent", (("short", 4000, 2500),
                                                 ("over", 4000, 5000)))
    def test_the_refused_bytes_are_still_on_disk(self, gates, request, shape,
                                                 allo, sent):
        name = f"{_uid(request)}.bin"
        assert _stor(W_ON, name, os.urandom(sent), allo=allo) == 550
        assert gates.size(name) == sent, (
            f"{shape}: refused {sent} bytes, disk holds {gates.size(name)}")

    @pytest.mark.parametrize("shape,allo,sent", (("short", 4000, 2500),
                                                 ("over", 4000, 5000)))
    def test_size_reports_the_refused_object_as_an_ordinary_file(
            self, gates, request, shape, allo, sent):
        """`SIZE` is the command a client uses to decide whether it already has
        the file.  It answers 213 with the partial length — the same reply
        shape a complete file of that length would draw."""
        name = f"{_uid(request)}.bin"
        assert _stor(W_ON, name, os.urandom(sent), allo=allo) == 550
        assert _size(W_ON, name) == f"213 {sent}", _size(W_ON, name)

    @pytest.mark.parametrize("shape,allo,sent", (("short", 4000, 2500),
                                                 ("over", 4000, 5000)))
    def test_retr_serves_the_refused_object_in_full(self, gates, request,
                                                    shape, allo, sent):
        """And the consequence: the next client to GET the name is served the
        rejected bytes with a 226, with no way to know the upload that produced
        them was refused."""
        payload = os.urandom(sent)
        name = f"{_uid(request)}.bin"
        assert _stor(W_ON, name, payload, allo=allo) == 550
        code, body = _retr(W_ON, name)
        assert code == 226, code
        assert body == payload

    def test_the_refusal_does_not_disturb_a_previous_complete_object(
            self, gates, request):
        """The other half of the same fact, and the one that decides how bad it
        is: a refused STOR overwrites what was there.  A client that re-uploads
        a file it already has, and is truncated mid-flight, ends with the
        partial — the 550 does not restore the previous contents."""
        name = f"{_uid(request)}.bin"
        assert _stor(W_ON, name, b"C" * 4000, allo=4000) == 226
        assert _stor(W_ON, name, b"D" * 2500, allo=4000) == 550
        assert gates.disk(name).read_bytes() == b"D" * 2500

    def test_a_disarmed_plane_leaves_the_same_bytes_with_a_226(self, gates,
                                                               request):
        """The comparison that says what the flag actually buys: on the
        disarmed planes the identical truncation leaves the identical file and
        answers 226 instead of 550.  The whole difference the operator paid for
        is the reply code — the disk is the same either way."""
        payload = os.urandom(2500)
        armed = f"{_uid(request)}-armed.bin"
        assert _stor(W_ON, armed, payload, allo=4000) == 550
        for label, port in DISARMED:
            name = f"{_uid(request)}-{label}.bin"
            assert _stor(port, name, payload, allo=4000) == 226
            assert gates.disk(name).read_bytes() == \
                gates.disk(armed).read_bytes(), label


# --------------------------------------------------------------------------- #
# F. brix_gridftp_gsi — the written `off`, and DEFECT CANDIDATE #111            #
# --------------------------------------------------------------------------- #

class TestTheWrittenGsiOffEqualsItsOmission:
    """G_OFF carries `brix_gridftp_gsi off` BESIDE a certificate, key and CA;
    G_ABS carries the same three PKI directives and no flag.

    The material is what makes this a measurement of the flag rather than of
    the deployment: ftp_module_merge.c:142 only builds a GSI context when
    `enable && gsi`, so without the certificate present on both planes, `off`
    and "no GSI configured" would be the same server and the equality would be
    trivially true for the wrong reason.
    """

    @pytest.mark.parametrize("command", ("FEAT", "AUTH GSSAPI", "AUTH TLS",
                                         "AUTH XYZ", "PBSZ 0", "PROT C",
                                         "PROT P", "ADAT AAAA"))
    def test_the_two_disarmed_planes_answer_identically(self, gates, command):
        off = _dialogue(G_OFF, [command])[0]
        absent = _dialogue(G_ABS, [command])[0]
        assert off == absent, (command, off, absent)

    def test_the_disarmed_planes_advertise_no_security_extensions(self, gates):
        """FEAT is the only place the flag is visible to a client that has not
        tried to authenticate, so it is the one that decides whether a peer can
        discover the arm before committing to it."""
        for label, port in GSI_DISARMED:
            feat = _dialogue(port, ["FEAT"])[0]
            text = " ".join(feat)
            assert "AUTH GSSAPI" not in text, (label, feat)
            assert " DCAU" not in text, (label, feat)
            assert "SIZE" in text and "REST STREAM" in text, (label, feat)

    @pytest.mark.parametrize("mechanism", ("GSSAPI", "TLS", "XYZ"))
    def test_every_auth_mechanism_is_refused_on_a_disarmed_plane(self, gates,
                                                                 mechanism):
        """534 for all three, including the one the server would understand if
        the flag were on — a disarmed plane does not distinguish "unknown
        mechanism" from "mechanism not offered", which is the right answer."""
        for label, port in GSI_DISARMED:
            reply = _reply(_dialogue(port, [f"AUTH {mechanism}"])[0])
            assert reply.startswith("534"), (label, mechanism, reply)

    def test_adat_before_auth_is_refused_on_every_plane(self, gates):
        """The state machine's floor, and the same on all three arms: ADAT is
        meaningless without an accepted AUTH, and the armed plane does not
        relax it."""
        for label, port in ALL_GSI:
            reply = _reply(_dialogue(port, ["ADAT AAAA"])[0])
            assert reply.startswith("503"), (label, reply)

