"""Test cases for audit16v_tpc_off_arms — preamble (fixtures/helpers/mocks) lives in
_test_audit16v_tpc_off_arms_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16v_tpc_off_arms_helpers")


# --------------------------------------------------------------------------- #
# A — brix_tpc_allow_local off: the address gate, and whether the token and the
#     omission are the same zero
# --------------------------------------------------------------------------- #
class TestTheAddressGateArm:

    def test_the_disarmed_plane_refuses_a_loopback_source(self, planes):
        """[error] The token, doing the thing no config had ever asked it to."""
        status, err, _dst = planes.pull("disarmed", "root://127.0.0.1//x.dat")  # net-literal-allow: the loopback source the arm under test governs
        assert status == kXR_error, status
        assert "resolves to a prohibited address" in err, err
        assert "allow_local=0" in err, err

    def test_the_absent_plane_refuses_it_identically(self, planes):
        """The claim the corpus has been resting on, measured.

        Four of the seven disarming arms are also the compiled default, and
        every existing test of them reads the default off a plane that writes
        nothing.  If the token and the omission ever diverged, everything those
        tests prove would be about a configuration no operator wrote.  Same
        refusal, same printed merge value, is what makes them interchangeable.
        """
        status, err, _dst = planes.pull("absent", "root://127.0.0.1//x.dat")  # net-literal-allow: the loopback source the arm under test governs
        assert status == kXR_error, status
        assert "resolves to a prohibited address" in err, err
        assert "allow_local=0" in err, err

    def test_the_armed_plane_admits_the_same_source(self, planes):
        """[success] The control: on with the same URL, the address gate is not
        what answers.  Some later leg may still fail — nothing is listening on
        the default TPC port — but not this one."""
        status, err, _dst = planes.pull("armed", "root://127.0.0.1//x.dat")  # net-literal-allow: the loopback source the arm under test governs
        assert status == kXR_error, status
        assert "prohibited" not in err, err

    def test_the_pulling_plane_admits_it_too(self, planes):
        """PULLING carries the ARMED value of this one directive; that is the
        whole reason it can measure the other six."""
        status, err, _dst = planes.pull("pulling", "root://127.0.0.1//x.dat")  # net-literal-allow: the loopback source the arm under test governs
        assert status == kXR_error, status
        assert "prohibited" not in err, err

    def test_link_local_follows_the_same_arm(self, planes):
        """The flag covers loopback AND link-local; the arm must not be read as
        "127/8 only"."""
        status, err, _dst = planes.pull("disarmed", "root://169.254.0.1//x.dat")
        assert status == kXR_error, status
        assert "resolves to a prohibited address" in err, err
        status, err, _dst = planes.pull("pulling", "root://169.254.0.1//x.dat")
        assert status == kXR_error, status
        assert "prohibited" not in err, err

    def test_the_arm_does_not_reach_private_ranges(self, planes):
        """[security-neg, inverted] A disarming arm that refused MORE than it
        governs would look like a working gate while breaking unrelated pulls.
        RFC-1918 is brix_tpc_allow_private's business (default on, deliberately
        untouched by this config), so it must pass the same plane that just
        refused loopback."""
        status, err, _dst = planes.pull("disarmed", "root://10.255.255.1//x.dat")
        assert status == kXR_error, status
        assert "prohibited" not in err, (
            "allow_local off must not close the private ranges: %r" % err)

    def test_the_refusal_prints_the_merged_value(self, planes):
        """Why this arm is measurable at all rather than inferred.

        ``net_target_dns.c`` formats both flags into the refusal, so "the
        explicit off produced the same merged value as the omission" is read off
        the wire instead of argued from the merge function.
        """
        _s, off_err, _d = planes.pull("disarmed", "root://127.0.0.1//x.dat")  # net-literal-allow: the loopback source the arm under test governs
        _s, absent_err, _d = planes.pull("absent", "root://127.0.0.1//x.dat")  # net-literal-allow: the loopback source the arm under test governs
        assert "allow_local=0 allow_private=1" in off_err, off_err
        assert "allow_local=0 allow_private=1" in absent_err, absent_err


# --------------------------------------------------------------------------- #
# B — brix_tpc_source_guard off: the naming gate
# --------------------------------------------------------------------------- #
class TestTheNamingGateArm:

    # A loopback literal on NEITHER allowlist: the guard matches the string the
    # client asked for, so 127.0.0.2 and 127.0.0.1 are two different hosts even
    # though one machine answers both.
    UNLISTED = "127.0.0.2"  # net-literal-allow: an unlisted loopback literal is the point

    def test_the_armed_plane_refuses_a_host_off_the_allowlist(self, planes):
        """[error] The arm the corpus writes, refusing by NAME."""
        status, err, _dst = planes.pull(
            "armed", f"root://{self.UNLISTED}//x.dat")
        assert status == kXR_error, status
        assert "TPC source host not permitted" in err, err
        assert self.UNLISTED in err, err

    def test_the_pulling_plane_admits_it(self, planes):
        """The token nothing had written: the guard is off, so the name is not
        consulted and the pull proceeds to the gates that follow."""
        status, err, _dst = planes.pull(
            "pulling", f"root://{self.UNLISTED}//x.dat")
        assert status == kXR_error, status
        assert "not permitted" not in err, err

    def test_the_absent_plane_matches_the_explicit_off(self, planes):
        """ABSENT writes neither guard, and this plane also leaves allow_local
        unset — so the refusal it gives is the ADDRESS gate's, which is itself
        the proof that the naming gate stayed silent."""
        status, err, _dst = planes.pull(
            "absent", f"root://{self.UNLISTED}//x.dat")
        assert status == kXR_error, status
        assert "not permitted" not in err, err
        assert "resolves to a prohibited address" in err, err

    def test_the_two_gates_are_distinguishable_on_one_url(self, planes):
        """One source, four answers — which is what makes the messages evidence.

        ARMED refuses by name; DISARMED (guard off, allow_local off) refuses by
        address; PULLING refuses by neither; ORDERING has both armed and answers
        with the naming gate, which is §C's subject.
        """
        url = f"root://{self.UNLISTED}//x.dat"
        _s, armed, _d = planes.pull("armed", url)
        _s, disarmed, _d = planes.pull("disarmed", url)
        _s, pulling, _d = planes.pull("pulling", url)
        assert "not permitted" in armed and "prohibited" not in armed, armed
        assert "prohibited" in disarmed and "not permitted" not in disarmed, \
            disarmed
        assert "not permitted" not in pulling and "prohibited" not in pulling, \
            pulling

    def test_the_allowlist_admits_the_names_it_lists(self, planes):
        """[success] The guard is an allowlist, not a blocklist: the two entries
        ARMED does write must pass it."""
        # net-literal-allow: the allowlist entries under test are loopback names
        for host in ("localhost", BIND_HOST):  # net-literal-allow: as above
            status, err, _dst = planes.pull("armed", f"root://{host}//x.dat")
            assert status == kXR_error, status
            assert "not permitted" not in err, (host, err)


# --------------------------------------------------------------------------- #
# C — the order of the two gates, which is a security property of its own
# --------------------------------------------------------------------------- #
class TestWhichGateAnswersFirst:

    def test_a_loopback_literal_gets_the_naming_refusal(self, planes):
        """ORDERING has the naming gate armed and the address gate closed, so
        both would refuse.  The one that answers is the one that ran first."""
        status, err, _dst = planes.pull("ordering", "root://127.0.0.2//x.dat")  # net-literal-allow: an unlisted loopback literal both gates would refuse
        assert status == kXR_error, status
        assert "TPC source host not permitted" in err, err
        assert "prohibited" not in err, err

    def test_an_unresolvable_name_is_refused_without_a_lookup(self, planes):
        """[security-neg] The guard must not be a DNS oracle.

        A host the operator never allowlisted is refused on its NAME, so an
        attacker cannot use a TPC request to make the server resolve arbitrary
        names.  ``net_resolve_host`` has its own distinct message; seeing the
        guard's instead is what proves no lookup happened.
        """
        status, err, _dst = planes.pull(
            "ordering", f"root://{_unresolvable()}//x.dat")
        assert status == kXR_error, status
        assert "TPC source host not permitted" in err, err
        assert "DNS resolution failed" not in err, err

    def test_a_listed_name_then_meets_the_address_gate(self, planes):
        """Both gates are live on this plane — otherwise the test above would
        pass on a server whose address gate was simply broken."""
        status, err, _dst = planes.pull("ordering", "root://localhost//x.dat")  # net-literal-allow: the ORDERING allowlist entry is a loopback name
        assert status == kXR_error, status
        assert "not permitted" not in err, err
        assert "prohibited" in err and "allow_local=0" in err, err

    def test_a_guardless_plane_does_reach_the_resolver(self, planes):
        """The other half: with the guard off the same unresolvable name gets a
        DNS failure, so the silence on ORDERING was the guard's doing and not a
        resolver that never answers."""
        status, err, _dst = planes.pull(
            "pulling", f"root://{_unresolvable()}//x.dat")
        assert status == kXR_error, status
        assert "DNS resolution failed" in err, err

    def test_the_c_runs_the_guard_before_the_policy(self):
        """The source pin behind the whole section."""
        text = _source(PREPARE_C)
        guard = text.index("brix_tpc_source_guard_check(")
        policy = text.index("brix_tpc_check_src_policy(", guard)
        assert guard < policy, "the naming gate no longer precedes the address gate"
        assert "without a DNS lookup" in text[:policy], (
            "the ordering is no longer documented as deliberate")
        assert "TPC source host not permitted" in _source(GUARD_C)


# --------------------------------------------------------------------------- #
# D — brix_require_pgwrite off: the wire-integrity gate on native uploads
# --------------------------------------------------------------------------- #
class TestTheCleartextWriteArm:

    def _upload(self, planes, plane, remote, data):
        sock = _handshake_login(HOST, planes.port(plane))
        try:
            fh = _open(sock, remote.encode())
            status, err = _write(sock, fh, 0, data)
            if status == kXR_OK:
                _close(sock, fh)
            return status, err
        finally:
            sock.close()

    def test_the_armed_plane_refuses_a_cleartext_write(self, planes):
        """[error] The arm the corpus writes."""
        remote = f"/audit16v_pgw_on_{uuid.uuid4().hex}.bin"
        status, err = self._upload(planes, "armed", remote, os.urandom(4096))
        assert status == kXR_error, status
        assert err == kXR_Unsupported, err
        path = planes.disk(remote)
        assert not path.exists() or path.stat().st_size == 0, \
            "a refused cleartext write must not commit bytes"

    def test_the_disarmed_plane_accepts_it(self, planes):
        """[the token] What ``brix_require_pgwrite off`` buys: the stock upload
        op, back."""
        remote = f"/audit16v_pgw_off_{uuid.uuid4().hex}.bin"
        data = os.urandom(4096)
        status, err = self._upload(planes, "disarmed", remote, data)
        assert status == kXR_OK, (status, err)
        assert planes.disk(remote).read_bytes() == data

    def test_the_absent_plane_accepts_it_identically(self, planes):
        """``nginx_root_require_pgwrite.conf`` says of its OFF_PORT plane that
        the directive is "deliberately omitted (default off)" and tests the
        permissive path there.  This is the assertion that entitles it to."""
        remote = f"/audit16v_pgw_absent_{uuid.uuid4().hex}.bin"
        data = os.urandom(4096)
        status, err = self._upload(planes, "absent", remote, data)
        assert status == kXR_OK, (status, err)
        assert planes.disk(remote).read_bytes() == data

    def test_the_armed_plane_refuses_writev_too(self, planes):
        """[security-neg] kXR_writev is the sibling op with no CRC; a gate that
        only closed kXR_write would be trivially side-stepped."""
        remote = f"/audit16v_pgw_wv_{uuid.uuid4().hex}.bin"
        sock = _handshake_login(HOST, planes.port("armed"))
        try:
            fh = _open(sock, remote.encode())
            status, err = _writev(sock, [(fh, 0, os.urandom(2048))])
        finally:
            sock.close()
        assert status == kXR_error, status
        assert err == kXR_Unsupported, err
        path = planes.disk(remote)
        assert not path.exists() or path.stat().st_size == 0

    def test_the_armed_plane_still_takes_a_pgwrite(self, planes):
        """[success / no false positive] The gate names the path it wants; the
        arm is only meaningful if that path still works beside all six of the
        TPC directives this plane also carries."""
        remote = f"/audit16v_pgw_ok_{uuid.uuid4().hex}.bin"
        data = os.urandom(6000)
        sock = _handshake_login(HOST, planes.port("armed"))
        try:
            fh = _open(sock, remote.encode())
            status, _off, cse = send_pgwrite(sock, fh, 0,
                                             build_payload(data, 0))
            assert status == kXR_status and cse == b"", (status, cse)
            status, err = _close(sock, fh)
            assert status == kXR_OK, (status, err)
        finally:
            sock.close()
        assert planes.disk(remote).read_bytes() == data


# --------------------------------------------------------------------------- #
# E — per-server independence: one worker, six answers
# --------------------------------------------------------------------------- #
class TestPerServerIndependence:

    def test_one_worker_holds_every_arm_at_once(self, planes):
        """None of the seven has a MAIN-level arm, so ``server {}`` is the only
        scope that can hold a value and the planes are the only unit of
        difference.  A shared bit anywhere — a merge that wrote through to the
        wrong conf, a slot offset transposed in the header — collapses this.

        Five planes, four distinct verdicts on ONE url.  ORDERING's is the odd
        one: its allowlist holds ``localhost`` alone, so the literal never
        reaches the address gate at all and it answers with the naming refusal —
        which is the §C ordering, restated here as a per-server fact.
        """
        url = "root://127.0.0.1//x.dat"  # net-literal-allow: the loopback source the arms govern
        verdicts = {}
        for plane in ("armed", "disarmed", "absent", "pulling", "ordering"):
            _s, err, _d = planes.pull(plane, url)
            verdicts[plane] = err
        assert "prohibited" in verdicts["disarmed"], verdicts
        assert "prohibited" in verdicts["absent"], verdicts
        assert "not permitted" in verdicts["ordering"], verdicts
        assert "prohibited" not in verdicts["ordering"], verdicts
        assert "prohibited" not in verdicts["armed"], verdicts
        assert "prohibited" not in verdicts["pulling"], verdicts

    def test_a_refusal_on_one_plane_does_not_follow_the_next(self, planes):
        """Sequenced deliberately: the refusing plane is asked first, so a
        verdict cached anywhere process-wide would be visible here."""
        _s, refused, _d = planes.pull("disarmed", "root://127.0.0.1//x.dat")  # net-literal-allow: the loopback source the arms govern
        assert "prohibited" in refused, refused
        _s, allowed, _d = planes.pull("pulling", "root://127.0.0.1//x.dat")  # net-literal-allow: the loopback source the arms govern
        assert "prohibited" not in allowed, allowed

    def test_the_write_arms_are_independent_too(self, planes):
        """The same, on the directive that lives in ``common`` rather than in
        the TPC block: a refusal on ARMED and an acceptance on PULLING, over one
        export, in one process."""
        refused = f"/audit16v_ind_on_{uuid.uuid4().hex}.bin"
        sock = _handshake_login(HOST, planes.port("armed"))
        try:
            status, err = _write(sock, _open(sock, refused.encode()), 0,
                                 os.urandom(1024))
        finally:
            sock.close()
        assert status == kXR_error and err == kXR_Unsupported, (status, err)

        allowed = f"/audit16v_ind_off_{uuid.uuid4().hex}.bin"
        data = os.urandom(1024)
        sock = _handshake_login(HOST, planes.port("pulling"))
        try:
            fh = _open(sock, allowed.encode())
            status, err = _write(sock, fh, 0, data)
            assert status == kXR_OK, (status, err)
            _close(sock, fh)
        finally:
            sock.close()
        assert planes.disk(allowed).read_bytes() == data


# --------------------------------------------------------------------------- #
# F — brix_tpc_require_source_size off: what an unverifiable copy is worth
# --------------------------------------------------------------------------- #
class TestTheSourceSizeArm:

    def test_a_clean_pull_completes_on_the_pulling_plane(self, planes,
                                                         clean_proxy):
        """[success] The floor everything below stands on: with no fault armed,
        the splice is a wire and the disarmed plane copies byte-exact."""
        name = planes.seed()
        status, err, dst = planes.pull("pulling", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_OK, (status, err)
        assert planes.disk(dst).read_bytes() == PAYLOAD

    def test_a_clean_pull_completes_on_the_armed_plane_too(self, planes,
                                                           clean_proxy):
        """[no false positive] ``require_source_size on`` must not cost a pull
        from a source that does declare one — which every brix source does."""
        name = planes.seed()
        status, err, dst = planes.pull("armed", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_OK, (status, err)
        assert planes.disk(dst).read_bytes() == PAYLOAD

    def test_the_armed_plane_refuses_a_source_that_declares_no_size(
            self, planes, clean_proxy):
        """[error] The gate doing its job: a source that answers the stat but
        will not say how big the file is leaves the destination with nothing to
        check the copy against, so the copy is refused."""
        clean_proxy.arm_gate(nosize=True)
        name = planes.seed()
        status, err, dst = planes.pull("armed", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_error, (status, err)
        assert "source declared no size" in err, err
        assert "brix_tpc_require_source_size is on" in err, err
        _assert_no_poison(planes, dst)

    def test_the_disarmed_arm_commits_the_unverifiable_copy(self, planes,
                                                            clean_proxy):
        """[the token] The same source, the same lie, the arm nobody wrote: the
        pull succeeds.  The bytes happen to be right — nothing on the
        destination knows that."""
        clean_proxy.arm_gate(nosize=True)
        name = planes.seed()
        status, err, dst = planes.pull("pulling", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_OK, (status, err)
        assert planes.disk(dst).read_bytes() == PAYLOAD

    def test_the_disarmed_arm_commits_a_short_copy_as_complete(self, planes,
                                                               clean_proxy):
        """[security-neg] What the off arm actually costs.

        The size gate is otherwise ALWAYS on — a delivered byte count that
        disagrees with the stat fails closed on every server.  Take the declared
        size away and that gate has nothing to compare against, so a truncated
        stream — half a frame and a forged EOF, a perfectly valid frame
        sequence — commits as a complete file.  This is the poison
        ``brix_tpc_require_source_size on`` exists to refuse, and the reason the
        arm is not merely a matter of taste.
        """
        clean_proxy.arm_gate(nosize=True, truncate=True)
        name = planes.seed()
        status, err, dst = planes.pull("pulling", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_OK, (status, err)
        committed = planes.disk(dst).read_bytes()
        assert len(committed) < len(PAYLOAD), (
            "the splice did not truncate; this case proves nothing otherwise")
        assert committed == PAYLOAD[:len(committed)]

    def test_the_always_on_gate_still_catches_truncation(self, planes,
                                                         clean_proxy):
        """The boundary of the finding above: ``off`` disables the DECLARATION
        requirement, never the comparison.  Truncate a pull whose source did
        declare its size and the disarmed plane fails it closed like any
        other."""
        clean_proxy.arm_gate(truncate=True)
        name = planes.seed()
        status, err, dst = planes.pull("pulling", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_error, (status, err)
        assert "TPC pull truncated" in err, err
        _assert_no_poison(planes, dst)

    def test_the_gate_is_one_branch_of_the_completion_check(self):
        """Source pin: the two arms are the two branches of one ``if``."""
        text = _source(STREAM_C)
        assert "if (t->src_size_known) {" in text, text[:0]
        assert ("} else if (t->conf != NULL "
                "&& t->conf->common.tpc_require_source_size)") \
            in text
        assert "brix_tpc_require_source_size is on" in text
