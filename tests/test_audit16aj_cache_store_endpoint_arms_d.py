"""Test cases for audit16aj_cache_store_endpoint_arms — preamble (fixtures/helpers/mocks) lives in
_test_audit16aj_cache_store_endpoint_arms_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16aj_cache_store_endpoint_arms_helpers")


class TestTheEventTheRefusalIsBookedAgainst:
    """Section E.  observability/metrics/s3.c declares eight low-cardinality
    `event` labels for brix_s3_events_total, and the reserved-name refusal used
    to be booked against `access_denied` because that was the constant beside
    the 403 it chose (#139).

    An operator reading the family saw an authorization failure where the
    resolver specified an absence — and both names sit in one series with one
    label set, so a dashboard could not separate them after the fact and
    invariant 8 rules out adding a label that would let it.  The refusal is now
    booked where the absence it must be indistinguishable from is booked.
    """

    def test_the_family_is_exposed_with_the_expected_label_set(self, srv):
        text = _scrape()
        assert "brix_s3_events_total" in text
        assert all(value >= 0 for value in _events(text).values())

    def test_a_reserved_name_moves_no_such_key_and_not_access_denied(self, srv):
        """DEFECT CANDIDATE #139, fixed.  A delta rather than an absolute,
        because the counters are process-wide and every other cell in this file
        shares them."""
        before = _events(_scrape())
        for _ in range(3):
            assert _s3(S3_OFF, "GET", "keep.dat.cinfo").status_code == 404
        after = _events(_scrape())
        assert after["no_such_key"] - before["no_such_key"] == 3
        assert after["access_denied"] == before["access_denied"]

    def test_a_genuinely_absent_key_moves_no_such_key(self, srv):
        """The control: the event the reserved name should have booked, booked
        by the request it is supposed to be indistinguishable from."""
        before = _events(_scrape())
        for _ in range(3):
            assert _s3(S3_OFF, "GET", "ghost-for-e.dat").status_code == 404
        after = _events(_scrape())
        assert after["no_such_key"] - before["no_such_key"] == 3
        assert after["access_denied"] == before["access_denied"]

    def test_the_armed_arm_books_the_absence_correctly(self, srv):
        """The same absent reserved key with the guard lifted: the two arms now
        agree, which is what makes the counter unreadable as an arm indicator
        too."""
        before = _events(_scrape())
        assert _s3(S3_ON, "GET", "ghost-for-e.cinfo").status_code == 404
        after = _events(_scrape())
        assert after["no_such_key"] - before["no_such_key"] == 1
        assert after["access_denied"] == before["access_denied"]

    def test_no_other_event_absorbs_the_refusal(self, srv):
        """`invalid_uri` and `access_denied` are the other plausible homes for a
        path the resolver rejected, and both stay still — the refusal is booked
        in exactly one place, and it is now the same place the absence is."""
        before = _events(_scrape())
        assert _s3(S3_OFF, "GET", "keep.dat.meta").status_code == 404
        after = _events(_scrape())
        moved = {k for k in after if after[k] != before[k]}
        assert moved == {"no_such_key"}, (before, after)


# --------------------------------------------------------------------------- #
# F. The root:// plane                                                         #
# --------------------------------------------------------------------------- #

class TestTheRootPlane:
    """Section F.  The stream declaration is the one the corpus HAD written —
    `on`, once, in nginx_mu_sidecar_store.conf — so this plane is where the
    directive was understood, and the three checks that read it are
    open_request.c:205, stat.c:316 and statx.c:232.

    Three checks, and the opcodes that are NOT in that list are #141.
    """

    @pytest.mark.parametrize("name", RESERVED, ids=RESERVED_IDS)
    def test_stat_serves_every_reserved_pattern_on_the_armed_arm(self, srv, name):
        session = _session(ROOT_ON)
        try:
            _, status, body = _stat_path(session, "/" + name)
            assert status == kXR_ok, _err(body)
            assert _stat_fields(body)[1] == str(len(SECRET))
        finally:
            session.close()

    @pytest.mark.parametrize("port", (ROOT_OFF, ROOT_ABS))
    @pytest.mark.parametrize("name", RESERVED, ids=RESERVED_IDS)
    def test_stat_refuses_every_reserved_pattern_on_the_disarmed_arms(
            self, srv, port, name):
        session = _session(port)
        try:
            _, status, body = _stat_path(session, "/" + name)
            assert status != kXR_ok
            assert _err(body) == 3011
        finally:
            session.close()

    @pytest.mark.parametrize("port", (ROOT_ON, ROOT_OFF, ROOT_ABS))
    def test_the_genuine_sibling_stats_on_every_arm(self, srv, port):
        session = _session(port)
        try:
            _, status, body = _stat_path(session, "/" + KEEP)
            assert status == kXR_ok, _err(body)
            assert _stat_fields(body)[1] == str(len(KEEP_BYTES))
        finally:
            session.close()

    @pytest.mark.parametrize("port,expected", [(ROOT_ON, kXR_ok), (ROOT_OFF, None)])
    def test_open_for_read_follows_the_same_arm(self, srv, port, expected):
        session = _session(port)
        try:
            status, body = _open(session, "/keep.dat.cinfo", kXR_open_read)
            if expected == kXR_ok:
                assert status == kXR_ok, _err(body)
            else:
                assert status != kXR_ok and _err(body) == 3011
            keep_status, keep_body = _open(session, "/" + KEEP, kXR_open_read)
            assert keep_status == kXR_ok, _err(keep_body)
        finally:
            session.close()

    @pytest.mark.parametrize("port,armed", [(ROOT_ON, True), (ROOT_OFF, False),
                                            (ROOT_ABS, False)])
    def test_creating_a_sidecar_follows_the_same_arm(self, srv, port, armed):
        """kXR_open with kXR_new is a CREATE, so the guard fires on a name that
        does not exist yet — the arm decides whether a cache node may persist a
        sidecar at all."""
        session = _session(port)
        try:
            status, body = _open(session, f"/created-{port}.cinfo",
                                 kXR_new | kXR_open_updt)
            if armed:
                assert status == kXR_ok, _err(body)
            else:
                assert status != kXR_ok and _err(body) == 3011
            plain, plain_body = _open(session, f"/created-{port}.dat",
                                      kXR_new | kXR_open_updt)
            assert plain == kXR_ok, _err(plain_body)
        finally:
            session.close()

    @pytest.mark.parametrize("port,armed", [(ROOT_ON, True), (ROOT_OFF, False),
                                            (ROOT_ABS, False)])
    def test_statx_fails_the_whole_batch_for_one_reserved_member(
            self, srv, port, armed):
        """statx.c:232 checks each path and returns on the first refusal, so a
        batch that names one reserved path loses the answers for the legitimate
        paths beside it.  Consistent with a genuinely absent member, which fails
        the batch the same way — stated so the behaviour is on record rather
        than assumed."""
        session = _session(port)
        try:
            status, body = _statx(session, ["/" + KEEP, "/keep.dat.cinfo"])[1:]
            if armed:
                assert status == kXR_ok, _err(body)
                assert len(body) == 2
            else:
                assert status != kXR_ok and _err(body) == 3011

            alone = _statx(session, ["/" + KEEP])[1:]
            assert alone[0] == kXR_ok, _err(alone[1])

            missing = _statx(session, ["/" + KEEP, "/ghost.dat"])[1:]
            assert missing[0] != kXR_ok and _err(missing[1]) == 3011
        finally:
            session.close()

    def test_a_near_miss_member_does_not_fail_the_batch(self, srv):
        """The control for the cell above: `keep.dat.CINFO` differs from a
        reserved name by case alone and rides through on every arm."""
        session = _session(ROOT_OFF)
        try:
            status, body = _statx(session, ["/" + KEEP, "/keep.dat.CINFO"])[1:]
            assert status == kXR_ok, _err(body)
            assert len(body) == 2
        finally:
            session.close()


class TestTheRootRefusalTextNoLongerDiscloses:
    """DEFECT CANDIDATE #140, fixed.  Both refusals carry 3011 and the WebDAV
    plane's equivalent pair was always byte-identical — but kXR_stat's error
    STRING was not: the reserved name got the guard's own "file not found" and
    a genuine miss got the errno text.  Two strings for one status is an oracle,
    and it answered for names that are absent from the export as well.

    Both arms of kXR_stat and kXR_statx now say `strerror(ENOENT)`, which is what
    the miss they must be indistinguishable from says.
    """

    def test_stat_says_the_same_thing_about_both(self, srv):
        session = _session(ROOT_OFF)
        try:
            reserved = _stat_path(session, "/keep.dat.cinfo")[2]
            missing = _stat_path(session, "/ghost.dat")[2]
            assert _err(reserved) == _err(missing) == 3011
            assert _reason(reserved) == _reason(missing) == \
                b"No such file or directory"
        finally:
            session.close()

    def test_the_text_no_longer_gives_the_policy_away(self, srv):
        """The disclosure proper, closed: `ghost.cinfo` is absent from the
        export, and nothing in the answer says the NAME had anything to do with
        it."""
        assert not (srv / "ghost.cinfo").exists()
        session = _session(ROOT_OFF)
        try:
            reserved = _stat_path(session, "/ghost.cinfo")[2]
            plain = _stat_path(session, "/ghost.dat")[2]
            assert _reason(reserved) == _reason(plain) == \
                b"No such file or directory"
        finally:
            session.close()

    def test_statx_carries_the_same_text(self, srv):
        """statx refuses the whole batch on one reserved member (section F), and
        it had the same second string; the fix has to cover both call sites or
        the oracle simply moves to the batching verb."""
        session = _session(ROOT_OFF)
        try:
            reserved = _statx(session, ["/keep.dat.cinfo"])[1:]
            missing = _statx(session, ["/ghost.dat"])[1:]
            assert _err(reserved[1]) == _err(missing[1]) == 3011
            assert _reason(reserved[1]) == _reason(missing[1]) == \
                b"No such file or directory"
        finally:
            session.close()

    def test_the_armed_arm_says_it_too(self, srv):
        """The control: with the guard lifted the export answers for itself, and
        it reaches the same text — so the two arms are no longer distinguishable
        by the refusal string either."""
        session = _session(ROOT_ON)
        try:
            assert _reason(_stat_path(session, "/ghost.cinfo")[2]) == \
                b"No such file or directory"
        finally:
            session.close()

    def test_open_does_not_disclose(self, srv):
        """The second control, and the arm that was already correct when #140
        was raised: open_request.c reaches the same guard and has always
        answered both cases with one string.  It is left untouched, so a
        regression on it would be a separate fault and not a re-opening of
        this one."""
        session = _session(ROOT_OFF)
        try:
            reserved = _open(session, "/keep.dat.cinfo", kXR_open_read)[1]
            missing = _open(session, "/ghost.dat", kXR_open_read)[1]
            assert _err(reserved) == _err(missing) == 3011
            assert _reason(reserved) == _reason(missing) == b"file not found"
        finally:
            session.close()

