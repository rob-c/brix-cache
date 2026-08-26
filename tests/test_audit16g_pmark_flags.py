"""Test cases for audit16g_pmark_flags — preamble (fixtures/helpers/mocks) lives in
_test_audit16g_pmark_flags_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16g_pmark_flags_helpers")


class TestTheMasterSwitch:
    """`brix_pmark` gates every other flag here: webdav_dispatch_pmark returns
    before it looks at anything else when enable is 0 (dispatch.c:108)."""

    @_needs_nginx
    def test_on_marks_the_flow_and_reports_it(self, pmark):
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(MASTER[ON]))
        assert response.status_code == 200, response.text[:200]
        assert response.content == PAYLOAD
        assert _states(rows) == ["end", "start"], rows
        assert {(app, exp, act) for app, _, exp, act in rows} == \
            {("arm-base", EXP, ACT)}, rows
        assert delta == {STARTED: 1.0, ENDED: 1.0, SENT: 2.0}, delta

    @_needs_nginx
    def test_off_marks_nothing_at_all(self, pmark):
        """The arm the audit says was never written.  Not "no datagram" — no
        counter either, including map_unresolved_total: the mapping is never
        consulted, because flow_begin is never called."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(MASTER[OFF]))
        assert response.status_code == 200, response.text[:200]
        assert rows == [], rows
        assert delta == {}, delta

    @_needs_nginx
    def test_absent_is_the_same_silence_as_off(self, pmark):
        """`brix_pmark` merges to 0 (config.c:42), so the two arms are one
        behaviour — which is the result, not the assumption."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(MASTER[ABSENT]))
        assert response.status_code == 200, response.text[:200]
        assert rows == [], rows
        assert delta == {}, delta

    @_needs_nginx
    def test_off_cannot_be_undone_from_the_wire(self, pmark):
        """Security-negative: `scitag.flow` is a client-supplied value, and the
        only thing it can do is choose codes for a flow the SERVER decided to
        mark.  With the master switch off there is no flow to choose codes for,
        so a client cannot conjure marking — or a firefly aimed at itself — out
        of a query string."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(MASTER[OFF],
                              query=f"?scitag.flow={OVERRIDE_FLOW}"))
        assert response.status_code == 200, response.text[:200]
        assert rows == [], rows
        assert delta == {}, delta


# --------------------------------------------------------------------------- #
# §B — brix_pmark_firefly: the out-of-band report                              #
# --------------------------------------------------------------------------- #

class TestTheFireflyReport:
    """`firefly` decides whether pmark_emit runs, and nothing else: the label,
    the mapping and the flow object are all built first (firefly.c:233-245)."""

    @_needs_nginx
    def test_on_emits_the_pair_of_datagrams(self, pmark):
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(FIREFLY[ON]))
        assert response.status_code == 200, response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert delta == {STARTED: 1.0, ENDED: 1.0, SENT: 2.0}, delta

    @_needs_nginx
    def test_absent_emits_them_too(self, pmark):
        """`firefly` merges to 1 (config.c:43) — one of the three flags in this
        tranche whose never-written `off` arm is the only way to reach the
        disabled behaviour at all."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(FIREFLY[ABSENT]))
        assert response.status_code == 200, response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert delta == {STARTED: 1.0, ENDED: 1.0, SENT: 2.0}, delta

    @_needs_nginx
    def test_off_stops_the_datagrams_without_stopping_the_flow(self, pmark):
        """DEFECT CANDIDATE #72.  The off arm still counts a started flow, and
        can never count an ended one, so `started - ended` — the natural
        "in progress" expression — grows without bound on a healthy server."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(FIREFLY[OFF]))
        assert response.status_code == 200, response.text[:200]
        assert rows == [], rows
        assert delta == {STARTED: 1.0}, delta
        assert ENDED not in delta, \
            "flows_ended_total moved on the firefly-off arm — DEFECT #72 was " \
            "fixed and this test now describes the old behaviour"

    @_needs_nginx
    def test_the_phantom_backlog_grows_with_every_transfer(self, pmark):
        """#72 again, as an operator would meet it: three transfers, three
        phantom flows in progress, and nothing in the log."""
        for _ in range(3):
            assert pmark.get(FIREFLY[OFF]).status_code == 200
        metrics = pmark.metrics()
        assert metrics[STARTED] == 3.0, metrics
        assert metrics[ENDED] == 0.0, metrics
        assert "pmark" not in pmark.log or "flows" not in pmark.log

    @_needs_nginx
    @_needs_ipv6
    def test_off_leaves_the_in_band_mark_running(self, pmark):
        """The row that makes the pair worth writing.  brix_pmark_firefly off
        disables the REPORT, not the MARK: the flow label is applied at
        firefly.c:233-236, before and independently of the emit gate.  The
        control is the same request on the same worker with firefly on."""
        _settle_for_a_clean_probe()
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(FIREFLY[OFF], host=HOST6))
        assert response.status_code == 200, response.text[:200]
        assert rows == [], rows
        assert delta.get(SENT, 0.0) == 0.0, delta
        labelled = delta.get(FL_SET, 0.0) + delta.get(FL_FAILED, 0.0)
        assert labelled == 1.0 or _probe_declined(pmark.log), (
            f"a marked IPv6 flow neither leased a label nor logged a refused "
            f"probe (DEFECT #74): {delta}")


# --------------------------------------------------------------------------- #
# §C — brix_pmark_scitag_cgi: the client-supplied override                     #
# --------------------------------------------------------------------------- #

class TestTheClientOverride:
    """`scitag_cgi` is the first of the three mapping priorities
    (mapping.c:445-447): with it off, the query string is not read at all and the
    path/defsfile mapping decides alone."""

    @_needs_nginx
    def test_on_honours_the_client_flow_id(self, pmark):
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(CGI[ON], query=f"?scitag.flow={OVERRIDE_FLOW}"))
        assert response.status_code == 200, response.text[:200]
        assert {(exp, act) for _, _, exp, act in rows} == \
            {(OVERRIDE_EXP, OVERRIDE_ACT)}, rows
        assert delta[STARTED] == 1.0, delta

    @_needs_nginx
    def test_absent_honours_it_too(self, pmark):
        """`scitag_cgi` merges to 1 (config.c:45)."""
        _, rows, _, _ = pmark.measure(
            lambda: pmark.get(CGI[ABSENT], query=f"?scitag.flow={OVERRIDE_FLOW}"))
        assert {(exp, act) for _, _, exp, act in rows} == \
            {(OVERRIDE_EXP, OVERRIDE_ACT)}, rows

    @_needs_nginx
    def test_off_refuses_the_client_flow_id(self, pmark):
        """Security-negative: the never-written arm is the one that stops a
        client choosing its own SciTags codes.  A flow that would have been
        (2,1) at the client's request is reported as the (2,5) the site
        configured, so a tenant cannot mislabel its traffic as another
        activity — or another experiment — in the NREN's accounting."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(CGI[OFF], query=f"?scitag.flow={OVERRIDE_FLOW}"))
        assert response.status_code == 200, response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert {(app, exp, act) for app, _, exp, act in rows} == \
            {("arm-cgioff", EXP, ACT)}, rows
        assert delta[STARTED] == 1.0, delta

    @_needs_nginx
    @pytest.mark.parametrize("arm", [CGI[ON], CGI[OFF]],
                             ids=["scitag_cgi-on", "scitag_cgi-off"])
    def test_an_out_of_range_flow_id_is_ignored_on_both_arms(self, pmark, arm):
        """brix_pmark_parse_scitag returns NGX_ERROR for a value outside the
        16-bit range, and mapping.c treats that as "no override" rather than as a
        failure — so the transfer completes and the configured mapping is used,
        on the arm that reads the query as much as on the arm that does not."""
        response, rows, _, _ = pmark.measure(
            lambda: pmark.get(arm, query=f"?scitag.flow={BAD_FLOW}"))
        assert response.status_code == 200, response.text[:200]
        assert {(exp, act) for _, _, exp, act in rows} == {(EXP, ACT)}, rows


# --------------------------------------------------------------------------- #
# §D — brix_pmark_http_plain: which HTTP methods are marked at all             #
# --------------------------------------------------------------------------- #

class TestPlainHttpMarking:
    """The flag narrows the marking surface rather than switching marking off:
    COPY (WebDAV TPC) is marked whenever brix_pmark is on, and GET/PUT only when
    http_plain is on as well (dispatch.c:108-112)."""

    @_needs_nginx
    def test_on_marks_a_plain_put(self, pmark):
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.put(PLAIN[ON], "written.txt", PAYLOAD))
        assert response.status_code in (201, 204), response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert delta[STARTED] == 1.0, delta

    @_needs_nginx
    def test_off_leaves_a_plain_get_unmarked(self, pmark):
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(PLAIN[OFF]))
        assert response.status_code == 200, response.text[:200]
        assert response.content == PAYLOAD
        assert rows == [], rows
        assert delta == {}, delta

    @_needs_nginx
    def test_absent_leaves_it_unmarked_too(self, pmark):
        """`http_plain` merges to 0 (config.c:48) — XRootD parity, where pmark
        covers transfers and not every HTTP request."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(PLAIN[ABSENT]))
        assert response.status_code == 200, response.text[:200]
        assert rows == [], rows
        assert delta == {}, delta

    @_needs_nginx
    @pytest.mark.parametrize("arm,app",
                             [(PLAIN[OFF], "arm-ploff"), (PLAIN[ON], "arm-base")],
                             ids=["http_plain-off", "http_plain-on"])
    def test_a_copy_is_marked_on_both_arms(self, pmark, arm, app):
        """The row that says what the off arm actually means.  A COPY on the off
        arm is marked exactly as on the on arm, so an operator who writes
        `brix_pmark_http_plain off` still gets TPC firefly — and an operator who
        reads it as "packet marking off" is wrong."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.copy(arm, f"copied-{app}.txt"))
        assert response.status_code in (201, 204), response.text[:200]
        assert (pmark.data / arm / f"copied-{app}.txt").exists()
        assert _states(rows) == ["end", "start"], rows
        assert {name for name, _, _, _ in rows} == {app}, rows
        assert delta[STARTED] == 1.0, delta


# --------------------------------------------------------------------------- #
# §E — brix_pmark_firefly_origin: the copy aimed at the client                  #
# --------------------------------------------------------------------------- #

class TestTheOriginCopy:
    """`firefly_origin` sends every datagram a second time, to the CLIENT's own
    address at the fixed port 10514 (firefly.c:146-162).  The test binds that
    port itself, which is the only way to observe it."""

    @_needs_nginx
    def test_on_reports_to_the_client_as_well_as_the_collector(self, pmark):
        response, rows, delta, origin = pmark.measure(
            lambda: pmark.get(ORIGIN[ON]), origin=True)
        assert response.status_code == 200, response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert _states(origin) == ["end", "start"], origin
        assert {(app, exp, act) for app, _, exp, act in origin} == \
            {("arm-oron", EXP, ACT)}, origin
        assert delta[STARTED] == 1.0, delta

    @_needs_nginx
    def test_off_reports_only_to_the_collector(self, pmark):
        response, rows, delta, origin = pmark.measure(
            lambda: pmark.get(ORIGIN[OFF]), origin=True)
        assert response.status_code == 200, response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert origin == [], origin
        assert delta == {STARTED: 1.0, ENDED: 1.0, SENT: 2.0}, delta

    @_needs_nginx
    def test_absent_reports_only_to_the_collector(self, pmark):
        """`firefly_origin` merges to 0 (config.c:46)."""
        _, rows, delta, origin = pmark.measure(
            lambda: pmark.get(ORIGIN[ABSENT]), origin=True)
        assert _states(rows) == ["end", "start"], rows
        assert origin == [], origin
        assert delta == {STARTED: 1.0, ENDED: 1.0, SENT: 2.0}, delta

    @_needs_nginx
    def test_the_origin_copy_is_never_counted(self, pmark):
        """DEFECT CANDIDATE #73.  Four datagrams leave the box and the
        exposition reports two: the origin sendto's return value is discarded
        (firefly.c:158-161), so neither firefly_sent_total nor
        firefly_dropped_total sees it."""
        _, rows, delta, origin = pmark.measure(
            lambda: pmark.get(ORIGIN[ON]), origin=True)
        assert len(rows) == 2 and len(origin) == 2, (rows, origin)
        assert delta[SENT] == 2.0, \
            f"sent_total counted the origin copies — DEFECT #73 was fixed: {delta}"
        assert DROPPED not in delta, delta

    @_needs_nginx
    def test_a_client_that_is_not_listening_is_invisible(self, pmark):
        """#73's other half, and the arm an operator actually runs: nothing is
        bound on the client's 10514, so both origin datagrams go nowhere.  The
        transfer succeeds, the collector still gets its pair, and the exposition
        shows no drop at all — there is no signal anywhere that half the
        configured reporting is failing."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(ORIGIN[ON]))
        assert response.status_code == 200, response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert delta == {STARTED: 1.0, ENDED: 1.0, SENT: 2.0}, delta
        assert _origin_diagnostics(pmark.log) == [], \
            "the origin leg is reported after all — DEFECT #73 was fixed"


# --------------------------------------------------------------------------- #
# §F — brix_pmark_flowlabel: the in-band IPv6 technique                        #
# --------------------------------------------------------------------------- #

def _probe_declined(log):
    """Did this worker's one-time capability probe get refused?  That is the only
    thing that can make an IPv6 flow attempt no lease at all, and it is reported
    nowhere except the log (DEFECT #74).  §H pins the message text, so this
    predicate cannot quietly become always-false."""
    return PROBE_NOTICE in log


def _settle_for_a_clean_probe():
    """Wait out the previous test's probe lease before provoking this one.

    Each instance in this file is fresh (the lifecycle fixture is per-test), so
    each one probes, and each probe leaves an exclusive kernel entry on the one
    fixed label that outlives the worker by several seconds — DEFECT #74's
    collision, reproduced by the test file itself.  Measured on this host: the
    entry is still held at 6s and free at 10s.

    The wait is a flat sleep and NOT a poll, because a REFUSED lease refreshes
    the blocking entry's lifetime (the kernel's fl_release() stamps lastuse on
    the EPERM path), so a loop that checks whether the label is free is the one
    thing guaranteed to keep it busy.
    """
    time.sleep(FL_SETTLE)


def _hold_the_probe_label():
    """Occupy the exact label the server's capability probe asks for, so that the
    probe is refused with EPERM for certain rather than by luck.

    Returns the holding socket.  A lingering entry from an earlier pmark worker
    is the same poison and can expire mid-test, so a refusal is retried — but
    exactly ONCE, after a full settle, and never in a loop: a refused lease
    refreshes the blocking entry, so a retry loop is the one thing certain to
    keep the label busy for as long as it runs.
    """
    holder = _lease(PROBE_LABEL)
    if not isinstance(holder, socket.socket):
        _settle_for_a_clean_probe()
        holder = _lease(PROBE_LABEL)
    if not isinstance(holder, socket.socket):
        pytest.skip(f"cannot occupy the probe label 0x{PROBE_LABEL:05x}: {holder}")
    return holder


def _origin_diagnostics(log):
    """Log lines that say anything about the origin firefly leg.

    Deliberately generous — any pmark line naming the fixed origin port, the
    word `origin`, or a send failure counts — so that DEFECT #73's "there is no
    signal anywhere" claim fails the moment a signal is added.
    """
    return [line for line in log.splitlines()
            if "pmark" in line and (str(ORIGIN_PORT) in line
                                    or "origin" in line
                                    or "sendto" in line)]


@_needs_ipv6
class TestTheFlowLabel:
    """The REQUIRED SciTags technique, and the one whose `off` arm was never
    written.  Every test here dials the IPv6 loopback: brix_pmark_flowlabel_apply
    declines an AF_INET or v4-mapped peer before it touches the kernel
    (flowlabel.c:166-174), so over 127.0.0.1 the flag has no observable arm."""

    @_needs_nginx
    def test_off_never_leases_a_label_and_the_on_arm_next_door_does(self, pmark):
        """The pair, inside ONE worker.  The off leg is exact: neither flow-label
        counter moves, while the firefly plane is untouched.  The on leg is the
        control that says the off leg's silence was the flag and not the host —
        and it has to allow for a refused probe, because the probe leases a fixed
        label exclusively and any other holder on the machine wins it (#74)."""
        _, rows, off_delta, _ = pmark.measure(
            lambda: pmark.get(FLOWLABEL[OFF], host=HOST6))
        assert _states(rows) == ["end", "start"], rows
        assert FL_SET not in off_delta and FL_FAILED not in off_delta, off_delta
        assert off_delta == {STARTED: 1.0, ENDED: 1.0, SENT: 2.0}, off_delta
        assert not _probe_declined(pmark.log), \
            "the off arm probed the capability it was told not to use"

        _settle_for_a_clean_probe()
        _, rows, on_delta, _ = pmark.measure(
            lambda: pmark.get(FLOWLABEL[ON], host=HOST6))
        assert _states(rows) == ["end", "start"], rows
        attempted = on_delta.get(FL_SET, 0.0) + on_delta.get(FL_FAILED, 0.0)
        assert attempted == 1.0 or _probe_declined(pmark.log), (
            f"the on arm neither leased a label nor logged a refused probe: "
            f"{on_delta}")

    @_needs_nginx
    def test_absent_leases_a_label_like_the_on_arm(self, pmark):
        """`flowlabel` merges to 1 (config.c:44), so `base` — which writes none
        of the six — is the on arm by default."""
        _settle_for_a_clean_probe()
        _, rows, delta, _ = pmark.measure(
            lambda: pmark.get(FLOWLABEL[ABSENT], host=HOST6))
        assert _states(rows) == ["end", "start"], rows
        attempted = delta.get(FL_SET, 0.0) + delta.get(FL_FAILED, 0.0)
        assert attempted == 1.0 or _probe_declined(pmark.log), delta

    @_needs_nginx
    def test_an_ipv4_peer_never_reaches_a_lease(self, pmark):
        """The fail-open family gate.  Over IPv4 the on arm leases nothing — not
        a label, not a failure — because getpeername reports AF_INET and apply()
        declines (flowlabel.c:166-171).  A v4-only site therefore sees a flag
        with no effect on the counters.

        It does NOT see a flag with no effect at all: see the next test."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(FLOWLABEL[ON]))
        assert response.status_code == 200, response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert FL_SET not in delta and FL_FAILED not in delta, delta

    @_needs_nginx
    def test_an_ipv4_peer_still_triggers_the_capability_probe(self, pmark):
        """DEFECT CANDIDATE #76.  ``brix_pmark_flowlabel_apply`` calls
        ``brix_pmark_flowlabel_usable`` in the SAME condition as its fd check —
        before getpeername and therefore before it knows the peer's family
        (flowlabel.c:158-160).  An IPv4 request on a v4-only deployment thus
        performs the whole probe: a socket, an EXCLusive kernel lease of the one
        fixed label, and — when that lease is refused — a NOTICE about a
        technique that could not have applied to this connection anyway.

        Held deterministic by occupying the label first, so the refusal is
        certain and the NOTICE is proof the probe ran.  ``apply_addr``, the
        libcurl/TPC entry point, orders the same two checks the other way
        (flowlabel.c:185-189) — one function short-circuits on family, its
        sibling does not, which is what marks this a defect rather than a
        deliberate order.  §H pins both orders.
        """
        holder = _hold_the_probe_label()
        try:
            response, rows, delta, _ = pmark.measure(
                lambda: pmark.get(FLOWLABEL[ON]))
        finally:
            holder.close()

        assert response.status_code == 200, response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert FL_SET not in delta and FL_FAILED not in delta, delta
        assert _probe_declined(pmark.log), (
            "an IPv4 request no longer probes the IPv6 capability — DEFECT #76 "
            f"was fixed:\n{pmark.log[-2000:]}")

    @_needs_nginx
    def test_the_off_arm_does_not_probe_over_ipv4_either(self, pmark):
        """The control for #76, and a security-adjacent one: with the flag off,
        nothing about the connection can make brix touch the flow-label manager,
        so an operator who disables the technique really does stop brix asking
        the kernel for CAP_NET_ADMIN-shaped capabilities."""
        holder = _hold_the_probe_label()
        try:
            response, _, delta, _ = pmark.measure(
                lambda: pmark.get(FLOWLABEL[OFF]))
        finally:
            holder.close()

        assert response.status_code == 200, response.text[:200]
        assert FL_SET not in delta and FL_FAILED not in delta, delta
        assert not _probe_declined(pmark.log), \
            f"the off arm probed anyway:\n{pmark.log[-2000:]}"

    @_needs_nginx
    def test_a_blocked_probe_degrades_to_firefly_only(self, pmark):
        """DEFECT CANDIDATE #74, made deterministic: the test holds the exact
        label the probe asks for, so the probe's setsockopt is refused with
        EPERM for the whole life of this worker.

        What the operator gets is a working server with the REQUIRED in-band
        technique silently off: the transfer succeeds, the firefly plane is
        unaffected, no flow-label counter moves in either direction — a refused
        probe never reaches the increment at flowlabel.c:134 — and the only
        evidence anywhere is one NOTICE.
        """
        holder = _hold_the_probe_label()
        try:
            response, rows, delta, _ = pmark.measure(
                lambda: pmark.get(FLOWLABEL[ON], host=HOST6))
        finally:
            holder.close()

        assert response.status_code == 200, response.text[:200]
        assert response.content == PAYLOAD
        assert _states(rows) == ["end", "start"], rows
        assert delta == {STARTED: 1.0, ENDED: 1.0, SENT: 2.0}, delta
        assert _probe_declined(pmark.log), \
            f"a refused probe was not reported at all:\n{pmark.log[-2000:]}"

    @_needs_nginx
    def test_the_label_space_is_thirty_two_wide_per_activity(self, pmark):
        """DEFECT CANDIDATE #75.  Five entropy bits and an exclusive lease give
        one (experiment, activity) pair exactly 32 labels, each held by its
        connection.  Forty flows are held open at once, so the ceiling is
        arithmetic: at most 32 can be stamped and at least 8 must be refused.

        Measured on this host: 22 stamped, 18 refused — the refusals start at the
        second flow rather than at the 33rd, because the entropy is drawn with
        replacement.  Every one of the forty transfers still completes, which is
        why the ceiling is invisible without this counter.
        """
        _settle_for_a_clean_probe()
        sessions = []
        try:
            before = pmark.metrics()
            codes = set()
            for _ in range(FL_FLOWS):
                session = requests.Session()
                sessions.append(session)
                codes.add(pmark.get(FLOWLABEL[ON], host=HOST6,
                                    session=session).status_code)
            after = pmark.metrics()
        finally:
            for session in sessions:
                session.close()

        delta = _delta(before, after)
        def _assert_test_the_label_space_is_thirty_two_wide_per_activity_1():
            assert codes == {200}, codes
            assert delta[STARTED] == float(FL_FLOWS), delta

        _assert_test_the_label_space_is_thirty_two_wide_per_activity_1()
        attempted = delta.get(FL_SET, 0.0) + delta.get(FL_FAILED, 0.0)
        if attempted == 0.0:
            _check_test_the_label_space_is_thirty_two_wide_per_activity_1(delta, pmark)
            pytest.skip("this worker's flow-label probe was refused (DEFECT "
                        "#74), so the label space cannot be exercised here")
        def _assert_test_the_label_space_is_thirty_two_wide_per_activity_2():
            assert attempted == float(FL_FLOWS), \
                f"a marked IPv6 flow neither stamped nor failed: {delta}"
            assert delta.get(FL_SET, 0.0) <= FL_SPACE, \
                f"more labels than the entropy mask can spell: {delta}"

        _assert_test_the_label_space_is_thirty_two_wide_per_activity_2()
        _check_test_the_label_space_is_thirty_two_wide_per_activity_2(delta)

