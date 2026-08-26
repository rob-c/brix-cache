"""Test cases for audit15o_cms_windows — preamble (fixtures/helpers/mocks) lives in
_test_audit15o_cms_windows_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit15o_cms_windows_helpers")


def test_the_probe_cap_is_the_number_of_nodes_asked(cms, nodes):
    """success: with brix_cms_state_fanout 2 and four nodes exporting the
    path, exactly two kYR_state probes leave the manager.

    locate_fanout_state() (locate_manager.c:158) walks the node table until
    `sent` reaches the cap, so the cap is not a hint about load — it is the
    exact number of frames on the wire.  Which two nodes get asked is table
    order and is deliberately not asserted.
    """
    fan, _other = nodes
    path = "/fan/cap-fast.dat"

    elapsed, status, _body = _timed_locate(cms.port, path)

    probed = [n for n in fan if n.of(CMS_RR_STATE, path)]
    total = sum(len(n.of(CMS_RR_STATE, path)) for n in fan)
    def _assert_test_the_probe_cap_is_the_number_of_nodes_asked_1():
        assert total == FAST_STATE_FANOUT, \
            (f"brix_cms_state_fanout {FAST_STATE_FANOUT} must put exactly "
             f"{FAST_STATE_FANOUT} kYR_state frames on the wire, saw {total} "
             f"across nodes {[n.dport for n in probed]}\n{_errlog(cms)[-2000:]}")
        assert len(probed) == FAST_STATE_FANOUT, \
            "the cap counts nodes, not frames — no node may be probed twice"

    _assert_test_the_probe_cap_is_the_number_of_nodes_asked_1()
    # No node answers kYR_have, so the window expires into a kXR_wait.
    def _assert_test_the_probe_cap_is_the_number_of_nodes_asked_2():
        assert status in (kXR_wait, kXR_error), \
            f"an unanswered probe window must not redirect: {status}"
        assert elapsed >= LOCATE_WINDOW * 0.5, \
            (f"a probed locate must have PARKED for the window, "
             f"returned in {elapsed:.3f}s")

    _assert_test_the_probe_cap_is_the_number_of_nodes_asked_2()


def test_a_cap_larger_than_the_cluster_asks_every_covering_node(cms, nodes):
    """success: the slow manager's brix_cms_state_fanout 6 exceeds the five
    registered nodes, so the four that export the path all get probed — the
    cap is a ceiling, never a target."""
    fan, _other = nodes
    path = "/fan/cap-slow.dat"

    _elapsed, _status, _body = _timed_locate(cms.extra_ports["SLOW_PORT"],
                                             path)

    per_node = [len(n.of(CMS_RR_STATE, path)) for n in fan]
    assert per_node == [1, 1, 1, 1], \
        (f"a cap of {SLOW_STATE_FANOUT} over four covering nodes must probe "
         f"each exactly once, got {dict(zip([n.dport for n in fan], per_node))}"
         f"\n{_errlog(cms)[-2000:]}")


def test_a_node_that_does_not_export_the_path_is_never_probed(cms, nodes):
    """security-neg: the /other node is skipped even though the slow
    manager's cap has room for it.

    This is the assertion the cap alone cannot make.  A kYR_have from a node
    that does not hold the path would name a server the client must not be
    sent to, so brix_srv_paths_cover() has to run BEFORE the cap, not as a
    tie-break once the cap is full.  A cap of six over five nodes leaves no
    room for the alternative explanation.
    """
    fan, other = nodes
    path = "/fan/scoped.dat"

    _timed_locate(cms.extra_ports["SLOW_PORT"], path)

    assert other.of(CMS_RR_STATE) == [], \
        (f"node {other.dport} exports only /other and must never be probed "
         f"for {path}: {other.of(CMS_RR_STATE)}")
    assert sum(len(n.of(CMS_RR_STATE, path)) for n in fan) == len(FAN_DPORTS), \
        "the covering nodes must still all have been probed"


# =========================================================================== #
# B. What the cap is a budget OF.                                             #
# =========================================================================== #

def test_the_probe_cap_is_charged_per_locate_not_per_path(cms, nodes):
    """success: the cap is a per-REQUEST budget.

    This config carries no brix_cms_emptylife, which is the shipped default
    (server_conf_merge_cluster.c:306 — 0 means negative caching is off), so an
    expired probe window remembers nothing and the retry of a path spends the
    cap over again: two probes, then two more.  That is the guarantee
    brix_cms_state_fanout actually makes — "no single locate storms more than
    N nodes", never "no path costs more than N probes" — and it is the shape
    an operator sizing the directive against a retrying client needs.

    The opt-in negative cache that changes this (§2.6) is
    test_cms_parity_wave.py's subject, not this file's; the point here is only
    that the cap is unaffected by it either way.
    """
    fan, _other = nodes
    path = "/fan/twice.dat"

    first_elapsed, _status, _body = _timed_locate(cms.port, path)
    after_first = sum(len(n.of(CMS_RR_STATE, path)) for n in fan)
    assert after_first == FAST_STATE_FANOUT, \
        f"the first locate must spend the cap, sent {after_first}"

    second_elapsed, _status2, _body2 = _timed_locate(cms.port, path)
    after_second = sum(len(n.of(CMS_RR_STATE, path)) for n in fan)

    assert after_second == 2 * FAST_STATE_FANOUT, \
        (f"the retry must spend the cap again, not more and not less: probe "
         f"count went {after_first} -> {after_second}")
    assert second_elapsed >= LOCATE_WINDOW * 0.5, \
        (f"with negatives off the retry must PARK again, not answer from a "
         f"cache: {second_elapsed:.3f}s after {first_elapsed:.3f}s")


# =========================================================================== #
# C. brix_cms_locate_timeout — the parent park, measured as a difference.     #
# =========================================================================== #

def test_the_parent_park_ends_in_kxr_wait(cms, nodes):
    """success: a locate no registered node covers walks past the probe leg
    and the registry into locate_try_cms_parent(), which parks the client and
    answers kXR_wait 5 when the timeout fires.

    /lost is covered by nobody: the four data nodes export /fan, the fifth
    exports /other, and the two managers register themselves under /elsewhere
    precisely so their own registry rows cannot stand in for a holder.
    """
    fan, other = nodes
    path = "/lost/absent.dat"

    elapsed, status, body = _timed_locate(cms.port, path)

    assert status == kXR_wait, \
        (f"an unresolved parent locate must answer kXR_wait, got {status} "
         f"{body!r}\n{_errlog(cms)[-2000:]}")
    assert _wait_seconds(body) == 5, \
        f"recv.c:75 sends kXR_wait 5, got {_wait_seconds(body)}"
    assert elapsed >= FAST_LOCATE_TIMEOUT * 0.6, \
        (f"the client must have been PARKED for the timeout, answered in "
         f"{elapsed:.3f}s (timeout {FAST_LOCATE_TIMEOUT}s)")
    # The probe leg found nobody to ask, so it fell through without sending.
    assert all(n.of(CMS_RR_STATE, path) == [] for n in fan + [other]), \
        "no node exports /lost — none may be probed for it"


def test_a_longer_timeout_parks_the_client_longer(cms, nodes):
    """success: the slow manager differs from the fast one only in these
    three values, so the extra seconds on the wire are brix_cms_locate_timeout
    and nothing else.

    Both parks are measured in the same test so a host that is slow is slow
    for both halves; the assertion is on the gap, not on either absolute.
    """
    fast_elapsed, fast_status, _f = _timed_locate(cms.port, "/lost/gap-a.dat")
    slow_elapsed, slow_status, _s = _timed_locate(
        cms.extra_ports["SLOW_PORT"], "/lost/gap-b.dat")

    assert fast_status == slow_status == kXR_wait, \
        f"both managers must park then wait: {fast_status} / {slow_status}"
    assert slow_elapsed - fast_elapsed >= LOCATE_GAP, \
        (f"brix_cms_locate_timeout {SLOW_LOCATE_TIMEOUT}s vs "
         f"{FAST_LOCATE_TIMEOUT}s must show on the wire: "
         f"{slow_elapsed:.3f}s vs {fast_elapsed:.3f}s "
         f"(need a gap of {LOCATE_GAP}s)")
    assert slow_elapsed >= SLOW_LOCATE_TIMEOUT * 0.6, \
        (f"the slow park cannot finish early: {slow_elapsed:.3f}s "
         f"(timeout {SLOW_LOCATE_TIMEOUT}s)")


def test_a_parent_locate_never_converges_however_often_the_client_retries(
        cms, nodes):
    """DEFECT CANDIDATE #49 — the parent-locate forward is write-only.

    ngx_brix_cms_send_locate() emits CMS_RR_LOCATE (=2); cms_srv_frame_routes[]
    has no row for it, so the parent recognises the opcode by name in
    cms_srv_frame_unknown() and drops it with a debug-only log line.  The
    parent here IS this same nginx's CMS face — a live, healthy, registered
    manager — and it still never answers.

    So a hierarchy cannot resolve upward and, on a build without --with-debug,
    never says why: the client sees kXR_wait, retries, and is parked for the
    whole timeout again, forever.  Three round trips are enough to call it a
    livelock rather than a slow start.

    The retries also pin the safety half of recv.c:60-76: a parent timeout
    caches nothing.  brix_pending_set_path() is called by the state fan-out
    leg alone, so a parent that was merely slow, unreachable or mid-restart
    can never turn one bad minute into a cluster-wide cached NotFound.  Every
    attempt below therefore costs the full timeout rather than getting
    cheaper.
    """
    path = "/lost/livelock.dat"

    outcomes = [_timed_locate(cms.port, path) for _ in range(3)]

    assert all(status == kXR_wait for _e, status, _b in outcomes), \
        (f"{DEFECT49}\nstatuses: {[s for _e, s, _b in outcomes]}")
    assert all(elapsed >= FAST_LOCATE_TIMEOUT * 0.6
               for elapsed, _s, _b in outcomes), \
        (f"{DEFECT49}\nelapsed: "
         f"{[round(e, 3) for e, _s, _b in outcomes]}")


# =========================================================================== #
# D. brix_cms_fanout_window — a deadline, not a delay.                        #
# =========================================================================== #

def test_the_silent_success_window_holds_the_client(cms, nodes):
    """success: the node executor is silent on success, so "no kYR_error
    before the deadline" IS the success signal — with silent holders the
    kXR_ok arrives exactly one brix_cms_fanout_window later."""
    fan, other = nodes
    path = "/fan/del-fast.dat"

    elapsed, status, body = _timed_rm(cms.port, path)

    assert status == kXR_ok, \
        (f"a silent window must settle as success, got {status} {body!r}\n"
         f"{_errlog(cms)[-2000:]}")
    forwarded = [len(n.of(CMS_RR_RM, path)) for n in fan]
    assert forwarded == [1, 1, 1, 1], \
        f"every holder must receive the delete, got {forwarded}"
    assert other.of(CMS_RR_RM) == [], \
        f"node {other.dport} does not export /fan and must get no delete"
    assert elapsed >= FAST_FANOUT_WINDOW * 0.5, \
        (f"the client must have been parked for the window, answered in "
         f"{elapsed:.3f}s")


def test_a_longer_window_holds_it_longer(cms, nodes):
    """success: the same delete against the same silent holders through the
    manager whose only difference is brix_cms_fanout_window 2500ms."""
    fast_elapsed, fast_status, _f = _timed_rm(cms.port, "/fan/gap-fast.dat")
    slow_elapsed, slow_status, _s = _timed_rm(
        cms.extra_ports["SLOW_PORT"], "/fan/gap-slow.dat")

    assert fast_status == slow_status == kXR_ok, \
        f"both deletes must succeed: {fast_status} / {slow_status}"
    assert slow_elapsed - fast_elapsed >= FANOUT_GAP, \
        (f"brix_cms_fanout_window {SLOW_FANOUT_WINDOW}s vs "
         f"{FAST_FANOUT_WINDOW}s must show on the wire: "
         f"{slow_elapsed:.3f}s vs {fast_elapsed:.3f}s "
         f"(need a gap of {FANOUT_GAP}s)")


def test_every_node_answering_settles_the_window_early(cms, nodes):
    """error: the window is a DEADLINE.  When every holder answers,
    brix_cms_fanout_note_error() finalizes at got_err == expected
    (fanout.c:355) instead of waiting it out — so the failure is reported on
    the slow manager in far less than its 2500ms, carrying the node's text.

    Measured on the SLOW manager on purpose: on the fast one a 300ms window is
    too close to the round trip for "early" to mean anything.
    """
    fan, _other = nodes
    for node in fan:
        node.error_reply = (kXR_NotFound, b"replica pinned")

    elapsed, status, body = _timed_rm(cms.extra_ports["SLOW_PORT"],
                                      "/fan/early.dat")

    assert status == kXR_error, \
        (f"a node error inside the window must fail the delete, got {status} "
         f"{body!r}\n{_errlog(cms)[-2000:]}")
    assert "replica pinned" in _error_text(body), \
        f"the client must see the node's own text: {body!r}"
    assert elapsed < SLOW_FANOUT_WINDOW, \
        (f"all holders answered, so the deadline must be cut short: "
         f"{elapsed:.3f}s of a {SLOW_FANOUT_WINDOW}s window")


# =========================================================================== #
# E. brix_metadata_only — a role flag with two visible halves.                #
# =========================================================================== #

def test_a_metadata_only_server_advertises_the_meta_role_bit(cms):
    """success: protocol_role_flags() (protocol.c:84) ORs kXR_attrMeta into
    the kXR_protocol reply, which is how a stock client learns not to ask this
    node for bytes.  The manager on {PORT} is the control: it sets the bit for
    kXR_isManager and must not set this one."""
    meta_flags = _protocol_flags(cms.extra_ports["META_PORT"])
    mgr_flags = _protocol_flags(cms.port)

    assert meta_flags & kXR_attrMeta, \
        (f"brix_metadata_only must advertise kXR_attrMeta (0x{kXR_attrMeta:08x}), "
         f"flags were 0x{meta_flags:08x}")
    assert not mgr_flags & kXR_attrMeta, \
        (f"a server without the directive must not advertise it, "
         f"flags were 0x{mgr_flags:08x}")
    assert mgr_flags & kXR_isManager, \
        "the control must still be recognisable as the manager it is"


def test_open_is_refused_on_a_metadata_only_server(cms):
    """error: open_request.c:69 answers kXR_Unsupported with a message that
    names the reason, so a client can tell "this node holds no data" apart
    from "this file is missing" — the file it asks for exists on disk."""
    sock = _xrd_session(cms.extra_ports["META_PORT"])
    try:
        status, body = _open(sock, "/meta/seed.txt", kXR_open_read)
    finally:
        sock.close()

    assert status == kXR_error, \
        f"a metadata-only server must refuse kXR_open, got {status} {body!r}"
    assert _error_code(body) == kXR_Unsupported, \
        (f"the refusal must be kXR_Unsupported ({kXR_Unsupported}), got "
         f"{_error_code(body)}: {_error_text(body)}")
    assert "metadata-only" in _error_text(body), \
        f"the message must name the reason: {_error_text(body)!r}"


def test_the_namespace_still_answers_on_a_metadata_only_server(cms):
    """success: metadata is the whole point of the role — kXR_stat must keep
    working, or the directive would just be an offline switch."""
    sock = _xrd_session(cms.extra_ports["META_PORT"])
    try:
        status, body = _stat(sock, "/meta/seed.txt")
    finally:
        sock.close()

    assert status == kXR_ok, \
        f"kXR_stat must still answer on a metadata-only server: {status} {body!r}"
    # "<id> <size> <flags> <mtime>" (stat_line.h) — the size field, not a
    # substring match, so the assertion cannot pass on a coincidental inode.
    fields = body.split(b"\x00", 1)[0].split()
    assert len(fields) >= 4, f"malformed stat line: {body!r}"
    assert int(fields[1]) == len(SEED), \
        f"the stat line must carry the real size {len(SEED)}: {body!r}"


def test_a_create_open_is_refused_by_the_role_not_by_read_only(cms):
    """security-neg: the block carries brix_allow_write on, so a create-open
    reaching the writable path would succeed.  It must be refused with the
    SAME kXR_Unsupported — proving brix_metadata_only is a role and not an
    alias for brix_read_only, and that the refusal is not something a write
    flag can talk its way past.
    """
    sock = _xrd_session(cms.extra_ports["META_PORT"])
    try:
        status, body = _open(sock, "/meta/new.dat", kXR_open_updt | kXR_new)
    finally:
        sock.close()

    assert status == kXR_error, \
        f"a write-open must be refused too, got {status} {body!r}"
    assert _error_code(body) == kXR_Unsupported, \
        (f"a metadata-only refusal, not a read-only one: got "
         f"{_error_code(body)}: {_error_text(body)}")
    assert not (Path(cms.data_root) / "meta" / "new.dat").exists(), \
        "a refused create must not have touched the filesystem"


# =========================================================================== #
# F. Guard negatives — parse-time, against tmp_path copies only.              #
# =========================================================================== #

def test_a_non_numeric_probe_cap_is_refused_at_parse_time(tmp_path):
    """security-neg: brix_cms_state_fanout is a num slot; a value nginx
    cannot read as one must stop the config, never silently mean 0 (which
    would disable the probe leg without saying so)."""
    rc, err = _nginx_t(
        _guard_conf("        brix_cms_state_fanout notanumber;\n"),
        tmp_path, "badcap.conf")

    assert rc != 0, f"a non-numeric probe cap must fail nginx -t:\n{err}"
    assert "invalid number" in err, \
        f"the refusal must name the problem: {err}"


def test_a_malformed_window_duration_is_refused_at_parse_time(tmp_path):
    """security-neg: brix_cms_fanout_window is a msec slot.  A misspelled
    duration must be refused, not rounded — a window silently read as 0 would
    finalize every fan-out before a single node could answer."""
    rc, err = _nginx_t(
        _guard_conf("        brix_cms_fanout_window 300millis;\n"),
        tmp_path, "badwindow.conf")

    assert rc != 0, f"a malformed duration must fail nginx -t:\n{err}"
    assert "invalid value" in err, \
        f"the refusal must name the problem: {err}"
