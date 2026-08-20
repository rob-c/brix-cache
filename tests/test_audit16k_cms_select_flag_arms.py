"""The five CMS selection-policy flags whose `off` arm was never written.

WHY THIS FILE EXISTS
--------------------
Tranche 16 re-runs the audit's Method steps 1-2 at (directive, value)
granularity, and `directives_cms.h` is the second-largest flag table in the
tree.  Five of its flags are one subsystem — how a manager picks a data server
— and all five have the same shape: the `on` arm is written by a config or a
test, the `off` arm is written nowhere.

    brix_cms_affinity      on: nginx_cms_affinity.conf     off: NOWHERE
    brix_cms_locate_multi  on: nginx_cms_affinity.conf     off: NOWHERE
    brix_cms_fanout        on: nginx_cms_fanout.conf       off: NOWHERE
    brix_cms_stage_select  on: test_cms_parity_wave.py     off: NOWHERE
    brix_cms_dfs           on: test_cms_parity_wave.py     off: NOWHERE

All five are `NGX_STREAM_SRV_CONF | NGX_CONF_FLAG` and all five merge to 0
(`brix_merge_srv_cms_*`, core/config/server_conf_merge_cluster.c:228-315), so
`off` and absent produce the same merged value and no reading here can be a
value comparison.  Each arm is read as the observable its flag owns.

THE FINDING — DEFECT CANDIDATE #87 (per-server directive, process-wide effect)
-----------------------------------------------------------------------------
`brix_cms_affinity` and `brix_cms_locate_multi` are declared identically and
merged two lines apart (server_conf_merge_cluster.c:228-229).  Their `off` arms
do NOT behave alike:

*   `locate_multi` is read per request off the connection's own server conf
    (`lc->conf->cms.locate_multi`, root/read/locate_manager.c:294), so each
    server block's arm governs that block.
*   `affinity` is not read from a conf at all.  The merge calls
    `brix_srv_set_affinity(1)` (:230-232) when the flag is on, which latches a
    process-wide global (`brix_srv_affinity`, net/manager/registry.c:16) that
    selection reads for every server in the process
    (net/manager/registry_select.c:392).  Nothing ever calls it with 0.

So `brix_cms_affinity off` on a server block is not a way to say no: one `on`
anywhere in the process — including in a `brix_cms_server` block that answers no
client traffic at all — makes every other server sticky however emphatically its
own config denies it.  That is not hypothetical shape: `nginx_cms_affinity.conf`
is exactly that topology (two root faces, one process), and §C measures the
`off` face being overridden through the CMS-server face, alongside the
`locate_multi` control where the same experiment comes out per-server.

The latch is one-way in the other direction too, which is why this is a
directive-scope defect and not a mere ordering hazard: there is no arm, no
context and no order of blocks that can turn affinity back off once any block
has turned it on.

WHAT WAS ALREADY OWNED, AND WHAT WAS NOT
----------------------------------------
The `on` arms are covered, thoroughly, by three files this one deliberately does
not restate:

*   `test_cms_affinity_multi.py` owns affinity stickiness (one path, one node,
    stable across sessions), the drained-node rule and the multi list's path
    scoping and token hygiene.
*   `test_cms_fanout_rm.py` owns the fan-out itself: a two-holder kXR_rm reaching
    both nodes, a partial failure surfacing, and the single-holder fallback.
*   `test_cms_parity_wave.py` owns stage-aware selection and the dfs fan-out
    skip.  Its stage-select control arm writes NO directive, which is the audit's
    point: absent has been read, the arm has not.

What none of them can say is what the `off` arm does, and for affinity that gap
is where the defect was hiding: with the flag on in the only config that has it,
the latch is invisible.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
Nothing here is a claim about the `on` arms' correctness — each appears only as
the control an `off` arm is read against, and the affinity `on` case in §C
exists solely to prove the probe can detect stickiness at all (without it, "off
sent every path to one node" would be indistinguishable from a broken probe).
The CMS wire, the registry's freshness and blacklist tiers, and the locate
window's fan-out belong to the files above.

Run:
    PYTHONPATH=tests pytest tests/test_audit16k_cms_select_flag_arms.py -v
"""

import struct
import time

import pytest

from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT
# The manager topology, the wire-speaking data node and the client probes belong
# to the parity wave; this file borrows them rather than restating either end.
from _test_cms_parity_wave_helpers import (CMS_RR_PING, CMS_RR_STATE,
                                           CMS_RR_STATUS, CMS_ST_STAGE,
                                           FakeNode, _locate, _mgr,
                                           _wait_selectable, _xrd_session,
                                           kXR_NotFound, kXR_error, kXR_ok,
                                           kXR_redirect, kXR_wait)
# The kXR_rm request and the forwarded-frame opcode belong to the fan-out file.
from test_cms_fanout_rm import CMS_RR_RM, _rm
# The parse-tier scaffold and its diagnostic filter belong to the tranche's
# file 10, which built them for exactly this question one table earlier.
from test_audit16j_root_caps_flags import _diagnostics, _parse

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.timeout(120),
              # The ledger name below is the parity wave's, so this file must
              # share its group or two drivers would race one fixed port.
              pytest.mark.xdist_group("lc-cms-parity")]

MGR = "lc-cms-parity-mgr"

# The five, in the order server_conf_merge_cluster.c merges them.
FLAGS = ("brix_cms_affinity", "brix_cms_locate_multi", "brix_cms_fanout",
         "brix_cms_stage_select", "brix_cms_dfs")

# Advertised data ports for the fake nodes.  Never bound — the manager only ever
# quotes them back in a redirect — but distinct from every other CMS file's set
# so a leaked registration from a neighbouring suite could not be mistaken for
# one of these nodes.
DPORT_COOL = 42451      # util 1  — the metric winner for every path
DPORT_HOT = 42452       # util 90 — reachable only by an affinity stick
COOL_UTIL, HOT_UTIL = 1, 90

# Twelve fixed paths.  The affinity stick is `fresh_cands[fnv1a(path) % n]`
# (registry_select.c:392), a pure function of the path and the registry's slot
# order, so this set partitions the same way on every run — the probe below is
# deterministic, not statistical, and the constants are what make it so.
AFF_PATHS = tuple(f"/aff16k/p{i:02d}.bin" for i in range(12))


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _fnv1a32(text):
    """The affinity stick's hash, mirrored from src/core/fnv.h (basis 0x811c9dc5,
    prime 0x01000193) as srv_sel_path_hash() applies it — over the path bytes,
    NUL excluded.  Mirrored rather than derived: the point of the reading below
    is that the stick IS this function, so a test that asked the server for the
    answer would assert nothing."""
    h = 0x811C9DC5
    for byte in text.encode():
        h = ((h ^ byte) * 0x01000193) & 0xFFFFFFFF
    return h


def _registered(*nodes):
    """Block until the manager has each node in its registry.

    The manager pings every accepted connection on its own timer, so the first
    ping a node sees is the manager's own statement that the login was processed
    — a stronger precondition than any sleep, and the parity wave's own idiom.
    """
    for node in nodes:
        assert node.wait_frame(CMS_RR_PING) is not None, (
            f"node dport={node.dport} never registered with the manager")


def _selected_ports(root_port, paths):
    """The redirect target for each path, as a list in `paths` order.

    Every path is polled to a redirect first, so a probe that runs before the
    second registration lands cannot read as "affinity sent everything to one
    node".
    """
    return [_wait_selectable(root_port, path, None) for path in paths]


def _two_nodes(cms_port):
    """The cool/hot pair every selection reading in this file is measured on.

    Utilisation is the metric here (no brix_cms_sched, no load weight), so the
    cool node wins every path unless something other than the metric is
    choosing — which is precisely what affinity is.
    """
    cool = FakeNode(cms_port, DPORT_COOL, util=COOL_UTIL)
    hot = FakeNode(cms_port, DPORT_HOT, util=HOT_UTIL)
    _registered(cool, hot)
    return cool, hot


# --------------------------------------------------------------------------- #
# §A — the parse tier                                                          #
# --------------------------------------------------------------------------- #

class TestTheParseTier:
    """Step 1 of the audit's method, asked of all ten pairs: is the arm even
    accepted, and is it accepted only where the merge can act on it."""

    @pytest.mark.parametrize("arm", ("on", "off"))
    @pytest.mark.parametrize("flag", FLAGS)
    def test_both_arms_are_accepted_in_a_stream_server(self, tmp_path, flag,
                                                       arm):
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} {arm};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("value", ("1", "yes"))
    @pytest.mark.parametrize("flag", FLAGS)
    def test_a_value_outside_the_two_arms_is_refused(self, tmp_path, flag,
                                                     value):
        """The spellings an operator brings from other config languages must
        not silently become one of the two arms."""
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} {value};\n")
        assert rc != 0, f"{flag} {value} was accepted: {out}"

    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, flag):
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} on off;\n")
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_a_duplicate_is_refused(self, tmp_path, flag):
        """Which is what makes every negative in this class unambiguous: a
        second occurrence is diagnosed before a value or arity error is."""
        rc, out = _parse(tmp_path,
                         KNOBS=f"        {flag} on;\n        {flag} off;\n")
        assert rc != 0, out
        assert "duplicate" in out, out

    @pytest.mark.parametrize("slot", ("STREAM_KNOBS", "HTTP_KNOBS",
                                      "LOC_KNOBS", "OUTER"))
    @pytest.mark.parametrize("flag", FLAGS)
    def test_every_other_placement_is_refused(self, tmp_path, flag, slot):
        """All five merge functions implement parent inheritance, and all five
        directives are declared NGX_STREAM_SRV_CONF and nothing else — so the
        parent slot (STREAM_KNOBS here) can never hold a written value and the
        inheritance arm of that merge is unreachable rather than untested.

        The refusal must be a placement one: "unknown directive" would mean the
        stream module was not loaded and the case measured nothing.
        """
        rc, out = _parse(tmp_path, **{slot: f"    {flag} on;\n"})
        assert rc != 0, out
        assert "is not allowed here" in out, out
        assert "unknown directive" not in out, out

    def test_the_five_off_arms_load_together_and_say_nothing(self, tmp_path):
        """Silence is part of the subject.  A flag that merges to 0 must not
        advise anything when it is written `off`, or the audit's "never written"
        would have been noticed as log noise years ago."""
        knobs = "".join(f"        {flag} off;\n" for flag in FLAGS)
        rc, out = _parse(tmp_path, KNOBS=knobs)
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    def test_two_servers_may_disagree_on_every_arm(self, tmp_path):
        """The parse-tier half of "the scope is per-server": a config where one
        block says on and another says off is not a combination the parser
        objects to.  §C is where the two flags' answers diverge at runtime.
        """
        second = ("    server {\n"
                  f"        listen {PARSE_PLACEHOLDER_PORT + 2};\n"
                  "        brix_root on;\n"
                  "        brix_auth none;\n"
                  + "".join(f"        {flag} off;\n" for flag in FLAGS)
                  + "    }\n")
        knobs = "".join(f"        {flag} on;\n" for flag in FLAGS)
        rc, out = _parse(tmp_path, KNOBS=knobs, EXTRA=second)
        assert rc == 0, out


# --------------------------------------------------------------------------- #
# §B — the observable each `off` arm owns                                      #
# --------------------------------------------------------------------------- #

def test_locate_multi_off_answers_one_redirect_not_the_live_set(lifecycle):
    """success: with two eligible nodes registered and the flag written off,
    kXR_locate answers a single kXR_redirect.

    The multi arm is a different STATUS, not a longer body
    (`brix_send_ok(... list ...)`, locate_manager.c:305), so the off arm's
    reading is that the client is handed one server to go to and is never given
    a set to choose from.
    """
    root_port, cms_port = _mgr(lifecycle, MGR, "brix_cms_locate_multi off;",
                               "audit-16k locate_multi off arm")
    cool, hot = _two_nodes(cms_port)
    try:
        got = _wait_selectable(root_port, "/multi16k/off.bin", None)
        assert got in (DPORT_COOL, DPORT_HOT), got

        status, body = _locate(root_port, "/multi16k/off.bin")
        assert status == kXR_redirect, (
            f"locate_multi off must redirect, got status {status} body {body!r}")
        assert b"Sr" not in body, (
            f"a redirect body must not carry a server list: {body!r}")
    finally:
        cool.close()
        hot.close()


def test_stage_select_off_keeps_the_utilisation_pick(lifecycle):
    """success: a read of a file no node holds still goes to the least-utilised
    node when the flag is written off, even though the other node advertised
    staging.

    The parity wave's control arm writes no directive at all; this is the arm.
    """
    root_port, cms_port = _mgr(lifecycle, MGR, "brix_cms_stage_select off;",
                               "audit-16k stage_select off arm")
    cool, hot = _two_nodes(cms_port)
    try:
        hot.send(CMS_RR_STATUS, CMS_ST_STAGE)      # the roomiest stage node
        time.sleep(0.5)                            # let the status land
        got = _wait_selectable(root_port, "/stage16k/off.bin", DPORT_COOL)
        assert got == DPORT_COOL, (
            f"stage_select off must keep the utilisation pick, got {got}")
    finally:
        cool.close()
        hot.close()


def test_dfs_off_probes_the_cluster_and_never_invents_a_holder(lifecycle):
    """success + security-neg: with the flag written off the manager fans a
    kYR_state out to the node before deciding, and an unheld file is never
    answered with a redirect however many times it is asked for.

    This is the security-relevant half of the pair.  `brix_cms_dfs on` is an
    operator's promise that every node holds every file, and the manager takes
    it on trust: it skips the existence probe entirely
    (locate_manager.c:209-213), so every path resolves to a redirect whether or
    not anything is there.  The arm that withdraws the promise has to restore
    the probe, and both halves of that are read here — the probe leaves the
    manager, and no answer in a whole series of retries is a redirect.

    The verdict is deliberately read as "not a redirect" rather than as
    kXR_NotFound: without brix_cms_emptylife there is no negative entry to
    answer from, so each retry opens a fresh fan-out window and parks the client
    with kXR_wait.  Pinning the NotFound would be testing the negative cache,
    which test_cms_parity_wave.py owns.
    """
    root_port, cms_port = _mgr(
        lifecycle, MGR, "brix_cms_locate_window 400ms; brix_cms_dfs off;",
        "audit-16k dfs off arm")
    node = FakeNode(cms_port, DPORT_COOL)     # never answers kYR_state
    try:
        _registered(node)
        seen = []
        for _ in range(6):
            status, body = _locate(root_port, "/dfs16k/off.bin")
            seen.append(status)
            assert status != kXR_redirect, (
                f"an unheld file must not be located, got a redirect to port "
                f"{struct.unpack('>i', body[:4])[0]}; answers so far {seen}")
            if status == kXR_error:
                assert struct.unpack(">I", body[:4])[0] == kXR_NotFound, body
            time.sleep(0.3)

        assert node.wait_frame(CMS_RR_STATE) is not None, (
            "dfs off must fan a kYR_state probe out to the node; frames "
            f"seen: {[c for c, _m, _p in node.frames]}")
        assert kXR_wait in seen or kXR_error in seen, (
            f"expected the client to be parked or refused, got {seen}")
    finally:
        node.close()


def test_fanout_off_falls_back_to_one_node_and_forwards_nothing(lifecycle):
    """success + security-neg: a kXR_rm on a path with TWO holders is answered
    with a redirect and no node receives a forwarded delete.

    Both halves matter.  The redirect is the off arm's observable; the absence
    of a kXR_ok is the security-negative — the fan-out path answers kXR_ok on a
    silent window (fanout.c:283), so an off arm that kept the aggregation but
    lost the forwarding would report a delete that never happened.  The
    fan-out file owns the single-holder fallback, which is the same verdict
    reached for a topology reason; this is the verdict reached because the
    operator said so.
    """
    root_port, cms_port = _mgr(lifecycle, MGR, "brix_cms_fanout off;",
                               "audit-16k fanout off arm")
    cool, hot = _two_nodes(cms_port)
    try:
        # Both holders must be selectable before the delete, or the fallback
        # would be the single-holder one the fan-out file already owns.
        assert _wait_selectable(root_port, "/fan16k/off.bin", None) in (
            DPORT_COOL, DPORT_HOT)

        sock = _xrd_session(root_port)
        try:
            status, body = _rm(sock, "/fan16k/off.bin")
        finally:
            sock.close()

        assert status == kXR_redirect, (
            f"fanout off must hand the delete to one node, got status "
            f"{status} body {body!r}")
        assert status != kXR_ok, "a delete nobody executed must not report ok"
        for node in (cool, hot):
            assert node.count(CMS_RR_RM) == 0, (
                f"node dport={node.dport} received a forwarded delete with "
                f"the fan-out off: {node.frames}")
    finally:
        cool.close()
        hot.close()


# --------------------------------------------------------------------------- #
# §C — the two flags' `off` arms, and why only one of them is honoured         #
# --------------------------------------------------------------------------- #

def test_affinity_on_reaches_the_node_the_metric_would_never_pick(lifecycle):
    """control: the probe can see stickiness at all.

    With the flag on, selection is `fresh_cands[fnv1a(path) % n_fresh]` and the
    metric is not consulted, so some of the twelve paths land on the node whose
    utilisation is 90.  Without this reading, every "all twelve went to the cool
    node" below could be explained by a probe that cannot distinguish the two
    nodes.
    """
    root_port, cms_port = _mgr(lifecycle, MGR, "brix_cms_affinity on;",
                               "audit-16k affinity on control")
    cool, hot = _two_nodes(cms_port)
    try:
        ports = _selected_ports(root_port, AFF_PATHS)
        assert set(ports) == {DPORT_COOL, DPORT_HOT}, (
            f"affinity on must partition the paths across both fresh nodes, "
            f"got {ports}")
    finally:
        cool.close()
        hot.close()


def test_affinity_off_alone_in_the_process_follows_the_metric(lifecycle):
    """success: the arm, read where nothing else in the process contradicts it —
    every one of the twelve paths goes to the least-utilised node, which is what
    "not sticky" looks like from a client."""
    root_port, cms_port = _mgr(lifecycle, MGR, "brix_cms_affinity off;",
                               "audit-16k affinity off arm")
    cool, hot = _two_nodes(cms_port)
    try:
        ports = _selected_ports(root_port, AFF_PATHS)
        assert set(ports) == {DPORT_COOL}, (
            f"affinity off must leave the metric in charge, got {ports}")
    finally:
        cool.close()
        hot.close()


def test_locate_multi_off_survives_a_sibling_server_saying_on(lifecycle):
    """success: the same experiment as the one below, on the flag whose read is
    per-connection — the root face's `off` is honoured even though the sibling
    CMS-server block in the same process says `on`.

    This is the control that makes the next test a defect and not a property of
    the topology: two flags, declared identically and merged two lines apart,
    given the same disagreement between two blocks of one process.
    """
    root_port, cms_port = _mgr(lifecycle, MGR, "brix_cms_locate_multi off;",
                               "audit-16k locate_multi off vs sibling on",
                               srv_extra="brix_cms_locate_multi on;")
    cool, hot = _two_nodes(cms_port)
    try:
        _wait_selectable(root_port, "/multi16k/sibling.bin", None)
        status, body = _locate(root_port, "/multi16k/sibling.bin")
        assert status == kXR_redirect, (
            f"a sibling block's `on` must not reach this server: status "
            f"{status} body {body!r}")
    finally:
        cool.close()
        hot.close()


def test_affinity_off_cannot_undo_a_sibling_server_saying_on(lifecycle):
    """DEFECT CANDIDATE #87: the root face writes `brix_cms_affinity off` and is
    sticky anyway, because the CMS-server block in the same process wrote `on`.

    `brix_srv_set_affinity(1)` (server_conf_merge_cluster.c:230-232) latches a
    process-wide global that selection reads for every server
    (registry_select.c:392); nothing ever calls it with 0.  So the merged value
    of THIS server's flag is 0 and its selection is sticky regardless — the
    directive is per-server in its declaration and process-wide in its effect,
    and its `off` arm has no way to express itself.

    The block that overrides it here answers no client traffic at all: it is the
    `brix_cms_server` face the data nodes register into.  A deployment does not
    have to be doing anything unusual to hit this — `nginx_cms_affinity.conf`
    (the suite's only config for the flag) is two root faces in one process, and
    a manager pair that wants stickiness on one face and load balance on the
    other cannot have it.
    """
    root_port, cms_port = _mgr(lifecycle, MGR, "brix_cms_affinity off;",
                               "audit-16k affinity off vs sibling on",
                               srv_extra="brix_cms_affinity on;")
    cool, hot = _two_nodes(cms_port)
    try:
        ports = _selected_ports(root_port, AFF_PATHS)
        assert set(ports) == {DPORT_COOL, DPORT_HOT}, (
            f"the finding is that `off` is overridden — if this server really "
            f"honoured its own arm the paths would all be on {DPORT_COOL}; "
            f"got {ports}")
    finally:
        cool.close()
        hot.close()


def test_the_forced_stick_is_the_documented_path_hash(lifecycle):
    """security-neg (state confusion): the stickiness forced on the `off` face is
    the design-of-record path hash, not an arbitrary per-face assignment.

    This is what bounds the defect above to "the arm is inexpressible" rather
    than "the cluster disagrees with itself".  The stick has to be a pure
    function of the path so that every worker of every manager picks the same
    member of the same candidate set (registry_select.c:226-229); if the face
    that was overridden stuck differently from the face that asked, two managers
    in one process would disagree about where a path lives — a far worse defect
    than an inexpressible arm.

    Read without a second instance, because one lifecycle name may be registered
    once per test: the twelve paths' fnv1a buckets are computed here and the
    reading is that bucket → port is a bijection.  That says every path in a
    bucket landed on one node and the two buckets landed on different nodes,
    which is the hash's signature, and it says so without depending on which
    node the registry happened to slot first.
    """
    root_port, cms_port = _mgr(lifecycle, MGR, "brix_cms_affinity off;",
                               "audit-16k affinity latch partition",
                               srv_extra="brix_cms_affinity on;")
    cool, hot = _two_nodes(cms_port)
    try:
        ports = _selected_ports(root_port, AFF_PATHS)
    finally:
        cool.close()
        hot.close()

    buckets = [_fnv1a32(path) % 2 for path in AFF_PATHS]
    pairs = sorted(set(zip(buckets, ports)))
    assert len(pairs) == 2, (
        f"bucket -> port must be a bijection; got {pairs} from\n"
        f"  buckets {buckets}\n  ports   {ports}")
