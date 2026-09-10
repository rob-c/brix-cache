"""
tests/test_phase115_cms_space_floor.py — Phase-115 W8.4: §2.4 `cms.space`
enforcement, and the §2.9 ManTree security-negative the register row was
missing.

§2.4 — THE HALF THAT WAS NEVER THERE
------------------------------------
Every data node already advertised a free-space policy floor: `brix_cms_min_free`
rides the **mSpace** field of its kYR_login (src/net/cms/send.c).  The manager
parsed that field and threw the value away (`/* mSpace */ (void) tlv_read_next`),
so the floor was enforced nowhere — a node could be selected for writes right
past the level it had itself declared unsafe, all the way to ENOSPC.  W8.4 keeps
the value, latches a write-block against the live fSpace from the kYR_load
heartbeat, and gates write selection on it.

Four decisions this file pins, because each could reasonably have gone the
other way:
  * WRITES ONLY.  A full disk is a reason not to put new bytes on a node, never
    a reason to stop reading the bytes it already holds.
  * DEGRADE, NOT REFUSE.  A blocked node joins the §2.3 last-resort tier, so a
    mesh where every node is below its floor still selects — badly and
    visibly — instead of answering "no servers".
  * STICKY WITH A CLAMPED HIGH-WATER MARK.  The block clears at
    `brix_cms_space_hwm`, clamped UP to the node's own floor, so a hwm below the
    floor cannot make a node flap in and out of the write set per heartbeat.
  * SELF-SCOPED.  An absurd advertised floor can only remove its own advertiser.

§2.9 — WHAT THE REGISTER ROW GOT WRONG
--------------------------------------
The W8.4 row claimed "No test file matches 'mantree'".  That is a filename
grep, not a coverage fact: test_cms_parity_wave.py already proves the offload
(`test_max_direct_offloads_to_supervisor`) and its error path
(`test_max_direct_without_supervisor_admits`).  Only the security-negative was
genuinely absent, and it is here: an offloaded login must leave NO registry
footprint.  If it registered anyway, the cap would be a lie in both directions —
the manager would keep selecting a node it had just disowned, and that node
would go on counting toward the cap it was evicted for exceeding.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest \
        tests/test_phase115_cms_space_floor.py -v
"""

import struct
import time

import pytest

from _test_cms_parity_wave_helpers import (
    CMS_RR_LOAD,
    CMS_RR_PING,
    CMS_RR_TRY,
    FakeNode,
    _load_payload,
    _locate,
    _mgr,
    _redir_port,
    _wait_selectable,
    _xrd_resp,
    _xrd_session,
)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.timeout(90),
              pytest.mark.xdist_group("lc-p115-cms-space")]

MGR = "lc-p115-cms-space-mgr"

kXR_open = 3010
kXR_redirect = 4004
kXR_new, kXR_open_updt, kXR_mkpath = 0x0008, 0x0020, 0x0100
WRITE_CREATE = kXR_new | kXR_open_updt | kXR_mkpath

# A node whose advertised floor is the whole uint32 space can never be above it.
ABSURD_FLOOR = 0xFFFFFFFF


# ── driving a WRITE through the manager ───────────────────────────────────

def _write_open(port, path):
    """One kXR_open with create|update|mkpath; returns (status, body).

    A manager answers open with a redirect to the selected node (open_manager.c),
    and manager_mode deliberately runs selection BEFORE the local write gate, so
    no brix_allow_write is needed on the redirector face.
    """
    sock = _xrd_session(port)
    try:
        raw = path.encode()
        sock.sendall(struct.pack("!2sHHH2s6s4sI", b"\x00\x04", kXR_open, 0,
                                 WRITE_CREATE, b"\x00\x00", b"\x00" * 6,
                                 b"\x00" * 4, len(raw)) + raw)
        return _xrd_resp(sock)
    finally:
        sock.close()


def _wait_write_target(port, path, want_port, timeout=10.0):
    """Poll write-opens until one redirects to want_port; return that port."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = _write_open(port, path)
        if last[0] == kXR_redirect:
            got = _redir_port(last[1])
            if got == want_port:
                return got
        time.sleep(0.2)
    raise AssertionError(f"write-open {path} never selected {want_port}: "
                         f"last={last}")


def _write_target(port, path):
    """The node a single write-open selects right now (asserts it redirected)."""
    status, body = _write_open(port, path)
    assert status == kXR_redirect, \
        f"write-open {path} must redirect on a manager, got status {status}"
    return _redir_port(body)


def _settle(*nodes):
    """Block until every node is registered (the manager has spoken to it)."""
    for node in nodes:
        assert node.wait_frame(CMS_RR_PING) is not None, \
            f"node {node.dport} never registered"


# ═══ §2.4 success: the floor moves a write off the roomiest node ═══════════

def test_write_skips_the_node_below_its_own_advertised_floor(lifecycle):
    """success: the blocked node is the one WITH more free space, so only the
    §2.4 latch can explain the verdict.

    Write selection scores on free_mb, highest wins (registry_select_sched.c:115).
    `roomy` reports 8000 MB against `lean`'s 3000, so without enforcement it wins
    every write.  It also advertises a 9000 MB floor, which it is below.  A
    redirect to `lean` is therefore attributable to the floor and to nothing else
    — not to load, not to staleness, not to path coverage.
    """
    root_port, cms_port = _mgr(
        lifecycle, MGR, "brix_cms_space_enforce on;",
        "§2.4 cms.space: honour the advertised mSpace floor for writes.")
    roomy = FakeNode(cms_port, 42421, free_mb=8000, min_free=9000)
    lean = FakeNode(cms_port, 42422, free_mb=3000, min_free=100)
    try:
        _settle(roomy, lean)
        assert _wait_write_target(root_port, "/space/w.dat", 42422) == 42422
        # And it is a real preference, not a coin flip: repeated opens agree.
        for _ in range(3):
            assert _write_target(root_port, "/space/w2.dat") == 42422
    finally:
        roomy.close()
        lean.close()


# ═══ §2.4 compat: the shipped default is a byte-for-byte no-op ═════════════

def test_without_enforcement_the_advertised_floor_changes_nothing(lifecycle):
    """error-path/compat: same two nodes, `brix_cms_space_enforce` left unset —
    the roomy-but-under-floor node wins writes exactly as it did before W8.4.

    This is the test that makes the previous one mean something.  Without it,
    "lean was selected" is equally consistent with the floor working and with
    the free-space metric having been broken in the same change.
    """
    root_port, cms_port = _mgr(
        lifecycle, MGR, "",
        "§2.4 cms.space: default off must be the pre-W8.4 behaviour.")
    roomy = FakeNode(cms_port, 42423, free_mb=8000, min_free=9000)
    lean = FakeNode(cms_port, 42424, free_mb=3000, min_free=100)
    try:
        _settle(roomy, lean)
        assert _wait_write_target(root_port, "/space/off.dat", 42423) == 42423
    finally:
        roomy.close()
        lean.close()


# ═══ §2.4 success: hysteresis — recovery to the floor is not enough ════════

def test_the_block_clears_at_the_high_water_mark_not_at_the_floor(lifecycle):
    """success: the three-phase latch.

    floor 5000, hwm 6000.  The node walks 8000 -> 4000 -> 5500 -> 6500 and the
    write target must be roomy, lean, LEAN AGAIN, roomy.  The third step is the
    whole point: 5500 is above the floor the node declared, and a memoryless
    gate would readmit it there.  A node hovering at its floor would then flip
    on every heartbeat, and each flip moves a write.
    """
    root_port, cms_port = _mgr(
        lifecycle, MGR,
        "brix_cms_space_enforce on; brix_cms_space_hwm 6000;",
        "§2.4 cms.space: sticky block with a high-water-mark release.")
    roomy = FakeNode(cms_port, 42425, free_mb=8000, min_free=5000)
    lean = FakeNode(cms_port, 42426, free_mb=3000, min_free=100)
    try:
        _settle(roomy, lean)
        path = "/space/hyst.dat"
        assert _wait_write_target(root_port, path, 42425) == 42425

        def _report(free_mb):
            roomy.send(CMS_RR_LOAD, 0, _load_payload(free_mb=free_mb))
            time.sleep(0.6)     # let the manager ingest the heartbeat

        _report(4000)
        assert _write_target(root_port, path) == 42426, \
            "below its floor, the roomy node must lose writes"

        _report(5500)
        assert _write_target(root_port, path) == 42426, \
            ("5500 MB is above the 5000 MB floor but below the 6000 MB hwm — "
             "the block is sticky and must NOT have cleared here")

        _report(6500)
        assert _wait_write_target(root_port, path, 42425) == 42425, \
            "at the hwm the node must be readmitted to write selection"
    finally:
        roomy.close()
        lean.close()


# ═══ §2.4 security-negative: the floor is self-scoped, and read-safe ═══════

def test_an_absurd_floor_removes_only_its_advertiser_and_only_for_writes(
        lifecycle):
    """security-neg: three claims in one topology.

    `hostile` advertises a 4294967295 MB floor — the largest the wire can carry
    — so it is permanently blocked, and exports `r /`.  `honest` exports only
    `r /shared`.  That asymmetry separates the three questions:

      1. On a path BOTH export, the write goes to honest.  A node's own claim
         removes that node; there is no field by which one node's mSpace can
         raise the bar for another (the confused-deputy shape).
      2. On a path only hostile exports, a READ still redirects to it.  The
         latch must not be reachable from the read plane, or a node could take
         its own data offline by lying about space.
      3. On that same path a WRITE still redirects to it.  Last-resort, not a
         refusal: when the only holder is blocked, "here, and it may fail" beats
         a false kXR_NotFound for a path that demonstrably exists.
    """
    root_port, cms_port = _mgr(
        lifecycle, MGR, "brix_cms_space_enforce on;",
        "§2.4 cms.space: an advertised floor is scoped to its advertiser.")
    hostile = FakeNode(cms_port, 42427, paths=b"r /", free_mb=8000,
                       min_free=ABSURD_FLOOR)
    honest = FakeNode(cms_port, 42428, paths=b"r /shared", free_mb=3000,
                      min_free=100)
    try:
        _settle(hostile, honest)

        # 1. shared path: hostile removed itself, honest takes the write.
        assert _wait_write_target(root_port, "/shared/w.dat", 42428) == 42428

        # 2. hostile-only path: reads are untouched by the latch.
        assert _wait_selectable(root_port, "/private/r.dat", 42427) == 42427

        # 3. hostile-only path: the write degrades onto it, never refuses.
        assert _wait_write_target(root_port, "/private/w.dat", 42427) == 42427
    finally:
        hostile.close()
        honest.close()


# ═══ §2.9 security-negative: an offloaded login leaves no footprint ════════

def test_an_offloaded_login_never_enters_the_registry(lifecycle):
    """security-neg: the node handed a kYR_try must not also be selectable.

    §2.9 is already covered on the success and no-supervisor paths
    (test_cms_parity_wave.py::test_max_direct_*).  What was missing is the
    negative: cms_srv_login_admission runs BEFORE brix_srv_register, and the
    offload branch closes the session (`cms_srv_fail_close`) rather than
    falling through.  If it did fall through, the cap would be a lie in both
    directions — the manager would keep selecting a node it had just disowned,
    and that node would go on counting toward the cap it was evicted for
    exceeding, so the next login would be offloaded too and the tree would
    never stop growing sideways.

    max_direct 1 with a supervisor already present makes the second SERVER
    login the offloaded one.
    """
    root_port, cms_port = _mgr(
        lifecycle, MGR, "",
        "§2.9 ManTree: an offloaded login must leave no registry footprint.",
        srv_extra="brix_cms_server_max_direct 1;")
    # mode = manager|server = role "R", the supervisor the offload targets.
    #
    # The three utilisations are load-bearing, not decoration (2026-09-07).  A
    # supervisor IS selectable — nothing in srv_sel_scan de-prefers role "R",
    # only "P" peers — so on equal metrics all three nodes tie, and with
    # `cms.sched fuzz` off (the default) srv_sel_fuzz_pick returns the strict
    # best, which is whichever node the scan reached first: the supervisor.
    # That made the settle assertion below fail, and, worse, would have made
    # the security poll vacuous — an offloaded node that HAD registered would
    # still never have been picked over the two nodes ahead of it.  Reads
    # minimise util_pct, so ordering the three the other way round (the
    # offloaded node the most attractive of all) makes both assertions sharp:
    # 42432 must win while 42433 is absent, and 42433 would win the instant it
    # appeared.
    sup = FakeNode(cms_port, 42431, mode=0x02 | 0x08, util=9)
    first = FakeNode(cms_port, 42432, util=5)
    try:
        _settle(sup, first)
        assert _wait_selectable(root_port, "/mantree.dat", 42432) == 42432

        offloaded = FakeNode(cms_port, 42433, util=1)
        try:
            frame = offloaded.wait_frame(CMS_RR_TRY)
            assert frame is not None, "the capped login got no kYR_try"
            assert offloaded.wait_closed(), \
                "an offloaded login must be closed, not left half-admitted"

            # The security claim: it is nowhere in the registry.  Poll for the
            # whole window a registration would have needed, so "not yet" and
            # "never" cannot be confused.
            deadline = time.time() + 5
            while time.time() < deadline:
                status, body = _locate(root_port, "/mantree.dat")
                if status == kXR_redirect:
                    assert _redir_port(body) != 42433, \
                        "the offloaded node was selectable — it registered"
                time.sleep(0.25)
        finally:
            offloaded.close()
    finally:
        sup.close()
        first.close()
