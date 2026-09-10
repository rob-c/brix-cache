# test_phase115_cms_locate_coalesce.py — §2.15 dynamic-locate request
# coalescing.  Wire constants, the hold-open data node, the off-thread client
# and the manager factory live in _test_phase115_cms_coalesce_helpers.py;
# `reexport` pulls that namespace in here so each test reads as one story.
#
# WHAT is under test: `brix_cms_coalesce on` makes a locate for a path that
# already has a kYR_state window in flight PARK on that window instead of
# opening a second one.  WHY it matters: N clients asking for the same cold
# path used to cost N fan-outs at every node in the cluster.  HOW it is
# observed: _HeldNode refuses to answer until told to, so the wave stays open
# across both arrivals and "did the follower probe?" is a plain frame count
# taken while both clients are demonstrably parked.
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_phase115_cms_coalesce_helpers")

import time                                                     # noqa: E402


def _both(first, second, timeout=12.0):
    """Join both client threads and return their redirect ports."""
    first.join(timeout=timeout)
    second.join(timeout=timeout)
    assert not first.is_alive() and not second.is_alive(), \
        "a locate never returned — the wave was never resolved"
    return first.port(), second.port()


def test_two_locates_for_one_path_open_a_single_state_wave(lifecycle):
    """Success: the follower rides the leader's window, and both are answered.

    The node is probed exactly once even though two independent sessions asked
    for the path, and the single kYR_have it eventually sends resolves BOTH.
    """
    root_port, cms_port = _coalescing_mgr(
        lifecycle, True, "§2.15 one wave serves two waiters")
    node = _HeldNode(cms_port, 42461)
    try:
        assert node.wait_ready(), "the node was never pinged by the manager"

        path = "/data/coalesce/one"
        first, second = _run_pair(root_port, path)
        assert node.wait_probe(path), "the leader never opened a state wave"
        time.sleep(1.0)                 # the follower has provably arrived

        assert len(node.probes_for(path)) == 1, (
            "the follower opened its own wave: "
            f"{node.probes_for(path)}")

        node.answer(path)
        assert _both(first, second) == (42461, 42461)
    finally:
        node.close()


def test_without_coalescing_each_locate_opens_its_own_wave(lifecycle):
    """Control: with the directive off the second locate probes again.

    Without this, "one probe" in the test above could equally mean the manager
    had stopped probing for a second reason — a cached verdict, a fan-out cap,
    a dead node.  The only difference between the two runs is the directive.
    """
    root_port, cms_port = _coalescing_mgr(
        lifecycle, False, "§2.15 control: coalescing off")
    node = _HeldNode(cms_port, 42462)
    try:
        assert node.wait_ready(), "the node was never pinged by the manager"

        path = "/data/coalesce/two"
        first, second = _run_pair(root_port, path)
        assert node.wait_probe(path), "the leader never opened a state wave"
        time.sleep(1.0)

        assert len(node.probes_for(path)) == 2, (
            "coalescing is off yet the second locate did not probe: "
            f"{node.probes_for(path)}")

        # One have per outstanding probe: each wave is resolved on its own
        # streamid, which is exactly the cost §2.15 exists to remove.
        for sid in node.probes_for(path):
            node.answer(path, streamid=sid)
        assert _both(first, second) == (42462, 42462)
    finally:
        node.close()


def test_a_refresh_locate_never_rides_someone_elses_wave(lifecycle):
    """Security-negative: `kXR_refresh` must not be served by a stale window.

    A client sets kXR_refresh precisely because it distrusts what the manager
    already believes.  Handing it the leader's in-flight answer would let one
    client's timing silently satisfy another client's freshness demand, so the
    refresh opens its own wave even with coalescing on.
    """
    root_port, cms_port = _coalescing_mgr(
        lifecycle, True, "§2.15 refresh never coalesces")
    node = _HeldNode(cms_port, 42463)
    try:
        assert node.wait_ready(), "the node was never pinged by the manager"

        path = "/data/coalesce/refresh"
        first, second = _run_pair(root_port, path, second_options=kXR_refresh)
        assert node.wait_probe(path), "the leader never opened a state wave"
        time.sleep(1.0)

        assert len(node.probes_for(path)) == 2, (
            "a kXR_refresh locate was served off an in-flight window: "
            f"{node.probes_for(path)}")

        for sid in node.probes_for(path):
            node.answer(path, streamid=sid)
        assert _both(first, second) == (42463, 42463)
    finally:
        node.close()


def test_a_forged_have_from_a_non_exporting_node_wakes_neither_waiter(
        lifecycle):
    """Security-negative: the paths-cover gate holds on the coalesced wake.

    Parking a follower on the leader's window adds a second way to be woken by
    a kYR_have.  A node that exports only `/other` therefore gets two chances
    to claim `/data/...` — the honest reply to a probe it should never receive,
    and an unsolicited frame on a streamid it invented.  Neither may redirect
    a client to it.  The honest half of the test runs first so "no redirect"
    cannot pass merely because the node was never usable at all.
    """
    root_port, cms_port = _coalescing_mgr(
        lifecycle, True, "§2.15 forged have wakes nobody")
    node = _HeldNode(cms_port, 42464, paths=b"r /other")
    try:
        assert node.wait_ready(), "the node was never pinged by the manager"

        # Honest half — the node is registered, selectable and answers for a
        # path it really exports.
        owned = "/other/coalesce/ok"
        first, second = _run_pair(root_port, owned)
        assert node.wait_probe(owned), "the node was not probed for its own path"
        node.answer(owned)
        assert _both(first, second) == (42464, 42464)

        # Forged half — same node, a path outside its export.  The frame is
        # sent BEFORE anyone asks, on a streamid that answers no probe of
        # ours, so it has every chance to poison the loc cache first.
        hidden = "/data/coalesce/hidden"
        node.answer(hidden, streamid=0x5EC0DE)      # unsolicited
        time.sleep(0.5)

        third, fourth = _run_pair(root_port, hidden)
        time.sleep(1.0)
        assert not node.probes_for(hidden), (
            "a node exporting only /other was probed for "
            f"{hidden}: {node.probes_for(hidden)}")

        third.join(timeout=12.0)
        fourth.join(timeout=12.0)
        for who, client in (("leader", third), ("follower", fourth)):
            assert client.error is None, f"{who} raised: {client.error!r}"
            if client.status == kXR_redirect:
                assert _redir_port(client.body) != 42464, (
                    f"the {who} was redirected to a node that does not "
                    f"export {hidden} — the forged kYR_have was believed")
    finally:
        node.close()
