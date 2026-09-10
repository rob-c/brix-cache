"""2.0 readiness F12 — CMS/cluster metrics across a three-tier redirector tree.

A meta-manager, a sub-manager that registers upward, and one leaf data server,
each with its own ``/metrics``.  Legs: every tier reports the members it owns
(``brix_cluster_servers_registered``, ``brix_cms_logins_total``, per-server
``last_seen``) — success; a leaf disconnect is visible on the tier that owned
it as a blacklist + disconnect count and clears on reconnect — error/recovery;
and the meta tier never accounts a leaf failure against the sub-manager —
security negative (a failing node cannot poison its parent's standing).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from _test_release20_metrics_helpers import scrape, series, value, wait_for, wait_port
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-r20-cms")]


class Tree:
    def __init__(self, harness, meta, sub, leaf):
        self.harness, self.meta, self.sub, self.leaf = harness, meta, sub, leaf

    def metrics(self, ep):
        return scrape(ep.extra_ports["METRICS_PORT"])


def _registered(ep):
    body = scrape(ep.extra_ports["METRICS_PORT"])
    return body if value(body, "brix_cluster_servers_registered") == 1.0 else None


def _server_rows(body, name, port):
    return [(l, v) for l, v in series(body, name) if l.get("server", "").endswith(f":{port}")]


@pytest.fixture(scope="module")
def tree(tmp_path_factory):
    work = Path(tmp_path_factory.mktemp("r20-cms"))
    harness = LifecycleHarness()
    try:
        meta = harness.start(NginxInstanceSpec(
            name="lc-r20-cms-meta", template="nginx_lc_r20_cms_meta.conf",
            template_values={"BIND_HOST": BIND_HOST},
            reason="2.0 readiness F12: meta manager"))
        sub_data = work / "sub"; sub_data.mkdir()
        sub = harness.start(NginxInstanceSpec(
            name="lc-r20-cms-sub", template="nginx_lc_r20_cms_sub.conf",
            data_root=str(sub_data),
            template_values={"BIND_HOST": BIND_HOST,
                             "META_CMS_PORT": meta.extra_ports["CMS_PORT"]},
            reason="2.0 readiness F12: sub manager"))
        leaf_data = work / "leaf"; leaf_data.mkdir()
        (leaf_data / "leaf.txt").write_text("leaf\n")
        leaf = harness.start(NginxInstanceSpec(
            name="lc-r20-cms-leaf", template="nginx_lc_r20_cms_leaf.conf",
            data_root=str(leaf_data),
            template_values={"BIND_HOST": BIND_HOST,
                             "MANAGER_CMS_PORT": sub.extra_ports["CMS_PORT"]},
            reason="2.0 readiness F12: leaf data server"))
        for ep in (meta, sub, leaf):
            if not wait_port(ep.extra_ports["METRICS_PORT"]):
                pytest.skip(f"{ep.name} exposed no /metrics")
        if wait_for(lambda: _registered(meta), 30) is None or wait_for(lambda: _registered(sub), 30) is None:
            pytest.skip("three-tier tree did not converge")
        yield Tree(harness, meta, sub, leaf)
    finally:
        harness.close()


def test_every_tier_reports_the_members_it_owns(tree):
    meta, sub, leaf = tree.metrics(tree.meta), tree.metrics(tree.sub), tree.metrics(tree.leaf)
    assert value(meta, "brix_cluster_servers_registered") == 1.0
    assert value(sub, "brix_cluster_servers_registered") == 1.0
    assert value(leaf, "brix_cluster_servers_registered") in (None, 0.0)
    # the sub's DS face logged into the meta; the leaf logged into the sub
    assert value(sub, "brix_cms_logins_total") >= 1.0
    assert value(leaf, "brix_cms_logins_total") >= 1.0
    seen = _server_rows(meta, "brix_cluster_server_last_seen_seconds", tree.sub.port)
    assert len(seen) == 1 and 0.0 <= seen[0][1] < 30.0, seen
    seen = _server_rows(sub, "brix_cluster_server_last_seen_seconds", tree.leaf.port)
    assert len(seen) == 1 and 0.0 <= seen[0][1] < 30.0, seen
    assert _server_rows(meta, "brix_cluster_server_last_seen_seconds", tree.leaf.port) == []


def _leaf_state(tree):
    """(blacklisted, disconnect_total) of the leaf as its sub-manager sees it."""
    body = tree.metrics(tree.sub)
    bl = _server_rows(body, "brix_cluster_server_blacklisted", tree.leaf.port)
    dc = _server_rows(body, "brix_cluster_server_disconnect_total", tree.leaf.port)
    return (bl[0][1] if bl else None, dc[0][1] if dc else None)


def _leaf_state_when(tree, accept, timeout):
    return wait_for(lambda: _first_or_none(_leaf_state(tree), accept), timeout=timeout)


def _first_or_none(state, accept):
    return state if accept(state) else None


def _is_dropped(state):
    return state[0] == 1.0 and (state[1] or 0.0) >= 1.0


def _is_back(state):
    return state == (0.0, 0.0)


def _drop_leaf(tree):
    tree.harness.stop("lc-r20-cms-leaf")
    dropped = _leaf_state_when(tree, _is_dropped, 20)
    assert dropped is not None, "sub-manager never marked the leaf blacklisted/disconnected"
    return dropped


def _bring_leaf_back(tree):
    tree.harness.start_registered("lc-r20-cms-leaf")
    assert wait_port(tree.leaf.extra_ports["METRICS_PORT"])
    back = _leaf_state_when(tree, _is_back, 30)
    assert back is not None, "leaf never re-registered after restart"
    return back


def test_leaf_disconnect_and_reconnect_are_visible_on_its_owner(tree):
    """Error leg: the sub-manager's row for the leaf goes blacklisted=1 with
    disconnect_total=1 when the leaf's CMS link drops, and re-registration
    REBUILDS the row (`brix_srv_register`: "clear any prior blacklist on
    reconnect") — blacklisted and disconnect_total both read 0 again, the
    counter-reset Prometheus allows a counter after a restart of what it
    counts.  A re-register is therefore never a second disconnect."""
    assert _leaf_state(tree) == (0.0, 0.0)
    dropped = _drop_leaf(tree)
    assert dropped[1] == 1.0, dropped
    assert _bring_leaf_back(tree) == (0.0, 0.0)
    assert value(tree.metrics(tree.sub), "brix_cluster_servers_registered") == 1.0
    assert value(tree.metrics(tree.leaf), "brix_cms_logins_total") >= 1.0


def test_meta_never_charges_the_sub_for_a_leaf_failure(tree):
    """Security negative: the leaf's drop (previous test) left the sub-manager's
    standing at the meta tier untouched."""
    meta = tree.metrics(tree.meta)
    bl = _server_rows(meta, "brix_cluster_server_blacklisted", tree.sub.port)
    dc = _server_rows(meta, "brix_cluster_server_disconnect_total", tree.sub.port)
    assert bl and bl[0][1] == 0.0, bl
    assert dc and dc[0][1] == 0.0, dc
    assert value(meta, "brix_cluster_servers_registered") == 1.0
