"""
test_audit15f_cluster_tuning.py — manager-side cluster tuning
(testsuite-combinatorial-coverage-audit 2026-08-15, §B1 zero-coverage
appendix): brix_cms_load_weight, brix_dashboard_cluster_stale_after,
brix_cms_server_tcp_keepalive and brix_cms_server_tcp_user_timeout appear in
no test configuration, so the manager's load-weighted selection blend, the
cluster panel's staleness verdict and the accept leg's dead-peer options have
never been driven.

One template (nginx_audit15f_clustertune.conf) started per test, because
brix_cms_load_weight is set ONCE per process (server_conf_merge_cluster.c calls
brix_srv_set_load_weight into a process global): the two arms of the weight
cross are two nginx processes, not two server blocks.  Fake Python data nodes
(the parity wave's FakeNode) register over the real CMS wire, kXR_locate reads
the selection verdict off the root:// face, and the two anonymous dashboard
faces read the SAME registry through different staleness windows.

Cases:
  * success       — with the weight at 100 the read metric IS the heartbeat
    machine load, so the cooler of two otherwise identical nodes wins;
  * negative      — with the weight off the same two nodes and the same LOAD
    frames leave selection on util_pct alone, and the tie keeps the
    first-registered node (srv_sel_metric_better's strict comparison);
  * defect pin    — a LOAD heartbeat ZEROES the node's registered free space:
    the emitter writes a bare [2-byte len][6 load bytes] blob but the parser
    walks it as a tagged scalar, so cms_srv_parse_load_free_mb always returns
    0 (defect candidate #16);
  * success       — each dashboard face reports its own stale_after_ms;
  * success       — the same live node, in the same second, reads fresh through
    the 90s window and stale through the 1ms one;
  * security-neg  — the anonymous cluster view redacts the node's host and
    omits port/paths/vnid/stage;
  * success       — with brix_cms_server_tcp_keepalive on, the manager's
    ACCEPTED socket carries a kernel keepalive timer;
  * negative      — with the flag off the same socket carries none, while the
    node stays registered.

Run:
    PYTHONPATH=tests pytest tests/test_audit15f_cluster_tuning.py -v
"""

import json
import os
import time
import urllib.request

import pytest

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, BIND_HOST, SERVER_HOST
from _test_audit15f_helpers import SS_BIN, socket_timers
from _test_cms_parity_wave_helpers import (FakeNode, _load_payload,
                                           _wait_selectable, CMS_RR_LOAD)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.timeout(120),
              pytest.mark.xdist_group("lc-audit15f-cltune")]

HOT_PORT, COOL_PORT = 42901, 42902      # advertised data ports (never dialled)


def _mgr(lifecycle, reason, extra="", srv_extra=""):
    """Start the tuning manager; returns the endpoint."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    return lifecycle.start(NginxInstanceSpec(
        name="lc-audit15f-cltune",
        template="nginx_audit15f_clustertune.conf",
        protocol="root",
        readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST,
                         "CMS_EXTRA": extra,
                         "CMSSRV_EXTRA": srv_extra},
        reason=reason))


def _cluster(http_port):
    """The anonymous /brix/api/v1/cluster panel as parsed JSON."""
    url = f"http://{SERVER_HOST}:{http_port}/brix/api/v1/cluster"
    with urllib.request.urlopen(url, timeout=8) as resp:
        return json.loads(resp.read().decode())


def _wait_stale(http_port, timeout=10.0):
    """Poll the panel until its first server reads stale; returns that entry.

    The verdict is `heartbeat_age_ms > stale_after_ms`, so a 1ms window is NOT
    stale during the millisecond the entry is created — a read that lands that
    fast is a race, not a verdict.  Polling for the flip keeps the assertion
    about the window rather than about scheduling luck.
    """
    deadline = time.time() + timeout
    entry = None
    while time.time() < deadline:
        entry = _cluster(http_port)["servers"][0]
        if entry["stale"] is True:
            return entry
        time.sleep(0.05)
    raise AssertionError(f"entry never aged past the 1ms window: {entry}")


def _wait_servers(http_port, count, timeout=10.0):
    """Poll the panel until `count` servers are registered; returns them."""
    deadline = time.time() + timeout
    seen = []
    while time.time() < deadline:
        seen = _cluster(http_port).get("servers", [])
        if len(seen) >= count:
            return seen
        time.sleep(0.1)
    raise AssertionError(f"registry never reached {count} server(s): {seen}")


# ── brix_cms_load_weight: the manager-side selection blend ────────────────

def test_the_cooler_node_wins_when_the_load_is_weighted(lifecycle):
    """success: at weight 100 the read metric is purely the heartbeat machine
    load, so the cool node wins even though it registered SECOND (and would
    lose the util_pct tie)."""
    ep = _mgr(lifecycle, "audit-15f brix_cms_load_weight 100 selection blend",
              extra="brix_cms_load_weight 100;")
    http = ep.extra_ports["HTTP_PORT"]
    hot = FakeNode(ep.extra_ports["CMS_PORT"], HOT_PORT)
    try:
        _wait_servers(http, 1)          # hot takes slot 0 — the tie-break seat
        cool = FakeNode(ep.extra_ports["CMS_PORT"], COOL_PORT)
        try:
            _wait_servers(http, 2)
            hot.send(CMS_RR_LOAD, 0, _load_payload(cpu=90, net=90))
            cool.send(CMS_RR_LOAD, 0, _load_payload(cpu=5, net=5))
            got = _wait_selectable(ep.port, "/weighted.dat", COOL_PORT)
            assert got == COOL_PORT
        finally:
            cool.close()
    finally:
        hot.close()


def test_with_the_weight_off_the_load_is_ignored(lifecycle):
    """negative control: the SAME two nodes and the SAME LOAD frames, with the
    weight off, leave the metric at util_pct — equal here, so the strict
    comparison keeps the first-registered (hot) node."""
    ep = _mgr(lifecycle, "audit-15f brix_cms_load_weight 0 control arm",
              extra="brix_cms_load_weight 0;")
    http = ep.extra_ports["HTTP_PORT"]
    hot = FakeNode(ep.extra_ports["CMS_PORT"], HOT_PORT)
    try:
        _wait_servers(http, 1)
        cool = FakeNode(ep.extra_ports["CMS_PORT"], COOL_PORT)
        try:
            servers = _wait_servers(http, 2)
            hot.send(CMS_RR_LOAD, 0, _load_payload(cpu=90, net=90))
            cool.send(CMS_RR_LOAD, 0, _load_payload(cpu=5, net=5))
            # Both nodes are candidates and equally utilised — the only reason
            # the hot one can win is that the load plays no part.
            assert {s["util_pct"] for s in servers} == {7}, servers
            got = _wait_selectable(ep.port, "/unweighted.dat", HOT_PORT)
            assert got == HOT_PORT
        finally:
            cool.close()
    finally:
        hot.close()


def test_a_load_heartbeat_preserves_the_registered_free_space(lifecycle):
    """defect #16 RETIRED: cms_srv_parse_load_free_mb once walked the LOAD
    payload's bare [2-byte len][6 bytes] blob with tlv_read_next, stopped on
    the 0x00 pseudo-tag, and stored free_mb=0 on every heartbeat — flattening
    write selection.  The parser was fixed (Pup blob skipped before the tagged
    free-space int), so a heartbeat now carries BOTH halves: the load bytes
    land AND the registered free space survives."""
    ep = _mgr(lifecycle, "audit-15f LOAD free_mb parse pin")
    http = ep.extra_ports["HTTP_PORT"]
    node = FakeNode(ep.extra_ports["CMS_PORT"], HOT_PORT, free_mb=5000)
    try:
        servers = _wait_servers(http, 1)
        assert servers[0]["free_mb"] == 5000, servers   # from LOGIN
        node.send(CMS_RR_LOAD, 0, _load_payload(cpu=3, free_mb=5000))
        deadline = time.time() + 6
        while time.time() < deadline:
            servers = _cluster(http)["servers"]
            if servers and servers[0]["load_pct"] == 3:
                break
            time.sleep(0.1)
        assert servers[0]["load_pct"] == 3, servers     # the load bytes land
        assert servers[0]["free_mb"] == 5000, (
            "the LOAD heartbeat zeroed free_mb again — defect #16 regressed: "
            f"{servers}")
    finally:
        node.close()


# ── brix_dashboard_cluster_stale_after: the panel's staleness window ──────

def test_each_dashboard_face_reports_its_own_stale_window(lifecycle):
    """success: the knob is per-location and is echoed as stale_after_ms."""
    ep = _mgr(lifecycle, "audit-15f cluster stale window echo")
    assert _cluster(ep.extra_ports["HTTP_PORT"])["stale_after_ms"] == 90000
    assert _cluster(ep.extra_ports["HTTP2_PORT"])["stale_after_ms"] == 1


def test_the_short_window_calls_the_same_live_node_stale(lifecycle):
    """success cross: one registry, one heartbeating node, two windows — the
    stale verdict follows the location's own configuration, not the node."""
    ep = _mgr(lifecycle, "audit-15f cluster stale verdict cross")
    node = FakeNode(ep.extra_ports["CMS_PORT"], HOT_PORT)
    try:
        _wait_servers(ep.extra_ports["HTTP_PORT"], 1)
        short = _wait_stale(ep.extra_ports["HTTP2_PORT"])
        generous = _cluster(ep.extra_ports["HTTP_PORT"])["servers"][0]
        # The same live entry, read through both faces: only the window differs.
        assert generous["stale"] is False, (short, generous)
        # Same entry, same clock: the age is well inside the generous window,
        # so the flip is the directive and nothing else.
        assert generous["heartbeat_age_ms"] < 90000, generous
    finally:
        node.close()


def test_the_anonymous_cluster_view_never_leaks_the_node_port(lifecycle):
    """security-negative: the read-only anonymous tier redacts the host and
    omits the infra detail (port, exported paths, vnid, stage bit).  The face
    carries a password, so this cookie-less GET really is the anonymous tier —
    without one check_auth admits everybody and nothing is ever redacted."""
    ep = _mgr(lifecycle, "audit-15f anonymous cluster redaction")
    node = FakeNode(ep.extra_ports["CMS_PORT"], HOT_PORT)
    try:
        server = _wait_servers(ep.extra_ports["HTTP_PORT"], 1)[0]
        assert server["host"] == "[redacted]", server
        for leaked in ("port", "paths", "vnid", "stage"):
            assert leaked not in server, (leaked, server)
        assert str(HOT_PORT) not in json.dumps(server), server
    finally:
        node.close()


# ── brix_cms_server_tcp_*: the accept leg's dead-peer options ─────────────

def test_the_accept_leg_carries_the_configured_keepalive_timer(lifecycle):
    """success: with the flag on, the manager's accepted socket is armed with
    SO_KEEPALIVE + the tight probe schedule (ss shows the keepalive timer)."""
    if not os.path.exists(SS_BIN):
        pytest.skip("ss(8) not available")
    ep = _mgr(lifecycle, "audit-15f cms accept-leg keepalive on",
              srv_extra="brix_cms_server_tcp_keepalive on;\n"
                        "        brix_cms_server_tcp_user_timeout 4s;")
    node = FakeNode(ep.extra_ports["CMS_PORT"], HOT_PORT)
    try:
        _wait_servers(ep.extra_ports["HTTP_PORT"], 1)
        rest = socket_timers(local_port=ep.extra_ports["CMS_PORT"],
                             peer_port=node.sock.getsockname()[1])
        assert "keepalive" in rest, rest
    finally:
        node.close()


def test_without_the_flag_the_accept_leg_has_no_keepalive_timer(lifecycle):
    """negative control: the same node, the same manager, the flag off — no
    keepalive timer on the accepted socket, and the node still registers (the
    option is hardening, never a precondition for joining)."""
    if not os.path.exists(SS_BIN):
        pytest.skip("ss(8) not available")
    ep = _mgr(lifecycle, "audit-15f cms accept-leg keepalive off",
              srv_extra="brix_cms_server_tcp_keepalive off;")
    node = FakeNode(ep.extra_ports["CMS_PORT"], HOT_PORT)
    try:
        _wait_servers(ep.extra_ports["HTTP_PORT"], 1)
        rest = socket_timers(local_port=ep.extra_ports["CMS_PORT"],
                             peer_port=node.sock.getsockname()[1])
        assert "keepalive" not in rest, rest
    finally:
        node.close()
