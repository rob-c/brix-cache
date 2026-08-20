"""
test_audit15f_cms_node_legs.py — node-side CMS client tuning
(testsuite-combinatorial-coverage-audit 2026-08-15, §B1 zero-coverage
appendix): brix_cms_perf_interval, brix_cms_send_timeout,
brix_cms_tcp_keepalive and brix_cms_tcp_user_timeout appear in no test
configuration, so the freshness window of the external load feed, the bound on
a dial that never completes, and the dead-peer options on the upward socket
have never been driven.

Everything the node talks to is in-test Python: a StubManager that records every
CMS frame (the LOAD heartbeat carries the machine-load bytes, so the feed is
observable on the wire), or a SYN black hole — a listener whose accept queue is
already full, so a dial neither completes nor is refused, which is the only
shape that lets a connect deadline expire.

Cases:
  * success       — with brix_cms_perf_interval 1s a feed that printed once
    goes stale after 2x the interval and the /proc meter takes back over;
  * negative      — the same one-shot feed at the default 30s interval is still
    fresh in the same window, so the revert above is the directive's doing;
  * security-neg  — a feed line over the 1000 bound is REJECTED (the previous
    values stand) and an in-range one is clamped to 100: a garbled monitor can
    neither lie about nor wrap the node's advertised load;
  * success       — brix_cms_send_timeout 400ms bounds the dial into the black
    hole, so brix_cms_connect_failures_total climbs;
  * negative      — the default 10s bound leaves the same dial outstanding and
    the counter at zero;
  * success       — the upward leg carries the kernel keepalive timer;
  * negative      — with brix_cms_tcp_keepalive off the same leg carries none,
    and the node still logs in (the option is hardening, never a precondition);
  * success       — brix_cms_tcp_user_timeout 2s ends a dial the 30s event-loop
    deadline has not reached, so the counter climbs from the KERNEL's verdict;
  * negative      — the same 30s deadline without the knob leaves the dial
    outstanding, which is what makes the arm above the directive's doing;
  * success       — a node carrying the knob still logs in and heartbeats
    against a live manager (hardening, never a precondition).

The user_timeout arm closes the last knob the audit deferred on the node leg.
It was filed as "set and parsed, no local observable" because nothing reads
TCP_USER_TIMEOUT back — ss(8) does not print it and there is no getsockopt from
another process.  The observable is behavioural instead: TCP_USER_TIMEOUT
bounds a SYN-retransmit sequence, and it does so even when it is set AFTER the
non-blocking connect has been issued, which is exactly where connect.c:476
applies it.  Hold the event-loop deadline (brix_cms_send_timeout) far above the
knob and the only thing that can end the dial is the kernel.

Its sibling brix_cms_server_tcp_user_timeout stays deferred, now for a sharper
reason: the accept leg needs unacked outbound data — or keepalive probing —
against a peer whose kernel has stopped answering, and no local userspace peer
can be made to stop answering (a closed socket RSTs, a SIGSTOPped process still
ACKs from kernel context).  Reproducing it needs a netns with a DROP rule
(`unshare -rn`) or a two-host lab, not another fake node.

Run:
    PYTHONPATH=tests pytest tests/test_audit15f_cms_node_legs.py -v
"""

import os
import re
import socket
import time
import urllib.request

import pytest

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, BIND_HOST, SERVER_HOST
from _test_audit15f_helpers import SS_BIN, socket_timers
from _test_cms_parity_wave_helpers import (StubManager, CMS_RR_LOAD,
                                           CMS_RR_LOGIN)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.timeout(120),
              pytest.mark.xdist_group("lc-audit15f-clnode")]

FED_CPU = 77                    # the feed's cpu figure — not a /proc value


def _node(lifecycle, reason, manager_port, extra=""):
    """Start the data node pointed at `manager_port`; returns the endpoint."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15f-clnode",
        template="nginx_audit15f_cmsnode.conf",
        protocol="root",
        readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST,
                         "MANAGER_PORT": manager_port,
                         "CMS_EXTRA": extra},
        reason=reason))
    metrics_port = endpoint.extra_ports["METRICS_PORT"]
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((SERVER_HOST, metrics_port), timeout=0.5):
                return endpoint
        except OSError:
            time.sleep(0.1)
    pytest.fail(
        f"CMS node root listener started, but metrics listener did not become "
        f"ready on {SERVER_HOST}:{metrics_port}")


def _one_shot_pgm(tmp_path, *lines):
    """A feed that prints its lines once and then stays alive and silent — an
    exit would be respawned (perf_pgm.c's 5s backoff) and re-feed the values,
    which is precisely what a staleness test must not have happen."""
    pgm = tmp_path / "perf.sh"
    body = "".join(f"echo '{line}'\n" for line in lines)
    pgm.write_text(f"#!/bin/sh\n{body}sleep 3600\n")
    pgm.chmod(0o755)
    return pgm


def _load_bytes(payload):
    """The six machine-load bytes behind the blob's 2-byte length prefix."""
    return list(payload[2:8])


def _wait_load(stub, pred, start=0, timeout=15.0):
    """The first LOAD frame at or after index `start` whose load bytes satisfy
    `pred`; None if the window closes first."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for code, _mod, payload in stub.frames[start:]:
            if code == CMS_RR_LOAD and len(payload) >= 8:
                vals = _load_bytes(payload)
                if pred(vals):
                    return vals
        time.sleep(0.1)
    return None


def _all_loads(stub, start=0):
    return [_load_bytes(p) for c, _m, p in stub.frames[start:]
            if c == CMS_RR_LOAD and len(p) >= 8]


def _connect_failures(metrics_port):
    """brix_cms_connect_failures_total — the only external witness that a dial
    was torn down before LOGIN (connect.c:287 counts it in the teardown)."""
    url = f"http://{SERVER_HOST}:{metrics_port}/metrics"
    with urllib.request.urlopen(url, timeout=5) as resp:
        text = resp.read().decode("utf-8", "replace")
    match = re.search(r"^brix_cms_connect_failures_total\s+([0-9.e+]+)\s*$",
                      text, re.MULTILINE)
    assert match is not None, "metrics never exported the counter"
    return int(float(match.group(1)))


def _wait_failures(metrics_port, want, timeout=20.0):
    deadline = time.time() + timeout
    seen = 0
    while time.time() < deadline:
        seen = _connect_failures(metrics_port)
        if seen >= want:
            return seen
        time.sleep(0.25)
    return seen


class BlackHole:
    """A listener whose accept queue is already full: further SYNs are dropped,
    so a dial hangs instead of completing or being refused.  Nothing else
    reproduces a connect that outlives its deadline on loopback."""

    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        from ephemeral_port import free_port
        self._sock.bind((BIND_HOST, free_port(BIND_HOST)))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(0)          # backlog 0: one queued connection
        self._filler = socket.create_connection((SERVER_HOST, self.port),
                                                timeout=5)

    def close(self):
        for sock in (self._filler, self._sock):
            try:
                sock.close()
            except OSError:
                pass


# ── brix_cms_perf_interval: the external feed's freshness window ──────────

def test_a_short_perf_interval_expires_the_external_feed(lifecycle, tmp_path):
    """success: the feed prints cpu=77 once; the override is valid for 2x
    brix_cms_perf_interval, so within a few heartbeats of that the LOAD frames
    carry the /proc meter's figure again — a wedged monitor degrades, it does
    not keep lying."""
    stub = StubManager()
    try:
        _node(lifecycle, "audit-15f perf feed goes stale at 2x the interval",
              stub.port,
              f'brix_cms_perf_pgm "{_one_shot_pgm(tmp_path, "77 1 2 3 4")}";\n'
              "        brix_cms_perf_interval 1s;")
        fed = _wait_load(stub, lambda v: v[0] == FED_CPU)
        assert fed is not None, f"the feed never reached a LOAD: {stub.frames}"
        assert fed[1:5] == [1, 2, 3, 4], fed      # net xeq mem pag, as fed
        after = len(stub.frames)
        assert _wait_load(stub, lambda v: v[0] != FED_CPU, start=after) \
            is not None, ("the stale override was still being sent: "
                          f"{_all_loads(stub, after)}")
    finally:
        stub.stop()


def test_the_default_perf_interval_keeps_the_same_reading_fresh(lifecycle,
                                                                tmp_path):
    """negative control: the identical one-shot feed, with the interval left at
    its 30s default, is fresh for a minute — so every heartbeat in the window
    that expired it above still carries 77."""
    stub = StubManager()
    try:
        _node(lifecycle, "audit-15f perf feed default freshness window",
              stub.port,
              f'brix_cms_perf_pgm "{_one_shot_pgm(tmp_path, "77 1 2 3 4")}";')
        assert _wait_load(stub, lambda v: v[0] == FED_CPU) is not None
        after = len(stub.frames)
        time.sleep(6)                             # 3x the expiry above
        loads = _all_loads(stub, after)
        assert len(loads) >= 3, f"too few heartbeats to judge: {loads}"
        assert {v[0] for v in loads} == {FED_CPU}, loads
    finally:
        stub.stop()


def test_a_garbled_perf_line_never_reaches_the_heartbeat(lifecycle, tmp_path):
    """security-negative: a monitor that emits out-of-range columns must not be
    able to set the node's advertised load.  999 is in range and clamps to 100;
    1001 is past perf_parse_field's bound, so the whole SECOND line is rejected
    and its net=5 never appears."""
    stub = StubManager()
    try:
        _node(lifecycle, "audit-15f perf feed clamp + malformed-line reject",
              stub.port,
              'brix_cms_perf_pgm "%s";'
              % _one_shot_pgm(tmp_path, "999 999 999 999 999",
                              "1001 5 5 5 5"))
        clamped = _wait_load(stub, lambda v: v[:5] == [100] * 5)
        assert clamped is not None, (
            f"the clamped feed never reached a LOAD: {_all_loads(stub)}")
        # The rejected line would have shown up as net=5 beside a cpu of 100.
        assert all(v[1] != 5 for v in _all_loads(stub)), _all_loads(stub)
    finally:
        stub.stop()


# ── brix_cms_send_timeout: the bound on a dial that never completes ───────

def test_a_tight_send_timeout_fails_a_dial_into_a_black_hole(lifecycle):
    """success: the connect + first-write window is the knob's, so a dial that
    the peer never answers is torn down in 400ms and counted — repeatedly, as
    the cold-start retry policy re-dials."""
    hole = BlackHole()
    try:
        ep = _node(lifecycle, "audit-15f brix_cms_send_timeout 400ms bound",
                   hole.port, "brix_cms_send_timeout 400ms;")
        seen = _wait_failures(ep.extra_ports["METRICS_PORT"], 2)
        assert seen >= 2, f"only {seen} dial(s) hit the deadline"
    finally:
        hole.close()


def test_the_default_send_timeout_leaves_the_dial_outstanding(lifecycle):
    """negative control: the same black hole with the default 10s bound — the
    dial is still in flight, so nothing has failed yet.  The counter moving
    here would mean the deadline, not the directive, ended the dial above."""
    hole = BlackHole()
    try:
        ep = _node(lifecycle, "audit-15f default send timeout control arm",
                   hole.port)
        time.sleep(5)                 # 12x the tight bound, half the default
        assert _connect_failures(ep.extra_ports["METRICS_PORT"]) == 0
    finally:
        hole.close()


# ── brix_cms_tcp_keepalive: dead-peer reaping on the upward leg ───────────

def test_the_upward_leg_carries_a_keepalive_timer_by_default(lifecycle):
    """success: the client leg is armed with SO_KEEPALIVE and the tight probe
    schedule, which the kernel reports as a pending keepalive timer."""
    if not os.path.exists(SS_BIN):
        pytest.skip("ss(8) not available")
    stub = StubManager()
    try:
        _node(lifecycle, "audit-15f cms client-leg keepalive default",
              stub.port)
        assert stub.wait(CMS_RR_LOGIN) is not None, "node never logged in"
        rest = socket_timers(peer_port=stub.port)
        assert "keepalive" in rest, rest
    finally:
        stub.stop()


def test_turning_the_keepalive_off_leaves_the_upward_leg_bare(lifecycle):
    """negative control: the same node against the same manager with the flag
    off — no keepalive timer, and the link is otherwise unaffected (it logs in
    and heartbeats exactly as before)."""
    if not os.path.exists(SS_BIN):
        pytest.skip("ss(8) not available")
    stub = StubManager()
    try:
        _node(lifecycle, "audit-15f cms client-leg keepalive off",
              stub.port, "brix_cms_tcp_keepalive off;")
        assert stub.wait(CMS_RR_LOGIN) is not None, "node never logged in"
        rest = socket_timers(peer_port=stub.port)
        assert "keepalive" not in rest, rest
        assert stub.wait(CMS_RR_LOAD) is not None, "no heartbeat without it"
    finally:
        stub.stop()


# ── brix_cms_tcp_user_timeout: the kernel's own bound on the same dial ────

# Deliberately far above the knob: whatever ends these dials, it is not the
# event-loop deadline.  10s of observation cannot reach 30s.
LONG_DEADLINE = "brix_cms_send_timeout 30s;"


def test_the_kernel_user_timeout_ends_a_dial_the_deadline_has_not_reached(
        lifecycle):
    """success: with the event-loop deadline at 30s and TCP_USER_TIMEOUT at 2s,
    the SYN retransmits into the black hole are abandoned by the kernel with
    ETIMEDOUT; the dial surfaces as a writable-with-error event, is torn down
    before LOGIN and counted.  Two failures inside the observation window are
    two more than the 30s deadline could have produced."""
    hole = BlackHole()
    try:
        ep = _node(lifecycle, "audit-15f brix_cms_tcp_user_timeout 2s bound",
                   hole.port,
                   f"{LONG_DEADLINE}\n        brix_cms_tcp_user_timeout 2s;")
        seen = _wait_failures(ep.extra_ports["METRICS_PORT"], 2, timeout=25.0)
        assert seen >= 2, (
            f"only {seen} dial(s) ended; TCP_USER_TIMEOUT did not reach the "
            "connect socket (connect.c:476 applies it after "
            "ngx_event_connect_peer, which must still bound the SYN sequence)")
    finally:
        hole.close()


def test_the_same_long_deadline_alone_leaves_the_dial_outstanding(lifecycle):
    """negative control: identical node, identical black hole, identical 30s
    deadline — only the knob is gone.  Nothing fails, so the arm above is the
    directive's doing and not the retry policy's."""
    hole = BlackHole()
    try:
        ep = _node(lifecycle, "audit-15f cms user-timeout control arm",
                   hole.port, LONG_DEADLINE)
        time.sleep(10)                # 5x the knob above, a third of the bound
        assert _connect_failures(ep.extra_ports["METRICS_PORT"]) == 0
    finally:
        hole.close()


def test_a_node_carrying_the_user_timeout_still_joins_a_live_manager(lifecycle):
    """success: the knob is dead-peer hardening, so a reachable manager must be
    unaffected — the node logs in and heartbeats with a 2s TCP_USER_TIMEOUT on
    the same socket that carries them."""
    stub = StubManager()
    try:
        _node(lifecycle, "audit-15f cms user-timeout against a live manager",
              stub.port, "brix_cms_tcp_user_timeout 2s;")
        assert stub.wait(CMS_RR_LOGIN) is not None, "node never logged in"
        assert stub.wait(CMS_RR_LOAD) is not None, "no heartbeat under the knob"
    finally:
        stub.stop()
