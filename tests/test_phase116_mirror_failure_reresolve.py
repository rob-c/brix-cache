"""
test_phase116_mirror_failure_reresolve.py — phase-116 W5.2: an unreachable
shadow costs one mirror, not the whole TTL.

WHAT: A stream `brix_mirror_url` naming a stub-controlled host.  While the
      shadow accepts, the mirror dials it and the target is left alone; once
      the address stops accepting, the failed connect books a target failure
      and the registry re-resolves the name far ahead of its TTL.  A shadow
      that accepts but never answers is NOT a target failure, and neither a
      literal target nor a spoofed answer ever arms a retry or a dial.
WHY:  the mirror carries a copy of client traffic.  Before W5.2 a shadow that
      moved address stayed dead until the TTL expired (every mirror in that
      window lost); after it, an off-path answer must still never redirect
      that copy, and a reachable-but-silent shadow must not trigger a
      re-resolve storm.
HOW:  `nginx_lc_p116_dns_mirror.conf` under the lifecycle harness; a kXR_stat
      on the primary is the mirrored request, and the dashboard's per-target
      `resolutions` counter is the driver's own view of the re-resolve (the
      answer is still in nginx's resolver cache, so the wire cannot show it).
"""
from __future__ import annotations

import time

import pytest

from _phase116_helpers import (HAVE_NGINX, BIND_HOST, DnsLab, TcpSink, dns_panel,
                               dns_target, kXR_error, kXR_ok, stat, wait_for_state,
                               wait_until)
from ephemeral_port import free_port
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p116-dns-mirror")]

SHADOW = "shadow.lab.test"
LITERAL_HOST = "127.0.0.1"   # net-literal-allow: the literal-target negative
# A long answer TTL with a long floor: nothing but the W5.2 failure hook can
# re-resolve inside a test's lifetime.
TTL = 300
SLOW_REFRESH = "ipv6=off min_ttl=120s"


def _start(lifecycle, lab, target, reason, timeout="600ms", **values):
    if not HAVE_NGINX:
        pytest.skip("nginx binary unavailable")
    return lifecycle.start(NginxInstanceSpec(
        name="lc-p116-dns-mirror", template="nginx_lc_p116_dns_mirror.conf",
        protocol="http", readiness="tcp",
        template_values=lab.values(MIRROR_TARGET=target, MIRROR_TIMEOUT=timeout,
                                   RESOLVER_EXTRA=SLOW_REFRESH, **values),
        reason=reason))


def _mirrored_stat(root_port: int) -> int:
    """One kXR_stat — a path-based, replayable request, so the primary's
    answer is followed by exactly one shadow launch per target."""
    st = stat(root_port, "/f.txt")
    assert st in (kXR_ok, kXR_error), st
    return st


def test_reachable_shadow_is_dialled_and_left_alone(lifecycle, tmp_path):
    """Success: the mirror follows the record, and a shadow that accepts (even
    one that never answers) books no failure and no early re-resolve."""
    sink = TcpSink(BIND_HOST).start()
    port = sink.port
    lab = DnsLab(tmp_path)
    try:
        lab.stub.add_a(SHADOW, BIND_HOST, ttl=TTL)
        ep = _start(lifecycle, lab, f"{SHADOW}:{port}", "mirror reaches a live shadow")
        assert wait_for_state(ep.port, SHADOW, "resolved"), dns_target(ep.port, SHADOW)
        before = dns_target(ep.port, SHADOW)
        _mirrored_stat(ep.extra_ports["ROOT_PORT"])
        assert sink.wait_for_dial(timeout=10), "the mirror never dialled the shadow"
        assert sink.accepts[0][1] == BIND_HOST
        # the sink speaks no xrootd: the mirror times out on the handshake.
        # That is a mirror error, never a DNS failure — the address answered.
        time.sleep(1.5)
        after = dns_target(ep.port, SHADOW)
        assert after["state"] == "resolved", after
        assert after["failures"] == before["failures"], (before, after)
        assert after["resolutions"] == before["resolutions"], (before, after)
    finally:
        lab.close()
        sink.stop()


def test_shadow_that_stops_accepting_reresolves_ahead_of_the_ttl(lifecycle, tmp_path):
    """Error: the connect fails, so the target is re-resolved in ~0.5s instead
    of waiting out the 300s answer (min_ttl 120s)."""
    sink = TcpSink(BIND_HOST).start()
    port = sink.port
    lab = DnsLab(tmp_path)
    try:
        lab.stub.add_a(SHADOW, BIND_HOST, ttl=TTL)
        ep = _start(lifecycle, lab, f"{SHADOW}:{port}", "shadow address stops accepting")
        assert wait_for_state(ep.port, SHADOW, "resolved")
        root = ep.extra_ports["ROOT_PORT"]
        _mirrored_stat(root)
        assert sink.wait_for_dial(timeout=10)
        before = dns_target(ep.port, SHADOW)["resolutions"]
        sink.stop()                                   # nothing listens now
        _mirrored_stat(root)                          # this mirror's connect fails
        assert wait_until(lambda: dns_target(ep.port, SHADOW)["resolutions"] > before,
                          timeout=8), \
            f"a refused mirror never re-resolved the target (resolutions={before})"
        row = dns_target(ep.port, SHADOW)
        assert row["state"] == "resolved", row       # the name still answers
    finally:
        lab.close()
        sink.stop()


def test_spoofed_answer_never_reaches_the_mirror(lifecycle, tmp_path):
    """Security-negative: an off-path answer for another qname must not
    redirect the copy of client traffic — the target stays unresolved and no
    mirror is ever launched."""
    sink = TcpSink(BIND_HOST).start()
    port = sink.port
    lab = DnsLab(tmp_path)
    try:
        lab.stub.add_a(SHADOW, BIND_HOST, ttl=TTL)
        lab.stub.spoof_qname = "attacker.lab.test"
        ep = _start(lifecycle, lab, f"{SHADOW}:{port}", "spoofed shadow answers")
        assert wait_until(lambda: (dns_target(ep.port, SHADOW) or {}).get("state")
                          == "failed", timeout=25), dns_target(ep.port, SHADOW)
        for _ in range(3):
            _mirrored_stat(ep.extra_ports["ROOT_PORT"])
        time.sleep(1.0)
        row = dns_target(ep.port, SHADOW)
        assert row["resolutions"] == 0 and row["addresses"] == 0, row
        assert not sink.accepts, "a mirror followed a spoofed answer"
    finally:
        lab.close()
        sink.stop()


def test_literal_target_never_arms_a_retry(lifecycle, tmp_path):
    """Security-negative: a dead literal shadow must not turn every mirrored
    request into a resolver wake-up — note_failure is inert for a literal."""
    port = free_port(BIND_HOST)
    lab = DnsLab(tmp_path)
    try:
        ep = _start(lifecycle, lab, f"{LITERAL_HOST}:{port}",
                    "literal shadow, nothing listening")
        row = dns_target(ep.port, LITERAL_HOST)
        assert row is not None and row["literal"] is True, dns_panel(ep.port)
        for _ in range(3):
            _mirrored_stat(ep.extra_ports["ROOT_PORT"])   # every connect refused
        time.sleep(1.0)
        after = dns_target(ep.port, LITERAL_HOST)
        assert after["next_retry_ms"] == 0, after
        assert after["resolutions"] == row["resolutions"], (row, after)
        assert not lab.stub.queries, "a literal mirror target queried the wire"
    finally:
        lab.close()
