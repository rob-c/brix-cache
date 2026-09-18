"""
test_phase116_reresolve.py — phase-116 W4/W5: runtime re-resolution.

WHAT: A record change moves the CMS manager dial to the new address without
      a reload; a dead target's retries back off between `brix_dns_retry`'s
      bounds; `min_ttl` floors the refresh cadence and `valid=` caps it.
WHY:  This is the nginx-Plus gap the phase closes: OSS nginx resolves an
      upstream name once at start and never again.
HOW:  Two recording sinks on two loopback addresses share one port; the
      stub swaps the A record between them and the suite watches which
      sink the reconnect reaches.  Backoff is read from the dashboard's
      per-target failure count (nginx's own resolver answers a cached
      NXDOMAIN for ten seconds, so wire queries cannot show the cadence);
      TTL bounds are read from the stub's question log.  A two-address
      record with nothing listening on the first address proves the dead
      member is left behind rather than dialled forever.
"""
from __future__ import annotations

import time

import pytest

from _phase116_helpers import (HAVE_NGINX, BIND_HOST, DnsLab, TcpSink, dns_target,
                               metric, metrics_text, wait_for_state, wait_until)
from dns_stub import TYPE_A
from ephemeral_port import free_port
from server_registry import NginxInstanceSpec
from lib_py.util import loopback_alias_usable

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p116-dns")]

MANAGER = "manager.lab.test"
ALT_HOST = "127.0.0.2"   # net-literal-allow: second loopback address for the record swap

# Linux routes all of 127.0.0.0/8 to lo; macOS assigns only 127.0.0.1, so the
# record swap has nowhere to point until an alias exists.
pytestmark.append(pytest.mark.skipif(
    not loopback_alias_usable(ALT_HOST),
    reason=f"{ALT_HOST} is not bindable on this host "
           f"(sudo ifconfig lo0 alias {ALT_HOST} up)"))


def _start(lifecycle, lab, port, reason, **values):
    if not HAVE_NGINX:
        pytest.skip("nginx binary unavailable")
    return lifecycle.start(NginxInstanceSpec(
        name="lc-p116-dns", template="nginx_lc_p116_dns.conf",
        protocol="http", readiness="tcp",
        template_values=lab.values(MANAGER_HOST=MANAGER, MANAGER_PORT=port, **values),
        reason=reason))


def test_record_change_moves_the_manager_dial(lifecycle, tmp_path):
    a = TcpSink(BIND_HOST).start()
    port = a.port
    b = TcpSink(ALT_HOST, port).start()
    lab = DnsLab(tmp_path)
    try:
        lab.stub.add_a(MANAGER, BIND_HOST, ttl=1)
        ep = _start(lifecycle, lab, port, "A record swap re-routes the CMS dial",
                    RESOLVER_EXTRA="ipv6=off min_ttl=1s")
        assert wait_for_state(ep.port, MANAGER, "resolved")
        assert a.wait_for_dial(), "first dial never reached sink A"
        before = dns_target(ep.port, MANAGER)["resolutions"]
        swapped_at = time.monotonic()
        lab.stub.swap_a(MANAGER, ALT_HOST, ttl=1)
        assert wait_until(lambda: dns_target(ep.port, MANAGER)["resolutions"] > before, timeout=15), \
            "the target was never re-resolved after the swap"
        a.drop_connections()
        assert b.wait_for_dial(timeout=45), "reconnect never reached sink B (new address)"
        assert b.accepts[0][0] > swapped_at
        assert metric(metrics_text(ep.port), "brix_dns_targets", state="resolved") == 1
    finally:
        lab.close()
        a.stop()
        b.stop()


def _assert_retry_bounded(row: dict, max_next_ms: int) -> None:
    """A failed target's armed retry must sit inside the configured max.

    `next_retry_ms` reads 0 in one honest window: the moment between the timer
    firing and the next retry being armed, when no retry IS pending because one
    is in flight.  A 50 ms poll lands there roughly once in seven runs, so
    demanding a positive value on EVERY sample tests the sampler's luck, not the
    backoff.  The armed-ness check therefore moves to _sample_retries, which
    asserts over the whole window instead of one instant.
    """
    assert row["state"] == "failed", row
    assert 0 <= row["next_retry_ms"] <= max_next_ms, row


def _sample_retries(http_port: int, host: str, seconds: float,
                    max_next_ms: int) -> list[tuple[float, int]]:
    """(elapsed, failures) at every change of the failure count, sampled from
    the dashboard row for `seconds`."""
    t0 = time.monotonic()
    seen: list[tuple[float, int]] = []
    armed = 0
    while time.monotonic() - t0 < seconds:
        row = dns_target(http_port, host)
        _assert_retry_bounded(row, max_next_ms)
        armed += row["next_retry_ms"] > 0
        if not seen or row["failures"] != seen[-1][1]:
            seen.append((time.monotonic() - t0, row["failures"]))
        time.sleep(0.05)
    # The teeth the per-sample assert used to carry: a target that never arms a
    # retry is stuck, and every sample reading 0 is exactly that signature.
    assert armed, f"no retry was ever armed for {host} in {seconds}s"
    return seen


def test_dead_target_retries_back_off(lifecycle, tmp_path):
    port = free_port(BIND_HOST)
    lab = DnsLab(tmp_path)
    try:
        ep = _start(lifecycle, lab, port, "retry cadence for a dead name",
                    RESOLVER_EXTRA="ipv6=off negative_ttl=0", RETRY="200ms 1s")
        assert wait_for_state(ep.port, MANAGER, "failed")
        seen = _sample_retries(ep.port, MANAGER, 4.0, 1300)
        failures = seen[-1][1] - seen[0][1]
        # 0.2 → 0.4 → 0.8 → 1.0 → 1.0 (+ ≤250 ms jitter) ≈ 4–6 retries in 4 s;
        # a flat 200 ms cadence would be ~20, a stuck timer 0.
        assert 2 <= failures <= 8, seen
        gaps = [b - a for (a, _), (b, _) in zip(seen, seen[1:])]
        assert gaps and max(gaps) <= 1.5 and gaps[-1] > gaps[0] * 1.5, gaps
    finally:
        lab.close()


def test_min_ttl_floors_the_refresh_cadence(lifecycle, tmp_path):
    port = free_port(BIND_HOST)
    lab = DnsLab(tmp_path)
    try:
        lab.stub.add_a(MANAGER, BIND_HOST, ttl=1)
        ep = _start(lifecycle, lab, port, "min_ttl=5s floors a 1s answer",
                    RESOLVER_EXTRA="ipv6=off min_ttl=5s")
        assert wait_for_state(ep.port, MANAGER, "resolved")
        lab.stub.clear_queries()
        time.sleep(6.0)
        n = len(lab.stub.queries_for(MANAGER, TYPE_A))
        assert n <= 2, f"{n} A queries in 6s under min_ttl=5s"
    finally:
        lab.close()


def test_valid_caps_the_refresh_cadence(lifecycle, tmp_path):
    port = free_port(BIND_HOST)
    lab = DnsLab(tmp_path)
    try:
        lab.stub.add_a(MANAGER, BIND_HOST, ttl=60)
        ep = _start(lifecycle, lab, port, "valid=2s caps a 60s answer",
                    RESOLVER_EXTRA="ipv6=off valid=2s min_ttl=1s")
        assert wait_for_state(ep.port, MANAGER, "resolved")
        lab.stub.clear_queries()
        # nginx's resolver serves an entry while `valid >= now` in whole
        # seconds, so a 2 s cap re-asks the wire every ~3 s: a 60 s answer
        # would give 0 queries here, valid=2s gives 2..3.
        time.sleep(7.5)
        n = len(lab.stub.queries_for(MANAGER, TYPE_A))
        assert 2 <= n <= 4, f"{n} A queries in 7.5s under valid=2s"
    finally:
        lab.close()


def test_a_dead_first_address_is_left_for_the_second(lifecycle, tmp_path):
    """W5.3: the whole answer set is kept, and a refused dial advances the
    published address (`brix_dns_target_note_failure` -> `brix_dns_target_next`).
    A driver that pinned addrs[0] would keep dialling a member that is down for
    as long as the record lives — the failure mode a multi-address record exists
    to avoid.  Note which trigger: for a target consumer like the CMS client the
    advance is failure-driven; per-connect round-robin is brix_upstream's and is
    pinned in test_phase116_upstream_async_resolve.py.
    """
    # Nothing listens on BIND_HOST:port, so the first dial is refused; only
    # the second address of the record can ever accept.
    live = TcpSink(ALT_HOST).start()
    port = live.port
    lab = DnsLab(tmp_path)
    try:
        lab.stub.add_a(MANAGER, BIND_HOST, ttl=30)
        lab.stub.add_a(MANAGER, ALT_HOST, ttl=30)
        ep = _start(lifecycle, lab, port, "a refused dial leaves the dead address",
                    RESOLVER_EXTRA="ipv6=off min_ttl=30s")
        row = wait_for_state(ep.port, MANAGER, "resolved")
        assert row and row["addresses"] == 2, row
        assert live.wait_for_dial(timeout=45), \
            "the dead first address was never left: nothing reached " + ALT_HOST
        # The advance has to SURVIVE: a re-resolution that restarted the
        # rotation at addrs[0] would drag every later reconnect back onto the
        # dead member, and the refused dials would keep accumulating.
        failures = metric(metrics_text(ep.port), "brix_cms_connect_failures_total")
        assert failures is not None and failures <= 2, \
            f"{failures} refused dials: the dead address is being re-dialled"
        # The dial failed, the name did not: the target stays `resolved` with
        # both addresses, and the rotation came out of the cached answer set
        # rather than a re-query per attempt.
        row = dns_target(ep.port, MANAGER)
        assert row["state"] == "resolved" and row["addresses"] == 2, row
        assert metric(metrics_text(ep.port), "brix_dns_targets", state="failed") in (0, None)
        assert len(lab.stub.queries_for(MANAGER, TYPE_A)) <= 2, \
            "a refused dial re-queried DNS instead of using the cached answer"
    finally:
        lab.close()
        live.stop()
