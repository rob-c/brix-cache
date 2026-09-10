"""
test_phase116_upstream_async_resolve.py — phase-116 W5: the proxy resolves async.

WHAT: A root:// proxy whose `brix_upstream` is a hostname.  Unresolvable
      at start, an open fails fast and the worker stays responsive; once the
      stub answers, the dial follows the record to a recording sink and the
      proxy's own lookup is a cache hit; a spoofed answer never resolves the
      upstream.
WHY:  The proxy connect path used to resolve inline with getaddrinfo(); the
      registry keeps start safe, but the per-open lookup is where a stalled
      resolver would freeze every session on the worker.
HOW:  `nginx_lc_p116_dns_upstream.conf` under the lifecycle harness; the
      open's wall time distinguishes a refusal from a hang.  A second sink
      on the record's second address shows successive dials rotating.
"""
from __future__ import annotations

import pytest

from _phase116_helpers import (HAVE_NGINX, BIND_HOST, DnsLab, TcpSink, dns_target, login,
                               metric, metrics_text, open_ro, wait_for_state, wait_until)
from dns_stub import TYPE_A
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p116-dns-upstream")]

UPSTREAM = "upstream.lab.test"
ALT_HOST = "127.0.0.2"   # net-literal-allow: the record's second address


@pytest.fixture()
def sink():
    s = TcpSink(BIND_HOST).start()
    yield s
    s.stop()


def _start(lifecycle, lab, sink, reason, **values):
    if not HAVE_NGINX:
        pytest.skip("nginx binary unavailable")
    return lifecycle.start(NginxInstanceSpec(
        name="lc-p116-dns-upstream", template="nginx_lc_p116_dns_upstream.conf",
        protocol="http", readiness="tcp",
        template_values=lab.values(UPSTREAM_HOST=UPSTREAM, UPSTREAM_PORT=sink.port,
                                   RESOLVER_EXTRA="ipv6=off", **values),
        reason=reason))


def test_unresolvable_upstream_fails_fast_and_keeps_the_worker_free(lifecycle, tmp_path, sink):
    lab = DnsLab(tmp_path)
    try:
        ep = _start(lifecycle, lab, sink, "upstream name does not exist")
        assert wait_for_state(ep.port, UPSTREAM, "failed"), dns_target(ep.port, UPSTREAM)
        root = ep.extra_ports["ROOT_PORT"]
        outcome, _, took = open_ro(root, "/f.txt", timeout=8.0)
        assert outcome != "timeout", "open hung on an unresolvable upstream"
        assert took < 5.0, f"open took {took:.1f}s"
        login(root).close()                       # the loop is free
        assert not sink.accepts
    finally:
        lab.close()


def test_record_appears_later_and_the_dial_follows_it(lifecycle, tmp_path, sink):
    lab = DnsLab(tmp_path)
    try:
        ep = _start(lifecycle, lab, sink, "upstream resolves after start")
        assert wait_for_state(ep.port, UPSTREAM, "failed")
        lab.stub.add_a(UPSTREAM, BIND_HOST)
        assert wait_for_state(ep.port, UPSTREAM, "resolved", timeout=30), dns_target(ep.port, UPSTREAM)
        root = ep.extra_ports["ROOT_PORT"]
        open_ro(root, "/f.txt", timeout=3.0)      # the sink speaks no xrootd: outcome irrelevant
        assert sink.wait_for_dial(timeout=10), "the proxy never dialled the resolved upstream"
        # brix_upstream dials from the target registry's answer set
        # (brix_dns_target_next): a second client costs no DNS round-trip.
        asked = len(lab.stub.queries_for(UPSTREAM, TYPE_A))
        resolutions = dns_target(ep.port, UPSTREAM)["resolutions"]
        open_ro(root, "/f.txt", timeout=3.0)
        assert sink.wait_for_dial(count=2, timeout=10), "the second client was not dialled"
        assert len(lab.stub.queries_for(UPSTREAM, TYPE_A)) == asked, "the second dial re-asked the wire"
        assert dns_target(ep.port, UPSTREAM)["resolutions"] == resolutions
        assert metric(metrics_text(ep.port), "brix_dns_targets", state="resolved") == 1
    finally:
        lab.close()


def test_spoofed_answer_never_resolves_the_upstream(lifecycle, tmp_path, sink):
    lab = DnsLab(tmp_path)
    try:
        lab.stub.add_a(UPSTREAM, BIND_HOST)
        lab.stub.spoof_qname = "attacker.lab.test"
        ep = _start(lifecycle, lab, sink, "spoofed upstream answers")
        assert wait_until(lambda: metric(metrics_text(ep.port), "brix_dns_lookups_total",
                                         result="timeout"), timeout=20)
        row = dns_target(ep.port, UPSTREAM)
        assert row["state"] != "resolved" and row["resolutions"] == 0, row
        outcome, _, took = open_ro(ep.extra_ports["ROOT_PORT"], "/f.txt", timeout=8.0)
        assert outcome != "timeout" and took < 6.0, (outcome, took)
        assert not sink.accepts, "a dial followed a spoofed answer"
    finally:
        lab.close()


def _open_until_both_dialled(root_port: int, a: TcpSink, b: TcpSink, opens: int = 6) -> None:
    """Open until both sinks have been dialled, or `opens` times.  The sinks
    speak no xrootd, so every open's own outcome is irrelevant — what is under
    test is which address the proxy connected to."""
    for _ in range(opens):
        if a.accepts and b.accepts:
            return
        open_ro(root_port, "/f.txt", timeout=3.0)


def test_successive_dials_rotate_through_the_answer_set(lifecycle, tmp_path, sink):
    """W5.3: brix_upstream takes its address per connect from
    brix_dns_target_next(), which rotates the cached answer set.  Pinning
    addrs[0] would send every session of every worker at one member of a
    record that exists precisely to spread them — invisible until that member
    saturates, because the name still resolves and every open still succeeds.
    """
    alt = TcpSink(ALT_HOST, sink.port).start()
    lab = DnsLab(tmp_path)
    try:
        lab.stub.add_a(UPSTREAM, BIND_HOST)
        lab.stub.add_a(UPSTREAM, ALT_HOST)
        ep = _start(lifecycle, lab, sink, "two upstream addresses rotate")
        row = wait_for_state(ep.port, UPSTREAM, "resolved")
        assert row and row["addresses"] == 2, row
        asked = len(lab.stub.queries_for(UPSTREAM, TYPE_A))
        _open_until_both_dialled(ep.extra_ports["ROOT_PORT"], sink, alt)
        assert sink.accepts and alt.accepts, \
            f"one address took every dial: {BIND_HOST}={len(sink.accepts)} {ALT_HOST}={len(alt.accepts)}"
        # The rotation is over the cached answer, not a lookup per connect.
        assert len(lab.stub.queries_for(UPSTREAM, TYPE_A)) == asked, "a dial re-asked the wire"
        assert dns_target(ep.port, UPSTREAM)["addresses"] == 2
    finally:
        lab.close()
        alt.stop()
