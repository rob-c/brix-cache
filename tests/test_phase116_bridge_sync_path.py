"""
test_phase116_bridge_sync_path.py — phase-116 amendment 7: the thread-pool ->
event-loop resolver bridge (src/net/dns/resolve_bridge.c).

WHAT: A blocking caller running on a thread-pool worker resolves through the
      export's own `brix_resolver` policy — not libc — by handing the question
      to the event loop and waiting for the answer.
WHY:  nginx's resolver is single-threaded event-loop state; every blocking
      brix caller (TPC pins, cache-origin and gsiftp connects, cvmfs probes,
      OCSP fetches) runs off the loop.  Without the bridge each of them
      silently falls back to libc — a different resolv.conf, a different
      search list, no shared cache and no dashboard row — which is exactly the
      nginx-Plus gap this phase closes, reopened one thread at a time.
HOW:  The cvmfs RTT origin probe is the one blocking resolver a server reaches
      with no client traffic at all: `brix_cvmfs_origin_select rtt` arms a
      per-worker timer that fires within 500 ms of init_process and posts a
      thread-pool task calling brix_dns_resolve_sync() (origin_probe.c:126).
      The origin name is answerable ONLY by this test's stub nameserver, so a
      question arriving at the stub — and a dial arriving at the sink behind
      the address it hands out — proves the thread used the worker's policy;
      libc would have asked the host resolver and got NXDOMAIN.
      brix_dns_bridge_requests_total is the same fact read from /metrics.
"""
from __future__ import annotations

import time

import pytest

from _phase116_helpers import (HAVE_NGINX, BIND_HOST, DnsLab, TcpSink, metric,
                               metrics_text, read_log, wait_until)
from dns_stub import RCODE_NXDOMAIN, TYPE_A
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p116-dns-bridge")]

# Resolvable by the stub alone: the host's own resolver answers NXDOMAIN for
# .lab.test, so "the sink was dialled" cannot be produced by a libc fallback.
ORIGIN = "origin.lab.test"
REPO = "brix.example.org"
REQUESTS = "brix_dns_bridge_requests_total"
TIMEOUTS = "brix_dns_bridge_timeouts_total"


def _start(lifecycle, lab, tmp_path, origin_port, reason, **values):
    if not HAVE_NGINX:
        pytest.skip("nginx binary unavailable")
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    return lifecycle.start(NginxInstanceSpec(
        name="lc-p116-dns-bridge", template="nginx_lc_p116_dns_bridge.conf",
        protocol="http", readiness="tcp",
        template_values=lab.values(ORIGIN_HOST=ORIGIN, ORIGIN_PORT=origin_port,
                                   CACHE_STORE=str(cache), REPO=REPO, **values),
        reason=reason))


def _bridge(http_port: int) -> tuple[float, float]:
    text = metrics_text(http_port)
    return metric(text, REQUESTS), metric(text, TIMEOUTS)


def test_a_thread_pool_caller_resolves_through_the_worker_policy(lifecycle, tmp_path):
    """Success: the probe thread crosses the bridge, the stub answers, and the
    connect lands on the address the stub — not libc — handed out."""
    sink = TcpSink(BIND_HOST).start()
    port = sink.port
    lab = DnsLab(tmp_path)
    try:
        lab.stub.add_a(ORIGIN, BIND_HOST, ttl=5)
        ep = _start(lifecycle, lab, tmp_path, port,
                    "cvmfs rtt probe resolves through the bridge",
                    RESOLVER_EXTRA="ipv6=off")

        assert lab.stub.wait_for_query(ORIGIN, timeout=20), \
            "the probe thread never asked the configured resolver (libc fallback)"
        assert sink.wait_for_dial(timeout=20), \
            "no connect reached the address the stub answered with"
        requests, timeouts = _bridge(ep.port)
        assert requests is not None and requests >= 1, \
            f"{REQUESTS} stayed at {requests} while the probe was resolving"
        assert timeouts == 0, "the bridge gave up waiting for the event loop"
        assert "cvmfs rtt initial ranking" in read_log(ep.prefix), \
            "the probe never completed a ranking tick"
        # The A question is asked under the configured policy, so it carries
        # the policy's family choice: ipv6=off means A only, never AAAA.
        assert all(q.qtype == TYPE_A for q in lab.stub.queries_for(ORIGIN)), \
            "ipv6=off did not reach the bridged resolution"
    finally:
        lab.close()
        sink.stop()


def test_a_failed_bridge_resolution_is_the_policys_answer_not_a_libc_detour(
        lifecycle, tmp_path):
    """Error: NXDOMAIN from the configured resolver fails the probe — the
    crossing still counts, nothing is dialled, and the server keeps serving."""
    sink = TcpSink(BIND_HOST).start()
    port = sink.port
    lab = DnsLab(tmp_path)
    try:
        lab.stub.set_rcode(ORIGIN, RCODE_NXDOMAIN)
        ep = _start(lifecycle, lab, tmp_path, port,
                    "bridged resolution failure is contained",
                    RESOLVER_EXTRA="ipv6=off")

        assert lab.stub.wait_for_query(ORIGIN, timeout=20), \
            "the probe thread never asked the configured resolver"
        requests, timeouts = _bridge(ep.port)
        assert requests is not None and requests >= 1, \
            "a failing resolution must still count as a crossing"
        assert timeouts == 0, "a clean NXDOMAIN must not read as a bridge timeout"
        assert wait_until(lambda: "UNREACHABLE" in read_log(ep.prefix), timeout=20), \
            "the probe never reported the origin as unreachable"
        assert sink.accepts == [], \
            f"something dialled the origin port anyway: {sink.accepts}"
        # start-safe (W2): an unresolvable backend name neither blocks start
        # nor takes the listener down.
        assert metric(metrics_text(ep.port), REQUESTS) >= requests
    finally:
        lab.close()
        sink.stop()


def test_an_off_path_forged_answer_never_reaches_the_probe(lifecycle, tmp_path):
    """Security-negative: an answer carrying the wrong transaction id is a
    forgery; the bridged resolution must reject it and stay failed, however
    many times it is offered."""
    sink = TcpSink(BIND_HOST).start()
    port = sink.port
    lab = DnsLab(tmp_path)
    try:
        lab.stub.add_a(ORIGIN, BIND_HOST, ttl=5)
        lab.stub.spoof_id = True
        ep = _start(lifecycle, lab, tmp_path, port,
                    "forged transaction id is refused across the bridge",
                    RESOLVER_EXTRA="ipv6=off")

        assert lab.stub.wait_for_query(ORIGIN, count=2, timeout=30), \
            "the probe stopped asking after the first forged answer"
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            assert sink.accepts == [], \
                f"a forged answer was accepted and dialled: {sink.accepts}"
            time.sleep(0.2)
        assert "UNREACHABLE" in read_log(ep.prefix), \
            "the forged answer was not treated as a resolution failure"

        # And the genuine answer still works once the forgery stops: the
        # refusal is id validation, not a wedged resolver.
        lab.stub.spoof_id = False
        assert sink.wait_for_dial(timeout=30), \
            "the probe never recovered after the forgery stopped"
    finally:
        lab.close()
        sink.stop()
