"""
test_phase116_search_ndots.py — phase-116 W3: resolv.conf search list + ndots.

WHAT: A live root:// server whose `brix_cms_manager` names a short host that
      only resolves through the resolv.conf search list.  The stub nameserver
      records every question, so the suite pins the glibc candidate order
      (search suffixes first below ndots, absolute first at or above it),
      that `search=off` never suffixes, and that a name failing every
      candidate is reported as failed — not fatal.
WHY:  nginx's resolver has no search list; an operator's `brix_cms_manager
      mgr:1213` that works with xrootd's libc resolver must work here too,
      and a disabled search list must never let a suffix hijack a lookup.
HOW:  `nginx_lc_p116_dns.conf` under the lifecycle harness with
      `ipv6=off` so the question log holds A queries only; the manager
      address is a recording TCP sink, so "resolved" is also proven by the
      CMS dial reaching it.
"""
from __future__ import annotations

import pytest

from _phase116_helpers import (HAVE_NGINX, BIND_HOST, DnsLab, TcpSink, dns_target,
                               metric, metrics_text, wait_for_state, wait_until)
from dns_stub import TYPE_A
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p116-dns")]


@pytest.fixture()
def sink():
    s = TcpSink(BIND_HOST).start()
    yield s
    s.stop()


def _start(lifecycle, lab, host, sink, reason, **values):
    if not HAVE_NGINX:
        pytest.skip("nginx binary unavailable")
    return lifecycle.start(NginxInstanceSpec(
        name="lc-p116-dns", template="nginx_lc_p116_dns.conf",
        protocol="http", readiness="tcp",
        template_values=lab.values(MANAGER_HOST=host, MANAGER_PORT=sink.port, **values),
        reason=reason))


def _a_questions(lab):
    return [q.name for q in lab.stub.queries if q.qtype == TYPE_A]


def test_short_name_walks_the_search_list_in_order(lifecycle, tmp_path, sink):
    lab = DnsLab(tmp_path, search=("lab.test", "example.org"), ndots=2)
    try:
        lab.stub.add_a("mgr.example.org", BIND_HOST)
        ep = _start(lifecycle, lab, "mgr", sink, "search-list expansion of a 0-dot name",
                    RESOLVER_EXTRA="ipv6=off")
        assert wait_for_state(ep.port, "mgr", "resolved"), dns_target(ep.port, "mgr")
        asked = _a_questions(lab)
        assert asked[:2] == ["mgr.lab.test", "mgr.example.org"], asked
        assert "mgr" not in asked, asked            # absolute is tried last, never reached
        assert sink.wait_for_dial(), "the CMS dial never reached the manager sink"
        assert metric(metrics_text(ep.port), "brix_dns_targets", state="resolved") == 1
    finally:
        lab.close()


def test_name_at_ndots_tries_the_absolute_form_first(lifecycle, tmp_path, sink):
    lab = DnsLab(tmp_path, search=("lab.test",), ndots=2)
    try:
        lab.stub.add_a("mgr.corp.test", BIND_HOST)
        ep = _start(lifecycle, lab, "mgr.corp.test", sink, "ndots threshold: absolute first",
                    RESOLVER_EXTRA="ipv6=off")
        assert wait_for_state(ep.port, "mgr.corp.test", "resolved")
        asked = _a_questions(lab)
        assert asked[0] == "mgr.corp.test", asked
        assert "mgr.corp.test.lab.test" not in asked, asked
        assert sink.wait_for_dial()
    finally:
        lab.close()


def test_search_off_never_appends_a_suffix(lifecycle, tmp_path, sink):
    """Security negative: with the search list disabled the only name that
    may be asked is the configured one — a suffix the operator did not
    write cannot redirect the manager dial."""
    lab = DnsLab(tmp_path, search=("lab.test",), ndots=1)
    try:
        lab.stub.add_a("mgr.lab.test", BIND_HOST)         # would match via search
        ep = _start(lifecycle, lab, "mgr", sink, "search=off must not suffix",
                    RESOLVER_EXTRA="ipv6=off search=off")
        assert wait_for_state(ep.port, "mgr", "failed"), dns_target(ep.port, "mgr")
        asked = set(_a_questions(lab))
        assert asked == {"mgr"}, asked
        assert not sink.wait_for_dial(timeout=2.0), "a dial reached a suffix-resolved address"
        assert metric(metrics_text(ep.port), "brix_dns_targets", state="resolved") == 0
    finally:
        lab.close()


def test_every_candidate_nxdomain_reports_failed_not_fatal(lifecycle, tmp_path, sink):
    lab = DnsLab(tmp_path, search=("lab.test", "example.org"), ndots=1)
    try:
        ep = _start(lifecycle, lab, "mgr", sink, "all candidates NXDOMAIN",
                    RESOLVER_EXTRA="ipv6=off")
        row = wait_for_state(ep.port, "mgr", "failed")
        assert row, dns_target(ep.port, "mgr")
        assert row["failures"] >= 1 and row["last_error"], row
        asked = _a_questions(lab)
        assert {"mgr.lab.test", "mgr.example.org", "mgr"} <= set(asked), asked
        text = wait_until(lambda: (lambda t: t if metric(t, "brix_dns_lookups_total", result="nxdomain") else None)
                          (metrics_text(ep.port)))
        assert text and metric(text, "brix_dns_failures_total") >= 1
    finally:
        lab.close()
