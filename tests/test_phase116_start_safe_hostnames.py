"""
test_phase116_start_safe_hostnames.py — phase-116 W2/W4: start-safe targets.

WHAT: Every directive that names a host (`brix_cms_manager`, `brix_upstream`,
      `brix_mirror_url`) parses with the nameserver unreachable, a server
      whose nameserver is silent at start comes up and converges once DNS
      answers, an NXDOMAIN target is reported (dashboard `dns` panel,
      /metrics) rather than fatal while the server keeps serving, and spoofed
      answers — wrong transaction id, wrong question — never resolve a
      target.
WHY:  The user's requirement in one sentence: no hostname may prevent nginx
      starting when DNS is broken, and what happens instead must be visible.
HOW:  Parse probes over the scaffold with a resolv.conf pointing at a dead
      port; live runs under the lifecycle harness with the stub nameserver
      paused, empty, or spoofing, observed through the driver's own
      accounting (brix_dns_* families, the dns panel) and a recording sink
      standing in for the manager.
"""
from __future__ import annotations

import time

import pytest

from _phase116_helpers import (HAVE_NGINX, BIND_HOST, DnsLab, TcpSink, dns_target, login,
                               metric, metrics_text, parse, wait_for_state, wait_until)
from dns_stub import write_resolv_conf
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p116-dns")]

needs_nginx = pytest.mark.skipif(not HAVE_NGINX, reason="nginx binary unavailable")
MANAGER = "manager.lab.test"


@pytest.fixture()
def sink():
    s = TcpSink(BIND_HOST).start()
    yield s
    s.stop()


def _start(lifecycle, lab, sink, reason, **values):
    if not HAVE_NGINX:
        pytest.skip("nginx binary unavailable")
    return lifecycle.start(NginxInstanceSpec(
        name="lc-p116-dns", template="nginx_lc_p116_dns.conf",
        protocol="http", readiness="tcp",
        template_values=lab.values(MANAGER_HOST=MANAGER, MANAGER_PORT=sink.port, **values),
        reason=reason))


# --------------------------------------------------------------------------- #
# parse tier — hostnames never block `nginx -t`, even with DNS dead            #
# --------------------------------------------------------------------------- #

@needs_nginx
@pytest.mark.parametrize("line", [
    "brix_cms_manager manager.dead.test:1213;",
    "brix_upstream upstream.dead.test:1094;",
    "brix_mirror_url mirror.dead.test:1094;",
])
def test_hostname_directives_parse_with_the_nameserver_unreachable(tmp_path, line):
    p = write_resolv_conf(tmp_path / "resolv.conf", [("127.0.0.1", 1)], timeout=1, attempts=1)  # net-literal-allow: dead nameserver fixture (port 1); the point is that it never answers
    t0 = time.monotonic()
    rc, out = parse(tmp_path, STREAM_MAIN=f"brix_resolver auto path={p};", STREAM_KNOBS=line)
    took = time.monotonic() - t0
    assert rc == 0, f"{line!r}:\n{out}"
    assert took < 5.0, f"parse blocked on DNS for {took:.1f}s"


@needs_nginx
def test_a_literal_target_needs_no_resolver_at_all(tmp_path):
    rc, out = parse(tmp_path, STREAM_MAIN="brix_resolver off;",
                    STREAM_KNOBS="brix_cms_manager 127.0.0.1:1213;")  # net-literal-allow: dead manager address in a start-safety config; never reached
    assert rc == 0, out


# --------------------------------------------------------------------------- #
# live — start with DNS silent, converge when it answers                       #
# --------------------------------------------------------------------------- #

def test_starts_with_the_nameserver_silent_then_converges(lifecycle, tmp_path, sink):
    lab = DnsLab(tmp_path)
    try:
        lab.stub.paused = True                    # every query times out
        ep = _start(lifecycle, lab, sink, "start with a silent nameserver",
                    RESOLVER_EXTRA="ipv6=off")
        row = dns_target(ep.port, MANAGER)
        assert row and row["state"] in ("resolving", "failed"), row
        assert metric(metrics_text(ep.port), "brix_dns_targets", state="resolved") == 0
        assert wait_until(lambda: metric(metrics_text(ep.port), "brix_dns_lookups_total",
                                         result="timeout"), timeout=15)
        lab.stub.add_a(MANAGER, BIND_HOST)
        lab.stub.paused = False
        assert wait_for_state(ep.port, MANAGER, "resolved", timeout=30), dns_target(ep.port, MANAGER)
        assert sink.wait_for_dial(timeout=20), "CMS never dialled the manager after DNS recovered"
        text = metrics_text(ep.port)
        assert metric(text, "brix_dns_resolutions_total") >= 1
        assert metric(text, "brix_dns_targets", state="resolved") == 1
    finally:
        lab.close()


def test_nxdomain_target_is_reported_and_the_server_keeps_serving(lifecycle, tmp_path, sink):
    lab = DnsLab(tmp_path)
    try:
        ep = _start(lifecycle, lab, sink, "manager name does not exist",
                    RESOLVER_EXTRA="ipv6=off")
        row = wait_for_state(ep.port, MANAGER, "failed")
        assert row, dns_target(ep.port, MANAGER)
        assert row["failures"] >= 1 and row["last_error"] and row["next_retry_ms"] > 0, row
        assert row["literal"] is False and row["directive"] == "brix_cms_manager", row
        text = metrics_text(ep.port)
        assert metric(text, "brix_dns_failures_total") >= 1
        assert metric(text, "brix_dns_lookups_total", result="nxdomain") >= 1
        assert metric(text, "brix_dns_targets", state="failed") == 1
        login(ep.extra_ports["ROOT_PORT"]).close()   # the worker is not stalled
        assert not sink.accepts
    finally:
        lab.close()


# --------------------------------------------------------------------------- #
# security negatives — spoofed answers never resolve a target                  #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("spoof", ["id", "qname"])
def test_spoofed_answers_never_resolve(lifecycle, tmp_path, sink, spoof):
    lab = DnsLab(tmp_path)
    try:
        lab.stub.add_a(MANAGER, BIND_HOST)
        if spoof == "id":
            lab.stub.spoof_id = True
        else:
            lab.stub.spoof_qname = "attacker.lab.test"
        ep = _start(lifecycle, lab, sink, f"spoofed {spoof} answers",
                    RESOLVER_EXTRA="ipv6=off")
        assert wait_until(lambda: metric(metrics_text(ep.port), "brix_dns_lookups_total",
                                         result="timeout"), timeout=20), \
            "the spoofed answer was not discarded as a timeout"
        row = dns_target(ep.port, MANAGER)
        assert row["state"] != "resolved" and row["resolutions"] == 0, row
        text = metrics_text(ep.port)
        assert metric(text, "brix_dns_resolutions_total") == 0
        assert metric(text, "brix_dns_targets", state="resolved") == 0
        assert not sink.accepts, "a dial followed a spoofed answer"
    finally:
        lab.close()


# --------------------------------------------------------------------------- #
# brix_dns_status_zone — the operator's label on every target row              #
# --------------------------------------------------------------------------- #

@needs_nginx
@pytest.mark.parametrize("slot", ["STREAM_KNOBS", "HTTP_KNOBS"])
def test_status_zone_is_accepted_in_both_planes(tmp_path, slot):
    p = write_resolv_conf(tmp_path / "resolv.conf", [("127.0.0.1", 1)])  # net-literal-allow: dead nameserver fixture (port 1); never answers
    placed = {slot: "brix_dns_status_zone edge-a;"}
    if slot == "STREAM_KNOBS":
        placed["STREAM_MAIN"] = f"brix_resolver auto path={p};"
    else:
        placed["HTTP_KNOBS"] = f"brix_resolver auto path={p};\nbrix_dns_status_zone edge-a;"
    rc, out = parse(tmp_path, **placed)
    assert rc == 0, out


@needs_nginx
@pytest.mark.parametrize("line, needle", [
    ("brix_dns_status_zone;", "invalid number of arguments"),
    ("brix_dns_status_zone a;\nbrix_dns_status_zone b;", "is duplicate"),
])
def test_malformed_status_zone_is_refused(tmp_path, line, needle):
    rc, out = parse(tmp_path, STREAM_KNOBS=line)
    assert rc != 0, out
    assert needle in out, out


def test_status_zone_labels_the_target_rows_and_defaults_to_empty(lifecycle, tmp_path, sink):
    """The zone is how an operator tells two edges apart in one dashboard, so
    it has to reach the row — and stay empty rather than inventing a name when
    no zone is configured."""
    lab = DnsLab(tmp_path)
    try:
        lab.stub.add_a(MANAGER, BIND_HOST)
        ep = _start(lifecycle, lab, sink, "status zone labels the dns rows",
                    RESOLVER_EXTRA="ipv6=off",
                    STREAM_EXTRA="        brix_dns_status_zone edge-a;")
        assert wait_for_state(ep.port, MANAGER, "resolved"), dns_target(ep.port, MANAGER)
        assert dns_target(ep.port, MANAGER)["zone"] == "edge-a", dns_target(ep.port, MANAGER)

        # Same instance, zone removed: one lifecycle harness owns one name, so
        # the second config is a re-render + restart, not a second start().
        lifecycle.reconfigure("lc-p116-dns", STREAM_EXTRA="")
        lifecycle.restart("lc-p116-dns")
        assert wait_for_state(ep.port, MANAGER, "resolved"), dns_target(ep.port, MANAGER)
        assert dns_target(ep.port, MANAGER)["zone"] == "", dns_target(ep.port, MANAGER)
        # I-DNS-4: the zone is a config label, never a metric label — no
        # brix_dns_* series may carry it (or any other unbounded key).
        assert "edge-a" not in metrics_text(ep.port)
    finally:
        lab.close()
