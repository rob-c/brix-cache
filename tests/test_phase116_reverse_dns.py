"""
test_phase116_reverse_dns.py — phase-116 W5: reverse DNS through the one path.

WHAT: A root:// server with `brix_acc_resolve_hosts on` and an authdb whose
      only grant is an `h <fqdn>` host rule.  The stub nameserver owns the
      PTR zone for loopback, so the peer's name — and therefore the access
      decision — is whatever the stub says: the right name grants, no PTR
      or another name denies, a spoofed PTR answer is discarded and the
      decision still arrives promptly with the numeric peer.
WHY:  getnameinfo() on the event loop was the last blocking resolver call;
      the accept-time wait plus the reverse cache is what replaced it, and a
      host rule is the one consumer whose outcome shows both working.
HOW:  Clients bind distinct loopback source addresses (127.0.0.x) so each
      test owns a PTR name; the reverse-cache families and
      brix_acc_dns_pending_fallback_total (must stay 0: the accept path
      waited, nothing fell back) are read from /metrics.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from _phase116_helpers import (HAVE_NGINX, BIND_HOST, DnsLab, kXR_error, kXR_ok, metric,
                               metrics_text, stat, wait_until)
from dns_stub import TYPE_PTR, ptr_name
from server_registry import NginxInstanceSpec
from lib_py.util import loopback_alias_usable

GRANTED = "client.lab.test"
NO_PTR = "127.0.0.2"     # net-literal-allow: loopback peer with no PTR record
OTHER = "127.0.0.3"      # net-literal-allow: loopback peer whose PTR names another host
SPOOFED = "127.0.0.4"    # net-literal-allow: loopback peer whose PTR answer is spoofed

# Each cell connects FROM one of those addresses so the reverse lookup has a
# distinct peer to resolve. Linux answers for all of 127/8; macOS binds only
# 127.0.0.1, so the bind fails and the failure describes a refused connection
# rather than anything about reverse DNS. Skip with the fix, as the two sibling
# files in this family already do.
_UNBINDABLE = [addr for addr in (NO_PTR, OTHER, SPOOFED)
               if not loopback_alias_usable(addr)]

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.skipif(
                  bool(_UNBINDABLE),
                  reason="loopback aliases not bindable on this host: "
                         + " ".join(_UNBINDABLE)
                         + "; sudo ifconfig lo0 alias <addr> up for each"),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p116-dns-rev")]


class _Server:
    def __init__(self, lifecycle, tmp_path, lab):
        data = tmp_path / "data"
        (data / "pub").mkdir(parents=True)
        (data / "pub" / "f.txt").write_bytes(b"x\n")
        authdb = tmp_path / "authdb"
        authdb.write_text(f"h {GRANTED} /pub rl\n")
        self.ep = lifecycle.start(NginxInstanceSpec(
            name="lc-p116-dns-rev", template="nginx_lc_p116_dns_rev.conf",
            protocol="http", readiness="tcp", data_root=str(data),
            template_values=lab.values(AUTHDB_PATH=str(authdb), RESOLVER_EXTRA="ipv6=off"),
            reason="reverse DNS for xrdacc host rules through the brix resolver"))
        self.root = self.ep.extra_ports["ROOT_PORT"]
        self.http = self.ep.port

    def stat(self, source=None, timeout=10.0):
        t0 = time.monotonic()
        st = stat(self.root, "/pub/f.txt", source=source, timeout=timeout)
        return st, time.monotonic() - t0


@pytest.fixture()
def lab(tmp_path):
    if not HAVE_NGINX:
        pytest.skip("nginx binary unavailable")
    lab = DnsLab(tmp_path)
    lab.stub.add_ptr(BIND_HOST, GRANTED)
    lab.stub.add_ptr(OTHER, "other.lab.test")
    lab.stub.add_ptr(SPOOFED, GRANTED)
    yield lab
    lab.close()


@pytest.fixture()
def server(lifecycle, tmp_path, lab):
    return _Server(lifecycle, tmp_path, lab)


def test_ptr_name_matches_the_host_rule_and_is_cached(server, lab):
    st, _ = server.stat()
    assert st == kXR_ok, f"expected GRANT for {GRANTED}, got {st}"
    st, _ = server.stat()
    assert st == kXR_ok
    assert len(lab.stub.queries_for(ptr_name(BIND_HOST), TYPE_PTR)) == 1, \
        "the second accept should have hit the reverse cache"
    text = metrics_text(server.http)
    assert metric(text, "brix_dns_reverse_cache_hits_total") >= 1
    assert metric(text, "brix_dns_reverse_cache_entries") >= 1
    assert metric(text, "brix_acc_dns_pending_fallback_total") == 0


def test_peer_without_a_ptr_stays_numeric_and_is_denied(server, lab):
    st, _ = server.stat(source=NO_PTR)
    assert st == kXR_error
    st, _ = server.stat(source=NO_PTR)
    assert st == kXR_error
    assert len(lab.stub.queries_for(ptr_name(NO_PTR), TYPE_PTR)) == 1
    text = metrics_text(server.http)
    assert metric(text, "brix_dns_reverse_cache_negative_hits_total") >= 1
    assert metric(text, "brix_acc_dns_pending_fallback_total") == 0


def test_another_name_does_not_match(server):
    """Security negative: a PTR that resolves is not a match by itself."""
    st, _ = server.stat(source=OTHER)
    assert st == kXR_error


def test_spoofed_ptr_is_discarded_and_the_decision_still_arrives(server, lab):
    """Security negative + liveness: a wrong-id answer is ignored, the
    accept-time wait ends on the resolver timeout, the peer stays numeric."""
    lab.stub.spoof_id = True
    st, took = server.stat(source=SPOOFED, timeout=15.0)
    assert st == kXR_error
    assert took < 8.0, f"decision took {took:.1f}s"
    assert metric(metrics_text(server.http), "brix_acc_dns_pending_fallback_total") == 0


def test_reverse_lookups_are_counted_as_lookups(server):
    server.stat()
    assert wait_until(lambda: metric(metrics_text(server.http), "brix_dns_reverse_cache_misses_total"))
