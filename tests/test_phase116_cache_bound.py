"""
test_phase116_cache_bound.py — phase-116 W4: `brix_dns_cache_max` bounds both
per-worker DNS caches, including the one a remote peer fills.

WHAT: A root:// server with `brix_acc_resolve_hosts on`, so every accepted
      connection puts one entry into the reverse (PTR) cache keyed by the
      PEER's address.  A generous bound keeps every peer cached; a bound of
      one evicts; and no amount of peer-chosen source addresses grows the
      cache past the bound or corrupts the access decision.
WHY:  the bound used to be applied only when a runtime-resolved hostname was
      armed, so a block like this one — which registers no hostname at all —
      silently kept the 4096 default, and the reverse cache never honoured
      the directive in any configuration.  The key space here is chosen by
      the peer, which is exactly the cache that must be bounded.
HOW:  `nginx_lc_p116_dns_rev.conf` with the bound placed in the stream main
      block; `brix_dns_reverse_cache_entries` from /metrics is the observable,
      and the authdb `h` rule proves the decision survives eviction.
"""
from __future__ import annotations

import pytest

from _phase116_helpers import (HAVE_NGINX, BIND_HOST, DnsLab, kXR_error, kXR_ok, metric,
                               metrics_text, stat)
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p116-dns-rev")]

GRANTED = "client.lab.test"
# net-literal-allow: distinct loopback source addresses, one reverse-cache key each
PEERS = [f"127.0.0.{i}" for i in range(2, 10)]


def _start(lifecycle, tmp_path, lab, bound, reason):
    if not HAVE_NGINX:
        pytest.skip("nginx binary unavailable")
    data = tmp_path / "data"
    (data / "pub").mkdir(parents=True)
    (data / "pub" / "f.txt").write_bytes(b"x\n")
    authdb = tmp_path / "authdb"
    authdb.write_text(f"h {GRANTED} /pub rl\n")
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-p116-dns-rev", template="nginx_lc_p116_dns_rev.conf",
        protocol="http", readiness="tcp", data_root=str(data),
        template_values=lab.values(AUTHDB_PATH=str(authdb), RESOLVER_EXTRA="ipv6=off",
                                   STREAM_EXTRA=f"    brix_dns_cache_max {bound};"),
        reason=reason))
    return ep


@pytest.fixture()
def lab(tmp_path):
    if not HAVE_NGINX:
        pytest.skip("nginx binary unavailable")
    lab = DnsLab(tmp_path)
    lab.stub.add_ptr(BIND_HOST, GRANTED)
    for i, peer in enumerate(PEERS):
        lab.stub.add_ptr(peer, f"peer{i}.lab.test")
    yield lab
    lab.close()


def _entries(http_port: int) -> int:
    return metric(metrics_text(http_port), "brix_dns_reverse_cache_entries")


def test_a_generous_bound_keeps_every_peer_cached(lifecycle, tmp_path, lab):
    """Success: under a bound of 64 the three peers coexist in the cache and a
    repeat connection is a hit, not a second PTR query."""
    ep = _start(lifecycle, tmp_path, lab, 64, "reverse cache under a generous bound")
    for peer in [None] + PEERS[:2]:
        stat(ep.extra_ports["ROOT_PORT"], "/pub/f.txt", source=peer)
    assert _entries(ep.port) == 3, metrics_text(ep.port)
    hits = metric(metrics_text(ep.port), "brix_dns_reverse_cache_hits_total")
    stat(ep.extra_ports["ROOT_PORT"], "/pub/f.txt")
    assert metric(metrics_text(ep.port), "brix_dns_reverse_cache_hits_total") > hits
    assert metric(metrics_text(ep.port), "brix_acc_dns_pending_fallback_total") == 0


def test_the_bound_is_enforced_by_eviction(lifecycle, tmp_path, lab):
    """Error path: a bound of one is honoured — the cache never holds a second
    entry, and the directive is honoured in a block that registers no
    runtime-resolved hostname at all (it registers none)."""
    ep = _start(lifecycle, tmp_path, lab, 1, "reverse cache bounded to one entry")
    for peer in [None] + PEERS[:3]:
        stat(ep.extra_ports["ROOT_PORT"], "/pub/f.txt", source=peer)
        assert _entries(ep.port) <= 1, metrics_text(ep.port)
    assert _entries(ep.port) == 1


def test_a_peer_filled_cache_cannot_move_the_access_decision(lifecycle, tmp_path, lab):
    """Security-negative: eight peer-chosen source addresses churn a one-entry
    cache; the granted host is still granted and an ungranted one is still
    denied — eviction must re-resolve, never answer from a neighbour's row."""
    ep = _start(lifecycle, tmp_path, lab, 1, "peer-driven reverse-cache churn")
    root = ep.extra_ports["ROOT_PORT"]
    assert stat(root, "/pub/f.txt") == kXR_ok
    for peer in PEERS:
        assert stat(root, "/pub/f.txt", source=peer) == kXR_error, peer
        assert _entries(ep.port) <= 1
    assert stat(root, "/pub/f.txt") == kXR_ok, "the granted peer lost its grant"
    assert stat(root, "/pub/f.txt", source=PEERS[0]) == kXR_error
    assert metric(metrics_text(ep.port), "brix_acc_dns_pending_fallback_total") == 0
