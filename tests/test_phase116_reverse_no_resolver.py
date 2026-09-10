"""
test_phase116_reverse_no_resolver.py — phase-116: an `h` host rule must still
be decided when the configuration declares NEITHER a brix_resolver NOR a
thread_pool.

WHAT: The same root:// + xrdacc subject as test_phase116_reverse_dns.py, minus
      the resolver policy and minus the `thread_pool default` line, so the only
      reverse backend is the libc getnameinfo() the DNS module runs off the
      event loop.  The peer's PTR name comes from the host's own nsswitch
      (/etc/hosts), which is what makes `h localhost` decidable at all — an
      ngx_resolver-only PTR path could not see it.
WHY:  Phase 116 replaced a blocking getnameinfo() on the event loop with the
      reverse cache + thread hop.  ngx_thread_pool_get() declines when no pool
      was declared anywhere in the configuration, so on such a config every
      lookup failed, the failure was negative-cached, and the acc engine
      silently matched the numeric peer: `brix_acc_resolve_hosts on` stopped
      granting (caught by test_audit16q_acc_engine_flag_arms).
      brix_dns_backend_prepare() now registers the default pool at merge time
      for any server that consults the peer name.  This suite is the pin: it
      fails the moment that registration is dropped or the template acquires a
      resolver/pool that would hide the gap.
HOW:  Three arms on one lifecycle instance (the ledger slot is shared with
      test_phase116_reverse_dns.py, hence the same xdist_group): the peer whose
      PTR matches the rule is granted; a peer with no PTR is refused promptly
      rather than stalling; and a rule naming a host the peer is not stays
      refused — a failed or mismatched PTR never grants.
"""
from __future__ import annotations

import socket
import time
from pathlib import Path

import pytest

from _phase116_helpers import HAVE_NGINX, BIND_HOST, kXR_error, kXR_ok, stat
from config_parse import nginx_t
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p116-dns-rev")]

TEMPLATE = "nginx_lc_p116_dns_rev_noresolver.conf"
ORDER_TEMPLATE = "nginx_p116_pool_order.conf"


def _ptr(ip: str) -> str | None:
    try:
        return socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)[0]
    except OSError:
        return None


@pytest.fixture(scope="module")
def peer_name() -> str:
    """The PTR name the C code will see for the connecting peer."""
    name = _ptr(BIND_HOST)
    if not name:
        pytest.skip(f"host has no PTR for {BIND_HOST}; an `h` rule is undecidable")
    return name


@pytest.fixture(scope="module")
def nameless_peer() -> str:
    """A loopback source address the host resolves to no name at all."""
    for last in range(3, 24):
        ip = f"127.0.0.{last}"          # net-literal-allow: loopback peer probe
        if _ptr(ip) is None:
            return ip
    pytest.skip("every loopback address on this host has a PTR name")


@pytest.fixture()
def serve(lifecycle, tmp_path):
    """Start the subject with `rule` as the authdb's only grant."""
    if not HAVE_NGINX:
        pytest.skip("nginx binary unavailable")

    def _start(rule: str):
        data = tmp_path / "data"
        (data / "pub").mkdir(parents=True, exist_ok=True)
        (data / "pub" / "f.txt").write_bytes(b"x\n")
        authdb = tmp_path / "authdb"
        authdb.write_text(rule + "\n")
        ep = lifecycle.start(NginxInstanceSpec(
            name="lc-p116-dns-rev", template=TEMPLATE,
            protocol="http", readiness="tcp", data_root=str(data),
            template_values={"BIND_HOST": BIND_HOST, "AUTHDB_PATH": str(authdb)},
            reason="reverse DNS with no brix_resolver and no thread_pool"))
        return ep.extra_ports["ROOT_PORT"]

    return _start


def test_the_template_declares_no_resolver_and_no_thread_pool():
    """The absence under test — a stray directive here would void the suite."""
    body = (Path(__file__).parent / "configs" / TEMPLATE).read_text()
    directives = [line.split()[0] for line in body.splitlines()
                  if line.strip() and not line.lstrip().startswith("#")]
    assert "brix_resolver" not in directives, "template must declare no resolver"
    assert "thread_pool" not in directives, "template must declare no thread pool"


def test_host_rule_grants_when_only_libc_can_answer(serve, peer_name):
    port = serve(f"h {peer_name} /pub rl")
    assert stat(port, "/pub/f.txt") == kXR_ok, (
        f"`h {peer_name}` must grant the peer whose PTR is {peer_name}; a "
        "refusal means the reverse lookup found no backend and the engine fell "
        "back to the numeric peer")


def test_peer_without_a_ptr_is_refused_without_stalling(serve, peer_name,
                                                        nameless_peer):
    port = serve(f"h {peer_name} /pub rl")
    t0 = time.monotonic()
    st = stat(port, "/pub/f.txt", source=nameless_peer)
    waited = time.monotonic() - t0
    assert st == kXR_error, f"nameless peer {nameless_peer} must not be granted"
    assert waited < 8.0, f"decision took {waited:.1f}s — the lookup blocked"


def test_a_rule_for_another_host_never_grants(serve, peer_name):
    """Security-negative: the grant follows the PTR answer, not the request."""
    port = serve(f"h {peer_name}.invalid /pub rl")
    assert stat(port, "/pub/f.txt") == kXR_error, (
        f"peer named {peer_name} must not match `h {peer_name}.invalid`")


# ---- source pins: the wiring the live arms above depend on -------------------

SRC = Path(__file__).resolve().parent.parent / "src"


def test_both_merges_prepare_a_reverse_backend():
    """Every plane that can consult the peer name registers the backend.

    HTTP: brix_http_common_merge_loc_conf(); stream: brix_merge_srv_security().
    Dropping either call is the exact shape of the regression this suite pins,
    and it is invisible on a configuration that happens to declare a resolver.
    """
    for rel, trigger in (("core/config/http_common.c", "acc.resolve_hosts"),
                         ("core/config/server_conf_merge_security.c",
                          "BRIX_AUTH_HOST")):
        body = (SRC / rel).read_text()
        assert "brix_dns_backend_prepare(cf)" in body, \
            f"{rel} no longer prepares a reverse backend"
        assert trigger in body, f"{rel} no longer tests its reverse trigger"


def test_the_stream_peer_name_gate_reads_the_slot_the_directive_writes():
    """`brix_protbind` on the stream plane writes the srv-level array.

    Reading common.protbind there (as the first phase-116 draft did) is always
    NULL, so a protbind host template never armed the accept-time prefetch —
    every other stream consumer (login.c, protocol.c, gsi/auth.c) uses
    conf->protbind.
    """
    body = (SRC / "protocols/root/connection/peer_name.c").read_text()
    assert "brix_protbind_needs_hostname(sconf->protbind)" in body
    assert "sconf->common.protbind" not in body


def test_every_forward_resolver_outside_the_target_registry_prepares_a_backend():
    """The reverse hole has a forward twin; both are closed the same way.

    brix_dns_resolve() refuses with the same "no resolver and no thread pool
    available" text, so a config that resolves a name without registering a DNS
    target fails exactly like the `h`-rule regression did — silently, at the
    first lookup, long after `nginx -t` said the configuration was fine.
    """
    for rel, entry in (
            ("observability/pmark/config.c", "brix_pmark_set_firefly_dest"),
            ("net/proxy/directives.c", "brix_conf_set_proxy_upstream"),
            ("protocols/webdav/proxy_pool.c", "brix_proxy_pool_configure")):
        body = (SRC / rel).read_text()
        assert "brix_dns_backend_prepare(cf)" in body, \
            f"{rel}: {entry} resolves a name with no DNS backend prepared"


def test_the_two_safe_forward_callers_stay_safe():
    """The audit's other two callers are covered by a different mechanism.

    CMS registers its health-check target, so brix_dns_target_register() already
    prepares the backend; if that registration goes, CMS joins the class above
    and this test says so before a live mesh does.
    """
    body = (SRC / "net/cms/config.c").read_text()
    assert "brix_dns_target_register" in body, \
        "CMS no longer registers its health-check target — it now needs " \
        "brix_dns_backend_prepare() like the three forward callers"


def test_no_resolve_call_site_answers_with_a_blocking_lookup():
    """Security-negative for the fix: closing the hole must not reintroduce the
    synchronous lookup phase-116 removed.

    The cheap way to make either failure disappear is a getnameinfo()/
    getaddrinfo() fallback on the caller's side — that is the event-loop stall
    invariant 13 exists to remove, and it must never come back at a call site.
    """
    for rel in ("observability/pmark/config.c", "net/proxy/directives.c",
                "protocols/webdav/proxy_pool.c", "core/config/http_common.c",
                "core/config/server_conf_merge_security.c"):
        body = (SRC / rel).read_text()
        for banned in ("getnameinfo", "getaddrinfo", "gethostbyname",
                       "<netdb.h>"):
            assert banned not in body, \
                f"{rel} performs a blocking libc lookup ({banned}) — the " \
                f"DNS backend belongs behind brix_dns_* (invariant 13)"


@pytest.mark.skipif(not HAVE_NGINX, reason="nginx binary unavailable")
def test_an_explicit_thread_pool_declared_after_the_merge_still_parses(tmp_path):
    """The prepare must not collide with the operator's own `thread_pool`.

    ngx_thread_pool_add() creates the pool with threads=0 and the `thread_pool`
    directive rejects a redeclaration with `if (tp->threads)`, so registering
    the default pool from a merge handler is safe in either file order — but
    only for as long as the helper leaves threads alone.  The day it sets them,
    a configuration that names a host AND declares its own pool stops starting,
    which is precisely the failure phase 116 exists to prevent.
    """
    (tmp_path / "logs").mkdir()
    (tmp_path / "data").mkdir()
    r = nginx_t(ORDER_TEMPLATE, tmp_path,
                LOG_DIR=str(tmp_path / "logs"), DATA_ROOT=str(tmp_path / "data"),
                BIND_HOST=BIND_HOST, PORT=SHARED_PARSE_PLACEHOLDER_PORT,
                ROOT_PORT=SHARED_PARSE_PLACEHOLDER_PORT + 1)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert "duplicate thread pool" not in out


@pytest.mark.skipif(not HAVE_NGINX, reason="nginx binary unavailable")
def test_a_host_consulting_config_parses_with_no_pool_and_no_resolver(tmp_path):
    """`nginx -t` on the suite's own template — the no-DNS-at-all startup case.

    Requirement in one line: no hostname may stop nginx starting.  This is the
    configuration-time half of it for the reverse path; the live arms above are
    the runtime half.
    """
    for d in ("logs", "data", "tmp"):
        (tmp_path / d).mkdir()
    (tmp_path / "authdb").write_text("h localhost a rw\n")  # net-literal-allow: authdb host rule; the name is the subject under test
    r = nginx_t(TEMPLATE, tmp_path,
                LOG_DIR=str(tmp_path / "logs"), TMP_DIR=str(tmp_path / "tmp"),
                DATA_ROOT=str(tmp_path / "data"), BIND_HOST=BIND_HOST,
                PORT=SHARED_PARSE_PLACEHOLDER_PORT,
                ROOT_PORT=SHARED_PARSE_PLACEHOLDER_PORT + 1,
                AUTHDB_PATH=str(tmp_path / "authdb"))
    assert r.returncode == 0, r.stdout + r.stderr
