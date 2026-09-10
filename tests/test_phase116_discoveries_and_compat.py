"""
test_phase116_discoveries_and_compat.py — phase-116 discoveries, compat layers
and the census that keeps them covered.

WHAT: The facts the phase found rather than built — a WebDAV proxy pool whose
      async-resolution path is unreachable because nothing declares its zone,
      the config-time-only reading of resolv.conf (decision B), the threadless
      build's degrade arm, the five features that must ask for a DNS backend
      because they resolve names no target ever registered — plus two censuses
      that fail when a new phase-116 directive or metric family lands with no
      test naming it.
WHY:  A discovery recorded only in a doc decays: the next refactor "fixes" the
      inert code path or drops the `#if (NGX_THREADS)` arm and nothing goes
      red.  The censuses answer the standing instruction that every feature of
      this phase be explicitly covered — including features added after it.
HOW:  Pure source reading, no build and no fleet: the C tree and the
      tests/test_phase116_* corpus are both text.  Deliberately free of the
      suite's own imports so a broken port ladder or a missing binary cannot
      hide these.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.timeout(60)

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
DNS = SRC / "net" / "dns"
CORPUS = sorted(Path(__file__).resolve().parent.glob("test_phase116_*.py"))


def _text(*parts: str) -> str:
    return (REPO.joinpath(*parts)).read_text()


def _bare(text: str) -> str:
    """Source with block comments removed: a symbol named in prose is not a
    call site."""
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def _callers_of(pattern: str, suffixes: tuple[str, ...] = (".c",)) -> set[str]:
    """Repo-relative paths under src/ whose code (not comments) matches."""
    files: list[Path] = []
    for suffix in suffixes:
        files += sorted(SRC.rglob("*" + suffix))
    hits = {p.relative_to(REPO).as_posix() for p in files
            if "unittest" not in p.name and re.search(pattern, _bare(p.read_text()))}
    return hits


def corpus_text() -> str:
    return "\n".join(p.read_text() for p in CORPUS) + "\n" + "\n".join(
        p.read_text() for p in (REPO / "tests" / "configs").glob("nginx_lc_p116_*.conf"))


# --------------------------------------------------------------------------- #
# census — a new directive or metric family cannot land uncovered              #
# --------------------------------------------------------------------------- #

def test_every_dns_directive_is_named_by_the_phase_116_corpus():
    """Both command tables declare the same four directives; each must be
    written by at least one phase-116 test or template.  A fifth directive
    added later reddens here until it is exercised."""
    http = set(re.findall(r'ngx_string\("(brix_(?:dns_|resolver)[a-z_]*)"\)',
                          _text("src", "core", "config", "http_directives_ops.h")))
    stream = set(re.findall(r'ngx_string\("(brix_(?:dns_|resolver)[a-z_]*)"\)',
                            _text("src", "core", "config", "stream_common.c")))
    assert http == stream and http, (http, stream)
    corpus = corpus_text()
    uncovered = sorted(d for d in http if d not in corpus)
    assert not uncovered, f"phase-116 directives with no test naming them: {uncovered}"


def test_every_dns_metric_family_is_named_by_the_phase_116_corpus():
    families = sorted(set(re.findall(r'"(brix_dns_[a-z0-9_]+)',
                                     (DNS / "metrics.c").read_text())))
    assert len(families) >= 8, families
    corpus = corpus_text()
    uncovered = sorted(f for f in families if f not in corpus)
    assert not uncovered, f"exported DNS metric families with no test: {uncovered}"


# --------------------------------------------------------------------------- #
# decision B — resolv.conf is read at config time and never re-read            #
# --------------------------------------------------------------------------- #

def test_resolv_conf_is_loaded_only_from_the_config_time_directive():
    """A worker that re-stat'ed the file would give two workers two resolver
    policies mid-flight and make a reload's semantics depend on timing; the
    phase chose the explicit reload instead.  The only production caller of
    the loader is the directive handler."""
    assert _callers_of(r"\bbrix_resolv_conf_load\s*\(", (".c", ".h")) == {
        "src/net/dns/directive.c",      # the only caller
        "src/net/dns/resolv_conf.c",    # the definition
        "src/net/dns/resolv_conf.h",    # its declaration
    }
    # ... and nothing in the DNS tree re-opens a resolv.conf path at runtime.
    reopened = [name for name in ("resolve.c", "targets.c", "resolve_thread.c",
                                  "resolve_bridge.c")
                if re.search(r"\b(stat|fopen|open)\s*\([^)]*resolv",
                             _bare((DNS / name).read_text()))]
    assert reopened == [], reopened


# --------------------------------------------------------------------------- #
# the threadless build keeps a compiling, declining arm                        #
# --------------------------------------------------------------------------- #

BRIDGE_SYMBOLS = ("brix_dns_bridge_init_worker", "brix_dns_bridge_resolve",
                  "brix_dns_bridge_reverse", "brix_dns_bridge_stats")


def test_the_bridge_defines_every_symbol_in_both_thread_arms():
    """`#if (NGX_THREADS)` … `#else` … `#endif`: a build without threads has no
    thread-pool callers to bridge, but it still links.  Each public symbol is
    defined once on each side."""
    text = (DNS / "resolve_bridge.c").read_text()
    assert "#if (NGX_THREADS)" in text and "#else" in text and "#endif" in text
    head, _, tail = text.partition("\n#else")
    for sym in BRIDGE_SYMBOLS:
        assert re.search(rf"^{sym}\(", head, re.M), f"{sym} missing from the threaded arm"
        assert re.search(rf"^{sym}\(", tail, re.M), f"{sym} missing from the threadless arm"
    # The declining arm must answer "not bridged" rather than "resolved
    # nothing": a caller distinguishes NGX_DECLINED (use your fallback) from a
    # zero-address success.
    assert tail.count("NGX_DECLINED") >= 2, tail[:400]


def test_backend_prepare_degrades_rather_than_failing_without_threads():
    text = (DNS / "directive.c").read_text()
    body = text.split("brix_dns_backend_prepare(ngx_conf_t *cf)")[1].split("\n}")[0]
    assert "#if (NGX_THREADS)" in body and "#else" in body, body
    assert "ngx_thread_pool_add(cf, NULL)" in body, body
    assert body.rstrip().endswith("return NGX_CONF_OK;"), body


def test_every_feature_that_resolves_an_unregistered_name_asks_for_a_backend():
    """The five call sites of brix_dns_backend_prepare are the features that
    resolve a name brix_dns_target_register() never saw (a peer's PTR, a pmark
    destination, a proxy upstream, a WebDAV proxy-pool backend).  Pinning the
    set means a sixth such feature has to be added deliberately — and that a
    removal is noticed rather than silently degrading to "no resolver and no
    thread pool available"."""
    assert _callers_of(r"\bbrix_dns_backend_prepare\s*\(cf\)") == {
        "src/observability/pmark/config.c",
        "src/core/config/server_conf_merge_security.c",
        "src/core/config/http_common.c",
        "src/net/proxy/directives.c",
        "src/protocols/webdav/proxy_pool.c",
    }, callers


# --------------------------------------------------------------------------- #
# discovery — the WebDAV proxy pool is inert, and its DNS arm rides along      #
# --------------------------------------------------------------------------- #

def test_the_webdav_proxy_pool_is_never_configured_so_its_dns_arm_is_dormant():
    """brix_proxy_pool_configure() — which is where the pool asks for a DNS
    backend — has no caller: the SHM zone is never declared, pool_table()
    answers NULL, brix_proxy_pool_add() returns NGX_DECLINED and the admin
    route answers 404 proxy_pool_disabled.  The phase-116 preparation inside
    it is therefore dormant, not wrong; this pins both halves so wiring the
    pool up later cannot quietly drop the resolver preparation."""
    pool = _text("src", "protocols", "webdav", "proxy_pool.c")
    assert "brix_dns_backend_prepare(cf)" in pool, \
        "the pool no longer prepares a DNS backend for its async resolution"
    callers = _callers_of(r"\bbrix_proxy_pool_configure\s*\(") - {
        "src/protocols/webdav/proxy_pool.c"}          # its own definition
    assert callers == set(), \
        f"the pool is wired up now — give its resolution path a live test: {callers}"
    admin = _text("src", "observability", "dashboard", "api_admin_proxy.c")
    assert "proxy_pool_disabled" in admin, admin[:200]
    assert re.search(r"rc == NGX_DECLINED", admin), \
        "the admin route no longer degrades when the pool is absent"


def test_a_dial_that_never_became_a_link_tells_the_dns_target():
    """Amendment 12, half one: the CMS client's failure signal to the runtime
    DNS target has to leave from the teardown funnel that counts the failure,
    not only from the ngx_event_connect_peer() branch — on loopback a refused
    dial surfaces on the read/write side and never reaches that branch, so the
    dead address stayed published.  Structural, because the live proof
    (test_phase116_reresolve.py) needs a lane and this must red on a revert in
    any run."""
    connect = _bare(_text("src", "net", "cms", "connect.c"))
    teardown = connect[connect.index("BRIX_RESIL_METRIC_INC(cms_connect_failures_total)"):]
    teardown = teardown[:teardown.index("\n}")]
    assert "brix_dns_target_note_failure" in teardown, \
        "the teardown that counts a never-became-a-link dial no longer tells the DNS target"
    assert "ngx_exiting" in teardown, \
        "a draining worker must not arm a DNS refresh timer on its way out"
    # The connect-time site stays: a synchronous failure builds no connection
    # and so never reaches the teardown.
    assert connect.count("brix_dns_target_note_failure") == 2, \
        "expected exactly the connect-time and the teardown failure sites"


def test_a_re_resolution_keeps_the_address_it_already_publishes():
    """Amendment 12, half two: a refused dial advances the published address
    *and* schedules an early refresh, so an answer-apply path that restarted
    the rotation at addrs[0] undid the advance it had just caused.  The apply
    path must carry the published address across a re-resolution instead."""
    targets = _bare(_text("src", "net", "dns", "targets.c"))
    apply_path = targets[targets.index("dns_target_on_success(brix_dns_target_t *t"):]
    apply_path = apply_path[:apply_path.index("\n}")]
    assert "dns_target_carry_index" in apply_path, \
        "on_success no longer carries the published address across a refresh"
    assert "t->rr = 0;" not in apply_path, \
        "on_success restarts the rotation at addrs[0] again (amendment 12 reverted)"
    # The carry is a match against the incoming answer, not a blind keep: a
    # record that really changed still starts at index 0.
    carry = targets[targets.index("dns_target_carry_index(const brix_dns_target_t *t"):]
    carry = carry[:carry.index("\n}")]
    assert "ngx_memcmp" in carry and "return 0;" in carry, carry


# --------------------------------------------------------------------------- #
# the companion rule is per-file: keep the call sites 1:1 with the opt-out     #
# --------------------------------------------------------------------------- #

def test_every_ngx_parse_url_call_carries_its_own_no_resolve():
    """`check_dns_seam.py` applies the companion rule per FILE: one
    `no_resolve = 1` anywhere satisfies it however many times the file parses a
    URL.  Today every caller is 1:1, so a second call in an already-compliant
    file would be the one bypass the guard cannot see.  Pinning the ratio makes
    that a test failure rather than a silent hole."""
    off = {}
    for rel in sorted(_callers_of(r"\bngx_parse_url\s*\(", (".c", ".h"))):
        body = _bare((REPO / rel).read_text())
        calls = len(re.findall(r"\bngx_parse_url\s*\(", body))
        opts = len(re.findall(r"\bno_resolve\s*=\s*1\b", body))
        if calls != opts:
            off[rel] = (calls, opts)
    assert off == {}, f"ngx_parse_url calls without their own no_resolve: {off}"


# --------------------------------------------------------------------------- #
# W5.4 — SRV was not taken, and stays not taken                                #
# --------------------------------------------------------------------------- #

SRV_MARKERS = (r"ngx_resolve_start_srv", r"ngx_resolve_srv",
               r"NGX_RESOLVE_SRV", r"\bT_SRV\b", r"\bservice\s*=")

SRV_SCOPE = ("src/net/dns", "client/lib/net/resolve.c")


def _srv_scope_files() -> list[Path]:
    """The seam's own sources: a directory contributes its C files, a named
    file contributes itself."""
    files: list[Path] = []
    for rel in SRV_SCOPE:
        path = REPO / rel
        files += sorted(path.rglob("*.[ch]")) if path.is_dir() else [path]
    return files


def test_srv_resolution_is_still_not_taken():
    """Amendment 9 declined W5.4: `service=` has no consumer in the tree, so
    brix resolves A/AAAA only and an operator's SRV expectations are met by
    naming addresses.  Its sibling half (W6, decision B) is pinned above; this
    half lived in the doc and nowhere else, so an SRV lookup could land while
    the non-goal still read "not taken".  If this reddens the assertion is not
    what needs changing — amendment 9 is."""
    found = [f"{f.relative_to(REPO)}: {marker}"
             for f in _srv_scope_files()
             for marker in SRV_MARKERS
             if re.search(marker, _bare(f.read_text()))]
    assert found == [], (
        "phase-116 amendment 9 records SRV as not taken; these sites resolve "
        f"or accept one: {found}")
