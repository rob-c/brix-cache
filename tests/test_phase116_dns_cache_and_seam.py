"""
test_phase116_dns_cache_and_seam.py — phase-116 W4 + W6: answer cache, one seam.

WHAT: The strict one-DNS-path guard (tools/ci/check_dns_seam.py) proven on
      the real tree and on synthetic trees that plant each bypass class
      (libc forward/reverse resolvers, the blocking ngx_inet_resolve_host,
      OpenSSL connect BIOs, libcurl redirect following, an unpinned
      CURLOPT_URL, ngx_parse_url without no_resolve) — with no waiver marker
      and no backlog file in existence.  Then the per-worker answer cache
      live: positive answers are re-asked once per TTL, a negative answer is
      served from the negative cache for `negative_ttl`, and `negative_ttl=0`
      turns that cache off.
WHY:  The user's directive was "no dns seam backlog": every resolver in
      src/, client/ and shared/ goes through one path, and the guard that
      keeps it so must be shown to bite.  The cache is what keeps that one
      path from hammering the nameserver at retry pace.
HOW:  The guard's `scan()` is imported and pointed at tmp trees; the live
      half reads the stub's question log and the brix_dns_cache_* families.
"""
from __future__ import annotations

import ast
import importlib.util
import subprocess
import time
import tokenize
from io import StringIO
from pathlib import Path

import pytest

from _phase116_helpers import (HAVE_NGINX, BIND_HOST, DnsLab, TcpSink, dns_target,
                               metric, metrics_text, wait_for_state, wait_until)
from dns_stub import TYPE_A, parse_metrics
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p116-dns")]

REPO = Path(__file__).resolve().parent.parent
GUARD = REPO / "tools" / "ci" / "check_dns_seam.py"
MANAGER = "manager.lab.test"


def _guard():
    spec = importlib.util.spec_from_file_location("check_dns_seam", GUARD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tree(tmp_path, files: dict[str, str]) -> Path:
    root = tmp_path / "tree"
    for sub in ("src", "client", "shared", "tools", "contrib"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


# --------------------------------------------------------------------------- #
# W6 — the guard                                                                #
# --------------------------------------------------------------------------- #

def test_guard_is_green_on_the_real_tree():
    hits, count = _guard().scan(REPO)
    assert not hits, "\n".join(hits)
    assert count > 1000, count


def _docstring_lines(py_source: str) -> set[int]:
    """Every line number occupied by a module/class/function docstring."""
    lines: set[int] = set()
    for node in ast.walk(ast.parse(py_source)):
        if not isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)):
            continue
        if ast.get_docstring(node, clean=False) is not None:
            body = node.body[0]
            lines.update(range(body.lineno, body.end_lineno + 1))
    return lines


def _code_lines(py_source: str) -> tuple[list[str], list[str]]:
    """(identifiers+operators, string literals) of the guard's executable
    code: comments and docstrings dropped, so the header that *says* there
    is no waiver does not trip the check."""
    docs = _docstring_lines(py_source)
    names: list[str] = []
    strings: list[str] = []
    for tok in tokenize.generate_tokens(StringIO(py_source).readline):
        if tok.start[0] in docs:
            continue
        if tok.type == tokenize.STRING:
            strings.append(tok.string)
        elif tok.type != tokenize.COMMENT:
            names.append(tok.string)
    return names, strings


def test_guard_has_no_waiver_and_no_backlog():
    """The guard must not grandfather a call site: no waiver marker, no
    backlog file, no allowlist flag — only the seam files themselves.
    Identifiers and string literals are checked separately: a diagnostic
    may *say* "no waiver exists", but no name, flag, marker or path may
    implement one."""
    names, strings = _code_lines(GUARD.read_text())
    ident = " ".join(names).lower()
    for word in ("backlog", "allowlist", "grandfather", "waiver", "skip"):
        assert word not in ident, f"the guard's code names {word!r}"
    literal = " ".join(strings).lower()
    for word in ("dns-seam-allow", "backlog", "--allow", "--skip", "allowlist"):
        assert word not in literal, f"the guard's literals mention {word!r}"
    assert not list((REPO / "tools" / "ci").glob("*dns*backlog*")), \
        "a DNS-seam backlog file exists — the seam is meant to be complete, not grandfathered"
    assert not list((REPO / "tools" / "ci").glob("*dns*allow*")), \
        "a DNS-seam allowlist file exists"


@pytest.mark.parametrize("rel, code, label", [
    ("src/x/y.c", "rc = getaddrinfo(h, NULL, &hints, &res);", "libc forward resolver"),
    ("client/apps/z.c", "he = gethostbyname(name);", "libc forward resolver"),
    ("shared/w.c", "n = res_query(name, C_IN, T_A, buf, sizeof buf);", "libc forward resolver"),
    ("src/a.c", "getnameinfo(sa, len, host, sizeof host, NULL, 0, NI_NAMEREQD);", "libc reverse resolver"),
    ("src/b.c", "ngx_inet_resolve_host(pool, &u);", "nginx blocking resolver"),
    ("src/c.c", "#include <netdb.h>", "<netdb.h> include"),
    ("src/d.c", "BIO_set_conn_hostname(bio, host);", "OpenSSL connect BIO"),
    ("client/e.c", "curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);", "libcurl redirect follow"),
])
def test_guard_flags_each_bypass_class(tmp_path, rel, code, label):
    hits, _ = _guard().scan(_tree(tmp_path, {rel: code + "\n"}))
    assert hits, f"{code!r} in {rel} was not flagged"
    assert any(rel in h and label in h for h in hits), hits


@pytest.mark.parametrize("rel, code, label", [
    ("src/f.c", "curl_easy_setopt(h, CURLOPT_URL, url);", "CURLOPT_URL without an address pin"),
    ("src/g.c", "if (ngx_parse_url(cf->pool, &u) != NGX_OK) { return NGX_CONF_ERROR; }",
     "ngx_parse_url without no_resolve"),
])
def test_guard_requires_the_companion_pin(tmp_path, rel, code, label):
    hits, _ = _guard().scan(_tree(tmp_path, {rel: code + "\n"}))
    assert any(label in h for h in hits), hits


def test_guard_accepts_a_pinned_curl_and_a_no_resolve_parse(tmp_path):
    hits, _ = _guard().scan(_tree(tmp_path, {
        "src/f.c": "curl_easy_setopt(h, CURLOPT_URL, url);\nbrix_dns_curl_pin(h, &pin);\n",
        "src/g.c": "u.no_resolve = 1;\nngx_parse_url(cf->pool, &u);\n",
        "client/h.c": "curl_easy_setopt(h, CURLOPT_URL, url);\ncvmfs_curl_perform_pinned(h, host);\n",
    }))
    assert not hits, hits


def test_guard_accepts_the_seam_files_and_only_them(tmp_path):
    g = _guard()
    ok = _tree(tmp_path, {
        g.SERVER_FORWARD: "#include <netdb.h>\nrc = getaddrinfo(h, s, &hints, &res);\n",
        g.SERVER_REVERSE: "#include <netdb.h>\nrc = getnameinfo(sa, l, h, n, NULL, 0, 0);\n",
        g.CLIENT_SEAM: "#include <netdb.h>\nrc = getaddrinfo(h, s, &hints, &res);\n",
    })
    hits, _ = g.scan(ok)
    assert not hits, hits
    # security negative: the reverse seam may not also forward-resolve
    hits, _ = g.scan(_tree(tmp_path / "neg", {g.SERVER_REVERSE: "rc = getaddrinfo(h, s, &hints, &res);\n"}))
    assert any("libc forward resolver" in h for h in hits), hits


def test_guard_ignores_comments_but_not_code(tmp_path):
    hits, _ = _guard().scan(_tree(tmp_path, {
        "src/k.c": "/* the old getaddrinfo() path is gone */\n// gethostbyname(x)\nint x; /* getnameinfo( */\n",
    }))
    assert not hits, hits


def test_guard_cli_reports_the_hit_and_exits_one(tmp_path):
    import subprocess, sys
    root = _tree(tmp_path, {"src/x.c": "getaddrinfo(h, NULL, &hints, &res);\n"})
    r = subprocess.run([sys.executable, str(GUARD), "--root", str(root)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 1 and "src/x.c:1" in r.stderr and "no waiver exists" in r.stderr, r.stderr
    r = subprocess.run([sys.executable, str(GUARD), "--root", str(_tree(tmp_path / "ok", {}))],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and r.stdout.startswith("check_dns_seam: OK"), r


# --------------------------------------------------------------------------- #
# W4 — the answer cache, live                                                   #
# --------------------------------------------------------------------------- #

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


def _a_count(lab):
    return len(lab.stub.queries_for(MANAGER, TYPE_A))


def test_positive_answers_are_reasked_once_per_ttl(lifecycle, tmp_path, sink):
    lab = DnsLab(tmp_path)
    try:
        lab.stub.add_a(MANAGER, BIND_HOST, ttl=2)
        ep = _start(lifecycle, lab, sink, "positive cache follows the answer TTL",
                    RESOLVER_EXTRA="ipv6=off min_ttl=1s")
        assert wait_for_state(ep.port, MANAGER, "resolved")
        lab.stub.clear_queries()
        time.sleep(6.5)
        n = _a_count(lab)
        assert 2 <= n <= 5, f"{n} A queries in 6.5s for a 2s TTL"
        text = metrics_text(ep.port)
        assert metric(text, "brix_dns_cache_entries") >= 1
        assert metric(text, "brix_dns_resolutions_total") >= 3
    finally:
        lab.close()


def test_negative_answers_are_served_from_the_negative_cache(lifecycle, tmp_path, sink):
    lab = DnsLab(tmp_path)
    try:
        ep = _start(lifecycle, lab, sink, "negative cache absorbs retries",
                    RESOLVER_EXTRA="ipv6=off negative_ttl=3s", RETRY="200ms 200ms")
        assert wait_for_state(ep.port, MANAGER, "failed")
        assert wait_until(lambda: metric(metrics_text(ep.port), "brix_dns_cache_negative_hits_total"),
                          timeout=5), "no retry was answered by the negative cache"
        text = metrics_text(ep.port)
        assert metric(text, "brix_dns_lookups_total", result="nxdomain") >= 1
        assert metric(text, "brix_dns_cache_misses_total") >= 1
        row = dns_target(ep.port, MANAGER)
        assert row["failures"] >= 2, row
    finally:
        lab.close()


def test_negative_ttl_zero_disables_the_negative_cache(lifecycle, tmp_path, sink):
    lab = DnsLab(tmp_path)
    try:
        ep = _start(lifecycle, lab, sink, "negative_ttl=0 re-asks on every retry",
                    RESOLVER_EXTRA="ipv6=off negative_ttl=0", RETRY="200ms 200ms")
        assert wait_for_state(ep.port, MANAGER, "failed")
        assert wait_until(lambda: metric(metrics_text(ep.port), "brix_dns_lookups_total",
                                         result="nxdomain") >= 3, timeout=5)
        assert metric(metrics_text(ep.port), "brix_dns_cache_negative_hits_total") == 0
    finally:
        lab.close()


# --------------------------------------------------------------------------- #
# the hidden-resolver classes: libcurl's own resolvers and a second library    #
# --------------------------------------------------------------------------- #
# Each of these makes libcurl (or c-ares) resolve on its own terms behind the
# seam — a name, a DoH endpoint, a private nameserver list — so the answer
# never reaches the dashboard, the cache or the policy.  None occurs in the
# tree today: the rules exist so the first one cannot land quietly.

@pytest.mark.parametrize("rel, code, label", [
    ("src/p.c", "curl_easy_setopt(h, CURLOPT_CONNECT_TO, list);", "libcurl alternate resolver"),
    ("src/q.c", "curl_easy_setopt(h, CURLOPT_DOH_URL, \"https://doh/\");", "libcurl alternate resolver"),
    ("client/r.c", "curl_easy_setopt(h, CURLOPT_DNS_SERVERS, \"10.0.0.1\");", "libcurl alternate resolver"),
    ("src/s.c", "curl_easy_setopt(h, CURLOPT_DNS_INTERFACE, \"eth0\");", "libcurl alternate resolver"),
    ("shared/t.c", "ares_getaddrinfo(ch, name, NULL, &hints, cb, arg);", "c-ares resolver"),
])
def test_guard_flags_the_hidden_resolver_classes(tmp_path, rel, code, label):
    hits, _ = _guard().scan(_tree(tmp_path, {rel: code + "\n"}))
    assert any(rel in h and label in h for h in hits), hits


def test_guard_requires_a_pin_for_the_proxy_host_too(tmp_path):
    """libcurl resolves the PROXY host as well as the URL host — pinning only
    the URL leaves half the request resolving outside the seam."""
    g = _guard()
    hits, _ = g.scan(_tree(tmp_path, {
        "src/u.c": "curl_easy_setopt(h, CURLOPT_PROXY, proxy);\n"}))
    assert any("CURLOPT_PROXY without an address pin" in h for h in hits), hits
    hits, _ = g.scan(_tree(tmp_path / "ok", {
        "src/u.c": "curl_easy_setopt(h, CURLOPT_PROXY, proxy);\n"
                   "brix_dns_curl_pin(h, &pin);\n"}))
    assert not hits, hits


def _rule_allowance(guard, label: str) -> frozenset:
    """The per-rule file allowance the guard grants `label`."""
    for rule_label, _, files in guard.SYMBOL_RULES:
        if rule_label == label:
            return files
    raise AssertionError(f"the guard no longer carries a {label!r} rule")


def _labels_name_a_target(labels: list) -> bool:
    return any(MANAGER in value or ".lab.test" in value for _, value in labels)


def _sample_label_violation(name: str, labels: list) -> str:
    """An empty string when this sample's labels are bounded and name-free
    (I-DNS-4); the complaint otherwise."""
    keys = sorted(k for k, _ in labels)
    if not set(keys) <= {"state", "result"}:
        return f"{name} carries {keys}"
    if _labels_name_a_target(labels):
        return f"{name} carries a resolved name: {labels}"
    return ""


def _dns_label_violations(text: str) -> list[str]:
    """Every brix_dns_* sample's label keys are bounded, and no label value
    carries a resolved name."""
    bad = [_sample_label_violation(name, labels)
           for name, labels in parse_metrics(text)
           if name.startswith("brix_dns_")]
    return [b for b in bad if b]


def test_the_openssl_bio_allowance_is_one_file_and_its_hostport_is_numeric(tmp_path):
    """The single symbol allowance in the guard: the OCSP transport may open a
    connect BIO, because ocsp_connect_responder() has already resolved through
    brix_dns_resolve_sync() and hands BIO a numeric host:port.  Both halves are
    asserted — the allowance is scoped to that one file, and that file really
    does build its hostport with ngx_sock_ntop rather than passing a name."""
    g = _guard()
    allowed = _rule_allowance(g, "OpenSSL connect BIO")
    assert allowed == frozenset({"src/auth/crypto/ocsp_transport.c"}), allowed
    hits, _ = g.scan(_tree(tmp_path, {"src/auth/crypto/other.c":
                                      "BIO_new_connect(hostport);\n"}))
    assert any("OpenSSL connect BIO" in h for h in hits), hits
    src = (REPO / "src" / "auth" / "crypto" / "ocsp_request.c").read_text()
    assert "brix_dns_resolve_sync" in src and "ngx_sock_ntop" in src, \
        "the OCSP responder no longer resolves through the seam before BIO"


# --------------------------------------------------------------------------- #
# I-DNS-4 — DNS metrics stay low-cardinality (invariant 8)                      #
# --------------------------------------------------------------------------- #

def test_no_dns_metric_carries_a_per_target_label(lifecycle, tmp_path, sink):
    """A hostname in a label key multiplies the series by the number of names
    a site resolves, and a resolver is exactly where unbounded names arrive.
    Per-target detail lives in the dashboard rows; the exposition keeps two
    bounded keys.  Read live rather than from the C, because the census has to
    survive a family added through a template."""
    lab = DnsLab(tmp_path)
    try:
        lab.stub.add_a(MANAGER, BIND_HOST)
        ep = _start(lifecycle, lab, sink, "dns metric label census",
                    RESOLVER_EXTRA="ipv6=off")
        assert wait_for_state(ep.port, MANAGER, "resolved")
        text = metrics_text(ep.port)
        families = {name for name, _ in parse_metrics(text) if name.startswith("brix_dns_")}
        assert families, "no brix_dns_* families in the exposition"
        assert _dns_label_violations(text) == [], _dns_label_violations(text)
        # the target's own name is in the dashboard row instead — that is the
        # bounded place for it, and it must actually be there.
        assert dns_target(ep.port, MANAGER)["host"] == MANAGER
    finally:
        lab.close()


# --------------------------------------------------------------------------- #
# the guard's own reach: every language the scanned trees compile              #
# --------------------------------------------------------------------------- #
# client/apps/ceph builds and installs four C++ programs (client/Makefile
# :587-601 builds, :808-815 installs, the RPM spec ships them).  A guard that
# read only .c/.h left those shipped client binaries outside the one-DNS-path
# guarantee — a backlog by file extension, which this phase does not allow.

CXX_SUFFIXES = (".cc", ".cpp", ".cxx", ".hh", ".hpp")

# Suffixes that live under the scanned trees and are not compiled: docs, man
# pages, the Python/shell tooling that ships beside the sources, and contrib/'s
# config example, Grafana dashboard and Prometheus alert rules.
NON_SOURCE_SUFFIXES = {".md", ".py", ".sh", ".bash", ".txt", ".1", ".7",
                       ".example", ".json", ".yml"}


@pytest.mark.parametrize("rel", [f"client/apps/ceph/x{s}" for s in CXX_SUFFIXES])
def test_the_guard_reads_cxx_sources_too(tmp_path, rel):
    """A resolver call in a C++ client app is the same bypass it is in C."""
    hits, _ = _guard().scan(_tree(tmp_path, {rel: "getaddrinfo(h, s, &hints, &res);\n"}))
    assert any(rel in h and "libc forward resolver" in h for h in hits), hits


def test_every_suffix_the_scanned_trees_carry_is_scanned_or_named():
    """A census, not a sample: if a new language lands under a scanned tree,
    it must either be scanned or be named non-source here deliberately.  Silence about .cpp is what let the ceph apps ship
    unguarded.  Tracked files only, so a dirty build tree cannot skew it."""
    guard = _guard()
    tracked = subprocess.run(["git", "ls-files", *guard.SCAN_DIRS],
                             cwd=REPO, capture_output=True, text=True, check=True)
    seen = {Path(line).suffix for line in tracked.stdout.split() if "." in Path(line).name}
    unjudged = sorted(seen - set(guard.SOURCE_SUFFIXES) - NON_SOURCE_SUFFIXES)
    assert unjudged == [], (
        "these suffixes exist under the DNS seam guard's scanned trees and it "
        f"neither scans nor excludes them: {unjudged}")


def _shipped_ceph_cxx() -> set[str]:
    """The C++ sources client/Makefile builds and the RPM ships."""
    return {p.relative_to(REPO).as_posix()
            for p in (REPO / "client" / "apps" / "ceph").rglob("*")
            if p.suffix in CXX_SUFFIXES}


def test_the_ceph_cxx_apps_are_actually_scanned_in_the_real_tree():
    """The live proof for the synthetic cases above: the shipped C++ apps are
    in the guard's file set, so their first resolver call reddens CI."""
    scanned = {p.relative_to(REPO).as_posix() for p in _guard()._source_files(REPO)}
    shipped = _shipped_ceph_cxx()
    assert shipped, "the ceph C++ apps moved; re-point this test, do not delete it"
    assert shipped <= scanned, sorted(shipped - scanned)


# --------------------------------------------------------------------------- #
# the guard's other reach: every tree that holds non-test C                    #
# --------------------------------------------------------------------------- #
# tools/pblock-fsck is a standalone consistency oracle with its own install
# target (tools/pblock-fsck/Makefile:14-15).  It is shipped code that lived
# outside SCAN_DIRS, which is the same hole the C++ suffixes were: a bypass
# could land there and the guard would still print OK.  contrib/checksum-
# plugins/ was the third such tree: site checksum plugins are shared objects
# the worker dlopen()s (contrib/checksum-plugins/README.md), and the
# whole-repo census below caught the first one on 2026-09-07 -- a red, not
# a silence, which is what that census is for.

# Trees whose C is test code and uses libc deliberately.  k8s-tests mirrors
# tests/; brixtest ships nothing (no build file installs it).
TEST_TREES = ("tests", "k8s-tests", "brixtest")


def test_the_guard_reads_the_standalone_tools_too(tmp_path):
    """A resolver in tools/pblock-fsck is the same bypass it is in src/."""
    rel = "tools/pblock-fsck/pblock-fsck.c"
    hits, _ = _guard().scan(_tree(tmp_path, {rel: "getaddrinfo(h, s, &hints, &res);\n"}))
    assert any(rel in h and "libc forward resolver" in h for h in hits), hits


def _tracked_files() -> list[str]:
    """Every path git tracks, so a build tree cannot skew a census."""
    out = subprocess.run(["git", "ls-files"], cwd=REPO,
                         capture_output=True, text=True, check=True)
    return out.stdout.split()


def _unscanned_tracked_sources() -> list[str]:
    """Tracked C/C++ that is neither in SCAN_DIRS nor in a test tree."""
    guard = _guard()
    covered = tuple(d + "/" for d in guard.SCAN_DIRS + TEST_TREES)
    stray = []
    for rel in _tracked_files():
        if Path(rel).suffix in guard.SOURCE_SUFFIXES and not rel.startswith(covered):
            stray.append(rel)
    return sorted(stray)


def test_every_tracked_c_file_is_scanned_or_is_test_code():
    """The whole-repo census: a tracked C or C++ file is either inside
    SCAN_DIRS or inside a declared test tree.  A new shipped tool in a new
    directory has to be judged here rather than resolve unseen."""
    stray = _unscanned_tracked_sources()
    assert stray == [], (
        "these tracked C/C++ files are neither scanned by the DNS seam guard "
        f"nor declared test code: {stray}")


PLUGIN_TREE = "contrib/checksum-plugins"


def test_the_guard_reads_contrib_plugins_too(tmp_path):
    """A resolver call in a site plugin is the same bypass it is in src/."""
    rel = f"{PLUGIN_TREE}/brix_cks_x.c"
    hits, _ = _guard().scan(_tree(tmp_path, {rel: "getaddrinfo(h, s, &hints, &res);\n"}))
    assert any(rel in h and "libc forward resolver" in h for h in hits), hits


def test_a_plugin_that_includes_netdb_is_flagged_before_it_resolves(tmp_path):
    """The header is a needle of its own: a plugin cannot reach the libc
    resolvers without it, so the include alone reddens CI whatever the call
    is named."""
    rel = f"{PLUGIN_TREE}/brix_cks_x.c"
    hits, _ = _guard().scan(_tree(tmp_path, {rel: "#include <netdb.h>\n"}))
    assert any(rel in h and "<netdb.h> include" in h for h in hits), hits


def _shipped_plugin_sources(guard) -> set[str]:
    """The tracked C under contrib/checksum-plugins/: site plugins the worker loads."""
    return {rel for rel in _tracked_files()
            if rel.startswith(PLUGIN_TREE + "/") and Path(rel).suffix in guard.SOURCE_SUFFIXES}


def test_the_shipped_checksum_plugins_are_actually_scanned_in_the_real_tree():
    """The live proof: every tracked C file under the plugin tree is in the
    guard's file set, so its first resolver call reddens CI."""
    guard = _guard()
    shipped = _shipped_plugin_sources(guard)
    assert shipped, "the checksum plugins moved; re-point this test, do not delete it"
    scanned = {q.relative_to(REPO).as_posix() for q in guard._source_files(REPO)}
    assert shipped <= scanned, sorted(shipped - scanned)
