"""Guard: no hard-coded server host/IP literals outside the registry definitions.

WHY
    The test suite currently dials servers bound to ``127.0.0.1`` / ``localhost``
    / ``[::1]``.  The next step is to let the server registry point a port at a
    *different* endpoint — a kubernetes pod or a container — without editing a
    single test.  That is only possible if the host lives in exactly ONE place:
    the registry/definition layer (``settings.HOST`` / ``settings.HOST6`` and the
    ``fleet_*`` spec catalogue), which is already env-overridable
    (``TEST_SERVER_HOST`` → a pod hostname re-routes the whole fleet).  Every
    ``"127.0.0.1"`` a test hard-codes is a place that migration silently misses.

WHAT
    Fail — RED, no grandfathering — if *any* test file embeds a host literal
    (``localhost``, ``127.0.0.1``, ``0.0.0.0``, or the IPv6 forms ``::1`` /
    ``[::1]`` / ``[::]``) that a port swap would leave stranded.  A test must
    reach a server through

        from settings import HOST, HOST6           # the env-overridable host
        f"root://{HOST}:{port}/..."
        # or the resolved endpoint object:
        ep.host / ep.url                            # ServerEndpoint (registry)

    NOT a bare string literal.  There is NO baseline: the guard is red the moment
    a hard-coded host exists anywhere but the registry files below.

WHY NOT JUST ``grep``
    A straight ``grep`` over the tree yields ~1500 hits and would flag prose and
    payload as violations.  This guard walks the *AST* and only inspects
    string/bytes ``Constant`` nodes, so:
      * comments are invisible (they are not in the AST) and module/class/function
        docstrings are skipped explicitly — prose that merely *mentions* the
        loopback address is never a violation;
      * ``"foo::bar"`` / ``"fe80::1"`` / version strings / times are anchored out
        by the regexes;
      * a ``settings.HOST`` reference is an f-string field, not a literal, so the
        correct idiom is invisible too.

    The only escape hatch is a per-line, reason-bearing ``# net-literal-allow:
    <reason>`` marker (mirrors the src-tree ``/* vfs-seam-allow: <reason> */``
    seam, CLAUDE.md INVARIANT 12) for a genuine *subject-under-test* literal — a
    forged cert SAN ``IP:127.0.0.1``, a PROXY / host-ACL string the server must
    string-match, a config-generator ``listen 127.0.0.1:{p};`` line, a
    registry-model unit assertion — where the literal IS the thing being tested.

USAGE
    PYTHONPATH=tests pytest tests/test_no_hardcoded_hosts.py -v
    python3 tests/test_no_hardcoded_hosts.py    # print every offender; exit 1 if any
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# The registry / definition layer — the ONE sanctioned home for a host literal.
# These files DEFINE the endpoint (settings.HOST and friends, the fleet spec
# catalogue, the PKI/template value maps, the ephemeral-bind helper).  Everything
# else is a *consumer* and must indirect through them.  Keyed by path relative to
# tests/ (all are tree-root modules, so this equals the basename).
# ---------------------------------------------------------------------------
REGISTRY_ALLOW = {
    "settings.py",             # HOST / HOST6 / BIND_HOST / SERVER_HOST — the source of truth
    "server_registry.py",      # NginxInstanceSpec.host / ServerEndpoint / endpoint_for()
    "fleet_specs.py",          # declarative spec catalogue (per-role host overrides)
    "fleet_values.py",         # PKI / bind-host template value maps
    "fleet_ports.py",          # port ledger (no host literals; family member)
    "fleet_lifecycle_ports.py",
    "ephemeral_port.py",       # OS-assigned free-port helper (binds 127.0.0.1 to probe)
    "test_no_hardcoded_hosts.py",  # this guard: its own self-test corpus below
}

# Inline opt-out for a genuine subject-under-test literal (forged cert SAN, a
# PROXY / host-ACL payload the server must string-match, a config-generator
# ``listen``/backend line, a registry-model assertion).  Same-line marker,
# mirroring the src-tree ``/* vfs-seam-allow: <reason> */`` seam.  A bare marker
# with no reason is rejected so the escape hatch stays auditable.
_ALLOW_MARKER = re.compile(r"net-literal-allow:\s*\S")

# Forbidden host literals, anchored so a grep's false hits do NOT match:
#   * word-bounded IPv4 loopback / any-address,
#   * bracketed IPv6 URL forms,
#   * bare IPv6 loopback only when it is not part of a larger token
#     (``foo::bar``, ``fe80::1``, C++ ``ns::x`` do NOT match).
_HOST_PATTERNS = [
    ("localhost", re.compile(r"\blocalhost\b", re.IGNORECASE)),
    ("127.0.0.1", re.compile(r"\b127\.0\.0\.1\b")),
    ("0.0.0.0", re.compile(r"\b0\.0\.0\.0\b")),
    ("[::1]", re.compile(r"\[::1\]")),
    ("[::]", re.compile(r"\[::\]")),
    ("::1", re.compile(r"(?<![\w:.])::1(?![\w:.])")),
]


def _iter_py_files():
    """Every .py under tests/, minus caches."""
    skip = {"__pycache__", ".pytest_cache", ".git"}
    for p in sorted(TESTS.rglob("*.py")):
        if skip & set(p.parts):
            continue
        yield p


def _rel(p: Path) -> str:
    return p.relative_to(TESTS).as_posix()


def _is_allowlisted(rel: str) -> bool:
    return rel in REGISTRY_ALLOW or Path(rel).name in REGISTRY_ALLOW


def _docstring_ids(tree: ast.AST) -> set[int]:
    """Ids of the ``Constant`` nodes that are module/class/function docstrings."""
    out: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", None) or []
            if body and isinstance(body[0], ast.Expr):
                v = body[0].value
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    out.add(id(v))
    return out


def _token_in(value) -> str | None:
    """First forbidden host token present in a str/bytes literal value, or None."""
    if isinstance(value, bytes):
        try:
            text = value.decode("latin-1")
        except Exception:
            return None
    elif isinstance(value, str):
        text = value
    else:
        return None
    for token, pat in _HOST_PATTERNS:
        if pat.search(text):
            return token
    return None


def scan_source(source: str, filename: str = "<src>"):
    """Host-literal violations in one source string.

    Returns a list of ``(lineno, token, stripped_line)``.  Comments are absent
    from the AST; docstrings and same-line ``net-literal-allow`` markers are
    skipped.  One violation per offending literal node (a node that embeds two
    host forms counts once).
    """
    tree = ast.parse(source, filename=filename)
    lines = source.splitlines()
    docstrings = _docstring_ids(tree)
    viols = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or id(node) in docstrings:
            continue
        token = _token_in(node.value)
        if token is None:
            continue
        lineno = getattr(node, "lineno", 0) or 0
        end = getattr(node, "end_lineno", lineno) or lineno
        span = "\n".join(lines[max(lineno - 1, 0):end]) if lines else ""
        if _ALLOW_MARKER.search(span):
            continue
        raw = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
        viols.append((lineno, token, raw))
    return viols


def current_offenders() -> dict[str, list]:
    """{relpath: [(lineno, token, rawline), ...]} for every non-allowlisted file."""
    out: dict[str, list] = {}
    for p in _iter_py_files():
        rel = _rel(p)
        if _is_allowlisted(rel):
            continue
        src = p.read_text(encoding="utf-8", errors="replace")
        try:
            viols = scan_source(src, rel)
        except SyntaxError as e:  # a file that will not compile fails collection anyway
            raise AssertionError(f"{rel}: could not parse for host-literal scan: {e}") from e
        if viols:
            out[rel] = viols
    return out


# ---------------------------------------------------------------------------
# The zero-tolerance test — RED the moment any test hard-codes a host.
# ---------------------------------------------------------------------------
def test_no_hardcoded_host_literals():
    offenders = current_offenders()
    if not offenders:
        return
    total = sum(len(v) for v in offenders.values())
    lines = [
        f"{total} hard-coded host literal(s) in {len(offenders)} test file(s) — "
        "route each through settings.HOST / HOST6 (or ep.host / ep.url), or, for a "
        "genuine subject-under-test literal (cert SAN, PROXY/ACL payload, "
        "config-generator listen line), append `# net-literal-allow: <reason>`.",
        "Full list: python3 tests/test_no_hardcoded_hosts.py",
        "",
    ]
    for rel in sorted(offenders):
        viols = offenders[rel]
        lines.append(f"  {rel} ({len(viols)}):")
        for lineno, token, raw in viols:
            lines.append(f"      {rel}:{lineno}  [{token}]  {raw}")
    raise AssertionError("\n".join(lines))


def test_registry_allowlist_files_exist():
    """Guard against allowlist rot — every named definition file must be real."""
    missing = [
        name for name in REGISTRY_ALLOW
        if name != "test_no_hardcoded_hosts.py" and not (TESTS / name).exists()
    ]
    assert not missing, f"REGISTRY_ALLOW names a non-existent file: {missing}"


# ---------------------------------------------------------------------------
# Self-tests — prove the scanner's *precision* (the whole reason grep is wrong).
# These feed synthetic sources to scan_source() directly; no fleet, no I/O.
# ---------------------------------------------------------------------------
def _tokens(source: str):
    return {tok for _, tok, _ in scan_source(source)}


def test_scanner_flags_ipv4_and_ipv6_literals():
    assert _tokens('x = "127.0.0.1"') == {"127.0.0.1"}
    assert _tokens('x = "0.0.0.0"') == {"0.0.0.0"}
    assert _tokens('x = "localhost"') == {"localhost"}
    assert _tokens('x = "LOCALHOST"') == {"localhost"}          # case-insensitive
    assert _tokens('x = "::1"') == {"::1"}
    assert _tokens('u = f"http://[::1]:{p}/m"') == {"[::1]"}     # inside an f-string
    assert _tokens('b = b"127.0.0.1"') == {"127.0.0.1"}         # bytes literal (PROXY, wire)


def test_scanner_ignores_indirected_host():
    # The correct idiom — no literal, nothing to flag.
    assert _tokens('u = f"root://{HOST}:{port}/{path}"') == set()
    assert _tokens('u = f"root://{ep.host}:{ep.port}/"') == set()
    assert _tokens('u = ep.url') == set()


def test_scanner_ignores_comments_and_docstrings():
    assert _tokens("x = 1  # server binds on 127.0.0.1 and [::1]") == set()
    assert _tokens('"""Connects to 127.0.0.1 for the smoke test."""\nx = 1') == set()
    src = "def f():\n    '''dials localhost:8000'''\n    return 1\n"
    assert _tokens(src) == set()


def test_scanner_ignores_lookalikes():
    # Anchoring must reject non-host uses of the same characters.
    assert _tokens('s = "namespace::method"') == set()
    assert _tokens('s = "fe80::1"') == set()                    # link-local, not loopback
    assert _tokens('s = "v127.0.0.10"') == set()                # not word-bounded 127.0.0.1
    assert _tokens('s = "10.0.0.5"') == set()                   # an ordinary address


def test_scanner_honors_allow_marker():
    ok = 'san = "IP:127.0.0.1"  # net-literal-allow: forged cert SAN under test'
    assert _tokens(ok) == set()
    # A marker with no reason must NOT wave the literal through.
    bare = 'san = "127.0.0.1"  # net-literal-allow:'
    assert _tokens(bare) == {"127.0.0.1"}


def test_scanner_counts_once_per_node():
    # ``[::1]`` matches two patterns; a node with two host forms is still one hit.
    assert len(scan_source('u = "http://[::1]:8000"')) == 1
    assert len(scan_source('pair = "127.0.0.1 and ::1"')) == 1


if __name__ == "__main__":
    offenders = current_offenders()
    total = sum(len(v) for v in offenders.values())
    for rel in sorted(offenders):
        for lineno, token, raw in offenders[rel]:
            print(f"{rel}:{lineno}: [{token}] {raw}")
    print(f"\n{len(offenders)} file(s), {total} host-literal(s) outside the registry.")
    sys.exit(1 if offenders else 0)
