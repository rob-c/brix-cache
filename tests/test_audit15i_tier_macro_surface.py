"""
test_audit15i_tier_macro_surface.py — the audit's "tier-macro hole", closed as
a growth guard (§E of
docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-15.md).

§E's method note, verbatim: "literal `ngx_string("brix_...")` scans miss every
directive born from BRIX_TIER_DIRECTIVES / BRIX_BACKEND_ASYNC_DIRECTIVES
(prefix string-pasting) ... This is also a growth risk: a new macro family
silently hides new directives from name-based guards."

The audit worked around the hole by hand for one measurement.  A hand
workaround does not survive the next directive, so this file turns the note
into three standing properties:

  1. the inventory of directive-FACTORY macros is closed — a third family
     fails here, in the one place that knows how to expand them, instead of
     silently shrinking every name-based scan in the tree;
  2. the hole is real and its exact shape is pinned — 17 of the 20
     macro-generated directives have no `ngx_string("brix_...")` literal
     anywhere in src/, so a name-based scan sees nothing; the other 3 do,
     because the root:// stream plane declares the async triple by hand
     (src/protocols/root/stream/module.c:476) in addition to the http plane
     taking it from the macro;
  3. what the hole hides is LIVE surface — the invisible names parse on both
     planes right now, which is what makes their invisibility a problem.

Pure source analysis plus a handful of `nginx -t` parses; nothing boots.

DEFECT CANDIDATE #33 — the hole has already cost documentation.
docs/03-configuration/directives.md names 174 brix directives but misses 7 of
the 20 the macros generate (brix_cache_cold_store, brix_cache_global_cas,
brix_cache_passthrough, brix_cache_passthrough_max, and the whole
brix_backend_async triple).  Every one of the 13 that IS documented is a name a
literal scan would also have found via some other mention; the undocumented
seven are exactly the ones that only ever existed as macro expansions.
test_the_documentation_gap_matches_the_macro_hole pins the set: documenting one
makes it fail, and so does adding a new tier directive without documenting it.
"""

import os
import re
from pathlib import Path

import pytest

from _test_phase25_ratelimit_helpers import (
    _parse_fail,
    _http_values,
    _stream_values,
)
from settings import NGINX_BIN

def _check_test_no_other_construct_pastes_a_directive_name_together_1(stray):
    assert [s for s in stray if "BRIX_SOURCE_URL" not in s] == [], stray

def _guard_test_no_other_construct_pastes_a_directive_name_together_1(match, stray, path):
    if match.group(1) != "pfx":
        stray.append(f"{path.relative_to(REPO)}: {match.group(1)}")


REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
TIER_HEADER = SRC / "core" / "config" / "tier_directives.h"
CALL_SITE_HTTP = SRC / "core" / "config" / "http_common.c"
CALL_SITE_STREAM = SRC / "protocols" / "root" / "stream" / "directives_tier.h"
DIRECTIVES_DOC = REPO / "docs" / "03-configuration" / "directives.md"

# The closed set. Adding a family here is the deliberate act §E asks for: the
# author has to come to this file, which is also where the expansion lives.
KNOWN_FACTORIES = {"BRIX_TIER_DIRECTIVES", "BRIX_BACKEND_ASYNC_DIRECTIVES"}

# The three names the root:// stream plane ALSO declares literally, so a
# name-based scan does find them. Everything else the macros generate is
# invisible to such a scan — that is the hole.
LITERALLY_DECLARED_TOO = {
    "brix_backend_async",
    "brix_backend_async_batch",
    "brix_backend_async_wait",
}

# DEFECT CANDIDATE #33: macro-born directives missing from the directive
# reference. See the module docstring.
UNDOCUMENTED = {
    "brix_cache_cold_store",
    "brix_cache_global_cas",
    "brix_cache_passthrough",
    "brix_cache_passthrough_max",
    "brix_backend_async",
    "brix_backend_async_batch",
    "brix_backend_async_wait",
}
DEFECT33 = ("DEFECT CANDIDATE #33 has changed: the set of macro-generated "
            "directives missing from docs/03-configuration/directives.md is no "
            "longer the pinned one. If they were documented, shrink "
            "UNDOCUMENTED; if a NEW tier directive shipped undocumented, "
            "document it rather than widening the pin.")

_FACTORY_RE = re.compile(r"^#define\s+([A-Z][A-Z0-9_]*)\s*\(\s*pfx\s*,", re.M)
_PASTED_RE = re.compile(r'ngx_string\(\s*pfx\s+"([a-z0-9_]+)"')
_SOURCE_SUFFIXES = (".c", ".h")


def _macro_body(text, name):
    """The full body of a line-continued `#define name(...)`, from the #define
    line through the first line that does not end in a backslash."""
    start = text.index("#define " + name + "(")
    body = []
    for line in text[start:].splitlines():
        body.append(line)
        if not line.rstrip().endswith("\\"):
            break
    return "\n".join(body)


def _suffixes(name):
    return _PASTED_RE.findall(_macro_body(TIER_HEADER.read_text(encoding="utf-8"),
                                          name))


def _call_sites(macro):
    """Every `MACRO("<prefix>"` invocation in src/, as (path, prefix) pairs.
    The definition's own doc comment shows the call shape, so skip the header
    that defines it."""
    pattern = re.compile(re.escape(macro) + r'\(\s*"([a-z0-9_]+)"')
    found = []
    for path in sorted(SRC.rglob("*")):
        if path.suffix not in _SOURCE_SUFFIXES or path == TIER_HEADER:
            continue
        for prefix in pattern.findall(path.read_text(encoding="utf-8",
                                                     errors="replace")):
            found.append((path.relative_to(REPO), prefix))
    return found


def _generated_names():
    names = set()
    for macro in sorted(KNOWN_FACTORIES):
        for _, prefix in _call_sites(macro):
            names.update(prefix + suffix for suffix in _suffixes(macro))
    return names


def _src_blob():
    return "\n".join(p.read_text(encoding="utf-8", errors="replace")
                     for p in SRC.rglob("*") if p.suffix in _SOURCE_SUFFIXES)


def _tests_blob():
    tests = Path(__file__).resolve().parent
    return "\n".join(p.read_text(encoding="utf-8", errors="replace")
                     for p in tests.rglob("*")
                     if p.is_file() and p.suffix in (".py", ".conf"))


def _mentions(blob, name):
    """A whole-name match: `brix_stage` must not be satisfied by the unrelated
    `brix_stage_dir`."""
    return re.search(re.escape(name) + r"(?![A-Za-z0-9_])", blob) is not None


# --------------------------------------------------------------------------- #
# 1. The factory inventory is closed                                           #
# --------------------------------------------------------------------------- #


def test_only_the_known_directive_factories_exist():
    """§E's growth risk, as a tripwire: any macro that pastes a prefix onto a
    directive name is a factory, and every name-based guard in the tree is
    blind to it."""
    factories = set()
    for path in sorted(SRC.rglob("*")):
        if path.suffix not in _SOURCE_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for name in _FACTORY_RE.findall(text):
            if _PASTED_RE.search(_macro_body(text, name)):
                factories.add(name)
    assert factories == KNOWN_FACTORIES, (
        "a new directive-factory macro appeared. Teach this file to expand it "
        "(and re-run the audit's directive measurement), or the directives it "
        f"generates are invisible to every name-based scan: {factories}")


def test_no_other_construct_pastes_a_directive_name_together():
    """The factories are macros taking a literal `pfx`. A directive name built
    any other way — a differently-named macro parameter, a token paste — would
    slip past the scan above, so pin that none exists."""
    stray = []
    for path in sorted(SRC.rglob("*")):
        if path.suffix not in _SOURCE_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r'ngx_string\(\s*([A-Za-z_][A-Za-z0-9_]*)\s+"',
                                 text):
            _guard_test_no_other_construct_pastes_a_directive_name_together_1(match, stray, path)
    # BRIX_SOURCE_URL builds the Server header, not a directive name.
    _check_test_no_other_construct_pastes_a_directive_name_together_1(stray)


def test_the_factories_are_invoked_only_with_the_brix_prefix():
    """Both planes take the same grammar under the same prefix — the parity
    guarantee tier_directives.h exists to make. A second prefix would mean a
    second, differently-named copy of the whole tier grammar."""
    sites = _call_sites("BRIX_TIER_DIRECTIVES")
    assert {prefix for _, prefix in sites} == {"brix_"}, sites
    planes = {path for path, _ in sites}
    assert CALL_SITE_HTTP.relative_to(REPO) in planes, planes
    assert CALL_SITE_STREAM.relative_to(REPO) in planes, planes


def test_the_generated_inventory_is_the_expected_size():
    tier, async_ = _suffixes("BRIX_TIER_DIRECTIVES"), \
        _suffixes("BRIX_BACKEND_ASYNC_DIRECTIVES")
    assert len(tier) == 17, tier
    assert len(async_) == 3, async_
    assert len(set(tier) & set(async_)) == 0, "a suffix belongs to one family"
    assert len(_generated_names()) == 20, sorted(_generated_names())


# --------------------------------------------------------------------------- #
# 2. The hole itself                                                           #
# --------------------------------------------------------------------------- #


def test_the_tier_grammar_is_invisible_to_a_literal_directive_scan():
    """The §E claim, pinned to the byte: 17 of the 20 generated directives have
    no `ngx_string("<name>")` anywhere in src/, so the scan the audit's §Method
    used — and every other name-based guard — reports them as nonexistent."""
    blob = _src_blob()
    visible, invisible = set(), set()
    for name in _generated_names():
        (visible if f'ngx_string("{name}")' in blob else invisible).add(name)
    assert visible == LITERALLY_DECLARED_TOO, (
        "the literal/macro-only split moved. A name that gained a literal "
        f"declaration is now double-declared; a name that lost one just went "
        f"invisible to every name-based guard. visible={sorted(visible)}")
    assert len(invisible) == 17, sorted(invisible)


def test_the_hand_maintained_call_site_comment_still_lists_every_directive():
    """http_common.c annotates its BRIX_TIER_DIRECTIVES call with the names it
    expands to — the only place in the tree a reader can see them. That list is
    hand-written, so it can drift the moment the macro grows."""
    text = CALL_SITE_HTTP.read_text(encoding="utf-8")
    comment = text[text.index("/* The tier directives:"):
                   text.index("BRIX_TIER_DIRECTIVES(")]
    listed = re.findall(r"brix_[a-z0-9_]+", comment)
    assert listed == ["brix_" + s for s in _suffixes("BRIX_TIER_DIRECTIVES")], (
        "the comment at the BRIX_TIER_DIRECTIVES call site no longer matches "
        f"the macro it documents: {listed}")


def test_the_documentation_gap_matches_the_macro_hole():
    """DEFECT CANDIDATE #33 — see the module docstring."""
    doc = DIRECTIVES_DOC.read_text(encoding="utf-8")
    missing = {n for n in _generated_names() if not _mentions(doc, n)}
    assert missing == UNDOCUMENTED, f"{DEFECT33}\nmissing={sorted(missing)}"


def test_every_generated_directive_is_exercised_by_the_test_corpus():
    """The audit's own closure condition, applied to the names it had to
    expand by hand: all 20 appear in a template or an inline config."""
    blob = _tests_blob()
    missing = sorted(n for n in _generated_names() if not _mentions(blob, n))
    assert missing == [], (
        "macro-generated directives with no mention anywhere under tests/. "
        "No name-based guard will ever notice, because they have no literal "
        f"declaration to scan for: {missing}")


# --------------------------------------------------------------------------- #
# 3. The invisible surface is live                                             #
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                    reason="nginx binary not built")
@pytest.mark.parametrize("directive,value", [
    ("brix_cache_only_if_cached", "on"),
    ("brix_cache_passthrough_max", "8m"),
])
def test_an_invisible_directive_parses_on_both_planes(tmp_path, directive,
                                                      value):
    """These names cannot be found by scanning src/ for their own string, yet
    both planes accept them today. Invisible AND dead would be harmless;
    invisible and live is the risk §E is describing."""
    assert directive in _generated_names(), directive
    assert f'ngx_string("{directive}")' not in _src_blob(), (
        f"{directive} gained a literal declaration; pick another macro-only "
        "name for this test")
    stream = tmp_path / "stream"
    stream.mkdir()
    rc, out = _parse_fail(stream, "nginx_rl_stream.conf",
                          _stream_values(f"        {directive} {value};\n", ""))
    assert rc == 0, out
    http = tmp_path / "http"
    http.mkdir()
    rc, out = _parse_fail(http, "nginx_rl_http.conf",
                          _http_values(f"            {directive} {value};\n"))
    assert rc == 0, out
