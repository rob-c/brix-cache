"""2.0 release-readiness pins for the directive surface (axes (b), (c), (d) of
the register in docs/10-reference/release-2.0-readiness.md).

Three things the register promised and this file keeps true:

* every directive the module REGISTERS is documented somewhere a user reads
  (``docs/`` outside ``refactor/``/``doxygen/`` and outside the generated
  registry table) — the pre-2.0 audit found 74 that were not;
* the six directives the audit found registered-and-consumed but never
  parsed by any test now have accept / reject / placement cases;
* ``brix_pss_dca`` — registered in 1.4/1.5 with no consumer — is gone from
  the source AND is refused by the binary as an unknown directive, so a
  configuration cannot keep believing it does something.

Parse tier only: ``nginx -t`` against tests/configs/nginx_audit16nparse.conf
(one slot per nginx scope, both planes; no server is started).  Run with
``TEST_SKIP_SERVER_SETUP=1`` when no fleet is wanted.
"""

from pathlib import Path
import re
import sys

import pytest

from config_parse import nginx_t

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"
DIRECTIVES_MD = DOCS / "03-configuration" / "directives.md"
REGISTER_MD = DOCS / "10-reference" / "release-2.0-readiness.md"
GENERATED_END = "<!-- END GENERATED DIRECTIVE REGISTRY -->"
SCAFFOLD = "nginx_audit16nparse.conf"
PARSE_PORT = 13297   # never bound: `nginx -t` only

SLOTS = ("LOC_KNOBS", "SRV_KNOBS", "HTTP_KNOBS", "OUTER",
         "STREAM_KNOBS", "STREAM_MAIN", "EXTRA_LOC")

pytestmark = [pytest.mark.timeout(120)]


def _render(tmp_path, **placed):
    (tmp_path / "logs").mkdir(exist_ok=True)
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    values = {slot: "" for slot in SLOTS}
    for slot, line in placed.items():
        values[slot] = f"        {line}\n"
    return nginx_t(SCAFFOLD, tmp_path, PORT=PARSE_PORT, STREAM_PORT=PARSE_PORT,
                   LOG_DIR=str(tmp_path / "logs"), DATA=str(data), **values)


def _assert_accepted(result, line):
    assert result.returncode == 0, f"{line!r} should parse:\n{result.stderr}"


def _assert_refused(result, line, *needles):
    assert result.returncode != 0, f"{line!r} should be refused"
    text = result.stderr + result.stdout
    assert any(n in text for n in needles), \
        f"{line!r}: expected one of {needles} in:\n{text}"


# (directive line, legal slot, illegal slot) — the illegal slot is the
# security-negative: a per-server or per-location knob must not be accepted
# one scope wider than declared, where it would silently apply to every
# export.  Cross-plane placements may read "unknown directive" because nginx
# skips the other plane's command tables before it checks context.
MISPLACED = ("is not allowed here", "unknown directive")

SIX = [
    # stream, NGX_STREAM_SRV_CONF only
    ("brix_auth_maxfail 3;", "STREAM_KNOBS", "STREAM_MAIN"),
    ("brix_dirstats on;", "STREAM_KNOBS", "LOC_KNOBS"),
    ("brix_durable_commit off;", "STREAM_KNOBS", "SRV_KNOBS"),
    # http
    ("brix_webdav_header2cgi X-Brix-Token authz;", "LOC_KNOBS", "STREAM_KNOBS"),
    ("brix_oci_delegate_realm brix-oci-test;", "LOC_KNOBS", "SRV_KNOBS"),
]

INVALID = [
    ("brix_auth_maxfail abc;", "STREAM_KNOBS", "invalid number"),
    ("brix_auth_maxfail -1;", "STREAM_KNOBS", "invalid number"),
    ("brix_dirstats maybe;", "STREAM_KNOBS", "invalid value"),
    ("brix_durable_commit 1;", "STREAM_KNOBS", "invalid value"),
    ("brix_webdav_header2cgi X-Only-One;", "LOC_KNOBS", "invalid number of arguments"),
    ("brix_oci_delegate_realm one two;", "LOC_KNOBS", "invalid number of arguments"),
]


@pytest.mark.parametrize("line,legal,_illegal", SIX, ids=[s[0].split()[0] for s in SIX])
def test_accepted_in_declared_scope(tmp_path, line, legal, _illegal):
    _assert_accepted(_render(tmp_path, **{legal: line}), line)


@pytest.mark.parametrize("line,_legal,illegal", SIX, ids=[s[0].split()[0] for s in SIX])
def test_refused_one_scope_wider(tmp_path, line, _legal, illegal):
    _assert_refused(_render(tmp_path, **{illegal: line}), line, *MISPLACED)


@pytest.mark.parametrize("line,slot,needle", INVALID, ids=[s[0] for s in INVALID])
def test_invalid_value_or_arity_refused(tmp_path, line, slot, needle):
    _assert_refused(_render(tmp_path, **{slot: line}), line, needle)


def test_header2cgi_inherits_from_every_http_scope(tmp_path):
    """MAIN|SRV|LOC: the same line must parse at each of the three levels."""
    line = "brix_webdav_header2cgi X-Brix-Token authz;"
    for slot in ("HTTP_KNOBS", "SRV_KNOBS", "LOC_KNOBS"):
        _assert_accepted(_render(tmp_path, **{slot: line}), f"{slot}: {line}")


REMOVED_IN_2_0 = (
    ("brix_pss_dca", "STREAM_KNOBS"),
    ("brix_backend_passthrough_persist", "LOC_KNOBS"),
    # F1 / ADR-3b (2026-09-08): the seven brix_frm_* knobs of the dissolved
    # in-process engine that no subsystem could honestly own; the other six
    # accepted-only names were wired (tests/test_release20_frm_knobs.py).
    ("brix_frm_copycmd", "STREAM_KNOBS"),
    ("brix_frm_migrate_copycmd", "STREAM_KNOBS"),
    ("brix_frm_residency_cmd", "STREAM_KNOBS"),
    ("brix_frm_xfrhold", "STREAM_KNOBS"),
    ("brix_frm_max_per_source", "STREAM_KNOBS"),
    ("brix_frm_stage_dir", "STREAM_KNOBS"),
    ("brix_frm_force_scratch", "STREAM_KNOBS"),
)

# Empty since F1: every directive that parses drives something.  Kept as the
# named contract so a future "accepted, no effect" knob must be declared here
# and labelled in the prose, never slipped in silently.
ACCEPTED_ONLY_IN_2_0: tuple = ()


@pytest.mark.parametrize("name,slot", REMOVED_IN_2_0, ids=[n for n, _ in REMOVED_IN_2_0])
def test_removed_directive_is_refused_as_unknown(tmp_path, name, slot):
    """Security-negative for every 2.0 removal: a 1.x configuration that still
    carries the name must fail `nginx -t` loudly, in the scope it used to be
    legal in, instead of loading with a knob that never did anything."""
    line = f"{name} on;"
    _assert_refused(_render(tmp_path, **{slot: line}), line, "unknown directive")


@pytest.mark.parametrize("name", [n for n, _ in REMOVED_IN_2_0])
def test_removed_directive_is_gone_from_source_and_registry(name):
    needle = name[len("brix_"):]
    hits = [p.relative_to(REPO).as_posix() for p in (REPO / "src").rglob("*.[ch]")
            if needle in p.read_text(errors="ignore")]
    assert not hits, f"{name} plumbing still present: {hits}"
    table = DIRECTIVES_MD.read_text(encoding="utf-8").split(GENERATED_END)[0]
    assert name not in table


def _registered_names():
    sys.path.insert(0, str(REPO / "tools" / "ci"))
    import check_directive_registry as registry   # noqa: E402
    return sorted({row[0] for row in registry.collect()})


def _user_docs_text():
    parts = [DIRECTIVES_MD.read_text(encoding="utf-8").split(GENERATED_END, 1)[1]]
    for path in DOCS.rglob("*.md"):
        rel = path.relative_to(DOCS).as_posix()
        if rel.startswith(("refactor/", "doxygen/")) or path == DIRECTIVES_MD:
            continue
        parts.append(path.read_text(encoding="utf-8", errors="ignore"))
    return "\n".join(parts)


def test_every_registered_directive_is_documented_for_users():
    """The generated registry table proves a name exists; a user needs prose.
    Every registered directive must be mentioned in docs/ outside that table."""
    text = _user_docs_text()
    missing = [n for n in _registered_names()
               if not re.search(r"\b" + re.escape(n) + r"\b", text)]
    assert not missing, f"{len(missing)} registered directive(s) with no user-facing prose: {missing}"


def test_register_names_every_removed_or_accepted_only_directive():
    """The register must own every directive it removed and every one that
    parses but drives nothing, so a reader of the 2.0 docs is never told a
    knob does more than it does."""
    text = REGISTER_MD.read_text(encoding="utf-8")
    for name in ACCEPTED_ONLY_IN_2_0 + tuple(n for n, _ in REMOVED_IN_2_0):
        assert name in text, f"{name} missing from the 2.0 readiness register"
    registered = set(_registered_names())
    assert set(ACCEPTED_ONLY_IN_2_0) <= registered, \
        sorted(set(ACCEPTED_ONLY_IN_2_0) - registered)
    assert not (set(n for n, _ in REMOVED_IN_2_0) & registered)


def _heading_names(section, name):
    head = section.split("\n", 1)[0]
    return head.startswith(("`" + name, name)) or any(
        tok in head for tok in (f"`{name} ", f"`{name}`"))


def _prose_sections_naming(name):
    prose = DIRECTIVES_MD.read_text(encoding="utf-8").split(GENERATED_END, 1)[1]
    return [s for s in prose.split("\n#### ") if _heading_names(s, name)]


@pytest.mark.parametrize("name", ACCEPTED_ONLY_IN_2_0 or ["<none>"])
def test_every_accepted_only_directive_is_labelled_in_the_prose(name):
    """A user reading directives.md must be told a knob is inert on the spot,
    not only in the register: the #### section naming it says so.  Vacuous
    while the set is empty (2.0 F1 wired or removed every inert knob)."""
    if name == "<none>":
        assert not ACCEPTED_ONLY_IN_2_0
        return
    sections = _prose_sections_naming(name)
    assert sections, f"{name} has no #### section of its own"
    assert any("Accepted, no effect" in s for s in sections), \
        f"{name} is documented without the 'Accepted, no effect' label"
