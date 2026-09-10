"""Release-2.0 surface pins: the audit's discoveries no other suite holds.

docs/10-reference/release-2.0-readiness.md records what the 2.0 audit found and
changed; tests/test_release20_directive_surface.py pins the per-directive facts
(scope, arity, the nine removals, the accepted-only labels, documented-for-users).
This module pins the rest, so nothing reverts silently or becomes a mystery:

* the whole (name, plane) directive surface shipped in 2.0 — snapshot in
  tests/golden/release20_directive_surface.tsv; a registration may vanish only
  through REMOVED_AFTER_2_0 plus a CHANGELOG line (additions are free);
* the nine names removed in 2.0 (two on 2026-09-05, seven brix_frm_* under
  ADR-3b on 2026-09-08) survive only as history: the register, the changelog,
  docs/refactor/, and comment lines of test configs;
* the accepted-only set — empty since F1 wired or removed the last thirteen —
  is stated identically by the register (the constant), the quick-reference
  blockquote (absent when empty) and the "Accepted, no effect" prose label
  (unused when empty), and the live purge trio never carries that label;
* the purge trio's documented defaults are the merge defaults of
  src/core/config/tape_stage_conf.c, serve-while-filling documents `0`;
* the generated directive table is current (drift reds the fast tier);
* the quick-reference names every cache-store scheme the prose documents;
* every tests/ and tools/ci path the register cites exists, and its census never
  exceeds the live registry.

The PROSE half — the comparison/gap ledger rows, the quick-reference and
operator-doc reachability sweeps, the per-item handle citations and the "Axis
(e) ... open:" status banners — moved to tests/test_release20_ledger_pins.py
when this module crossed the 600-logical-line cap; it imports `_live_rows` from
here, so the two share one view of the live registry.

Static: no nginx, no fleet, no ports.
"""
from __future__ import annotations

import re
import sys

import pytest

from test_release20_directive_surface import (
    ACCEPTED_ONLY_IN_2_0, DIRECTIVES_MD, DOCS, REGISTER_MD, REMOVED_IN_2_0, REPO,
)

sys.path.insert(0, str(REPO / "tools" / "ci"))
import check_directive_registry as registry        # noqa: E402
import generate_directive_reference as generator   # noqa: E402

pytestmark = [pytest.mark.timeout(120)]

GOLDEN = REPO / "tests" / "golden" / "release20_directive_surface.tsv"
CHANGELOG = REPO / "CHANGELOG.md"
QUICK_REFERENCE = DOCS / "03-configuration" / "quick-reference.md"
TAPE_STAGE_CONF = REPO / "src" / "core" / "config" / "tape_stage_conf.c"
QUIRKS = DOCS / "10-reference" / "quirks.md"
QCONFIG_C = REPO / "src" / "protocols" / "root" / "query" / "config.c"
PLANES = frozenset({"http", "stream"})
ACCEPTED_ONLY_LABEL = "Accepted, no effect"
QUICK_REFERENCE_LABEL = "> **Accepted, no effect in 2.0:**"

# A (name, plane) registration retired after 2.0 is listed here together with a
# CHANGELOG line — the only way test_every_2_0_registration_is_still_present lets
# it go.  Empty at 2.0.0.
REMOVED_AFTER_2_0: tuple[tuple[str, str], ...] = ()

# Where a name removed in 2.0 may still be written.
HISTORY_FILES = frozenset({CHANGELOG, REGISTER_MD})
HISTORY_DIRS = (DOCS / "refactor",)

# directive, merged fields in tape_stage_conf.c, documented default, merge value
PURGE_DEFAULTS = (
    ("brix_frm_purge_watermark", ("purge_hi_ppm", "purge_lo_ppm"), "unset", 0),
    ("brix_frm_purge_max_bytes", ("purge_max_bytes",), "`0`", 0),
    ("brix_frm_purge_interval", ("purge_interval_ms",), "`5m`", 5 * 60 * 1000),
)

HEADING = re.compile(r"^(#{1,6} .*)$", re.M)
MERGE = re.compile(r"ngx_conf_merge_(?:\w+_)?value\(conf->(\w+),\s*prev->\1,\s*(\d+)\)")
DOC_DEFAULT = re.compile(r"\*\*Default:\*\*\s*(`[^`]*`|\w+)")
CITED_PATH = re.compile(r"(?:tests/(?:golden/)?[\w./-]+\.(?:py|tsv|json)|tools/ci/[\w-]+\.py)")
CENSUS = re.compile(r"(\d+) registrations, (\d+) names")


# --- the directive surface snapshot ------------------------------------------

def _golden_rows():
    rows = set()
    for line in GOLDEN.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            name, plane = line.split("\t")
            rows.add((name, plane))
    return rows


def _live_rows():
    return {(row[0], row[1]) for row in registry.collect()}


def _lost_registrations(golden, live, retired):
    return golden - live - set(retired)


def test_golden_surface_snapshot_is_not_vacuous():
    rows = _golden_rows()
    names = {name for name, _ in rows}
    assert len(rows) >= 700 and {plane for _, plane in rows} <= PLANES
    assert names.isdisjoint(name for name, _ in REMOVED_IN_2_0)
    assert set(ACCEPTED_ONLY_IN_2_0) <= names


def test_every_2_0_registration_is_still_present():
    lost = _lost_registrations(_golden_rows(), _live_rows(), REMOVED_AFTER_2_0)
    assert not lost, \
        f"registered in 2.0, gone now, not in REMOVED_AFTER_2_0: {sorted(lost)}"


def test_retirement_after_2_0_is_explicit_and_logged():
    live, changelog = _live_rows(), CHANGELOG.read_text(encoding="utf-8")
    for name, plane in REMOVED_AFTER_2_0:
        assert (name, plane) not in live, f"{name} ({plane}) listed as retired but still registered"
        assert name in changelog, f"{name} retired without a CHANGELOG line"


def test_lost_registration_detector_reports_and_forgives():
    row = ("brix_x", "http")
    assert _lost_registrations({row}, set(), ()) == {row}
    assert not _lost_registrations({row}, {row}, ())
    assert not _lost_registrations({row}, set(), (row,))


# --- names removed in 2.0 survive only as history ----------------------------

def _is_history(path):
    return path in HISTORY_FILES or any(d in path.parents for d in HISTORY_DIRS)


def _scanned_files():
    yield REPO / "README.md"
    yield from DOCS.rglob("*.md")
    yield from (REPO / "contrib").rglob("*")
    yield from (REPO / "tests" / "configs").glob("*.conf")


def _stray_lines(text, name):
    """1-based lines that use `name` outside a `#` comment."""
    return [n for n, line in enumerate(text.splitlines(), 1)
            if name in line and not line.lstrip().startswith("#")]


def _stray_mentions(name):
    stray = []
    for path in _scanned_files():
        if _is_history(path) or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        stray += [f"{path.relative_to(REPO)}:{n}" for n in _stray_lines(text, name)]
    return stray


@pytest.mark.parametrize("name", [name for name, _ in REMOVED_IN_2_0])
def test_removed_name_survives_only_as_history(name):
    assert name in REGISTER_MD.read_text(encoding="utf-8")
    assert name in CHANGELOG.read_text(encoding="utf-8")
    assert _stray_mentions(name) == []


def test_stray_line_detector_sees_prose_and_ignores_comments():
    text = "# brix_pss_dca was removed in 2.0\nbrix_pss_dca on;\n  # brix_pss_dca\nsee brix_pss_dca\n"
    assert _stray_lines(text, "brix_pss_dca") == [2, 4]
    assert _stray_lines(text, "brix_other") == []


# --- the accepted-only set is stated once, three ways -------------------------

def _sections(text):
    """(heading, body) per heading of a markdown text; a body ends at ANY heading level."""
    parts = HEADING.split(text)
    return list(zip(parts[1::2], parts[2::2]))


def _quick_reference_accepted_only():
    for line in QUICK_REFERENCE.read_text(encoding="utf-8").splitlines():
        if line.startswith(QUICK_REFERENCE_LABEL):
            return set(re.findall(r"`(brix_\w+)`", line))
    return set()


def _labelled_accepted_only():
    labelled = set()
    for heading, body in _sections(DIRECTIVES_MD.read_text(encoding="utf-8")):
        if ACCEPTED_ONLY_LABEL in body:
            labelled |= set(re.findall(r"brix_\w+", heading))
    return labelled


def test_quick_reference_states_the_accepted_only_set():
    assert _quick_reference_accepted_only() == set(ACCEPTED_ONLY_IN_2_0)


def test_prose_labels_exactly_the_accepted_only_set():
    assert _labelled_accepted_only() == set(ACCEPTED_ONLY_IN_2_0)


def test_live_purge_family_is_never_labelled_accepted_only():
    # watermark / interval / max_bytes (phase-115 W3.2) + policy / polprog (2.0 F4)
    purge = {name for name, _ in _live_rows() if name.startswith("brix_frm_purge_")}
    assert len(purge) == 5, purge
    assert purge.isdisjoint(ACCEPTED_ONLY_IN_2_0)
    assert purge.isdisjoint(_labelled_accepted_only())
    assert purge.isdisjoint(_quick_reference_accepted_only())


def test_section_splitter_keeps_general_prose_apart_from_directives():
    text = ("### S3 STS (`brix_a`)\n\nlive\n\n## Chapter\n\nAccepted, no effect means inert.\n"
            "#### `brix_b <n>`\n\nlive\n\n### Notes\n\nAccepted, no effect means inert.\n")
    heads = [h for h, _ in _sections(text)]
    assert heads == ["### S3 STS (`brix_a`)", "## Chapter", "#### `brix_b <n>`", "### Notes"]
    bodies = dict(_sections(text))
    assert ACCEPTED_ONLY_LABEL not in bodies["### S3 STS (`brix_a`)"]
    assert ACCEPTED_ONLY_LABEL not in bodies["#### `brix_b <n>`"]


# --- documented defaults are the code defaults -------------------------------

def _merge_defaults():
    return {field: int(value)
            for field, value in MERGE.findall(TAPE_STAGE_CONF.read_text(encoding="utf-8"))}


def _documented_default(name):
    for heading, body in _sections(DIRECTIVES_MD.read_text(encoding="utf-8")):
        if name in heading:
            match = DOC_DEFAULT.search(body)
            return match.group(1) if match else None
    return None


@pytest.mark.parametrize("directive, fields, documented, merged", PURGE_DEFAULTS)
def test_purge_default_documented_is_the_merge_default(directive, fields, documented, merged):
    code = _merge_defaults()
    assert {field: code.get(field) for field in fields} == dict.fromkeys(fields, merged)
    assert _documented_default(directive) == documented


def test_serve_while_filling_documents_off_by_default():
    assert _documented_default("brix_cache_serve_while_filling") == "`0`"


def test_default_readers_are_not_vacuous():
    assert "purge_interval_ms" in _merge_defaults()
    assert _documented_default("brix_no_such_directive") is None
    assert MERGE.findall("ngx_conf_merge_value(conf->a, prev->b, 1);") == []


# --- the generated table, the quick-reference, the register -------------------

def test_generated_directive_table_is_current(capsys):
    assert generator.main(["--check"]) == 0, capsys.readouterr()


def test_quick_reference_names_every_cache_store_scheme_and_the_fill_knob():
    prose = set(re.findall(r"brix_cache_store (\w+):", DIRECTIVES_MD.read_text(encoding="utf-8")))
    quick_text = QUICK_REFERENCE.read_text(encoding="utf-8")
    quick = set(re.findall(r"brix_cache_store (\w+):", quick_text))
    assert {"posix", "ram"} <= prose and prose <= quick, (prose, quick)
    assert "brix_cache_serve_while_filling" in quick_text


def test_register_cites_only_evidence_that_exists():
    cited = set(CITED_PATH.findall(REGISTER_MD.read_text(encoding="utf-8")))
    assert len(cited) >= 10, cited
    missing = sorted(path for path in cited if not (REPO / path).exists())
    assert missing == []


def test_register_census_never_exceeds_the_live_registry():
    match = CENSUS.search(REGISTER_MD.read_text(encoding="utf-8"))
    assert match, "the register's guard table no longer states its census"
    live = _live_rows()
    assert len(live) + len(REMOVED_AFTER_2_0) >= int(match.group(1))
    assert len({name for name, _ in live}) + len(REMOVED_AFTER_2_0) >= int(match.group(2))


# --- axis (e): the 2.0 feature-completion plan --------------------------------
#
# The 2026-09-07 scope decision made (c.2) and the former 2.1 list into 2.0 work
# items F1..F15.  A plan nobody checks rots the way the health-check row rotted:
# it was still promising a missing /metrics family two phases after the family
# shipped.  These three pins keep the plan honest -- every partial row owns an
# item, the item numbering has no holes and no dangling reference, and no table
# row may quietly push work past the tag again.

PLAN_ROW = re.compile(r"^\| \*\*F(\d+)\*\* \|", re.M)
PLAN_REF = re.compile(r"\*\*F(\d+)\*\*")
DEFERRAL_PHRASES = ("not in 2.0", "Optional for 2.1", "Decision for 2.1")


def _register_tables():
    """Every markdown table row of the register, header and rule lines dropped."""
    rows = []
    for line in REGISTER_MD.read_text(encoding="utf-8").splitlines():
        if line.startswith("|") and not set(line) <= set("|- "):
            rows.append(line)
    return rows


def _c2_rows():
    text = REGISTER_MD.read_text(encoding="utf-8")
    # Stop at ANY heading level: a "\n## " split runs past the sibling
    # "### (c.3)" and swallows its table, so its rows arrive here as
    # orphan (c.2) rows.
    section = re.split(r"\n#{1,6} ", text.split("### (c.2)", 1)[1], maxsplit=1)[0]
    return [ln for ln in section.splitlines()
            if ln.startswith("| ") and "| ---" not in ln and not ln.startswith("| Feature |")]


def test_the_completion_plan_is_contiguous_and_has_no_dangling_reference():
    """F-numbers are the only handle the (c.2) rows and the 'Remaining' table
    have on the plan, so a gap or a typo silently orphans a partial feature."""
    text = REGISTER_MD.read_text(encoding="utf-8")
    planned = [int(n) for n in PLAN_ROW.findall(text)]
    assert planned == sorted(set(planned)), planned
    assert planned == list(range(1, len(planned) + 1)), planned
    assert len(planned) >= 15, planned
    dangling = sorted({int(n) for n in PLAN_REF.findall(text)} - set(planned))
    assert dangling == [], f"referenced but not planned: F{dangling}"


def test_every_partial_by_design_row_names_a_completion_item():
    """(c.2) is now a work list: a row without an item is a feature that would
    ship partial under a register claiming 2.0 is feature complete."""
    rows = _c2_rows()
    assert len(rows) >= 7, rows
    orphans = [r.split("|")[1].strip() for r in rows if not PLAN_REF.search(r)]
    assert orphans == [], orphans


def test_no_table_row_defers_work_past_2_0():
    """The scope decision's teeth.  Prose may describe the ban; a table row that
    dispositions work as 'not in 2.0' or 'for 2.1' re-opens the deferral."""
    guilty = [row for row in _register_tables()
              if any(phrase in row for phrase in DEFERRAL_PHRASES)]
    assert guilty == [], guilty


def test_the_deferral_pin_is_not_vacuous():
    assert _register_tables() and _c2_rows()
    assert PLAN_REF.search("closed by **F3**")
    assert not PLAN_ROW.search("| F3 | not a plan row |")
    assert any(phrase in "was not in 2.0" for phrase in DEFERRAL_PHRASES)


# --- the Qconfig key inventory the client-facing quirks page promises --------
#
# The `caps` bullet in quirks.md had drifted: it said `version`/`role`/
# `sitename` are never answered, which stopped being true when they were given
# emitters and a `public_safe` column instead.  A reader debugging a `=0` was
# told to expect the opposite of what the server does.  Nothing checked the
# prose against the table, so tie them together.


def _qconfig_keys() -> list[str]:
    """Every key in brix_qconfig_table, in table order."""
    body = QCONFIG_C.read_text().split("brix_qconfig_table[] = {")[1].split("\n};")[0]
    return re.findall(r'^\s*\{\s*"([a-z0-9_.]+)"', body, re.M)


def _caps_bullet() -> str:
    text = QUIRKS.read_text()
    start = text.index("- **`caps` `=0` is ambiguous.**")
    return text[start:text.index("\n- ", start)]


def test_the_caps_bullet_names_every_key_the_server_answers():
    keys = _qconfig_keys()
    assert len(keys) > 10, "could not parse the Qconfig table"
    bullet = _caps_bullet()
    missing = [k for k in keys if f"`{k}`" not in bullet]
    assert not missing, f"quirks.md `caps` bullet omits answered keys: {missing}"


def test_the_caps_bullet_states_the_public_gateway_exception():
    """A `=0` means two different things; the bullet must say which is which."""
    bullet = _caps_bullet()
    assert "brix_read_only_public" in bullet
    withheld = re.findall(r'^\s*\{\s*"([a-z0-9_.]+)".*,\s*0\s*\},\s*$',
                          QCONFIG_C.read_text().split("brix_qconfig_table[] = {")[1]
                          .split("\n};")[0], re.M)
    assert withheld, "no withheld key parsed — the public_safe column moved"
    for key in withheld:
        assert f"`{key}`" in bullet, f"{key} is withheld but the bullet omits it"


def _help_lines_quoted_in(page):
    """(page name, family, text) for every `# HELP` line a doc page pastes in."""
    for line in page.read_text(encoding="utf-8").splitlines():
        if line.startswith("# HELP "):
            _, _, family, text = line.split(" ", 3)
            yield page.name, family, text.strip()


def _quoted_help_pairs():
    """Every HELP line quoted anywhere under docs/08-metrics-monitoring/."""
    for page in sorted((DOCS / "08-metrics-monitoring").glob("*.md")):
        yield from _help_lines_quoted_in(page)


def _stale_help_quotes(exported):
    """(quotes of a known family, those whose text no longer matches)."""
    quotes = [row for row in _quoted_help_pairs() if row[1] in exported]
    stale = [f"{name}: {fam}\n  doc: {text}\n  exporter: {exported[fam]}"
             for name, fam, text in quotes if text != exported[fam]]
    return quotes, stale


def _family_index_rows(section: str) -> dict:
    """family -> (type, HELP) parsed out of the Complete Family Index tables."""
    rows = re.findall(r"^\| `([a-z0-9_]+)` \| (counter|gauge|histogram) \| (.+?) \|$",
                      section, re.M)
    return {fam: (kind, text.strip()) for fam, kind, text in rows}

def test_every_help_line_quoted_in_the_docs_matches_the_exporter():
    """Operator docs paste sample scrapes; a reworded HELP leaves them lying.

    `brix_cache_occupancy_ratio` and `brix_cache_bytes` gained store-aware HELP
    text when the RAM tier landed, and the sample scrape in metrics-overview.md
    still carried the pre-2.0 "Filesystem occupancy ratio" wording — a reader
    diffing their own scrape against the doc would have concluded the build was
    wrong. `_cachemx_catalog_data.HELP` is the calibrated exporter text
    (tests/test_cachemx_help_text.py pins it against a live scrape), so the docs
    are checked against the same constant, not against a second transcription.
    """
    from _cachemx_catalog_data import HELP

    quotes, stale = _stale_help_quotes(HELP)
    assert len(quotes) > 10, f"only {len(quotes)} HELP lines — did the docs move?"
    assert not stale, "docs quote stale HELP text:\n" + "\n".join(stale)


def test_the_family_reference_covers_every_exported_family():
    """A family nobody documented is a family nobody can alert on.

    23 exported families were named in no user-facing page at all — the whole
    runtime-DNS cache group, the storage-export gauges, the watermark reaper
    trio, the write-through staging gauges, the mirror error counter and the
    rate-limit zone-health pair. The "Complete Family Index" section of
    metrics-overview.md answers for all of them, generated from the same
    calibrated catalogue the conformance suite pins against a live scrape, so
    the next family cannot ship undocumented.
    """
    from _cachemx_catalog_data import HELP
    from test_cachemx_catalog import CATALOG

    overview = (DOCS / "08-metrics-monitoring" / "metrics-overview.md").read_text(
        encoding="utf-8")
    assert "## Complete Family Index" in overview, "the family index section moved"
    page = overview.split("## Complete Family Index", 1)[1].split("## Next Steps")[0]
    rows = _family_index_rows(page)
    assert len(CATALOG) > 200, "the catalogue shrank — check the import"
    assert not sorted(set(CATALOG) - set(rows)), (
        f"the family index never lists: {sorted(set(CATALOG) - set(rows))}")
    assert not sorted(set(rows) - set(CATALOG)), (
        f"the family index lists retired families: {sorted(set(rows) - set(CATALOG))}")
    drifted = [f"{fam}: index says ({kind!r}, {text!r})"
               for fam, (kind, text) in sorted(rows.items())
               if (kind, text) != (CATALOG[fam], HELP[fam])]
    assert not drifted, "the family index drifted from the exporter:\n" + "\n".join(drifted)

