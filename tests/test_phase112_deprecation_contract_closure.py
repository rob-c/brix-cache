"""Phase-112 second wave: the deprecation-window CONTRACT, pinned.

`test_phase112_compatibility_closure.py` pins what the removal work discovered
about the surfaces themselves. This file pins the machinery that is supposed to
make the next removal happen on time — the part phase 112 armed and then, by
succeeding, emptied.

Phase 112 leaves three self-deleting pins behind: R14 (a deprecated variable
alias outliving its removal phase), R15 (a deprecated JSON access-log key
outliving its removal phase) and M2 (a deprecated Prometheus family outliving
its removal phase). All three are *dormant by design* and all three decide
whether to wake up by running a regular expression over English prose in
`docs/refactor/phase-<N>-*.md`. That design has three properties no assertion
held before this file:

  * compatibility — the trigger matches `**Status:** IMPLEMENTED` and nothing
                    else. `**Status**: IMPLEMENTED`, `Status: IMPLEMENTED` and
                    a status table cell all fail to match, and a pin that
                    fails to match reports NOTHING. Rewording one heading
                    disarms R14, R15 and M2 simultaneously, in silence, with
                    every guard still green — the one failure mode a
                    self-deleting pin cannot detect about itself.
  * compatibility — the trigger is written out TWICE, by hand, in two guards
                    that never import each other. Editing one copy disarms the
                    pins asymmetrically (the same drift class as phase-107's
                    two mutation-label tables).
  * security     — phase 112 emptied both removal registries: the allowlist
                    has no `removal:` row left and `DEPRECATED_METRICS` is
                    `{}`. R14 and M2 are therefore green because they have
                    nothing to look at, which is indistinguishable, from the
                    CI log, from green because they work. Two anti-vacuity
                    fixtures drive R14 and R15 from both sides so the rules
                    are proven live rather than merely quiet.

It also pins the two obligations the removal itself owes and that no code
carries: every one of the eleven deleted families is absent from the
exposition (only the latency histogram was pinned before), no `DEPRECATED`
notice survives in an emitted HELP line (such a notice re-advertises the dead
name to every scraper), and the release note carries the migration table —
which for the Group C families, whose deprecation window was announced but
never actually served, is the *sole* mitigation the phase accepted.

Run:
    PYTHONPATH=tests pytest tests/test_phase112_deprecation_contract_closure.py -v
"""

from __future__ import annotations

import importlib.util as _ilu
import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.xdist_group("phase112-closure")]

ROOT = Path(__file__).resolve().parent.parent
CI = ROOT / "tools" / "ci"
METRICS = ROOT / "src" / "observability" / "metrics"

# The phase whose doc arms all three pins, spelled as the guards spell it.
PHASE = "phase-112"

# W4's census: eleven families, four canonical replacements.
REMOVED_FAMILIES = (
    "brix_io_latency_usec",
    "brix_webdav_bytes_tx_total", "brix_s3_bytes_tx_total",
    "brix_bytes_tx_total", "brix_bytes_root_tx_total",
    "brix_webdav_bytes_rx_total", "brix_s3_bytes_rx_total",
    "brix_bytes_rx_total", "brix_bytes_root_rx_total",
    "brix_cache_hits_total", "brix_cache_misses_total",
)
CANONICAL_FAMILIES = ("brix_io_latency_seconds", "brix_io_bytes_read",
                      "brix_io_bytes_written", "brix_cache_requests_total")

# Spellings a reasonable author would consider equivalent to the live one.
# The trigger tolerates whitespace between the bolded label and the word —
# including a line break, so a wrapped status line still arms the pins — and
# letter case, but it tolerates no change to the punctuation of the label and
# the label must OPEN a line.
STATUS_STILL_ARMS = ("**Status:** IMPLEMENTED", "**Status:**\nIMPLEMENTED",
                     "**status:**   implemented",
                     "intro\n\n**Status:** IMPLEMENTED — and a trailing clause")
STATUS_SILENTLY_DISARMS = ("**Status**: IMPLEMENTED", "Status: IMPLEMENTED",
                           "| Status | IMPLEMENTED |",
                           "**Status:** _IMPLEMENTED_",
                           "the pin keys off `**Status:** IMPLEMENTED` in the doc")


def _load(name, rel):
    """Import a guard by path. Guards are scripts, not a package; loading one
    under its own module name keeps `main()` unexecuted."""
    spec = _ilu.spec_from_file_location(name, CI / rel)
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


W5 = _load("_w5_guard", "directive_registry_w5.py")
MN = _load("_metric_naming_guard", "check_metric_naming.py")


def _strip(text):
    """C source with comments removed — a comment naming a dead family is
    documentation, not exposition."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def _plant_access_log(base: Path, body: str) -> Path:
    """A stand-in access_log.c under a fake ROOT, at the path R15 reads."""
    path = base / "src" / "observability" / "metrics" / "access_log.c"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return path


def _r15_against(monkeypatch, base: Path, body: str):
    """Run R15 over a planted emitter, leaving the real refactor docs in place
    so the phase genuinely reads as IMPLEMENTED."""
    _plant_access_log(base, body)
    monkeypatch.setattr(W5, "ROOT", str(base))
    return W5._rule_r15()


def _emitted_families():
    return MN._emitted_families()


def _exposition_sources():
    return sorted(METRICS.glob("*.c"))


def _emitted_deprecation_notices():
    """Files whose EMITTED text (comments removed) still carries the word
    DEPRECATED — i.e. a notice a scraper would read, not one a developer
    would."""
    return [p.name for p in _exposition_sources()
            if "DEPRECATED" in _strip(p.read_text())]


def _changelog_breaking():
    """The `### Breaking` block of the `## Unreleased` section, or ""."""
    text = (ROOT / "CHANGELOG.md").read_text()
    unreleased = re.search(r"\n## Unreleased\n(.*?)(?=\n## )", text, re.S)
    if unreleased is None:
        return ""
    block = re.search(r"\n### Breaking\n(.*?)(?=\n### |\Z)",
                      unreleased.group(1), re.S)
    return block.group(1) if block else ""


# ---------------------------------------------------------------------------
# the trigger — one regex over prose, arming three pins
# ---------------------------------------------------------------------------


def test_the_three_pins_still_read_the_status_line_the_doc_actually_writes():
    """(compatibility) R14, R15 and M2 all decide whether to fire by searching
    a phase doc for `**Status:** IMPLEMENTED`. Nothing else in the repo depends
    on how that heading is punctuated, so a later editor may reasonably
    normalise it — and the failure is silent in both directions: the pins go
    dormant, every guard stays green, and the deprecated surface they were
    holding to a deadline simply never gets one again. This asserts the live
    doc still trips both guards TODAY, and records which reformattings survive
    (whitespace, including a line break; letter case) and which disarm the pins
    (any change to the punctuation of the bolded label, or moving it off the
    start of a line), so anyone normalising the heading is told to change the
    two regexes with it."""
    assert W5._phase_is_implemented(PHASE), (
        f"{PHASE}'s doc no longer reads as IMPLEMENTED to directive_registry_w5"
        " — R14 and R15 have gone dormant and will report nothing")
    assert MN._phase_is_implemented(PHASE), (
        f"{PHASE}'s doc no longer reads as IMPLEMENTED to check_metric_naming"
        " — M2 has gone dormant and will report nothing")
    for spelling in STATUS_STILL_ARMS:
        assert W5._IMPLEMENTED_RE.search(spelling), (
            f"the trigger no longer matches {spelling!r}; it has been tightened "
            "and phase docs written the old way have gone dormant")
    for spelling in STATUS_SILENTLY_DISARMS:
        assert W5._IMPLEMENTED_RE.search(spelling) is None, (
            f"the trigger now also matches {spelling!r}; this test's premise "
            "(that the match is exact) is stale — re-check what else it matches")


def test_both_guards_spell_the_implemented_trigger_identically():
    """(compatibility, drift) `_IMPLEMENTED_RE` is written out by hand in
    `directive_registry_w5.py` and again in `check_metric_naming.py`; the two
    guards never import each other, so nothing makes them agree. Tightening one
    copy disarms its pins while the other keeps firing, which reads as "the
    variable pins work and the metric pin is broken" rather than as drift."""
    assert W5._IMPLEMENTED_RE.pattern == MN._IMPLEMENTED_RE.pattern, (
        "the two hand-written IMPLEMENTED triggers have drifted:\n"
        f"  directive_registry_w5: {W5._IMPLEMENTED_RE.pattern!r}\n"
        f"  check_metric_naming:   {MN._IMPLEMENTED_RE.pattern!r}")
    assert W5._IMPLEMENTED_RE.flags == MN._IMPLEMENTED_RE.flags, (
        "the two triggers compile with different flags — one is case-sensitive")


def test_a_doc_that_only_quotes_the_trigger_leaves_the_pins_dormant(tmp_path,
                                                                    monkeypatch):
    """(security-neg) Found while pinning the trigger: phase 112's own W6
    section EXPLAINS the pin by quoting `**Status:** IMPLEMENTED` in a
    sentence, so the doc matched the trigger twice — once as its status
    heading and once as prose about the mechanism. Unanchored, any phase doc
    that documents this machinery arms it from its first PLANNED draft: R14,
    R15 and M2 all fire on the very commit that opens the deprecation window,
    demanding the removal of a surface that was deprecated seconds ago. The
    trigger is therefore anchored to the start of a line; a quoted mention,
    which is always indented or mid-sentence, no longer counts as a status."""
    planned = tmp_path / "phase-999-a-planned-phase.md"
    planned.write_text(
        "# Phase 999\n\n**Status:** PLANNED\n\n"
        "R15 fires once this doc says `**Status:** IMPLEMENTED`.\n")
    for guard, attr in ((W5, "_REFACTOR_DOCS"), (MN, "REFACTOR_DOCS")):
        monkeypatch.setattr(guard, attr, str(tmp_path))
        assert not guard._phase_is_implemented("phase-999"), (
            f"{guard.__name__} reads a PLANNED doc as IMPLEMENTED because it "
            "quotes the trigger — every pin it owns fires a whole deprecation "
            "window early")
    planned.write_text("# Phase 999\n\n**Status:** IMPLEMENTED\n")
    for guard in (W5, MN):
        assert guard._phase_is_implemented("phase-999"), (
            f"{guard.__name__} no longer recognises a real status heading — "
            "the anchoring has been tightened past the form docs use")


# ---------------------------------------------------------------------------
# anti-vacuity — the pins phase 112 emptied
# ---------------------------------------------------------------------------


def test_the_json_key_pin_fires_on_a_key_that_comes_back(monkeypatch, tmp_path):
    """(security-neg, anti-vacuity) R15 is the only one of the three pins with
    a non-empty registry left, so it alone can still fail a build — and it has
    never actually failed one, because the keys were already gone when it was
    armed. A rule that has only ever returned `[]` is untested. This plants an
    emitter that re-adds `from_cache` and requires R15 to name it."""
    assert W5._R15_REMOVED_JSON_KEYS, (
        "R15's key registry is empty — the last pin with anything to watch has "
        "become vacuous, and no guard would notice a deprecated key returning")
    findings = _r15_against(
        monkeypatch, tmp_path,
        r'"\"from_cache\":%s,\"bytes_served\":%O"')
    assert [rule for rule, _where, _msg in findings] == ["R15"], (
        "R15 stayed silent while a removed JSON key was emitted and its "
        f"removal phase ({PHASE}) reads IMPLEMENTED: {findings}")


def test_the_json_key_pin_ignores_the_canonical_key_it_lives_next_to(
        monkeypatch, tmp_path):
    """(compatibility) `bytes` is a prefix of its own replacement
    `bytes_served`, and `sub` — the replacement for `subject` — is a prefix of
    `subject` in the other direction. The registry therefore stores each key in
    KEY POSITION, escaped quotes and colon included (`\\"bytes\\":`), not as a
    bare word; a registry of bare names fires forever on the correct record,
    which reads as "the removal did not take" and invites putting the key
    back. R13 keeps the identical discipline on the presence side for the same
    reason."""
    findings = _r15_against(
        monkeypatch, tmp_path,
        r'"\"bytes_served\":%O,\"sub\":%s,\"cache_status\":%s,'
        r'\"backend_time_us\":%d"')
    assert findings == [], (
        "R15 fired on the canonical record — a removed key is being matched as "
        f"a prefix of its own replacement: {findings}")


def test_the_alias_pin_fires_only_once_the_window_has_closed():
    """(security-neg, anti-vacuity) Phase 112 deleted the last `removal:` row
    from the allowlist, so R14 now passes over an empty registry — green
    because there is nothing to check. Drive it directly from both sides: a
    registered alias whose removal phase is IMPLEMENTED must be reported, and
    the same alias with an open window (or already unregistered) must not, or
    the rule would either sleep through the next removal or block the next
    deprecation window from ever opening."""
    variables = [("brix_session_dn", "src/core/http/http_variables.c")]
    overdue = W5._rule_r14(variables, {"brix_session_dn": f"removal: {PHASE}"})
    assert [rule for rule, _name, _msg in overdue] == ["R14"], (
        "R14 stayed silent on an alias registered past its removal phase: "
        f"{overdue}")
    assert W5._rule_r14(variables,
                        {"brix_session_dn": "removal: phase-999"}) == [], (
        "R14 fired while the deprecation window was still open — no alias "
        "could ever be deprecated without failing CI on the same commit")
    assert W5._rule_r14([], {"brix_session_dn": f"removal: {PHASE}"}) == [], (
        "R14 fired for an alias nobody registers — the removal it demands has "
        "already happened")


# ---------------------------------------------------------------------------
# the removal's own obligations
# ---------------------------------------------------------------------------


def _present_removed_families(emitted):
    return [family for family in REMOVED_FAMILIES if family in emitted]


def _absent_canonical_families(emitted):
    return [family for family in CANONICAL_FAMILIES if family not in emitted]


def test_every_removed_metric_family_is_gone_from_the_exposition():
    """(feature) Only `brix_io_latency_usec` was pinned absent; the other ten
    were verified once, by hand, at removal time. The check has to run against
    what the EXPORTER declares rather than against the source text, because
    eight of the eleven were emitted through `SRV_COUNTER_HDR` macros that
    assemble their HELP line at compile time — a family can be perfectly
    invisible to a grep for `# HELP` and still land in a scrape."""
    emitted = _emitted_families()
    back = _present_removed_families(emitted)
    assert back == [], f"removed metric families are emitted again: {back}"
    missing = _absent_canonical_families(emitted)
    assert missing == [], (
        "a canonical replacement is not emitted, so the removed families' "
        f"facts are now exposed by nothing: {missing}")


def test_no_deprecation_notice_survives_in_the_exposition():
    """(compatibility) The eight Group B byte counters shipped in v1.5.0 with
    `# DEPRECATED` in their HELP text. That notice is itself a compatibility
    surface: it is served to every scraper, names the dead family, and outlives
    the series it annotates if a header string is kept "for the note". A
    surviving notice means either a family came back or the exporter is
    advertising a name it no longer emits."""
    offenders = _emitted_deprecation_notices()
    assert offenders == [], (
        "an emitted exposition string still carries a DEPRECATED notice "
        f"(comments excluded): {offenders}")


def test_the_release_note_carries_the_migration_the_unserved_window_owes():
    """(compatibility, release) Phase 110 rule 5 says a surface gets a served
    deprecation window before removal. The Group C families — the µs latency
    histogram, the cache hit/miss pair, the four JSON keys and the four cache
    variables — never got one: they were announced as deprecated in a release
    that shipped no replacement. The phase accepted that deviation on the
    stated grounds that the obligation it creates is editorial rather than
    technical, i.e. discharged by the CHANGELOG and by nothing else. Nothing
    in CI held the editorial half, which is the half that can quietly not
    happen."""
    breaking = _changelog_breaking()
    assert breaking, (
        "CHANGELOG.md has no `### Breaking` block under `## Unreleased` — the "
        "only mitigation phase 112 offered for the unserved window is missing")
    for surface in ("brix_session_dn", "$brix_cache_status", "from_cache",
                    "latency_us", "brix_io_bytes_read",
                    "brix_cache_requests_total", "brix_io_latency_seconds"):
        assert surface in breaking, (
            f"the migration table does not mention {surface}; an operator "
            "reading only the release note cannot complete the migration")
    assert re.search(r"now seconds", breaking), (
        "the release note does not state the latency UNIT change — a recording "
        "rule ported by name alone is wrong by a factor of 10^6")
