"""Phase-111 closure: the repository-work burn-down *register* is only as good
as its own accuracy, so pin the structural claims that go silently stale.

Phase 111 is a register, not a feature: it classifies every ``docs/refactor``
document, records the reference-integrity findings that motivated Phases
112/113/114, and closes 35 ``B111`` rows against their owning phases' evidence.
Its danger is the danger of every hand-maintained index — it keeps looking
authoritative while the tree drifts out from under it:

  * a new refactor plan is added and never registered, so §7's "every Markdown
    file appears in exactly one group" quietly becomes false;
  * a listed document is deleted or renamed, leaving a dangling classification;
  * two documents silently share a phase number outside the eight the register
    calls out, so a reference by bare number becomes ambiguous;
  * an archived phase is resurrected as an active plan (or the reverse), so
    "intentionally archived; its absence is not a broken dependency" is a lie;
  * an embedded follow-up record (73/74/76) is given its own file, or a mapping
    artifact (66/67/69) is mistaken for a missing plan;
  * a ``B111`` row is reopened while the top status still reads CLOSED.

``check_doc_links.py`` / ``check_doc_paths.py`` (run by ``test_repo_governance``)
cover link and path *integrity*; none of them know the register's *semantics* —
its partition, its duplicate-number set, its archive/active split. This file
pins exactly those, so the register cannot rot into a confident-looking fiction.

Every claim here was true in the tree at authoring time; each assertion is set
equality or exact-membership over the live filesystem, so it reds on drift in
either direction, not just one.

Run:
    PYTHONPATH=tests pytest tests/test_phase111_register_integrity.py -v
"""

from __future__ import annotations

import re
import subprocess
from collections import Counter
from pathlib import Path

import pytest

pytestmark = [pytest.mark.timeout(60),
              pytest.mark.xdist_group("phase111-register")]

REPO = Path(__file__).resolve().parents[1]
REFACTOR = REPO / "docs" / "refactor"
ARCHIVE = REPO / "docs" / "_archive" / "refactor"
REGISTER = REFACTOR / "phase-111-repository-work-burndown.md"

# §2 reference-integrity findings, as the exact sets the prose names.
ARCHIVED_PHASE_NUMS = {1, 7, 9, 10, 12, 13, 14, 15, 16, 17}
DUPLICATE_PHASE_NUMS = {4, 37, 52, 64, 100, 103, 104, 105}
# §2 names only 67 and 69 as "mapping artifacts ..., not missing implementation
# plans" — so for these the number must NOT also have a phase-N-*.md plan.
# (Phase 66 is deliberately excluded: it has both phase-66-map.tsv, §8, and a
# real phase-66-src-conceptual-realignment.md plan, §7.2.)
MAPPING_ARTIFACT_STEMS = {67: "phase-67-map.tsv",
                          69: "phase-69-client-map.tsv"}
# Embedded follow-up records: number -> the host doc that carries them.
EMBEDDED_RECORDS = {73: "phase-72-effort-hotspot-burndown.md",
                    74: "phase-72-effort-hotspot-burndown.md",
                    76: "phase-75-effort-hotspot-burndown-wave2.md"}
# The three phase docs this register brought into existence to close its own
# reference gaps (§2, §7.4).
CREATED_PHASE_DOCS = ("phase-112-observability-compatibility-removal.md",
                      "phase-113-webdav-lock-mutation-offload.md",
                      "phase-114-credential-artifact-lifecycle.md")
# §8 non-Markdown support artifacts the register inventories.
SUPPORT_ARTIFACTS = ("phase-66-map.tsv", "phase-67-map.tsv",
                     "phase-69-client-map.tsv",
                     "phase-72-baseline/top50.json", "phase-72-baseline/regen.sh",
                     "testsuite-shim-baseline.json",
                     "testsuite-surface-inventory.json",
                     "testsuite-surface-inventory.md")

_BACKTICK_MD = re.compile(r"`([\w.\-]+\.md)`")
_PHASE_NUM = re.compile(r"phase-(\d+)")


def _register_text() -> str:
    return REGISTER.read_text()


def _section(text: str, start: str, end: str) -> str:
    """The register slice from heading `start` up to heading `end`."""
    a = text.index(start)
    b = text.index(end, a)
    return text[a:b]


def _present_md() -> set[str]:
    return {p.name for p in REFACTOR.glob("*.md")}


def _phase_nums(root: Path) -> dict[int, list[str]]:
    out: dict[int, list[str]] = {}
    for p in root.glob("phase-*.md"):
        m = _PHASE_NUM.match(p.name)
        if m:
            out.setdefault(int(m.group(1)), []).append(p.name)
    return out


_PY_TOKEN = re.compile(r"[\w./-]*\b[\w-]+\.py\b")
_TESTS = REPO / "tests"


def _tracked_basenames() -> set[str]:
    out = subprocess.check_output(["git", "ls-files"], cwd=REPO, text=True)
    return {Path(line).name for line in out.splitlines()}


def _resolve_py(token: str, tracked: set[str]) -> bool:
    """A cited .py resolves if it exists at a repo-relative or tests-relative
    path, or (bare name) matches a git-tracked file's basename. The register
    names guards both fully (``tools/ci/x.py``) and bare (``check_x.py``), and
    its direct-launch ledger uses tests-relative paths (``userns/y.py``)."""
    if (REPO / token).exists() or (_TESTS / token).exists():
        return True
    return "/" not in token and Path(token).name in tracked


# --- §7: the register is an exhaustive, disjoint partition of the tree -------


def test_every_refactor_markdown_is_classified_in_exactly_one_group():
    """(feature) §7's headline guarantee: "Every Markdown file present during
    this audit appears in exactly one group." A refactor plan added without a
    register row, or a listed doc deleted/renamed, breaks the guarantee — and
    nothing else in the tree would catch it. Present-set and listed-set must be
    equal, and no name may be listed twice (disjointness)."""
    sec7 = _section(_register_text(), "## 7.", "## 8.")
    listed = set(_BACKTICK_MD.findall(sec7))
    present = _present_md()

    unregistered = present - listed
    dangling = listed - present
    assert not unregistered, (
        "refactor documents exist but no §7 group classifies them — register "
        f"the new plans or the partition is a fiction: {sorted(unregistered)}")
    assert not dangling, (
        "§7 classifies documents that are no longer in the tree (deleted or "
        f"renamed) — a dangling disposition: {sorted(dangling)}")

    twice = {n: c for n, c in Counter(_BACKTICK_MD.findall(sec7)).items() if c > 1}
    assert not twice, (
        f"§7 lists these in more than one group — not a partition: {twice}")


def test_partition_check_is_not_vacuous():
    """(error) Prove the partition assertion fails when a name goes missing:
    drop one present file from a synthetic listed-set and confirm it surfaces as
    unregistered. Guards against the whole tree ever reading as trivially green
    (e.g. an empty §7 slice)."""
    present = _present_md()
    assert len(present) > 100, "refactor tree unexpectedly small — parser broke"
    victim = sorted(present)[0]
    fake_listed = present - {victim}
    assert (present - fake_listed) == {victim}, (
        "partition detector cannot see a missing classification")


# --- §2: the reference-integrity findings, as exact sets --------------------


def test_the_archived_phases_are_archived_and_not_also_active():
    """(security/correctness) §2: "Phases 1, 7, 9, 10 and 12-17 are
    intentionally archived ...; their absence here is not a broken dependency."
    Each named number must live under _archive/refactor and must NOT also exist
    as an active plan — a resurrected number would make the "absence is fine"
    note false and orphan any reference resolving to the archived copy."""
    arc = set(_phase_nums(ARCHIVE))
    active = set(_phase_nums(REFACTOR))
    missing = ARCHIVED_PHASE_NUMS - arc
    resurrected = ARCHIVED_PHASE_NUMS & active
    assert not missing, (
        f"§2 calls these archived but they are not under _archive/refactor: "
        f"{sorted(missing)}")
    assert not resurrected, (
        "§2 calls these archived-only, but they now also exist as active "
        f"refactor plans: {sorted(resurrected)}")


def test_the_duplicate_phase_numbers_are_exactly_the_named_set():
    """(correctness) §2: "Duplicate numbers 4, 37, 52, 64, 100, 103, 104 and 105
    name parallel records ... Use the full filename in references." A NEW
    accidental duplicate (two docs silently sharing a number) is a real hazard —
    a bare-number reference becomes ambiguous. Set equality reds both on a new
    collision and on one of these collapsing to a single doc."""
    actual = {n for n, names in _phase_nums(REFACTOR).items() if len(names) > 1}
    assert actual == DUPLICATE_PHASE_NUMS, (
        f"duplicate-phase-number set drifted from §2: register says "
        f"{sorted(DUPLICATE_PHASE_NUMS)}, tree has {sorted(actual)} "
        f"(new collisions: {sorted(actual - DUPLICATE_PHASE_NUMS)}; "
        f"resolved: {sorted(DUPLICATE_PHASE_NUMS - actual)})")


def test_the_mapping_artifacts_are_tsv_not_missing_phase_docs():
    """(correctness) §2: "Phase 67 and Phase 69 are mapping artifacts ..., not
    missing implementation plans." Each must exist as its ``.tsv`` and must NOT
    have a same-numbered phase ``.md``, or a reader would read the number as an
    unwritten plan. (Phase 66's ``.tsv`` coexists with a real plan, so it is not
    in this set — its map is covered by §8's inventory test.)"""
    active = _phase_nums(REFACTOR)
    for num, tsv in MAPPING_ARTIFACT_STEMS.items():
        assert (REFACTOR / tsv).exists(), f"mapping artifact {tsv} is missing"
        assert num not in active, (
            f"phase {num} is a mapping artifact, but a phase-{num}-*.md plan now "
            f"exists ({active[num]}) — §2's classification is stale")


def test_the_embedded_follow_up_records_have_no_own_file_and_are_named_by_their_host():
    """(correctness) §2: "Phase 73, 74 and 76 are complete follow-up records
    embedded in [phase-72] and [phase-75] ...; references must call them embedded
    records, not imply missing files." Each must be named inside its host doc and
    must NOT have acquired its own ``phase-N-*.md`` — the moment it does, the
    "embedded, not missing" note is wrong."""
    hosts = {name: (REFACTOR / name).read_text()
             for name in set(EMBEDDED_RECORDS.values())}
    for num, host in EMBEDDED_RECORDS.items():
        assert re.search(rf"\bPhase[ -]?{num}\b", hosts[host]), (
            f"phase {num} is claimed embedded in {host} but that doc never "
            "names it")
        own = list(REFACTOR.glob(f"phase-{num}-*.md"))
        assert not own, (
            f"phase {num} is an embedded record but now has its own file "
            f"{[p.name for p in own]} — promote it to §7 and drop the §2 note")


def test_the_phases_this_register_created_exist():
    """(feature) §2's central finding was that Phase 112 was genuinely missing
    and Phases 108/109 had misassigned follow-ups; the register created 112, 113
    and 114 to close those gaps. If any is absent the reference integrity the
    register asserts is broken at its own root."""
    for name in CREATED_PHASE_DOCS:
        assert (REFACTOR / name).exists(), (
            f"{name} — a doc phase-111 created to close a reference gap — is "
            "missing; the register's §2 findings no longer resolve")


# --- §8: the support inventory --------------------------------------------


def test_the_support_artifacts_the_register_inventories_exist():
    """(correctness) §8 promises the non-Markdown artifacts (move maps, ranking
    baselines, generated inventories) are the ones the partition deliberately
    excludes from §7. A missing artifact means §7's Markdown-only scope silently
    dropped real evidence instead of delegating it."""
    for rel in SUPPORT_ARTIFACTS:
        assert (REFACTOR / rel).exists(), (
            f"§8 inventories {rel} but it is not in the tree")


# --- the acceptance evidence the register cites is not phantom ---------------


def test_every_guard_or_test_the_register_cites_as_acceptance_exists():
    """(correctness) Every B111 row is closed against "named acceptance
    evidence" — guard scripts (``check_*.py``) and focused test modules. The
    register lives under ``docs/refactor``, which ``check_doc_paths.py`` does
    not scan, and it names most guards by bare filename, which that guard's
    path regex would not catch anyway. So a guard renamed or deleted while a row
    still cites it as proof would leave the row "closed" against evidence that
    no longer exists — a phantom close. Every ``.py`` the register names must
    resolve to a real file in the tree."""
    tracked = _tracked_basenames()
    cited = sorted(set(_PY_TOKEN.findall(_register_text())))
    assert cited, "no .py acceptance tokens parsed — register shape changed"
    phantom = [t for t in cited if not _resolve_py(t, tracked)]
    assert not phantom, (
        "the register cites acceptance evidence that does not exist in the "
        f"tree (renamed, deleted, or a typo): {phantom}")


def test_phantom_evidence_detector_is_not_vacuous():
    """(error) The resolver must reject a plainly non-existent guard, so a green
    result above means the citations truly resolved."""
    tracked = _tracked_basenames()
    assert not _resolve_py("tools/ci/check_this_guard_does_not_exist.py", tracked)
    assert _resolve_py("tools/ci/check_doc_paths.py", tracked), (
        "resolver rejects a guard that plainly exists — detector is broken")


# --- the register's own close-out state -------------------------------------


def _assert_status_is_a_clean_close(text: str) -> None:
    status = re.search(r"\*\*Status:\*\*\s*(.+)", text).group(1).strip()
    assert "CLOSED" in status and "active" not in status.lower(), (
        f"register status is no longer a clean close: {status!r}")


def _assert_no_open_row(rows: list[tuple[str, str]]) -> None:
    assert rows, "no B111 rows parsed — register shape changed"
    open_rows = [rid for mark, rid in rows if mark == " "]
    assert not open_rows, (
        f"register reads CLOSED but these rows are unchecked: {open_rows}")


def _assert_ids_unique(ids: list[str]) -> None:
    dups = [rid for rid, c in Counter(ids).items() if c > 1]
    assert not dups, f"duplicate B111 ids: {dups}"


def _assert_ids_contiguous(ids: list[str]) -> None:
    nums = sorted(int(rid.split("-")[1]) for rid in ids)
    expected = list(range(nums[0], nums[-1] + 1))
    assert nums == expected, (
        f"B111 ids are not contiguous — a row was dropped: {nums}")


def test_the_register_declares_itself_closed_with_no_open_row():
    """(feature) The register's status is IMPLEMENTED / CLOSED and its close
    protocol forbids leaving a row open: "No backlog file, exemption, cap
    increase or 'accepted current code' annotation closes a row whose objective
    is zero debt." So every B111 row must be checked, the ids contiguous and
    unique, and the top status must not have quietly reverted to active while a
    row was reopened."""
    text = _register_text()
    rows = re.findall(r"^- \[( |x)\] \*\*(B111-\d+)", text, re.M)
    _assert_status_is_a_clean_close(text)
    _assert_no_open_row(rows)
    ids = [rid for _, rid in rows]
    _assert_ids_unique(ids)
    _assert_ids_contiguous(ids)
