"""Guards the guard that guards the ratchets — tools/ci/check_ratchet_monotonic.py.

Every quality ratchet in this repo (file size, complexity, todo/fixme, VFS seam,
LoC) compares the tree against a frozen backlog file, which makes all of them
defeatable the same way: append the offending entry to the backlog, or bump the
number next to it, and the guard goes green while the code gets worse. The
monotonicity guard closes that door, so its own failure modes matter — a version
of it that never fails would restore the hole invisibly.

The cases below drive the guard's real verdict logic against synthetic backlogs.
No git and no tracked file is touched: `run()` takes the base-revision reader as
a callable, and the head tree is a `tmp_path` copy — mutating a real backlog to
prove a negative is how a tracked config got corrupted on 2026-08-05.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "tools" / "ci" / "check_ratchet_monotonic.py"

# The one real ratchet used as the vehicle for the end-to-end cases; any entry
# in RATCHETS would do, and the last test asserts this one is still in the set.
SUBJECT = "tools/ci/file_size_backlog.txt"


def _load():
    """Import the guard by path — tools/ci has no __init__.py."""
    spec = importlib.util.spec_from_file_location("check_ratchet_monotonic", GUARD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


GUARD_MOD = _load()


def _tree(tmp_path: Path, head: str) -> Path:
    """Write `head` as the working-tree copy of the subject backlog."""
    target = tmp_path / SUBJECT
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(head, encoding="utf-8")
    return tmp_path


def _run(tmp_path: Path, base: str, head: str) -> int:
    """Run the guard over a synthetic tree with a synthetic baseline."""
    root = _tree(tmp_path, head)
    return GUARD_MOD.run(root, lambda path: base if path == SUBJECT else None)


# --- success: the ratchet turning the right way ------------------------------


def test_a_shrinking_backlog_passes(tmp_path: Path) -> None:
    """Burning down a backlog entry is the whole point — it must never redden."""
    base = "src/a.c\t812\nsrc/b.c\t640\n"
    assert GUARD_MOD.compare(base, "src/b.c\t640\n") == []
    assert _run(tmp_path, base, "src/b.c\t640\n") == 0


def test_a_lowered_allowance_passes(tmp_path: Path) -> None:
    """Shrinking a number in place is a burn-down too, not a change to block."""
    assert _run(tmp_path, "src/a.c\t812\n", "src/a.c\t700\n") == 0


def test_comments_and_blank_lines_are_free(tmp_path: Path) -> None:
    """Documenting a backlog must cost nothing, or nobody will document it."""
    head = "# why these are frozen: see docs/refactor/phase-56.md\n\nsrc/a.c\t812\n"
    assert _run(tmp_path, "src/a.c\t812\n", head) == 0


# --- error: the ways a backlog can grow --------------------------------------


def test_a_new_grandfathered_entry_fails(tmp_path: Path) -> None:
    """The common defeat: append the file you just broke to the backlog."""
    findings = GUARD_MOD.compare("src/a.c\t812\n", "src/a.c\t812\nsrc/new.c\t900\n")
    assert findings == ["NEW entry grandfathered: src/new.c"]
    assert _run(tmp_path, "src/a.c\t812\n", "src/a.c\t812\nsrc/new.c\t900\n") == 1


def test_a_raised_allowance_fails(tmp_path: Path) -> None:
    """The quiet defeat: keep the entry, widen the number beside it."""
    findings = GUARD_MOD.compare("src/a.c\t812\n", "src/a.c\t900\n")
    assert findings == ["allowance RAISED: src/a.c — was 812, now 900"]
    assert _run(tmp_path, "src/a.c\t812\n", "src/a.c\t900\n") == 1


def test_an_opaque_entry_counts_as_its_own_allowance(tmp_path: Path) -> None:
    """Listed backlogs (VFS seam, template refs) carry no number — presence is it."""
    base = "src/fs/backend/posix.c:\n"
    head = "src/fs/backend/posix.c:\nsrc/protocols/root/read.c:\n"
    assert GUARD_MOD.compare(base, head) == [
        "NEW entry grandfathered: src/protocols/root/read.c:"
    ]
    assert _run(tmp_path, base, head) == 1


def test_a_missing_baseline_is_reported_not_failed(tmp_path: Path) -> None:
    """Adopting a NEW ratchet must not fail the PR that introduces it."""
    root = _tree(tmp_path, "src/a.c\t812\n")
    assert GUARD_MOD.run(root, lambda path: None) == 0


def test_a_missing_head_file_is_skipped(tmp_path: Path) -> None:
    """A ratchet not present in the tree is out of scope, not a failure."""
    assert GUARD_MOD.run(tmp_path, lambda path: "src/a.c\t812\n") == 0


# --- security-negative: the guard must not be defeatable ---------------------


@pytest.mark.parametrize(
    "base, head",
    [
        # Trailing whitespace around the number must not read as a new entry
        # (which would be noise) NOR hide a raise.
        ("src/a.c\t812\n", "src/a.c\t900 \n"),
        # A duplicate line keeping the highest allowance: the widened copy is
        # what the guard must see, not the innocuous one next to it.
        ("src/a.c\t812\n", "src/a.c\t812\nsrc/a.c\t900\n"),
        # Comment camouflage: real growth hidden between comment lines.
        ("src/a.c\t812\n", "# burn-down tracked in phase-98\nsrc/a.c\t812\nsrc/new.c\t900\n"),
    ],
    ids=["padded-number", "duplicate-keeps-max", "comment-camouflage"],
)
def test_growth_cannot_be_disguised(tmp_path: Path, base: str, head: str) -> None:
    assert _run(tmp_path, base, head) == 1


def test_an_empty_base_and_head_is_not_a_pass_by_accident(tmp_path: Path) -> None:
    """An empty backlog is the goal state: it stays green, and still bites."""
    assert _run(tmp_path, "", "") == 0
    assert _run(tmp_path, "", "src/new.c\t900\n") == 1


def test_the_governed_set_covers_the_ratchets_that_gate_main() -> None:
    """The guard is only worth its runtime if it names the blocking ratchets.

    A future edit that quietly drops file size or complexity from RATCHETS
    reopens exactly the hole this guard exists to close, and every other test
    here would still pass."""
    assert SUBJECT in GUARD_MOD.RATCHETS
    for required in (
        "tools/ci/file_size_backlog.txt",
        "tools/ci/complexity_backlog.txt",
        "tools/ci/todo_fixme_backlog.txt",
        "tests/loc_baseline.txt",
    ):
        assert required in GUARD_MOD.RATCHETS, f"{required} is no longer monotonic"
    for path in GUARD_MOD.RATCHETS:
        assert GUARD_MOD.RATCHETS[path].strip(), f"{path} has no guard named against it"


def test_the_guard_is_wired_into_ci() -> None:
    """An unwired ratchet guard protects nothing — CI has to run it."""
    workflow = (ROOT / ".github/workflows/guards.yml").read_text(encoding="utf-8")
    assert GUARD.name in workflow, "guards.yml no longer runs check_ratchet_monotonic.py"
    assert "--base" in workflow, (
        "the CI step must pass an explicit base revision: a runner's default "
        "checkout has no useful origin/main to fall back on"
    )
