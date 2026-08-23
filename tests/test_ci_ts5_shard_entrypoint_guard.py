"""Guard #10 (`check_shard_entrypoints.py`) — does it actually fire?

The guard exists because TS-5 twice hit the same defect: a CLI written as
``if __name__ == "__main__":`` at the foot of a shard runs only while that
shard is ``exec``-ed into its parent's globals, and silently stops running the
moment the parent becomes a real package.  For the token forge that left
``prep_steps.FleetArtifactsStep`` exiting 0 over an empty directory, because it
invokes the helper with ``tolerate=True``.

Fourteen shard entry points in this tree are still composed that way and are
correct as they stand.  The guard pins the pairing rather than the practice, so
it must fail on exactly one thing: a shard that kept its ``__main__`` guard
after its parent stopped composing it.

Every case here builds its own scratch tree and points the guard at it with
``--root``.  Damaging the real tree to prove a guard fires would be a worse bug
than the one being guarded against.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

def _expression_1(tree):
    return (
        {p: p.read_bytes() for p in sorted(tree.rglob("*"))
                      if p.is_file()}
    )

def _expression_2(tree):
    return (
        {p: p.read_bytes() for p in sorted(tree.rglob("*"))
                          if p.is_file()}
    )

def _expression_3(tree):
    return (
        {p: p.read_bytes() for p in sorted(tree.rglob("*")) if p.is_file()}
    )


TESTS = pathlib.Path(__file__).resolve().parent
GUARD = TESTS.parent / "tools" / "ci" / "check_shard_entrypoints.py"

_PARENT = '''"""A composed parent."""
from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "thing_part2.py")
'''

_SHARD_WITH_CLI = '''"""A shard that owns the entry point."""


def run():
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
'''


def _run(root):
    return subprocess.run([sys.executable, str(GUARD), "--root", str(root)],
                          capture_output=True, text=True, timeout=120)


@pytest.fixture
def tree(tmp_path):
    """A parent that composes one shard, and the shard holds the CLI."""
    (tmp_path / "thing.py").write_text(_PARENT)
    (tmp_path / "thing_part2.py").write_text(_SHARD_WITH_CLI)
    return tmp_path


# ---------------------------------------------------------------------------
# success


def test_a_composed_shard_with_an_entry_point_passes(tree):
    """The arrangement fourteen live modules use is not what the guard hunts."""
    proc = _run(tree)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "1 shard entry point(s) still exec-composed" in proc.stdout


def test_the_real_tree_is_green():
    """The guard's own subject, so a regression here is not mistaken for setup."""
    proc = _run(TESTS)
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# error — the guard has to fail, or it is decoration


def test_breaking_the_composition_makes_the_guard_fail(tree):
    """Exactly the TS-5 defect: the parent moves on, the entry point does not.

    The shard is untouched — only the parent stops composing it, which is what
    a package move looks like from the shard's side.
    """
    (tree / "thing.py").write_text('"""Now a real package facade."""\n'
                                   'from thing_part2 import run  # noqa: F401\n')
    proc = _run(tree)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "thing_part2.py" in proc.stdout
    assert "can never run" in proc.stdout


def test_a_shard_without_an_entry_point_is_not_flagged(tree):
    """Most shards carry no CLI; orphaning one of those loses nothing."""
    (tree / "thing.py").write_text('"""Now a real package facade."""\n'
                                   'from thing_part2 import run  # noqa: F401\n')
    (tree / "thing_part2.py").write_text('"""No entry point here."""\n\n\n'
                                         'def run():\n    return 0\n')
    proc = _run(tree)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_a_bespoke_import_alias_still_reads_as_composition(tmp_path):
    """The alias is local, and the tree spells it thirteen different ways.

    `_load_continuations` (36 call sites) is only the largest family; there are
    also `_load_continuation` (7) and one-off names like `_load_webdav_state`
    and `_load_pblock_meta`.  A guard keyed on one hardcoded alias is blind to
    the other twelve, which is how `cvmfs_matrix_part2.py` read as orphaned
    while its parent was composing it on the line above.
    """
    (tmp_path / "thing.py").write_text(
        '"""A composed parent that renames the helper."""\n'
        "from split_continuation import load as _load_matrix_cells\n"
        '_load_matrix_cells(globals(), __file__, "thing_part2.py")\n'
    )
    (tmp_path / "thing_part2.py").write_text(_SHARD_WITH_CLI)
    proc = _run(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "1 shard entry point(s) still exec-composed" in proc.stdout


def test_a_bespoke_alias_that_stops_composing_still_fails(tmp_path):
    """Resolving the alias must not become a way to never fire.

    The security-negative twin of the case above: same bespoke spelling, but the
    parent no longer calls it, so the entry point is genuinely dead and the
    guard has to say so.
    """
    (tmp_path / "thing.py").write_text(
        '"""Imports the helper but composes nothing."""\n'
        "from split_continuation import load as _load_matrix_cells  # noqa: F401\n"
        "from thing_part2 import run  # noqa: F401\n"
    )
    (tmp_path / "thing_part2.py").write_text(_SHARD_WITH_CLI)
    proc = _run(tmp_path)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "thing_part2.py" in proc.stdout


def test_two_compositions_through_one_alias_are_both_seen(tmp_path):
    """A parent may compose more than once through the same name.

    `finditer` rather than `search`: stopping at the first call would leave
    every later shard looking unowned.
    """
    (tmp_path / "thing.py").write_text(
        '"""Two separate composition statements, one alias."""\n'
        "from split_continuation import load as _load_continuation\n"
        '_load_continuation(globals(), __file__, "thing_part2.py")\n'
        '_load_continuation(globals(), __file__, "thing_part3.py")\n'
    )
    (tmp_path / "thing_part2.py").write_text(_SHARD_WITH_CLI)
    (tmp_path / "thing_part3.py").write_text(_SHARD_WITH_CLI)
    proc = _run(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "2 shard entry point(s) still exec-composed" in proc.stdout


def test_the_inline_exec_idiom_counts_as_composition(tmp_path):
    """``operator_runtime.py`` predates ``split_continuation`` and open-codes it.

    It was the guard's first false positive: recognising only the shared helper
    would have demanded a fix to a module that is behaving correctly.
    """
    (tmp_path / "legacy.py").write_text(
        '"""Composes its shards the old way."""\n'
        "from pathlib import Path\n"
        'for _n in ("legacy_part2.py",):\n'
        "    _p = Path(__file__).with_name(_n)\n"
        '    exec(compile(_p.read_text(encoding="utf-8"), str(_p), "exec"),\n'
        "         globals())\n")
    (tmp_path / "legacy_part2.py").write_text(_SHARD_WITH_CLI)
    proc = _run(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "1 shard entry point(s) still exec-composed" in proc.stdout


# ---------------------------------------------------------------------------
# security-negative


def test_the_guard_never_writes_to_the_tree_it_scans(tree):
    """A guard that repairs what it inspects can hide the thing it found.

    It is also handed a path from the command line, so a write would be a write
    wherever it is pointed — including a tracked tree during a bad CI run.
    """
    before = _expression_1(tree)
    (tree / "thing.py").write_text('"""Now a real package facade."""\n')
    after_edit = _expression_2(tree)

    _run(tree)

    now = _expression_3(tree)
    def _assert_test_the_guard_never_writes_to_the_tree_it_scans_1():
        assert now == after_edit, "the guard modified the tree it was pointed at"
        assert set(now) == set(before), "the guard added or removed files"

    _assert_test_the_guard_never_writes_to_the_tree_it_scans_1()


def test_a_root_outside_the_repository_is_scanned_not_assumed(tmp_path):
    """``--root`` must not silently fall back to the real tree.

    If it did, a negative test that believed it was working on a scratch copy
    would in fact be asserting against the repository — the failure mode that
    once corrupted a tracked config in this suite.
    """
    empty = tmp_path / "nothing"
    empty.mkdir()
    proc = _run(empty)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "0 shard(s) scanned" in proc.stdout, proc.stdout
