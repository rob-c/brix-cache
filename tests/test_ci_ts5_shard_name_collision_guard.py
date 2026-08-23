"""Guard #12 (`check_shard_name_collisions.py`) — does it actually fire?

A shard is compiled into its parent's globals, so the unit has ONE module
namespace.  The complexity burndown hoisted expression bodies into helpers
numbered per file, and three composed units ended up binding the same name
twice.  Python resolves a function body's globals at call time, so the parent's
own call sites reached the shard's definition:

  * `c_auth_units`    — a `TypeError`, loud, one unit red.
  * `client_features` — a string helper rebound to an exit-code helper; the
    journal assertions compared against an int and quietly failed.
  * `gsi_trust_live`  — a skip path returned a parsed HTTP code instead.

Two of three were silent, which is why this is a guard and not a review note.

Every case builds its own scratch tree and points the guard at it with
`--root`; damaging the real tree to prove a guard fires would be a worse bug
than the one being guarded against.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

TESTS = pathlib.Path(__file__).resolve().parent
GUARD = TESTS.parent / "tools" / "ci" / "check_shard_name_collisions.py"

_PARENT = '''"""A composed parent."""
from split_continuation import load as _load_continuations


def _output(proc):
    return (proc.stdout or "") + (proc.stderr or "")


def run(proc):
    return _output(proc)


_load_continuations(globals(), __file__, "thing_part2.py")
'''

_CLEAN_SHARD = '''"""A shard whose helpers have their own names."""


def _exit_code(failed):
    return 0 if failed == 0 else 1


def run_shard(failed):
    return _exit_code(failed)
'''

#: The exact defect: same name, different meaning, and the parent never sees it.
_COLLIDING_SHARD = _CLEAN_SHARD.replace("_exit_code", "_output")


def _run(root):
    return subprocess.run([sys.executable, str(GUARD), "--root", str(root)],
                          capture_output=True, text=True, timeout=120)


@pytest.fixture
def tree(tmp_path):
    """A parent that composes one shard; no name is bound twice."""
    (tmp_path / "thing.py").write_text(_PARENT)
    (tmp_path / "thing_part2.py").write_text(_CLEAN_SHARD)
    return tmp_path


# ---------------------------------------------------------------------------
# success


def test_distinctly_named_helpers_pass(tree):
    proc = _run(tree)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "1 composed unit(s) scanned" in proc.stdout


def test_the_real_tree_is_green():
    """The guard's own subject, so a regression here is not mistaken for setup."""
    proc = _run(TESTS)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_an_uncomposed_neighbour_may_reuse_the_name(tmp_path):
    """Scope is the composed unit, not the directory.

    Two ordinary modules that both define `_output` are two namespaces and
    cannot collide — flagging them would make the guard unusable.
    """
    (tmp_path / "one.py").write_text("def _output(proc):\n    return proc\n")
    (tmp_path / "two.py").write_text("def _output(proc):\n    return proc\n")
    proc = _run(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_a_nested_helper_is_not_a_collision(tmp_path):
    """Only module level shares a namespace; a name inside a function or a
    method on a class is private to it."""
    (tmp_path / "thing.py").write_text(
        '"""A composed parent."""\n'
        "from split_continuation import load as _load_continuations\n\n\n"
        "def run():\n"
        "    def _output(proc):\n"
        "        return proc\n"
        "    return _output\n\n\n"
        '_load_continuations(globals(), __file__, "thing_part2.py")\n'
    )
    (tmp_path / "thing_part2.py").write_text(
        "class Shard:\n"
        "    def _output(self, proc):\n"
        "        return proc\n"
    )
    proc = _run(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# error — the guard has to fail, or it is decoration


def test_a_shard_rebinding_a_parent_helper_fails(tree):
    """The `client_features` defect, reduced: same name, different meaning."""
    (tree / "thing_part2.py").write_text(_COLLIDING_SHARD)
    proc = _run(tree)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "_output" in proc.stdout
    assert "thing.py:" in proc.stdout and "thing_part2.py:" in proc.stdout


def test_a_byte_identical_duplicate_still_fails(tree):
    """No "the bodies match, so it is harmless" exemption.

    `c_auth_units` carried three such copies and one that had drifted; the
    drifted one is the bug, and it is indistinguishable from the others until
    somebody edits a copy.
    """
    (tree / "thing_part2.py").write_text(
        "def _output(proc):\n"
        '    return (proc.stdout or "") + (proc.stderr or "")\n'
    )
    proc = _run(tree)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "_output" in proc.stdout


def test_a_second_definition_inside_one_file_fails(tree):
    """Python accepts a redefinition silently; the second wins and the first is
    dead code nobody meant to write."""
    (tree / "thing_part2.py").write_text(
        _CLEAN_SHARD + "\n\ndef _exit_code(failed):\n    return failed\n"
    )
    proc = _run(tree)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "_exit_code" in proc.stdout


def test_a_class_colliding_with_a_function_fails(tree):
    """Both bind a module-level name; which kind of statement did it is not the
    point."""
    (tree / "thing_part2.py").write_text(
        _CLEAN_SHARD + "\n\nclass _output:\n    pass\n"
    )
    proc = _run(tree)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "_output" in proc.stdout


# ---------------------------------------------------------------------------
# security-negative — the guard must not be silenceable


def test_a_shard_that_stops_being_composed_stops_being_scanned(tmp_path):
    """A collision cannot be laundered by *keeping* the composition and hiding
    the call — but it CAN legitimately end by ending the composition.

    The complementary risk is a guard that never fires because it fails to see
    a composition it should: the bespoke-alias spelling, which thirteen live
    modules use.  Renaming the helper import must not make a real collision
    invisible.
    """
    (tmp_path / "thing.py").write_text(
        _PARENT.replace("_load_continuations", "_load_matrix_cells"))
    (tmp_path / "thing_part2.py").write_text(_COLLIDING_SHARD)
    proc = _run(tmp_path)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "_output" in proc.stdout


def test_the_numbered_spelling_is_scanned_too(tmp_path):
    """`load_numbered(globals(), __file__, "stem_part", 2, 3)` owns two shards
    by inclusive bounds; a guard that only understood the named spelling would
    pass a unit whose shards collide."""
    (tmp_path / "thing.py").write_text(
        '"""A composed parent, numbered spelling."""\n'
        "from split_continuation import load_numbered as _load_continuations\n\n\n"
        "def _output(proc):\n"
        "    return proc\n\n\n"
        '_load_continuations(globals(), __file__, "thing_part", 2, 3)\n'
    )
    (tmp_path / "thing_part2.py").write_text(_CLEAN_SHARD)
    (tmp_path / "thing_part3.py").write_text("def _output(failed):\n    return failed\n")
    proc = _run(tmp_path)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "thing_part3.py:" in proc.stdout


def test_a_missing_shard_does_not_crash_the_guard(tree):
    """A parent may still name shards a move relocated. Reporting nothing is
    correct; raising would take the whole guard offline and every other unit
    with it."""
    (tree / "thing_part2.py").unlink()
    proc = _run(tree)
    assert proc.returncode == 0, proc.stdout + proc.stderr
