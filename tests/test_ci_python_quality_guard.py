"""`tools/ci/check_python_quality.py` — the CI spelling of the Python contract.

The contract itself is unit-tested in `test_python_quality.py`, against the
scoring engine. This file tests the *guard*: that the CLI the guards workflow
actually runs reports what the engine found, fails when it should, and does not
need pytest or a server fleet to do it.

That last point is the reason the CLI exists. `guards.yml` is a bare checkout —
no build, no `objs/nginx` — and this suite's `conftest.py` boots a fleet for any
pytest invocation under `tests/`. Running the contract through pytest there
would have failed on the missing binary rather than on anything about the code,
and a guard that reds for the wrong reason gets disabled.

Every case points the guard at a scratch tree with `--root`.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

TESTS = pathlib.Path(__file__).resolve().parent
GUARD = TESTS.parent / "tools" / "ci" / "check_python_quality.py"

_CLEAN = "def sample(value):\n    if value:\n        return 1\n    return 0\n"

#: Sequential independent branches multiply, so NPath passes 15 long before CCN
#: reaches its own limit of 15 — the shape the sweep kept finding.
_NPATH_BOMB = "def sample(a, b, c, d):\n" + "".join(
    f"    if {name}:\n        pass\n" for name in "abcd"
)

#: Eleven levels of nesting: every other metric here is trivially small.
_DEEP_NEST = "def sample(flag):\n" + "".join(
    f"{'    ' * (depth + 1)}if flag:\n" for depth in range(11)
) + f"{'    ' * 12}return 1\n"


def _run(root, *extra):
    return subprocess.run([sys.executable, str(GUARD), "--root", str(root), *extra],
                          capture_output=True, text=True, timeout=300)


@pytest.fixture
def tree(tmp_path):
    """A scratch repo with one scanned tree and one simple function in it."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "probe.py").write_text(_CLEAN)
    return tmp_path


# ---------------------------------------------------------------------------
# success


def test_a_simple_function_passes(tree):
    proc = _run(tree)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "check_python_quality: OK" in proc.stdout
    assert "nesting 10" in proc.stdout, "the limits belong in the green line too"


@pytest.mark.timeout(300)
def test_the_real_repository_is_green():
    """The guard's own subject: the whole tree meets the contract with no
    backlog and no exemption, which is the claim the commit makes.

    ~23s serially over 224k functions; the 30s default cap starves under a
    full parallel tier, so it carries the lizard-class 300s cap."""
    proc = subprocess.run([sys.executable, str(GUARD)], capture_output=True,
                          text=True, timeout=900)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_an_unscanned_tree_is_ignored(tmp_path):
    """Scope is `SCAN_ROOTS`. A file outside them is not this contract's
    business, and pretending otherwise would make the guard unrunnable against
    vendored or generated trees."""
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "awful.py").write_text(_NPATH_BOMB + _DEEP_NEST)
    proc = _run(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# error — the guard has to fail, or it is decoration


def test_a_path_explosion_fails_even_at_low_ccn(tree):
    """Four sequential independent branches: 16 paths, CCN only 5.

    This is precisely why the contract is five metrics and not one — a
    CCN-only gate calls this function fine.
    """
    (tree / "tests" / "probe.py").write_text(_NPATH_BOMB)
    proc = _run(tree)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "npath limit" in proc.stdout
    assert "tests/probe.py" in proc.stdout


def test_deep_nesting_fails(tree):
    (tree / "tests" / "probe.py").write_text(_DEEP_NEST)
    proc = _run(tree)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "nesting limit" in proc.stdout


def _lines_matching(text, needle):
    return [line for line in text.splitlines() if needle in line]


def test_output_is_capped_per_metric(tree):
    """One catastrophic file must not bury the other metrics' findings."""
    bombs = (_NPATH_BOMB.replace("sample", f"sample_{n}") for n in range(12))
    (tree / "tests" / "probe.py").write_text("".join(bombs))
    proc = _run(tree, "--limit", "3")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    printed = _lines_matching(proc.stdout, "npath limit")
    elided = _lines_matching(proc.stdout, "and 9 more")
    assert len(elided) == 1, proc.stdout
    assert len(printed) == 4, printed


# ---------------------------------------------------------------------------
# security-negative — the guard must not be silenceable


def test_an_analysis_error_fails_rather_than_passing_quietly(tree):
    """A file the analyzers cannot read must NOT be scored as compliant.

    Failing open is the dangerous direction: a syntax error, an encoding the
    parser rejects, or a crashed analyzer would otherwise contribute zero
    violations and the guard would print OK over an unexamined file.
    """
    (tree / "tests" / "broken.py").write_text("def sample(:\n")
    proc = _run(tree)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "metric analysis errored" in proc.stderr
    assert "broken.py" in proc.stderr


def test_there_is_no_exemption_pragma(tree):
    """No `# noqa`, `# nosec`-style escape hatch: the contract has no backlog
    and no per-line opt-out, so a comment must not buy silence."""
    (tree / "tests" / "probe.py").write_text(
        _NPATH_BOMB.replace("def sample", "# noqa\n# nosec\n# pragma: no cover\ndef sample"))
    proc = _run(tree)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "npath limit" in proc.stdout
