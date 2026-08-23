"""Guard #11 (`check_shim_entrypoints.py`) — does it actually fire?

The guard exists because a §10.2 shim carries names across a move but not
``__main__`` guards.  Guard #3 proves ``import x`` still yields everything it
did; nothing proved ``python3 tests/x.py`` still *does* anything.  Its first
run on the real tree found one: ``tests/fleet_prep.py`` had been a script that
generated the session artifacts and printed a line operators grep for, and
since TS-4 it had exited 0 having generated nothing.

Fifteen archived CLIs in this tree are paired with a live stack head that still
runs one.  The guard pins that pairing, so it must fail on exactly one thing:
an archive whose entry point has no live spelling left.

Every case builds its own scratch tree and points the guard at it with
``--root``.  Damaging the real tree to prove a guard fires would be a worse bug
than the one being guarded against.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

def _check_test_the_guard_never_writes_to_the_tree_it_checks_1(root):
    assert _run(root).returncode == 0

def _check_test_the_guard_never_writes_to_the_tree_it_checks_2(before, after):
    assert before == after, "the guard modified the tree it was asked to inspect"


TESTS = pathlib.Path(__file__).resolve().parent
GUARD = TESTS.parent / "tools" / "ci" / "check_shim_entrypoints.py"

_ARCHIVE_WITH_CLI = '''"""ARCHIVE — the flat body, frozen."""


def work():
    return 0


if __name__ == "__main__":
    raise SystemExit(work())
'''

_SHIM_WITH_CLI = '''"""A §10.2 shim that kept the entry point."""
import sys as _sys

import pkg.thing as _canonical

if __name__ == "__main__":
    raise SystemExit(_canonical.main(_sys.argv[1:]))

_sys.modules[__name__] = _canonical
'''

_SHIM_WITHOUT_CLI = '''"""A §10.2 shim that dropped the entry point."""
import sys as _sys

import pkg.thing as _canonical

_sys.modules[__name__] = _canonical
'''


def _run(root):
    return subprocess.run([sys.executable, str(GUARD), "--root", str(root)],
                          capture_output=True, text=True, timeout=120)


def _tree(root, shim=_SHIM_WITH_CLI, archive_name="thing_flat.py"):
    legacy = root / "brix_suite" / "_legacy"
    legacy.mkdir(parents=True, exist_ok=True)
    (legacy / archive_name).write_text(_ARCHIVE_WITH_CLI)
    if shim is not None:
        (root / "thing.py").write_text(shim)
    return root


@pytest.fixture
def tree(tmp_path):
    """An archive with a CLI, and a live shim that still runs one."""
    return _tree(tmp_path)


# --------------------------------------------------------------------------
# success — the arrangement the tree is actually in
# --------------------------------------------------------------------------

def test_a_paired_archive_and_shim_pass(tree):
    r = _run(tree)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "1 archived CLI" in r.stdout


def test_the_real_tree_is_clean():
    """The guard's own tree must pass — it is wired into `guards.yml`.

    The count is pinned, not floored, so that a shim losing its ``__main__``
    is as loud as one gaining it: silently dropping to 16 is the failure the
    guard exists to catch, and a ``>=`` would sail past it.  It moves when a
    cluster moves — 15 to 17 at the mesh cluster, which brought
    ``cms_mesh_servers`` and ``hybrid_mesh_servers`` with it, and 17 to 19 at
    the perf cluster, which brought ``load_test_part3`` (whose ``__main__``
    guard became ``run_cli``) and ``_perf_ab_helpers`` — and the number is
    meant to be read against that sentence, not simply bumped.

    Deliberately a literal rather than a count derived from the tree.  Deriving
    it would mean asserting the guard agrees with a second implementation of
    the guard's own scan, which passes in exactly the case that matters: both
    reading the tree the same wrong way.
    """
    r = subprocess.run([sys.executable, str(GUARD)],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "19 archived CLI" in r.stdout


def test_an_archive_without_a_cli_is_not_asked_for_one(tmp_path):
    """Most archives never had an entry point; they must not be graded on one."""
    legacy = tmp_path / "brix_suite" / "_legacy"
    legacy.mkdir(parents=True)
    (legacy / "quiet_flat.py").write_text('"""ARCHIVE."""\n\n\ndef work():\n    return 0\n')
    r = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "0 archived CLI" in r.stdout


# --------------------------------------------------------------------------
# error — the defect it was built for
# --------------------------------------------------------------------------

def test_a_shim_that_dropped_the_cli_fails(tmp_path):
    r = _run(_tree(tmp_path, shim=_SHIM_WITHOUT_CLI))
    assert r.returncode == 1
    assert "exits 0 without doing the work" in r.stdout


def test_a_guard_that_calls_nothing_is_not_an_entry_point(tmp_path):
    """`if __name__ == "__main__": pass` would satisfy a grep, not a caller."""
    shim = ('"""A shim with a decorative guard."""\n'
            'import pkg.thing as _canonical\n\n'
            'if __name__ == "__main__":\n'
            '    _EXIT = 0\n')
    r = _run(_tree(tmp_path, shim=shim))
    assert r.returncode == 1
    assert "calls nothing" in r.stdout


def test_a_vanished_stack_head_fails(tmp_path):
    r = _run(_tree(tmp_path, shim=None))
    assert r.returncode == 1
    assert "nowhere left to live" in r.stdout


def test_a_shard_archive_is_charged_to_the_module_callers_run(tmp_path):
    """`x509forge_part3` held the CLI; `python3 tests/x509forge.py` runs it.

    Charging the shard would ask for an entry point in a file no caller names,
    and would let the real one go missing from the file they do.
    """
    root = _tree(tmp_path, shim=None, archive_name="thing_part3_flat.py")
    (root / "thing_part3.py").write_text(_SHIM_WITH_CLI)
    r = _run(root)
    assert r.returncode == 1, "the shard must not satisfy the head's obligation"
    assert "tests/thing.py" in r.stdout

    (root / "thing.py").write_text(_SHIM_WITH_CLI)
    r = _run(root)
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_privately_named_module_is_its_own_stack_head(tmp_path):
    """`_xrdcl_worker` is private, not a shard — its head keeps the underscore.

    The head used to be computed by name arithmetic: drop `_partN…`, then strip
    a leading underscore, because mixins are spelled `_tokenforge_part2_mixina`
    while their parent is `tokenforge`.  That rule is right for a slice and
    wrong for a module that is simply private, and TS-5's clients cluster
    brought two of those.  The guard would have gone looking for
    `tests/xrdcl_worker.py`, found nothing, and reported a stranded entry point
    that was never stranded — a false red on a guard whose whole value is that
    a red means something.  The head is settled by asking the tree instead.
    """
    root = _tree(tmp_path, shim=None, archive_name="_priv_flat.py")
    (root / "_priv.py").write_text(_SHIM_WITH_CLI)
    r = _run(root)
    assert r.returncode == 0, r.stdout + r.stderr

    #: and the mixin spelling still resolves the other way
    root2 = _tree(tmp_path / "b", shim=None,
                  archive_name="_thing_part2_mixina_flat.py")
    (root2 / "thing.py").write_text(_SHIM_WITH_CLI)
    r = _run(root2)
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_shim_in_a_package_directory_is_found(tmp_path):
    """A shim need not sit at the top of `tests/`.

    The eight stub servers are shimmed at `tests/lib/`, because that is where
    twenty-six suites and two `cmdscripts` drivers already spell them.  The
    head resolver looked only at the top level, so every one of those archives
    read as a CLI whose stack head "no longer exists" — the same false red the
    underscore rule produced, arriving from the other direction.  Directory and
    underscore are both settled by asking the tree now, and both are pinned
    here: either alone leaves the other free to regress.
    """
    root = _tree(tmp_path, shim=None, archive_name="stub_server_flat.py")
    (root / "lib").mkdir()
    (root / "lib" / "stub_server.py").write_text(_SHIM_WITH_CLI)
    r = _run(root)
    assert r.returncode == 0, r.stdout + r.stderr

    #: and a package-directory shim that lost its CLI is still a violation —
    #: finding the file must not become a way of passing without checking it.
    root2 = _tree(tmp_path / "b", shim=None, archive_name="stub_server_flat.py")
    (root2 / "lib").mkdir()
    (root2 / "lib" / "stub_server.py").write_text(
        '"""No CLI here."""\nimport pkg.thing as _canonical\n')
    r = _run(root2)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "lib/stub_server.py" in r.stdout


def test_prose_about_main_is_not_an_entry_point(tmp_path):
    """Every shim in this cluster discusses `__main__` at length in its docstring.

    A regex-based guard would pass on the explanation and never look for the
    code, which is precisely backwards.
    """
    shim = ('"""This shim used to have an `if __name__ == "__main__":` block.\n\n'
            'It calls `_canonical.main(sys.argv[1:])` — or it would, if this\n'
            'were code rather than a paragraph about code.\n'
            '"""\n'
            '# if __name__ == "__main__":\n'
            '#     raise SystemExit(main())\n'
            'import pkg.thing as _canonical\n')
    r = _run(_tree(tmp_path, shim=shim))
    assert r.returncode == 1
    assert "exits 0 without doing the work" in r.stdout


# --------------------------------------------------------------------------
# security-negative — the guard must not be satisfiable by damage
# --------------------------------------------------------------------------

def test_deleting_the_archive_is_not_a_way_to_pass(tmp_path):
    """The archives are the evidence; a phase must not pass by removing it.

    The guard alone cannot see a deleted archive — nothing is left to compare
    against — so this pins the ratchet that can: `_legacy/` is append-only
    until TS-7, and `check_ratchet_monotonic.py` fails a shrinking baseline.
    Stated here so the hole is recorded rather than assumed closed.
    """
    root = _tree(tmp_path, shim=_SHIM_WITHOUT_CLI)
    assert _run(root).returncode == 1
    (root / "brix_suite" / "_legacy" / "thing_flat.py").unlink()
    assert _run(root).returncode == 0, "expected — see the docstring"

    live = TESTS / "brix_suite" / "_legacy"
    archives = sorted(p.name for p in live.glob("*_flat.py"))
    assert len(archives) >= 43, "the real archive set must not have shrunk"
    for name in ("fleet_prep_flat.py", "kdc_helpers_flat.py",
                 "token_differential_flat.py", "x509_differential_flat.py",
                 "x509_matrix_differential_flat.py"):
        assert name in archives, f"{name} disappeared from _legacy/"


def test_the_guard_never_writes_to_the_tree_it_checks(tmp_path):
    """A read-only guard, proven read-only — it is pointed at the real tree in CI."""
    root = _tree(tmp_path)
    before = {p: p.stat().st_mtime_ns for p in sorted(root.rglob("*")) if p.is_file()}
    _check_test_the_guard_never_writes_to_the_tree_it_checks_1(root)
    after = {p: p.stat().st_mtime_ns for p in sorted(root.rglob("*")) if p.is_file()}
    _check_test_the_guard_never_writes_to_the_tree_it_checks_2(before, after)
