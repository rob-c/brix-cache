"""Guard the pre-flight test-path validator in ``conftest_part2``.

WHAT: drives ``_validate_requested_paths`` directly with synthetic pytest
      ``config`` objects — no fleet, no servers, no I/O beyond ``tmp_path``.
WHY:  the validator runs in ``pytest_sessionstart`` *before* the fleet boots,
      so a false rejection aborts the whole lane with a UsageError that looks
      like a missing test file.  That is exactly what took the ``asan`` lane
      down on 2026-08-09: ``tools/ci/asan.py`` drives
      ``pytest test_sanitizer_smoke.py`` with ``cwd=tests``, the validator
      resolved that relative name against *rootdir* (the repo root), found
      nothing, and refused to start — while pytest itself would have collected
      the file without complaint.
HOW:  a fake config carries only what the validator reads (``args``,
      ``invocation_params.dir``, ``rootpath``).  The negatives prove the fix
      narrowed nothing: a path that exists under rootdir but not under the
      invocation dir must still be rejected, and a node-id suffix must not
      smuggle a nonexistent file past the check.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import conftest_part2


def _config(args, invocation_dir, rootpath, with_invocation_params: bool = True):
    """A stand-in for pytest's ``Config`` holding just the validator's inputs."""
    cfg = SimpleNamespace(args=list(args), rootpath=Path(rootpath))
    if with_invocation_params:
        cfg.invocation_params = SimpleNamespace(dir=Path(invocation_dir))
    return cfg


def _tree(tmp_path: Path) -> tuple[Path, Path]:
    """A repo-shaped tree: ``<root>/tests/test_leaf.py``."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_leaf.py").write_text("def test_ok():\n    assert True\n")
    return tmp_path, tests


# --- success ------------------------------------------------------------------


def test_bare_name_from_the_tests_dir_is_accepted(tmp_path):
    """The asan lane's shape: cwd=tests, argument is a bare file name."""
    root, tests = _tree(tmp_path)
    conftest_part2._validate_requested_paths(
        _config(["test_leaf.py"], invocation_dir=tests, rootpath=root)
    )


def test_root_relative_path_from_the_repo_root_is_accepted(tmp_path):
    """The documented local habit: cwd=repo root, argument is ``tests/…``."""
    root, _tests = _tree(tmp_path)
    conftest_part2._validate_requested_paths(
        _config(["tests/test_leaf.py"], invocation_dir=root, rootpath=root)
    )


def test_node_id_suffix_is_stripped_before_the_existence_check(tmp_path):
    """``file.py::test_case`` validates on the file half, not the whole string."""
    root, tests = _tree(tmp_path)
    conftest_part2._validate_requested_paths(
        _config(["test_leaf.py::test_ok"], invocation_dir=tests, rootpath=root)
    )


def test_absolute_paths_are_honoured_verbatim(tmp_path):
    """An absolute argument never gets joined onto the invocation dir."""
    root, tests = _tree(tmp_path)
    conftest_part2._validate_requested_paths(
        _config([str(tests / "test_leaf.py")], invocation_dir=root, rootpath=root)
    )


def test_rootpath_is_the_fallback_when_invocation_params_is_absent(tmp_path):
    """Older pytest builds expose no ``invocation_params``; rootdir still works."""
    root, _tests = _tree(tmp_path)
    conftest_part2._validate_requested_paths(
        _config(
            ["tests/test_leaf.py"],
            invocation_dir=root,
            rootpath=root,
            with_invocation_params=False,
        )
    )


# --- error --------------------------------------------------------------------


def test_a_genuinely_missing_path_still_aborts_the_session(tmp_path):
    root, tests = _tree(tmp_path)
    with pytest.raises(pytest.UsageError) as excinfo:
        conftest_part2._validate_requested_paths(
            _config(["test_typo.py"], invocation_dir=tests, rootpath=root)
        )
    assert "test_typo.py" in str(excinfo.value)


def test_every_missing_path_is_named_not_just_the_first(tmp_path):
    root, tests = _tree(tmp_path)
    with pytest.raises(pytest.UsageError) as excinfo:
        conftest_part2._validate_requested_paths(
            _config(
                ["test_leaf.py", "test_gone_a.py", "test_gone_b.py"],
                invocation_dir=tests,
                rootpath=root,
            )
        )
    message = str(excinfo.value)
    assert "test_gone_a.py" in message and "test_gone_b.py" in message
    assert "test_leaf.py," not in message  # the one that exists is not listed


# --- security-negative --------------------------------------------------------


def test_the_fix_did_not_widen_the_check_to_accept_either_base(tmp_path):
    """Resolution moved to the invocation dir — it was not made permissive.

    ``tests/test_leaf.py`` resolves under rootdir but not under a cwd of
    ``tests/``.  Accepting it would mean the validator tries both bases, which
    would let a wrong-but-plausible path through and boot the fleet for a
    session pytest cannot collect.
    """
    root, tests = _tree(tmp_path)
    with pytest.raises(pytest.UsageError):
        conftest_part2._validate_requested_paths(
            _config(["tests/test_leaf.py"], invocation_dir=tests, rootpath=root)
        )


def test_node_id_suffix_cannot_smuggle_a_nonexistent_file_through(tmp_path):
    """``::`` splitting must not become a way to skip the existence check."""
    root, tests = _tree(tmp_path)
    with pytest.raises(pytest.UsageError) as excinfo:
        conftest_part2._validate_requested_paths(
            _config(["test_gone.py::test_ok"], invocation_dir=tests, rootpath=root)
        )
    assert "test_gone.py" in str(excinfo.value)
    assert "::test_ok" not in str(excinfo.value)


def test_traversal_outside_the_tree_is_rejected_when_it_does_not_exist(tmp_path):
    """``../`` escapes are resolved, not trusted — a miss is still a miss."""
    root, tests = _tree(tmp_path)
    with pytest.raises(pytest.UsageError):
        conftest_part2._validate_requested_paths(
            _config(["../../etc/test_nope.py"], invocation_dir=tests, rootpath=root)
        )


def test_the_asan_lane_still_drives_pytest_from_the_tests_directory():
    """The regression is only fixed while asan keeps invoking from ``tests/``.

    If that lane ever moves its cwd, this test fails loudly rather than letting
    the validator's resolution base silently stop matching the caller.
    """
    asan = Path(__file__).resolve().parents[1] / "tools" / "ci" / "asan.py"
    source = asan.read_text()
    assert "test_sanitizer_smoke.py" in source
    assert "cwd=tests" in source
