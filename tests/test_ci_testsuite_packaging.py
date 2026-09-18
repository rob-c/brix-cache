"""BriXTest packaging boundary: pure imports, manifests, and a biting guard.

`brixtest` is the standalone distribution; `brix_suite` is the repository-side
adapter. Imports remain side-effect free, the dependency guard learns the
pyproject, and undeclared package dependencies still fail.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest
from lib_py.util import budget_scale

_REPO = Path(__file__).resolve().parents[1]
_SRC = _REPO / "brixtest" / "src"
_ADAPTER = _REPO / "tests"


def _load_deps_guard():
    spec = importlib.util.spec_from_file_location(
        "check_python_deps", _REPO / "tools/ci/check_python_deps.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_import_brixtest_is_side_effect_free():
    code = (
        "import os, sys\n"
        "env = dict(os.environ)\n"
        "before = set(sys.modules)\n"
        "import brixtest\n"
        "import brix_suite\n"
        "assert dict(os.environ) == env, 'import mutated the environment'\n"
        "leaked = [m for m in set(sys.modules) - before\n"
        "          if not m.startswith(('brixtest', 'brix_suite'))\n"
        "          and m not in sys.stdlib_module_names\n"
        "          and not m.split('.')[0] in sys.stdlib_module_names]\n"
        "assert not leaked, 'import dragged in: %s' % leaked\n"
        "assert brixtest.__version__ and brix_suite.__version__\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        env={"PYTHONPATH": str(_SRC) + ":" + str(_ADAPTER), "PATH": "/usr/bin:/bin"},
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_distribution_contains_only_the_standalone_core():
    manifest = (_REPO / "brixtest" / "pyproject.toml").read_text()
    assert 'packages = ["src/brixtest"]' in manifest
    assert 'src/brix_suite' not in manifest
    assert not (_SRC / "brix_suite").exists()
    assert (_ADAPTER / "brix_suite").is_dir()


def test_deps_guard_reads_pyproject_with_lane_precedence():
    guard = _load_deps_guard()
    lanes, findings = guard._declared(_REPO)
    assert not findings, findings
    # declared in requirements.txt (required) AND the pyproject xdist
    # extra (optional): the stronger claim must hold
    assert lanes.get("pytest-xdist") == "required"
    assert lanes.get("pytest") == "required"
    # extras reserved by the charter parse with their bounds intact
    assert lanes.get("cryptography") == "required"  # requirements.txt wins
    assert lanes.get("botocore") == "optional"  # optional in both manifests


# Same xdist group as tests/test_ci_guards.py's guard cells: the probe below
# plants a deliberately-undeclared import INSIDE the scanned tree, so while it
# exists any concurrent run of the real check_python_deps guard fails on it
# (measured: test_ci_guard_green[check_python_deps] failed with
# "_deps_probe_tmp.py imports totally_undeclared_dist").  One group = one
# worker = the two can never overlap.
# The guards this file drives scan the whole tree; that is seconds on the CI
# host but minutes inside an 8-worker lane, so the budget scales with the host
# exactly as the other ci-guards file does.
pytestmark = [pytest.mark.xdist_group("ci-guards"),
              pytest.mark.timeout(300 * budget_scale())]


def test_deps_guard_catches_undeclared_import_in_package(tmp_path):
    probe = _SRC / "brixtest" / "_deps_probe_tmp.py"
    probe.write_text("import totally_undeclared_dist\n")
    try:
        proc = subprocess.run(
            [sys.executable, str(_REPO / "tools/ci/check_python_deps.py")],
            capture_output=True, text=True,
        )
    finally:
        probe.unlink()
    assert proc.returncode != 0, "guard missed an undeclared package import"
    assert "totally_undeclared_dist" in proc.stdout + proc.stderr


def _build_hook_tree(tmp_path, *, requires='"hatchling>=1.25,<2"',
                     hook="hatch_build.py", section="targets.sdist.hooks.custom",
                     backend="hatchling.build", source="import hatchling\n"):
    """Construct a packaging manifest and imports without modifying the checkout."""
    guard = _load_deps_guard()
    for relative, lane in guard.REQ_FILES.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("lizard>=1.17,<2\n" if lane == "dev" else "")
    manifest = tmp_path / "brixtest/pyproject.toml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        '[project]\nname = "example"\nversion = "0"\ndependencies = []\n'
        f'[build-system]\nrequires = [\n{requires}\n]\nbuild-backend = "{backend}"\n'
        f'[tool.hatch.build.{section}]\npath = "{hook}"\n'
    )
    target = manifest.parent / hook
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source)
    return guard, tmp_path


@pytest.mark.parametrize("legacy_parser", [False, True])
@pytest.mark.parametrize("hook,section", [
    ("hatch_build.py", "targets.sdist.hooks.custom"),
    ("tools/package_hook.py", "targets.sdist.hooks.custom"),
    ("hatch_build.py", "hooks.custom"),
])
def test_build_hook_uses_declared_build_environment(tmp_path, monkeypatch,
                                                   legacy_parser, hook, section):
    guard, root = _build_hook_tree(tmp_path, hook=hook, section=section)
    if legacy_parser:
        monkeypatch.setitem(sys.modules, "tomllib", None)
    lanes, findings = guard._declared(root)
    assert not findings, findings
    assert lanes["hatchling"] == "dev", "build tooling must not become a runtime dependency"
    ok, findings = guard.run(root)
    assert ok, findings


def test_build_hook_default_filename_is_declared_by_custom_table(tmp_path):
    guard, root = _build_hook_tree(tmp_path)
    manifest = root / "brixtest/pyproject.toml"
    manifest.write_text(manifest.read_text().replace('path = "hatch_build.py"\n', ""))
    ok, findings = guard.run(root)
    assert ok, findings


@pytest.mark.parametrize("relative", [
    "tests/test_consumer.py", "brixtest/tests/test_consumer.py",
    "brixtest/src/example/consumer.py", "tools/ordinary_tool.py", "conftest.py",
])
def test_build_hook_does_not_allow_dev_imports_elsewhere(tmp_path, relative):
    guard, root = _build_hook_tree(tmp_path)
    consumer = root / relative
    consumer.parent.mkdir(parents=True, exist_ok=True)
    consumer.write_text("def consumer():\n    import hatchling\n")
    ok, findings = guard.run(root)
    assert not ok
    assert any(relative in row and "dev tooling" in row for row in findings), findings


@pytest.mark.parametrize("source,requires,dependency", [
    ("import hatchling\n", "", "hatchling"),
    ("import lizard\n", '"hatchling>=1.25,<2"', "lizard"),
    ("import undeclared_build_dependency\n", '"hatchling>=1.25,<2"',
     "undeclared_build_dependency"),
])
def test_build_hook_rejects_imports_outside_build_requires(tmp_path, source,
                                                         requires, dependency):
    guard, root = _build_hook_tree(tmp_path, source=source, requires=requires)
    ok, findings = guard.run(root)
    assert not ok
    assert any(dependency in row and "no requirements file declares" in row
               for row in findings), findings


def test_build_hook_cannot_use_runtime_dependency_missing_from_build_requires(tmp_path):
    guard, root = _build_hook_tree(tmp_path, source="import requests\n")
    (root / "requirements.txt").write_text("requests>=2.25,<3\n")
    ok, findings = guard.run(root)
    assert not ok
    assert any("requests" in row and "no requirements file declares" in row
               for row in findings), findings


@pytest.mark.parametrize("requires", ['"hatchling>=1.25"', '"hatchling<2"', '"hatchling"'])
def test_build_hook_requires_two_sided_dependency_bounds(tmp_path, requires):
    guard, root = _build_hook_tree(tmp_path, requires=requires)
    ok, findings = guard.run(root)
    assert not ok
    assert any("[build-system].requires" in row and "bound missing" in row
               for row in findings), findings


@pytest.mark.parametrize("hook", [
    "tests/package_hook.py", "src/example/package_hook.py", "test_hook.py",
    "conftest.py", "tools/hook_test.py", "../tests/package_hook.py",
    "tools/tests/package_hook.py", "tools/package/source.py",
])
def test_build_hook_cannot_reclassify_test_runtime_or_escaped_paths(tmp_path, hook):
    guard, root = _build_hook_tree(tmp_path, hook=hook)
    ok, findings = guard.run(root)
    assert not ok
    assert any("hook must be a non-test Python file" in row for row in findings), findings
    assert any("dev tooling" in row for row in findings), findings


def test_build_hook_cannot_reclassify_symlinked_test_source(tmp_path):
    guard, root = _build_hook_tree(tmp_path)
    target = root / "brixtest/hatch_build.py"
    source = root / "tests/consumer.py"
    source.parent.mkdir(parents=True, exist_ok=True)
    target.rename(source)
    target.symlink_to(source)
    ok, findings = guard.run(root)
    assert not ok
    assert any("hook must be a non-test Python file" in row for row in findings), findings


def test_build_hook_requires_matching_configured_backend(tmp_path):
    guard, root = _build_hook_tree(tmp_path, backend="setuptools.build_meta")
    ok, findings = guard.run(root)
    assert not ok
    assert any("dev tooling" in row for row in findings), findings


def test_build_hook_filename_alone_does_not_classify_tooling(tmp_path):
    guard, root = _build_hook_tree(tmp_path)
    manifest = root / "brixtest/pyproject.toml"
    manifest.write_text(manifest.read_text().split("[tool.hatch.build.")[0])
    ok, findings = guard.run(root)
    assert not ok
    assert any("dev tooling" in row for row in findings), findings


def test_build_hook_legacy_metadata_matches_current_manifest(tmp_path, monkeypatch):
    guard, root = _build_hook_tree(tmp_path)
    manifest = root / "brixtest/pyproject.toml"
    manifest.write_text(manifest.read_text().replace(
        '"hatchling>=1.25,<2"', '"hatchling>=1.25,<2",  # a bounded build requirement'
    ))
    expected = guard._build_tables(manifest)
    monkeypatch.setitem(sys.modules, "tomllib", None)
    assert guard._build_tables(manifest) == expected


def test_build_hook_legacy_metadata_rejects_unsupported_value(tmp_path, monkeypatch):
    guard, root = _build_hook_tree(tmp_path)
    manifest = root / "brixtest/pyproject.toml"
    manifest.write_text(manifest.read_text().replace(
        'path = "hatch_build.py"', 'path = unsupported_expression'
    ))
    monkeypatch.setitem(sys.modules, "tomllib", None)
    with pytest.raises(ValueError, match="unsupported dependency metadata"):
        guard._build_tables(manifest)


@pytest.mark.parametrize("legacy_parser", [False, True])
@pytest.mark.parametrize("guarded", [False, True])
def test_build_hook_real_dev_extra_remains_dev_tooling(monkeypatch, legacy_parser, guarded):
    guard = _load_deps_guard()
    expected = guard._parse_pyproject(_REPO / "brixtest/pyproject.toml")
    if legacy_parser:
        monkeypatch.setitem(sys.modules, "tomllib", None)
    assert guard._parse_pyproject(_REPO / "brixtest/pyproject.toml") == expected
    lanes, findings = guard._declared(_REPO)
    assert not findings, findings
    assert lanes["hatchling"] == "dev"
    finding = guard._import_finding(
        _REPO / "tests/example.py", _REPO, "hatchling", 1, guarded, lanes
    )
    assert "dev tooling" in finding


@pytest.mark.parametrize("legacy_parser", [False, True])
def test_build_hook_pep621_lane_precedence_matches_parsers(tmp_path, monkeypatch, legacy_parser):
    guard, root = _build_hook_tree(tmp_path)
    manifest = root / "brixtest/pyproject.toml"
    manifest.write_text(manifest.read_text().replace(
        "dependencies = []",
        'dependencies = ["required_pkg>=1,<2"]\n'
        '[project.optional-dependencies]\n'
        'feature = ["required_pkg>=1,<2", "optional_pkg>=1,<2"]\n'
        'dev = [\n"required_pkg>=1,<2", "optional_pkg>=1,<2", "dev_pkg>=1,<2",\n'
        '"hatchling>=1.25,<2"\n]'
    ))
    if legacy_parser:
        monkeypatch.setitem(sys.modules, "tomllib", None)
    lanes, findings = guard._declared(root)
    assert not findings, findings
    assert lanes["required-pkg"] == "required"
    assert lanes["optional-pkg"] == "optional"
    assert lanes["dev-pkg"] == "dev"
    _assert_build_tool_rejected_in_consumer(guard, root)


def _assert_build_tool_rejected_in_consumer(guard, root):
    consumer = root / "tests/consumer.py"
    consumer.parent.mkdir(exist_ok=True)
    consumer.write_text("def consumer():\n    import hatchling\n")
    ok, findings = guard.run(root)
    assert not ok
    assert any("consumer.py" in row and "dev tooling" in row for row in findings), findings
