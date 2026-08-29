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
pytestmark = pytest.mark.xdist_group("ci-guards")


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
