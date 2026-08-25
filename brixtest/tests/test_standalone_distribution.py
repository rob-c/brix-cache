"""BriXTest remains usable after removal from its host repository."""

import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _ignore(_directory, names):
    discarded = {"__pycache__", ".pytest_cache", ".complexipy_cache"}
    return discarded & set(names)


def test_complete_subproject_has_no_host_repository_import_or_symlink():
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "check_standalone.py")],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_copied_subproject_imports_without_host_repository(tmp_path):
    copied = tmp_path / "brixtest"
    shutil.copytree(ROOT, copied, ignore=_ignore)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(copied / "src")
    result = subprocess.run(
        [sys.executable, "-c", "import brixtest; print(brixtest.__version__)"],
        cwd=tmp_path, env=environment, capture_output=True, text=True,
        check=False, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "0.15.0"
