"""Regression tests for the generated storage-driver matrix contract."""

import os
from pathlib import Path
import subprocess
import sys


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "tools/diag/sd_slot_matrix.py"
DOC = REPO / "docs/09-developer-guide/storage-driver-slot-matrix.md"


def _run(doc: Path):
    env = dict(os.environ, BRIX_SD_MATRIX_DOC=str(doc))
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--check"], cwd=REPO, env=env,
        capture_output=True, text=True, timeout=30)


def test_checked_in_storage_driver_matrix_matches_source():
    result = _run(DOC)
    assert result.returncode == 0, result.stdout + result.stderr


def test_matrix_includes_the_function_local_gsiftp_driver():
    text = DOC.read_text()
    assert "| gsiftp |" in text
    assert "63 slots x 13 drivers = 819 cells" in text


def test_storage_driver_matrix_check_rejects_stale_content(tmp_path):
    stale = tmp_path / "matrix.md"
    stale.write_text(DOC.read_text().replace("| `open` | ✅", "| `open` | nil", 1))
    result = _run(stale)
    assert result.returncode == 1
    assert "checked-in matrix is stale" in result.stderr
    assert "generated-from-source" in result.stderr


def test_storage_driver_matrix_check_fails_closed_without_fences(tmp_path):
    malformed = tmp_path / "matrix.md"
    malformed.write_text("| op | posix |\n|---|---|\n")
    result = _run(malformed)
    assert result.returncode == 1
    assert "expected exactly one matrix begin/end fence" in result.stderr
