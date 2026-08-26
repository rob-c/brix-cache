#!/usr/bin/env python3
#
# WHAT: Fail CI when any Python file under tests/ (incl. tests/cmdscripts/),
#       utils/, or tools/ exceeds the size cap (600 LOGICAL lines — non-blank
#       physical lines, the same metric tests/cmdscripts/lint_loc.py already uses
#       for Python at its 800 tier).
#
# WHY:  Python file size was gated only at lint_loc's 800 hard tier and only over
#       tests/+utils/ — tools/ was ungated and there was no 600-line cap at all
#       (phase-103 §5.1). This is the Python twin of check_file_size.py: it caps at
#       the same 600 the C tree lives under, so an 800-line test module can no
#       longer creep in unreviewed. Every over-cap file fails unconditionally.
#
# HOW:  Logical LoC = non-blank physical lines (docstrings/comments-in-Python are
#       counted the same way lint_loc counts them — its comment regex is C-only, so
#       for Python "logical" is just "non-blank"; keeping one metric avoids drift).
#       Every file over CAP is reported as a failure; no exception list exists.
#
# USAGE:
#   tools/ci/check_py_file_size.py          # check (CI mode); non-zero exit on fail

import os
import sys
from pathlib import Path

CAP = 600
ROOT = Path(__file__).resolve().parents[2]

# The Python trees CI cares about. tests/cmdscripts/ lives under tests/.
_ROOTS = ("tests", "utils", "tools")


def _logical_loc(path: Path) -> int:
    """Non-blank physical lines — matches lint_loc.py's Python size metric."""
    return sum(
        1
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    )


def _tree_sizes(root: Path, top: str) -> list[tuple[str, int]]:
    """(repo-relative path, logical-loc) for every hand-written *.py under
    root/top; __pycache__ is skipped (generated)."""
    base = root / top
    if not base.is_dir():
        return []
    return [(f.relative_to(root).as_posix(), _logical_loc(f))
            for f in base.rglob("*.py")
            if f.is_file() and "__pycache__" not in f.parts]


def list_oversized(root: Path = ROOT) -> list[tuple[str, int]]:
    """(repo-relative path, logical-loc) for every *.py above the cap in the Python
    trees, sorted by codepoint (LC_ALL=C) for deterministic diagnostics."""
    rows: list[tuple[str, int]] = []
    for top in _ROOTS:
        rows.extend(_tree_sizes(root, top))
    rows = [(path, loc) for path, loc in rows if loc > CAP]
    return sorted(rows, key=lambda r: f"{r[0]}\t{r[1]}")


def check() -> int:
    fail_lines = [
        f"FAIL oversized file: {path} ({loc} > {CAP} logical) "
        f"— split it (coding-standards §1)"
        for path, loc in list_oversized()
    ]
    for line in fail_lines:
        print(line)
    if not fail_lines:
        print(f"check_py_file_size: OK (no .py files over {CAP} logical LOC)")
        return 0
    return 1


def main() -> int:
    os.chdir(ROOT)
    return check()


if __name__ == "__main__":
    sys.exit(main())
