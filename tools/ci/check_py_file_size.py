#!/usr/bin/env python3
#
# WHAT: Fail CI when any Python file under tests/ (incl. tests/cmdscripts/),
#       utils/, or tools/ exceeds the size cap (600 LOGICAL lines — non-blank
#       physical lines, the same metric tests/cmdscripts/lint_loc.py already uses
#       for Python at its 800 tier), UNLESS the file is an accepted, frozen
#       exception recorded in py_file_size_backlog.txt.
#
# WHY:  Python file size was gated only at lint_loc's 800 hard tier and only over
#       tests/+utils/ — tools/ was ungated and there was no 600 ratchet at all
#       (phase-103 §5.1). This is the Python twin of check_file_size.py: it caps at
#       the same 600 the C tree lives under, so an 800-line test module can no
#       longer creep in unreviewed. Same ratchet contract: grandfathered files may
#       only SHRINK; nothing NEW may cross the cap and no offender may GROW.
#
# HOW:  Logical LoC = non-blank physical lines (docstrings/comments-in-Python are
#       counted the same way lint_loc counts them — its comment regex is C-only, so
#       for Python "logical" is just "non-blank"; keeping one metric avoids drift).
#       The backlog stores "path<TAB>loc". Then:
#         - live file over the cap, not in backlog        -> FAIL (new offender)
#         - live file larger than its recorded loc         -> FAIL (grew)
#         - live file <= recorded loc                      -> OK   (shrinking is good)
#       Run with --regen ONLY after a deliberate, reviewed split.
#
# USAGE:
#   tools/ci/check_py_file_size.py          # check (CI mode); non-zero exit on fail
#   tools/ci/check_py_file_size.py --regen  # rewrite the backlog from the live tree

import os
import sys
from pathlib import Path

CAP = 600
ROOT = Path(__file__).resolve().parents[2]
BACKLOG = ROOT / "tools/ci/py_file_size_backlog.txt"

# The Python trees CI cares about. tests/cmdscripts/ lives under tests/.
_ROOTS = ("tests", "utils", "tools")


def _logical_loc(path: Path) -> int:
    """Non-blank physical lines — matches lint_loc.py's Python size metric."""
    return sum(
        1
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    )


def list_oversized(root: Path = ROOT) -> list[tuple[str, int]]:
    """(repo-relative path, logical-loc) for every *.py above the cap in the Python
    trees, sorted by codepoint (LC_ALL=C) so the ratchet compare and --regen output
    are deterministic. __pycache__ is skipped (generated)."""
    rows: list[tuple[str, int]] = []
    for top in _ROOTS:
        base = root / top
        if not base.is_dir():
            continue
        for f in base.rglob("*.py"):
            if f.is_file() and "__pycache__" not in f.parts:
                rows.append((f.relative_to(root).as_posix(), _logical_loc(f)))
    rows = [(path, loc) for path, loc in rows if loc > CAP]
    return sorted(rows, key=lambda r: f"{r[0]}\t{r[1]}")


def read_backlog() -> dict[str, int]:
    """key "path" -> frozen loc ceiling."""
    frozen: dict[str, int] = {}
    for line in BACKLOG.read_text().splitlines():
        if not line.strip():
            continue
        path, _, loc = line.partition("\t")
        frozen[path] = int(loc)
    return frozen


def regen() -> int:
    rows = list_oversized()
    BACKLOG.write_text("".join(f"{path}\t{loc}\n" for path, loc in rows))
    print(f"check_py_file_size: regenerated {BACKLOG} ({len(rows)} entries)")
    return 0


def check() -> int:
    if not BACKLOG.is_file():
        print(f"check_py_file_size: FAIL — backlog missing: {BACKLOG}", file=sys.stderr)
        return 1
    frozen = read_backlog()
    fail_lines: list[str] = []
    for path, loc in list_oversized():
        recorded = frozen.get(path)
        if recorded is None:
            fail_lines.append(
                f"FAIL new oversized file: {path} ({loc} > {CAP} logical) "
                f"— split it (coding-standards §1)"
            )
        elif loc > recorded:
            fail_lines.append(
                f"FAIL grew past frozen ceiling: {path} ({loc} > recorded {recorded})"
            )
    for line in fail_lines:
        print(line)
    if not fail_lines:
        print(f"check_py_file_size: OK (no new or growing .py over {CAP} logical LOC)")
        return 0
    print(
        "check_py_file_size: to accept a deliberate reduction, run: "
        "tools/ci/check_py_file_size.py --regen",
        file=sys.stderr,
    )
    return 1


def main() -> int:
    os.chdir(ROOT)
    if "--regen" in sys.argv[1:]:
        return regen()
    return check()


if __name__ == "__main__":
    sys.exit(main())
