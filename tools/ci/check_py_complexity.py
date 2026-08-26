#!/usr/bin/env python3
#
# WHAT: Fail CI when any Python function under tests/ (incl. tests/cmdscripts/),
#       utils/, or tools/ exceeds the cyclomatic complexity cap (CCN 15 — the same
#       "needs refactoring" threshold the C guard enforces).
#
# WHY:  Python complexity was the ONE maintainability dimension gated NOWHERE
#       (phase-103 §2.4: 153 functions over CCN 15 across the Python trees, all
#       invisible to CI). The C guard (check_complexity.py) proved the pattern;
#       this is its Python twin, so every over-cap function fails directly.
#
# HOW:  Complexity is measured by `lizard` (McCabe analyzer) via the shared
#       tools/readability.py front-end, invoked with lang="python". The backlog
#       reports every function above the cap; no exception list exists.
#
# USAGE:
#   tools/ci/check_py_complexity.py          # check (CI mode); non-zero exit on fail
#
# Requires: lizard  (pip install --user lizard)

import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# tools/readability.py owns lizard invocation + robust CSV parsing and the CCN cap
# — reuse it verbatim so this guard and check_complexity.py can never drift. The
# import-failure guidance mirrors check_complexity.py (CI builds from a fresh clone;
# a missing readability.py reads as "the guard is broken", so name the real cause).
_TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_TOOLS))
try:
    import readability  # noqa: E402
except ModuleNotFoundError as exc:            # pragma: no cover - CI-only path
    if exc.name != "readability":
        raise
    print(f"check_py_complexity: FAIL — its lizard engine {_TOOLS / 'readability.py'} "
          "is missing. This guard cannot measure anything without it. On CI that "
          "means the file exists in a working tree but was never committed: run "
          "`git status --porcelain tools/readability.py` and add it.",
          file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[2]

# The Python trees CI cares about. tests/cmdscripts/ lives under tests/, so scanning
# "tests" covers it; utils/ and tools/ hold the operator + CI tooling.
_ROOTS = ["tests", "utils", "tools"]


def gate_rows() -> list[tuple[str, str, int]]:
    """(file, func, ccn) for every Python function over the CCN cap, sorted by
    identity so diagnostics are deterministic."""
    lizard = readability.find_lizard()
    with ThreadPoolExecutor(max_workers=len(_ROOTS)) as pool:
        batches = pool.map(
            lambda root: readability.run_lizard(lizard, [root], lang="python"),
            _ROOTS,
        )
        funcs = [func for batch in batches for func in batch]
    rows = [
        (f["file"], f["func"], f["ccn"])
        for f in funcs
        if f["ccn"] > readability.CCN_MAX
    ]
    return sorted(rows, key=lambda r: (r[0], r[1], -r[2]))


def check() -> int:
    fail = False
    for file, func, ccn in gate_rows():
        key = f"{file}::{func}"
        print(f"FAIL over-complex function: {key} "
              f"(CCN {ccn} > {readability.CCN_MAX}) — decompose it (coding-standards §4/§8)")
        fail = True

    if not fail:
        print("check_py_complexity: OK (no Python functions over CCN 15)")
        return 0
    return 1


def main() -> int:
    # Run from the repo root so lizard's root paths — and the file column it reports
    # — line up with the backlog keys regardless of cwd.
    os.chdir(ROOT)
    return check()


if __name__ == "__main__":
    sys.exit(main())
