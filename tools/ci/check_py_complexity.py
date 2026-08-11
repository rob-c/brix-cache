#!/usr/bin/env python3
#
# WHAT: Fail CI when any Python function under tests/ (incl. tests/cmdscripts/),
#       utils/, or tools/ exceeds the cyclomatic complexity cap (CCN 15 — the same
#       "needs refactoring" threshold the C guard enforces), UNLESS that function
#       is an accepted, frozen exception recorded in py_complexity_backlog.txt.
#
# WHY:  Python complexity was the ONE maintainability dimension gated NOWHERE
#       (phase-103 §2.4: 153 functions over CCN 15 across the Python trees, all
#       invisible to CI). The C ratchets (check_complexity.py) proved the pattern;
#       this is its Python twin, so a 39-branch response encoder or a 30-branch
#       fixture builder can no longer land unnoticed. Same ratchet contract:
#       grandfathered offenders may only get SIMPLER; nothing NEW may cross the cap
#       and no grandfathered function may get MORE complex.
#
# HOW:  Complexity is measured by `lizard` (McCabe analyzer) via the shared
#       tools/readability.py front-end, invoked with lang="python". The backlog
#       stores "path::func<TAB>ccn". Then:
#         - live function over the cap, not in backlog   -> FAIL (new offender)
#         - live function above its recorded ccn          -> FAIL (grew)
#         - live function <= recorded ccn                 -> OK   (simplifying is good)
#       Run with --regen ONLY after a deliberate, reviewed simplification so the
#       frozen ceiling ratchets downward.
#
# USAGE:
#   tools/ci/check_py_complexity.py          # check (CI mode); non-zero exit on fail
#   tools/ci/check_py_complexity.py --regen  # rewrite the backlog from the live tree
#
# Requires: lizard  (pip install --user lizard)

import os
import sys
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
BACKLOG = ROOT / "tools/ci/py_complexity_backlog.txt"

# The Python trees CI cares about. tests/cmdscripts/ lives under tests/, so scanning
# "tests" covers it; utils/ and tools/ hold the operator + CI tooling.
_ROOTS = ["tests", "utils", "tools"]


def gate_rows() -> list[tuple[str, str, int]]:
    """(file, func, ccn) for every Python function over the CCN cap, sorted by
    identity so both the ratchet compare and --regen output are deterministic."""
    lizard = readability.find_lizard()
    funcs = readability.run_lizard(lizard, _ROOTS, lang="python")
    rows = [
        (f["file"], f["func"], f["ccn"])
        for f in funcs
        if f["ccn"] > readability.CCN_MAX
    ]
    return sorted(rows, key=lambda r: (r[0], r[1], -r[2]))


def read_backlog() -> dict[str, int]:
    """key "path::func" -> frozen ccn ceiling."""
    frozen: dict[str, int] = {}
    for line in BACKLOG.read_text().splitlines():
        if not line.strip():
            continue
        key, _, ccn = line.partition("\t")
        frozen[key] = int(ccn)
    return frozen


def regen() -> int:
    rows = gate_rows()
    BACKLOG.write_text("".join(f"{file}::{func}\t{ccn}\n" for file, func, ccn in rows))
    print(f"check_py_complexity: regenerated {BACKLOG} ({len(rows)} entries)")
    return 0


def check() -> int:
    if not BACKLOG.is_file():
        print(f"check_py_complexity: FAIL — backlog missing: {BACKLOG}", file=sys.stderr)
        return 1

    frozen = read_backlog()
    fail = False
    for file, func, ccn in gate_rows():
        key = f"{file}::{func}"
        recorded = frozen.get(key)
        if recorded is None:
            print(f"FAIL new over-complex function: {key} "
                  f"(CCN {ccn} > {readability.CCN_MAX}) — decompose it (coding-standards §4/§8)")
            fail = True
        elif ccn > recorded:
            print(f"FAIL grew past frozen ceiling: {key} (CCN {ccn} > recorded {recorded})")
            fail = True

    if not fail:
        print("check_py_complexity: OK (no new or growing Python functions over CCN 15)")
        return 0
    print("check_py_complexity: to accept a deliberate simplification, run: "
          "tools/ci/check_py_complexity.py --regen", file=sys.stderr)
    return 1


def main() -> int:
    # Run from the repo root so lizard's root paths — and the file column it reports
    # — line up with the backlog keys regardless of cwd.
    os.chdir(ROOT)
    if "--regen" in sys.argv[1:]:
        return regen()
    return check()


if __name__ == "__main__":
    sys.exit(main())
