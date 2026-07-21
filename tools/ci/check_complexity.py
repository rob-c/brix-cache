#!/usr/bin/env python3
#
# WHAT: Fail CI when any function under src/ or client/ exceeds the cyclomatic
#       complexity cap (CCN 15 — the standard "needs refactoring" threshold and
#       lizard's own default warning level), UNLESS that function is an accepted,
#       frozen exception recorded in complexity_backlog.txt.
#
# WHY:  High branch density is the #1 readability killer, but it was only ever
#       caught by eye in review. This guard ratchets it exactly like the
#       file-size guard (check_file_size.py): existing over-cap functions are
#       grandfathered and may only get SIMPLER; nothing NEW is allowed to cross
#       the cap, and no grandfathered function may get MORE complex. That turns
#       "a reviewer must notice a 90-branch function" into red/green.
#
# HOW:  Complexity is measured by `lizard` (McCabe analyzer). tools/readability.py
#       is the single lizard front-end; this guard imports it in-process to get
#       "file, func, ccn" for every function over the cap. The backlog stores those
#       same rows as "path::func<TAB>ccn". Then:
#         - live function over the cap, not in backlog   -> FAIL (new offender)
#         - live function above its recorded ccn          -> FAIL (grew)
#         - live function <= recorded ccn                 -> OK   (simplifying is good)
#       Run with --regen ONLY after a deliberate, reviewed simplification so the
#       frozen ceiling ratchets downward.
#
# USAGE:
#   tools/ci/check_complexity.py          # check (CI mode); non-zero exit on failure
#   tools/ci/check_complexity.py --regen  # rewrite the backlog from the live tree
#
# Requires: lizard  (pip install --user lizard)

import os
import sys
from pathlib import Path

# tools/readability.py owns lizard invocation + robust CSV parsing (lizard's
# signature column contains commas/quotes) and the CCN cap — reuse it verbatim
# so this guard and `readability.py --gate-csv` can never drift.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import readability  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
BACKLOG = ROOT / "tools/ci/complexity_backlog.txt"


def gate_rows() -> list[tuple[str, str, int]]:
    """(file, func, ccn) for every function over the CCN cap, sorted by identity
    so both the ratchet compare and --regen output are deterministic — the same
    rows, in the same order, as `readability.py --gate-csv`."""
    lizard = readability.find_lizard()
    funcs = readability.run_lizard(lizard, ["src", "client"])
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
    print(f"check_complexity: regenerated {BACKLOG} ({len(rows)} entries)")
    return 0


def check() -> int:
    if not BACKLOG.is_file():
        print(f"check_complexity: FAIL — backlog missing: {BACKLOG}", file=sys.stderr)
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
        print("check_complexity: OK (no new or growing functions over CCN 15)")
        return 0
    print("check_complexity: to accept a deliberate simplification, run: "
          "tools/ci/check_complexity.py --regen", file=sys.stderr)
    return 1


def main() -> int:
    # Run from the repo root so lizard's "src"/"client" paths — and the file
    # column it reports — line up with the backlog keys regardless of cwd.
    os.chdir(ROOT)
    if "--regen" in sys.argv[1:]:
        return regen()
    return check()


if __name__ == "__main__":
    sys.exit(main())
