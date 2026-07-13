#!/usr/bin/env bash
#
# WHAT: Fail CI when any function under src/ or client/ exceeds the cyclomatic
#       complexity cap (CCN 15 — the standard "needs refactoring" threshold and
#       lizard's own default warning level), UNLESS that function is an accepted,
#       frozen exception recorded in complexity_backlog.txt.
#
# WHY:  High branch density is the #1 readability killer, but it was only ever
#       caught by eye in review. This guard ratchets it exactly like the
#       file-size guard (check_file_size.sh): existing over-cap functions are
#       grandfathered and may only get SIMPLER; nothing NEW is allowed to cross
#       the cap, and no grandfathered function may get MORE complex. That turns
#       "a reviewer must notice a 90-branch function" into red/green.
#
# HOW:  Complexity is measured by `lizard` (McCabe analyzer); tools/readability.py
#       --gate-csv is the single lizard/CSV front-end and emits, deterministically,
#       "file,func,ccn" for every function over the cap. The backlog stores those
#       same rows as "path::func<TAB>ccn". Then:
#         - live function over the cap, not in backlog   -> FAIL (new offender)
#         - live function above its recorded ccn          -> FAIL (grew)
#         - live function <= recorded ccn                 -> OK   (simplifying is good)
#       Run with --regen ONLY after a deliberate, reviewed simplification so the
#       frozen ceiling ratchets downward.
#
# USAGE:
#   tools/ci/check_complexity.sh          # check (CI mode); non-zero exit on failure
#   tools/ci/check_complexity.sh --regen  # rewrite the backlog from the live tree
#
# Requires: lizard  (pip install --user lizard)
#
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
BACKLOG="$ROOT/tools/ci/complexity_backlog.txt"
READABILITY="$ROOT/tools/readability.py"
MODE="${1:-check}"

# Emit "path::func<TAB>ccn" for every function over the CCN cap, sorted.
# readability.py --gate-csv owns lizard invocation + robust CSV parsing (lizard's
# signature column contains commas/quotes that bash cannot safely split).
list_complex() {
    "$READABILITY" --gate-csv src client \
        | awk -F',' '{printf "%s::%s\t%s\n", $1, $2, $3}' \
        | sort
}

if [ "$MODE" = "--regen" ]; then
    list_complex > "$BACKLOG"
    echo "check_complexity: regenerated $BACKLOG ($(wc -l < "$BACKLOG") entries)"
    exit 0
fi

if [ ! -f "$BACKLOG" ]; then
    echo "check_complexity: FAIL — backlog missing: $BACKLOG" >&2
    exit 1
fi

fail=0
while IFS=$'\t' read -r key ccn; do
    recorded="$(awk -F'\t' -v k="$key" '$1==k {print $2}' "$BACKLOG")"
    if [ -z "$recorded" ]; then
        echo "FAIL new over-complex function: $key (CCN $ccn > 15) — decompose it (coding-standards §4/§8)"
        fail=1
    elif [ "$ccn" -gt "$recorded" ]; then
        echo "FAIL grew past frozen ceiling: $key (CCN $ccn > recorded $recorded)"
        fail=1
    fi
done < <(list_complex)

if [ "$fail" -eq 0 ]; then
    echo "check_complexity: OK (no new or growing functions over CCN 15)"
else
    echo "check_complexity: to accept a deliberate simplification, run: tools/ci/check_complexity.sh --regen" >&2
    exit 1
fi
