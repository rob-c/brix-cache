#!/usr/bin/env bash
#
# WHAT: Fail CI when any file under src/ exceeds the soft size cap
#       (coding-standards.md §1, "~500 lines" — one concept per file), UNLESS the
#       file is an accepted, frozen exception recorded in file_size_backlog.txt.
#
# WHY:  The ~500-line rule was documented but human-enforced — reviewers had to
#       notice size drift by eye. This guard ratchets it, mirroring the vfs-seam
#       backlog pattern: existing offenders are grandfathered and may only SHRINK;
#       nothing NEW is allowed to cross the cap, and no existing offender may GROW.
#       That converts "a reviewer must remember to check file size" into red/green.
#
# HOW:  The backlog holds "path<TAB>loc" for every file currently over the cap.
#         - live file over the cap, not in backlog        -> FAIL (new offender)
#         - live file larger than its recorded loc         -> FAIL (grew)
#         - live file <= recorded loc                      -> OK   (shrinking is good)
#       Run with --regen ONLY after a deliberate, reviewed change to lower entries
#       (e.g. after splitting a file) so the frozen ceiling ratchets downward.
#
# USAGE:
#   tools/ci/check_file_size.sh            # check (CI mode); non-zero exit on failure
#   tools/ci/check_file_size.sh --regen    # rewrite the backlog from the live tree
#
set -euo pipefail

CAP=500
ROOT="$(git rev-parse --show-toplevel)"
BACKLOG="$ROOT/tools/ci/file_size_backlog.txt"
MODE="${1:-check}"

# Emit "path<TAB>loc" (repo-relative) for every src file above the cap, sorted.
list_oversized() {
    find "$ROOT/src" \( -name '*.c' -o -name '*.h' \) -print | while read -r f; do
        n=$(wc -l < "$f")
        if [ "$n" -gt "$CAP" ]; then
            printf '%s\t%d\n' "${f#"$ROOT"/}" "$n"
        fi
    done | sort
}

if [ "$MODE" = "--regen" ]; then
    list_oversized > "$BACKLOG"
    echo "check_file_size: regenerated $BACKLOG ($(wc -l < "$BACKLOG") entries)"
    exit 0
fi

if [ ! -f "$BACKLOG" ]; then
    echo "check_file_size: FAIL — backlog missing: $BACKLOG" >&2
    exit 1
fi

fail=0
while IFS=$'\t' read -r path loc; do
    recorded="$(awk -F'\t' -v p="$path" '$1==p {print $2}' "$BACKLOG")"
    if [ -z "$recorded" ]; then
        echo "FAIL new oversized file: $path ($loc > $CAP) — split it (coding-standards §1)"
        fail=1
    elif [ "$loc" -gt "$recorded" ]; then
        echo "FAIL grew past frozen ceiling: $path ($loc > recorded $recorded)"
        fail=1
    fi
done < <(list_oversized)

if [ "$fail" -eq 0 ]; then
    echo "check_file_size: OK (no new or growing files over $CAP LOC)"
else
    echo "check_file_size: to accept a deliberate reduction, run: tools/ci/check_file_size.sh --regen" >&2
    exit 1
fi
