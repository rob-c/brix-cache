#!/usr/bin/env bash
#
# WHAT: Fail CI when lizard's copy-paste detector (-Eduplicate) finds a
#       duplicated code block across src/, client/ or shared/ that is NOT an
#       accepted, frozen exception recorded in duplication_backlog.txt.
#
# WHY:  Copy-paste is how helper reimplementation (a HARD BLOCK — see CLAUDE.md
#       HELPERS) actually happens: a block is cloned, then the copies drift.
#       Like the complexity guard (check_complexity.sh) this ratchets: existing
#       duplicate blocks are grandfathered; nothing NEW may be pasted, and a
#       fixed duplication may only be ratcheted OUT of the backlog, never back
#       in. That turns "a reviewer must spot 30 cloned lines" into red/green.
#
# HOW:  `lizard -Eduplicate` is run over src/, client/ and shared/ SEPARATELY
#       (one combined invocation over all three trees emits no duplicate output
#       on this box) and the results merged. Each "Duplicate block:" stanza is
#       a set of "path:start ~ end" member lines terminated by a ^^^^ rule.
#       Each block becomes a churn-stable-ish key: member tuples sorted and
#       joined as "path:start-end+path:start-end+...". Then:
#         - live block whose key is not in the backlog -> FAIL (new duplication)
#         - backlog block no longer live               -> OK (fixed; --regen
#           ratchets it out)
#       KNOWN LIMIT (v1): the key embeds line numbers, so unrelated edits that
#       shift a grandfathered block will surface it as "new". That is a signal
#       to look at it (and either fix it or --regen), not a bug in the guard.
#       Run with --regen ONLY after a deliberate, reviewed change so the
#       frozen set ratchets downward.
#
# USAGE:
#   tools/ci/check_duplication.sh          # check (CI mode); non-zero exit on failure
#   tools/ci/check_duplication.sh --regen  # rewrite the backlog from the live tree
#
# Requires: lizard  (pip install --user lizard)
#
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
BACKLOG="$ROOT/tools/ci/duplication_backlog.txt"
MODE="${1:-check}"
TREES=(src client shared)

if ! command -v lizard >/dev/null 2>&1; then
    echo "check_duplication: FAIL — lizard not found (pip install --user lizard)" >&2
    exit 1
fi

# Emit one line per live duplicate block: the sorted, '+'-joined member key
# "path:start-end+path:start-end". Runs lizard per tree (see HOW) and dedups
# (lizard sometimes emits the same stanza twice).
list_duplicates() {
    (
        cd "$ROOT"
        for tree in "${TREES[@]}"; do
            # lizard exits non-zero whenever any function trips its own CCN
            # warning threshold; that is check_complexity.sh's job, not ours.
            lizard -Eduplicate "$tree" 2>/dev/null || true
        done
    ) | awk '
        /^Duplicate block:/ { inblock = 1; n = 0; next }
        inblock && /^\^\^\^/ {
            # end of stanza: sort members, join with "+"
            for (i = 1; i <= n; i++)
                for (j = i + 1; j <= n; j++)
                    if (m[j] < m[i]) { t = m[i]; m[i] = m[j]; m[j] = t }
            key = m[1]
            for (i = 2; i <= n; i++) key = key "+" m[i]
            print key
            inblock = 0
            next
        }
        inblock && match($0, /^(.+):([0-9]+) ~ ([0-9]+)$/) {
            path = $0; sub(/:[0-9]+ ~ [0-9]+$/, "", path)
            split($0, a, /[: ]/)
            start = a[length(a) - 2]; end = a[length(a)]
            m[++n] = path ":" start "-" end
        }
    ' | sort -u
}

if [ "$MODE" = "--regen" ]; then
    list_duplicates > "$BACKLOG"
    echo "check_duplication: regenerated $BACKLOG ($(wc -l < "$BACKLOG") entries)"
    exit 0
fi

if [ ! -f "$BACKLOG" ]; then
    echo "check_duplication: FAIL — backlog missing: $BACKLOG" >&2
    exit 1
fi

fail=0
while IFS= read -r key; do
    if ! grep -qxF "$key" "$BACKLOG"; then
        echo "FAIL new duplicated block — extract a shared helper (coding-standards §8):"
        echo "$key" | tr '+' '\n' | sed 's/^/    /'
        fail=1
    fi
done < <(list_duplicates)

if [ "$fail" -eq 0 ]; then
    echo "check_duplication: OK (no duplicate blocks outside the frozen backlog)"
else
    echo "check_duplication: if a grandfathered block merely SHIFTED (line-number churn), or after a deliberate reviewed fix, run: tools/ci/check_duplication.sh --regen" >&2
    exit 1
fi
