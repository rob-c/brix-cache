#!/usr/bin/env bash
#
# check_readme_coverage.sh — substantial src/ directories must carry a README.
#
# WHAT: Fails (exit 1) when a directory at depth 1–2 under src/ contains two
#       or more C sources (*.c/*.h, non-recursive) but no README.md.
#
# WHY:  READMEs are the orientation layer for auditors; coverage decayed
#       exactly on the hardest directories (protocols/root, auth/authz,
#       tpc/*) until 2026-07-07. This makes coverage a ratchet: a new
#       subsystem directory ships with its README or CI is red.
#
# HOW:  find depth-1/2 dirs, count immediate C sources, require README.md
#       when the count is >= 2. Depth-3+ (e.g. protocols/root/*) is
#       encouraged but not gated.
#
# USAGE:
#   tools/ci/check_readme_coverage.sh
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

viol=0
while IFS= read -r d; do
    n="$(find "$d" -maxdepth 1 \( -name '*.c' -o -name '*.h' \) | wc -l)"
    if [ "$n" -ge 2 ] && [ ! -f "$d/README.md" ]; then
        echo "FAIL missing README.md: ${d#"$REPO"/}/ ($n C sources)"
        viol=1
    fi
done < <(find "$REPO/src" -mindepth 1 -maxdepth 2 -type d | sort)

[ "$viol" -eq 0 ] && echo "check_readme_coverage: OK"
exit "$viol"
