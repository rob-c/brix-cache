#!/usr/bin/env bash
#
# lint_loc.sh — Phase 38: file-size discipline lint + ratchet.
#
# Counts LOGICAL LoC (total - blank - pure-comment) for in-scope hand-written
# source and classifies each file into the tiers from
# docs/refactor/phase-38-file-size-unix-modularity.md (§2.1):
#
#   ideal  <= 500     watch 501-650     should 651-800     must > 800
#
# Advisory by default (--report); --strict gates a merge by failing when a
# non-baselined file exceeds the hard threshold, or a baselined file grows.
# --baseline (re)generates tests/loc_baseline.txt (the grandfathered offenders).
#
# Logical LoC matters, not raw: a file that is 800 raw but mostly the mandatory
# WHAT/WHY/HOW doc-blocks is not a monolith, so the standard's own documentation
# requirement never trips the linter.  Files genuinely cohesive yet long carry a
# one-line "loc-lint: exempt — <why>" comment near the top and are skipped.
#
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HARD=800                 # must-split threshold (tunable)
BASELINE="$ROOT/tests/loc_baseline.txt"
MODE="report"           # report | strict | baseline
case "${1:-}" in
  --strict)    MODE=strict ;;
  --baseline)  MODE=baseline ;;
  --report|"") MODE=report ;;
  *) echo "usage: lint_loc.sh [--report|--strict|--baseline]" >&2; exit 2 ;;
esac

# In-scope file set (§2.2/§2.3).  The shared libxrdproto C is build-in-place
# under src/, so it is already covered by the src/ globs; the shared/xrdproto/
# build harness itself is a declarative manifest and is excluded.
in_scope() {
  git -C "$ROOT" ls-files \
      'src/*.c' 'src/*.h' 'client/*.c' 'client/*.h' \
      'tests/*.sh' 'k8s-tests/*.sh' 'utils/*.sh' \
      'tests/*.py' 'utils/*.py' \
    | grep -vE '^(shared/xrdproto/)'
}

logical_loc() { grep -cvE '^[[:space:]]*$|^[[:space:]]*//|^[[:space:]]*/?\*' "$1"; }
is_exempt()   { head -40 "$1" | grep -q 'loc-lint:[[:space:]]*exempt'; }

# Build the current measurement table: "<loc>\t<path>" sorted desc, exemptions
# and missing files dropped.
measure() {
  while IFS= read -r f; do
    [ -f "$ROOT/$f" ] || continue
    is_exempt "$ROOT/$f" && continue
    printf '%s\t%s\n' "$(logical_loc "$ROOT/$f")" "$f"
  done < <(in_scope) | sort -rn
}

case "$MODE" in
  baseline)
    measure | awk -F'\t' -v h="$HARD" '$1>h {print $2"\t"$1}' > "$BASELINE"
    echo "wrote $(wc -l < "$BASELINE") baselined offender(s) to ${BASELINE#$ROOT/}"
    exit 0 ;;
esac

# Report: per-tier counts + the should/must lists (sorted, largest first).
echo "== file-size tiers (logical LoC) =="
measure | awk -F'\t' '
  {n++; t=($1<=500?"ideal":($1<=650?"watch":($1<=800?"should":"must")))
   c[t]++; if(t=="should"||t=="must") printf "  %-6s %5d  %s\n", toupper(t), $1, $2}
  END{printf "\n  total=%d  ideal=%d watch=%d should=%d must=%d\n",
             n, c["ideal"], c["watch"], c["should"], c["must"]}'

[ "$MODE" = report ] && exit 0

# Strict (ratchet): fail if a NON-baselined file exceeds HARD, or a baselined
# file grew beyond its recorded size.
fail=0
declare -A base
if [ -f "$BASELINE" ]; then
  while IFS=$'\t' read -r path loc; do base["$path"]=$loc; done < "$BASELINE"
fi
while IFS=$'\t' read -r loc path; do
  rec="${base[$path]:-}"
  if [ -z "$rec" ]; then
    [ "$loc" -gt "$HARD" ] && { echo "NEW over-threshold: $path ($loc > $HARD)"; fail=1; }
  elif [ "$loc" -gt "$rec" ]; then
    echo "baselined file grew: $path ($loc > recorded $rec)"; fail=1
  fi
done < <(measure)
[ "$fail" = 0 ] && echo "lint_loc: ratchet OK" || echo "lint_loc: ratchet FAILED"
exit "$fail"
