#!/usr/bin/env bash
#
# run_fanalyzer.sh — static-analysis regression ratchet over the addon sources.
#
# WHAT: compiles every module source under GCC's symbolic-execution static
#       analyzer (-fanalyzer) and FAILS (exit 1) when a NEW finding appears that
#       is not in the recorded baseline (tools/ci/fanalyzer_baseline.txt) —
#       use-after-free, double-free, memory/fd leak, NULL dereference, etc.
#
# WHY: -fanalyzer reasons about error / early-return branches the test suite may
#       never hit, where leaks and double-frees hide. But GCC's analyzer is also
#       interprocedurally limited: it raises FALSE positives where ownership is
#       transferred into a container that a separate function frees (the cache /
#       catalog "leaks"), on nginx's ngx_queue iteration idiom (a "use-after-free"
#       that is not one), and on SHM pointers it cannot model. So a "zero findings"
#       gate is not workable here. Instead we freeze today's findings as a baseline
#       and gate only on NEW ones — the same backlog-ratchet model as
#       check_vfs_seam.sh. A genuinely new leak/UAF in changed code still fails.
#
# HOW: reuse the EXACT $(CFLAGS) and $(ALL_INCS) from a configured nginx build
#       tree (so the analyzer sees the real defines/includes), minus -Werror* (we
#       collect findings across all files instead of aborting on the first), and
#       run `gcc -fanalyzer -c -o /dev/null` on each source in parallel. Each
#       [-Wanalyzer-...] line is normalised to "path│kind│message" (line/column
#       stripped so unrelated edits do not churn the baseline) and diffed against
#       the baseline. --regen rewrites the baseline after a deliberate review.
#
# USAGE:
#   tools/ci/run_fanalyzer.sh                 # gate: exit 1 on findings not in baseline
#   tools/ci/run_fanalyzer.sh --regen         # rewrite the baseline (review the diff!)
#   NGX_BUILD=/path/to/nginx tools/ci/run_fanalyzer.sh
#   tools/ci/run_fanalyzer.sh --filter src/auth/gsi   # restrict to a path prefix (faster, no gate)
#
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NGX_BUILD="${NGX_BUILD:-/tmp/nginx-1.28.3}"
MK="${NGX_BUILD}/objs/Makefile"
JOBS="${JOBS:-$(nproc)}"
BASELINE="${REPO}/tools/ci/fanalyzer_baseline.txt"

REGEN=0
FILTER=""
while [ $# -gt 0 ]; do
  case "$1" in
    --regen)  REGEN=1 ;;
    --filter) shift; FILTER="${1:-}" ;;
    *)        FILTER="$1" ;;   # bare path-prefix arg, back-compat
  esac
  shift
done

# Files exempted from the gate (basename match). Keep empty — add only with a
# written rationale next to the entry.
ANALYZER_SKIP=(
  # e.g. "third_party_blob.c   # vendored, analyzed upstream"
)

fail() { echo "run_fanalyzer: $*" >&2; exit 2; }

command -v gcc >/dev/null 2>&1 || fail "gcc not found"
[ -f "$MK" ] || fail "no configured build at ${NGX_BUILD} (need objs/Makefile; run ./configure first)"

# Pull the fully-expanded flags straight from the build's Makefile, then strip the
# -Werror promotions so analyzer findings are collected rather than aborting.
read_var() {
  # CFLAGS / ALL_INCS live in objs/Makefile (the top-level Makefile only
  # delegates), so read them from there. -s + --no-print-directory keep make's
  # own chatter off stdout so only the printf payload survives.
  make -s --no-print-directory -C "$NGX_BUILD" -f objs/Makefile \
    --eval="__pf: ; @printf '%s' \"\$($1)\"" __pf 2>/dev/null
}
CFLAGS="$(read_var CFLAGS)"
ALL_INCS="$(read_var ALL_INCS)"
[ -n "$CFLAGS" ] || fail "could not read CFLAGS from ${MK}"
CFLAGS="$(printf '%s' "$CFLAGS" | sed -E 's/-Werror(=[a-z-]+)?//g')"

# Collect the addon sources actually compiled into this build.
mapfile -t SRCS < <(grep -oE "${REPO}/src/[^ ]+\.c" "$MK" | sort -u)
[ "${#SRCS[@]}" -gt 0 ] || fail "no addon sources found in ${MK}"

skip_match() {
  local base; base="$(basename "$1")"
  local e
  for e in "${ANALYZER_SKIP[@]}"; do
    [ "${e%%[[:space:]]*}" = "$base" ] && return 0
  done
  return 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export CFLAGS ALL_INCS WORK NGX_BUILD

analyze_one() {
  local src="$1" rc
  # ALL_INCS carries build-relative -I paths (-I src/core, -I objs), so run from
  # the build tree exactly as the Makefile recipe does. The source path is absolute.
  ( cd "$NGX_BUILD" && gcc -fanalyzer -fanalyzer-verbosity=1 -fno-diagnostics-color \
      -c $CFLAGS $ALL_INCS "$src" -o /dev/null ) 2>"$WORK/err.$$"
  rc=$?
  # Keep only analyzer diagnostics.
  grep -E '\[-Wanalyzer-[a-z-]+\]' "$WORK/err.$$" >>"$WORK/findings.txt" 2>/dev/null || true
  # A non-zero exit with NO analyzer finding means the file failed to COMPILE
  # (bad flags / missing header) — the analysis never ran, so this must not pass
  # as "clean". Record it as a hard error.
  if [ "$rc" -ne 0 ] && ! grep -qE '\[-Wanalyzer-' "$WORK/err.$$"; then
    { echo "COMPILE-ERROR: $src"; grep -E ': (error|fatal error):' "$WORK/err.$$" | head -3; } \
      >>"$WORK/compile_errors.txt"
  fi
  rm -f "$WORK/err.$$"
}
export -f analyze_one skip_match
export ANALYZER_SKIP

: >"$WORK/findings.txt"
: >"$WORK/compile_errors.txt"
TODO=()
for src in "${SRCS[@]}"; do
  [ -n "$FILTER" ] && [[ "$src" != "${REPO}/${FILTER}"* ]] && continue
  skip_match "$src" && continue
  TODO+=("$src")
done
count="${#TODO[@]}"
[ "$count" -gt 0 ] || fail "no sources selected (filter='${FILTER}')"

printf '%s\n' "${TODO[@]}" | xargs -P "$JOBS" -I{} bash -c 'analyze_one "$@"' _ {}

echo "== analyzed ${count} source file(s) under -fanalyzer =="

# Hard stop if any file did not compile — a clean result is only meaningful when
# the analyzer actually ran on every file.
if [ -s "$WORK/compile_errors.txt" ]; then
  ce="$(grep -c '^COMPILE-ERROR:' "$WORK/compile_errors.txt")"
  echo "---- compile errors (${ce}) — analysis did NOT run on these ----"
  head -20 "$WORK/compile_errors.txt"
  fail "${ce} file(s) failed to compile under the analyzer flags (bad NGX_BUILD / flag extraction?)"
fi

# Normalise findings to a churn-stable key: drop the build-tree and repo prefixes,
# strip ":line:col:", collapse to "path│kind│message". Sorted + de-duped.
normalise() {
  sed -E -e "s|${NGX_BUILD}/||g" -e "s|${REPO}/||g" \
         -e 's|:[0-9]+:[0-9]+:[[:space:]]*warning:[[:space:]]*| │ |' \
         -e 's|[[:space:]]*\[(-Wanalyzer-[a-z-]+)\].*|  │ \1|' \
    "$1" | sort -u
}
normalise "$WORK/findings.txt" >"$WORK/current.txt"
cur="$(wc -l <"$WORK/current.txt" | tr -d ' ')"
echo "== ${cur} analyzer finding(s) (baseline + new) =="

if [ "$REGEN" -eq 1 ]; then
  [ -n "$FILTER" ] && fail "--regen must run over the FULL tree (drop --filter)"
  { echo "# fanalyzer baseline — known/false-positive findings, line:col stripped."
    echo "# Regenerate with: tools/ci/run_fanalyzer.sh --regen   (review the diff!)"
    cat "$WORK/current.txt"
  } >"$BASELINE"
  echo "run_fanalyzer: baseline rewritten (${cur} findings) → ${BASELINE}"
  exit 0
fi

# A --filter run analyses only a subset, so it cannot gate against the full
# baseline (absent files would look "fixed"). Report only.
if [ -n "$FILTER" ]; then
  echo "run_fanalyzer: filter run (no gate). Findings under '${FILTER}':"
  cat "$WORK/current.txt"
  exit 0
fi

[ -f "$BASELINE" ] || fail "no baseline at ${BASELINE} — create it with --regen"
grep -vE '^[[:space:]]*#' "$BASELINE" | sed '/^[[:space:]]*$/d' | sort -u >"$WORK/baseline.txt"

# New = current minus baseline.
comm -23 "$WORK/current.txt" "$WORK/baseline.txt" >"$WORK/new.txt"
new="$(wc -l <"$WORK/new.txt" | tr -d ' ')"
if [ "$new" -gt 0 ]; then
  echo "---- NEW analyzer findings not in baseline (${new}) ----"
  cat "$WORK/new.txt"
  echo "run_fanalyzer: FAIL — ${new} new finding(s). Fix them, or if false-positive," >&2
  echo "               review and re-baseline with: tools/ci/run_fanalyzer.sh --regen" >&2
  exit 1
fi
echo "run_fanalyzer: OK — no new findings beyond the ${cur}-entry baseline"
