#!/usr/bin/env bash
#
# run_codechecker.sh — Clang Static Analyzer + clang-tidy regression ratchet.
#
# WHAT: runs Ericsson CodeChecker (clangsa + clang-tidy) over every addon source
#       compiled into the configured nginx build, and FAILS (exit 1) when a NEW
#       finding appears that is not in the recorded baseline
#       (tools/ci/codechecker_baseline.txt). Complements run_fanalyzer.sh: GCC
#       -fanalyzer reasons about ownership/leak/UAF along error branches; clangsa
#       + clang-tidy add a large, orthogonal checker set (dead stores, logic
#       errors, API misuse, security, bugprone-* etc.). Two engines, one model.
#
# WHY:  Same reasoning as the -fanalyzer ratchet: a "zero findings" gate is not
#       workable over a large C base (clang-tidy's default profile is opinionated
#       and raises stylistic/false-positive findings on nginx idioms). So we freeze
#       today's findings and gate only on NEW ones — the backlog-ratchet model used
#       by check_vfs_seam.sh / run_fanalyzer.sh / check_file_size.sh. A genuinely new
#       bug in changed code still fails CI.
#
# HOW:  1. Reuse the EXACT $(CFLAGS)/$(ALL_INCS) from the configured build tree
#          (same extraction as run_fanalyzer.sh) so the analyzer sees the real
#          defines/includes; strip -Werror so findings are collected, not aborted.
#       2. Synthesize a compile_commands.json (one clang entry per addon .c) — no
#          build interception / bear / ld-logger needed.
#       3. CodeChecker analyze (clangsa + clang-tidy), skipping the nginx build tree
#          and system headers so only OUR code is gated.
#       4. CodeChecker parse -e json → normalise each finding to a churn-stable key
#          "relpath │ checker │ report_hash". report_hash is CONTENT-based (stable
#          across unrelated line moves), so the baseline does not churn on edits.
#       5. Diff current vs baseline; NEW findings fail. --regen rewrites the baseline.
#
# USAGE:
#   tools/ci/run_codechecker.sh                 # gate: exit 1 on findings not in baseline
#   tools/ci/run_codechecker.sh --regen         # rewrite the baseline (review the diff!)
#   NGX_BUILD=/path/to/nginx tools/ci/run_codechecker.sh
#   tools/ci/run_codechecker.sh --filter src/auth/gsi   # restrict to a prefix (report-only, no gate)
#   ANALYZERS="clangsa" tools/ci/run_codechecker.sh     # override analyzer set
#
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NGX_BUILD="${NGX_BUILD:-/tmp/nginx-1.28.3}"
MK="${NGX_BUILD}/objs/Makefile"
JOBS="${JOBS:-$(nproc)}"
BASELINE="${REPO}/tools/ci/codechecker_baseline.txt"
ANALYZERS="${ANALYZERS:-clangsa clang-tidy}"
# Checks disabled by policy — each MUST have a reason. These contradict the build's
# own warning config or are pure noise for an nginx module; the ratchet handles the
# rest. Override with CC_DISABLE="" to see the full default profile.
CC_DISABLE_DEFAULT=(
  clang-diagnostic-unused-parameter   # the build sets -Wno-unused-parameter (deliberate)
  misc-header-include-cycle           # structural noise: nginx module include graph is legitimately cyclic
)
read -r -a CC_DISABLE <<<"${CC_DISABLE:-${CC_DISABLE_DEFAULT[*]}}"
CC="${CODECHECKER:-CodeChecker}"
command -v "$CC" >/dev/null 2>&1 || CC="$HOME/.local/bin/CodeChecker"

REGEN=0
FILTER=""
while [ $# -gt 0 ]; do
  case "$1" in
    --regen)  REGEN=1 ;;
    --filter) shift; FILTER="${1:-}" ;;
    *)        FILTER="$1" ;;   # bare path-prefix arg, back-compat with run_fanalyzer.sh
  esac
  shift
done

fail() { echo "run_codechecker: $*" >&2; exit 2; }

command -v "$CC" >/dev/null 2>&1 || fail "CodeChecker not found (pip install --user codechecker); also needs clang + clang-tidy"
command -v clang >/dev/null 2>&1 || fail "clang not found (clangsa backend)"
[ -f "$MK" ] || fail "no configured build at ${NGX_BUILD} (need objs/Makefile; run ./configure first)"

# --- flags straight from the build Makefile, -Werror stripped (as run_fanalyzer.sh) ---
read_var() {
  make -s --no-print-directory -C "$NGX_BUILD" -f objs/Makefile \
    --eval="__pf: ; @printf '%s' \"\$($1)\"" __pf 2>/dev/null
}
CFLAGS="$(read_var CFLAGS)"
ALL_INCS="$(read_var ALL_INCS)"
[ -n "$CFLAGS" ] || fail "could not read CFLAGS from ${MK}"
CFLAGS="$(printf '%s' "$CFLAGS" | sed -E 's/-Werror(=[a-z-]+)?//g')"

# --- addon sources actually compiled into this build ---
mapfile -t SRCS < <(grep -oE "${REPO}/src/[^ ]+\.c" "$MK" | sort -u)
[ "${#SRCS[@]}" -gt 0 ] || fail "no addon sources found in ${MK}"

# Apply --filter (prefix under repo root). A filtered run analyses only a subset,
# so it CANNOT gate against the full baseline (absent files would look "fixed").
SELECTED=()
for src in "${SRCS[@]}"; do
  [ -n "$FILTER" ] && [[ "$src" != "${REPO}/${FILTER}"* ]] && continue
  SELECTED+=("$src")
done
[ "${#SELECTED[@]}" -gt 0 ] || fail "no sources selected (filter='${FILTER}')"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- synthesize compile_commands.json (directory = build tree; ALL_INCS is build-relative) ---
# Pass the src list via a file (NOT stdin): `python3 - <<PY` already consumes stdin
# for the program text, so a piped list would be swallowed.
printf '%s\n' "${SELECTED[@]}" >"$WORK/srcs.txt"
python3 - "$WORK/compile_commands.json" "$NGX_BUILD" "$CFLAGS" "$ALL_INCS" "$WORK/srcs.txt" <<'PY'
import json, sys
out, directory, cflags, incs, srcfile = sys.argv[1:6]
srcs = [l.strip() for l in open(srcfile) if l.strip()]
db = [{"directory": directory,
       "command": f"clang -c {cflags} {incs} {s} -o /dev/null",
       "file": s} for s in srcs]
json.dump(db, open(out, "w"))
print(f"compile_commands.json: {len(db)} entrie(s)")
PY

# Skip the nginx build tree + system headers so only repo/src findings are gated.
cat >"$WORK/skip.txt" <<EOF
-${NGX_BUILD}/*
-/usr/*
+${REPO}/src/*
-*
EOF

DISABLE_ARGS=()
for c in "${CC_DISABLE[@]}"; do [ -n "$c" ] && DISABLE_ARGS+=(--disable "$c"); done

echo "== analyzing ${#SELECTED[@]} source file(s) with: ${ANALYZERS} (-j ${JOBS}) =="
[ "${#DISABLE_ARGS[@]}" -gt 0 ] && echo "   disabled by policy: ${CC_DISABLE[*]}"
# CodeChecker analyze exits non-zero when any TU has findings OR fails to compile;
# we inspect the report dir ourselves, so tolerate its exit code here.
"$CC" analyze "$WORK/compile_commands.json" \
    --analyzers ${ANALYZERS} \
    "${DISABLE_ARGS[@]}" \
    -i "$WORK/skip.txt" \
    -j "$JOBS" \
    -o "$WORK/reports" >"$WORK/analyze.log" 2>&1 || true

# --- compile-error hard stop: a clean result is only meaningful if analysis RAN ---
# CodeChecker parks TUs it could not compile under <reports>/failed/.
if [ -d "$WORK/reports/failed" ] && [ -n "$(ls -A "$WORK/reports/failed" 2>/dev/null)" ]; then
  fc="$(ls -1 "$WORK/reports/failed" | wc -l | tr -d ' ')"
  echo "---- ${fc} translation unit(s) FAILED to compile — analysis did NOT run on them ----"
  ls -1 "$WORK/reports/failed" | head -20
  echo "(see $WORK/analyze.log; likely a clang-incompatible flag or missing header / bad NGX_BUILD)" >&2
  fail "${fc} TU(s) failed under the analyzer flags — fix flag extraction before trusting a clean gate"
fi

# --- normalise findings to a churn-stable key: relpath │ checker │ report_hash ---
"$CC" parse "$WORK/reports" -e json >"$WORK/parse.json" 2>/dev/null || true
python3 - "$WORK/parse.json" "$REPO" >"$WORK/current.txt" <<'PY'
import json, sys, os
path, repo = sys.argv[1], sys.argv[2].rstrip("/") + "/"
try:
    doc = json.load(open(path))
except Exception:
    doc = {}
reports = doc.get("reports", doc if isinstance(doc, list) else [])
seen = set()
for r in reports:
    f = r.get("file")
    fp = f.get("path") if isinstance(f, dict) else f
    fp = (fp or "").replace(repo, "")
    if not fp.startswith("src/"):
        continue
    key = f"{fp} │ {r.get('checker_name','?')} │ {r.get('report_hash','')}"
    seen.add(key)
for k in sorted(seen):
    print(k)
PY
cur="$(wc -l <"$WORK/current.txt" | tr -d ' ')"
echo "== ${cur} finding(s) (baseline + new) =="

if [ "$REGEN" -eq 1 ]; then
  [ -n "$FILTER" ] && fail "--regen must run over the FULL tree (drop --filter)"
  { echo "# codechecker baseline — clangsa + clang-tidy findings, keyed by content hash."
    echo "# Format: <repo-relative path> │ <checker> │ <report_hash>"
    echo "# Regenerate with: tools/ci/run_codechecker.sh --regen   (review the diff!)"
    cat "$WORK/current.txt"
  } >"$BASELINE"
  echo "run_codechecker: baseline rewritten (${cur} findings) → ${BASELINE}"
  exit 0
fi

if [ -n "$FILTER" ]; then
  echo "run_codechecker: filter run (no gate). Findings under '${FILTER}':"
  # Human-readable view for the subset.
  "$CC" parse "$WORK/reports" 2>/dev/null || cat "$WORK/current.txt"
  exit 0
fi

[ -f "$BASELINE" ] || fail "no baseline at ${BASELINE} — create it with --regen"
grep -vE '^[[:space:]]*#' "$BASELINE" | sed '/^[[:space:]]*$/d' | sort -u >"$WORK/baseline.txt"

comm -23 "$WORK/current.txt" "$WORK/baseline.txt" >"$WORK/new.txt"
new="$(wc -l <"$WORK/new.txt" | tr -d ' ')"
if [ "$new" -gt 0 ]; then
  echo "---- NEW findings not in baseline (${new}) ----"
  cat "$WORK/new.txt"
  echo "run_codechecker: FAIL — ${new} new finding(s). For a human view of one file, run:" >&2
  echo "               tools/ci/run_codechecker.sh --filter <path-prefix>" >&2
  echo "               Fix them, or if false-positive, review and re-baseline with --regen" >&2
  exit 1
fi
echo "run_codechecker: OK — no new findings beyond the ${cur}-entry baseline"
