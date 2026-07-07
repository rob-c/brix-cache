#!/usr/bin/env bash
#
# run_stage_reconcile_tests.sh — compile + run the stage-journal reconcile
# NULL-cycle regression against the compiled stage_engine.o.
#
# Proves brix_stage_reconcile defers (no crash, journal kept) when ngx_cycle
# is NULL, and drops corrupt records normally when a cycle log exists. See
# tests/c/test_stage_reconcile_nullcycle.c for the full rationale.
#
# Usage:  tests/c/run_stage_reconcile_tests.sh [path-to-nginx-src-dir]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
NGX_SRC="${1:-/tmp/nginx-1.28.3}"
OBJS_DIR="${NGX_SRC}/objs"
ENGINE_OBJ="${OBJS_DIR}/addon/xfer/stage_engine.o"
BIN="$(mktemp /tmp/test_stage_reconcile.XXXXXX)"

if [[ ! -f "${ENGINE_OBJ}" ]]; then
    echo "ERROR: ${ENGINE_OBJ} not found. Build the module first (./configure && make)." >&2
    exit 2
fi

# Include dirs mirror the module build's ALL_INCS (nginx core + our src/).
INCS=(-I "${NGX_SRC}/src/core" -I "${NGX_SRC}/src/event"
      -I "${NGX_SRC}/src/event/modules" -I "${NGX_SRC}/src/os/unix"
      -I "${OBJS_DIR}" -I "${REPO}/src")

cc -O -Wall "${INCS[@]}" -o "${BIN}" \
    "${HERE}/test_stage_reconcile_nullcycle.c" "${ENGINE_OBJ}"

"${BIN}"
rc=$?
rm -f "${BIN}"
exit "${rc}"
