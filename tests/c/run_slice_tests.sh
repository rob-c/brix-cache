#!/usr/bin/env bash
#
# run_slice_tests.sh — compile and run the Phase 26 slice-library unit tests.
#
# Links the test against the real compiled slice.o + meta.o objects from the
# nginx build tree (no running server needed).  Tiny stubs for the two cache
# externals (xrootd_cache_file_ready, xrootd_cache_meta_path) and the nginx log
# core live in test_slice.c itself.
#
# Usage:  tests/c/run_slice_tests.sh [path-to-nginx-objs-dir]
# Default objs dir: /tmp/nginx-1.28.3/objs
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OBJS_DIR="${1:-/tmp/nginx-1.28.3/objs}"
CACHE_OBJ="${OBJS_DIR}/addon/cache"
BIN="$(mktemp /tmp/test_slice.XXXXXX)"

if [[ ! -f "${CACHE_OBJ}/slice.o" || ! -f "${CACHE_OBJ}/meta.o" ]]; then
    echo "ERROR: slice.o/meta.o not found under ${CACHE_OBJ}." >&2
    echo "Build the module first (make -j\$(nproc) in the nginx tree)." >&2
    exit 2
fi

cc -O -Wall -o "${BIN}" "${HERE}/test_slice.c" \
   "${CACHE_OBJ}/slice.o" "${CACHE_OBJ}/meta.o"

"${BIN}"
rc=$?
rm -f "${BIN}"
exit "${rc}"
