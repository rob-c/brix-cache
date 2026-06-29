#!/usr/bin/env bash
#
# run_cache_admit_tests.sh — compile + run the shared admission-filter unit tests.
#
# Links the test against the real compiled cache_admit.o from the nginx build
# tree. cache_admit.o references only libc + libregex, so no nginx stubs are
# needed; the test mirrors ngx_array_t/ngx_str_t/prefix-entry layouts.
#
# Usage:  tests/c/run_cache_admit_tests.sh [path-to-nginx-objs-dir]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OBJS_DIR="${1:-/tmp/nginx-1.28.3/objs}"
CACHE_OBJ="${OBJS_DIR}/addon/cache"
BIN="$(mktemp /tmp/test_cache_admit.XXXXXX)"

if [[ ! -f "${CACHE_OBJ}/cache_admit.o" ]]; then
    echo "ERROR: cache_admit.o not found under ${CACHE_OBJ}." >&2
    echo "Build the module first (./configure && make in the nginx tree)." >&2
    exit 2
fi

cc -O -Wall -o "${BIN}" "${HERE}/test_cache_admit.c" "${CACHE_OBJ}/cache_admit.o"

"${BIN}"
rc=$?
rm -f "${BIN}"
exit "${rc}"
