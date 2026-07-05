#!/usr/bin/env bash
#
# run_cache_storage_tests.sh — compile + run the cache-key unit test against the
# compiled cache_key.o (pure, libc-only). No nginx runtime / stubs needed.
#
# Usage:  tests/c/run_cache_storage_tests.sh [path-to-nginx-objs-dir]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OBJS_DIR="${1:-/tmp/nginx-1.28.3/objs}"
CACHE_OBJ="${OBJS_DIR}/addon/cache"
BIN="$(mktemp /tmp/test_cache_storage.XXXXXX)"

if [[ ! -f "${CACHE_OBJ}/cache_key.o" ]]; then
    echo "ERROR: cache_key.o not found under ${CACHE_OBJ}." >&2
    echo "Build the module first (./configure && make)." >&2
    exit 2
fi

cc -O -Wall -o "${BIN}" "${HERE}/test_cache_storage.c" "${CACHE_OBJ}/cache_key.o"

"${BIN}"
rc=$?
rm -f "${BIN}"
exit "${rc}"
