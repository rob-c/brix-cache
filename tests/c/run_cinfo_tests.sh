#!/usr/bin/env bash
#
# run_cinfo_tests.sh — compile and run the §9 .cinfo bitmap unit tests.
#
# Links the test against the real compiled cinfo.o from the nginx build tree
# (no running server needed).  cinfo.o references only libc, so no stubs are
# required; test_cinfo.c mirrors the on-disk struct layout + the public
# prototypes (kept byte-compatible with src/fs/cache/cinfo.h).
#
# Usage:  tests/c/run_cinfo_tests.sh [path-to-nginx-objs-dir]
# Default objs dir: /tmp/nginx-1.28.3/objs
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OBJS_DIR="${1:-/tmp/nginx-1.28.3/objs}"
CACHE_OBJ="${OBJS_DIR}/addon/cache"
BIN="$(mktemp /tmp/test_cinfo.XXXXXX)"

if [[ ! -f "${CACHE_OBJ}/cinfo.o" ]]; then
    echo "ERROR: cinfo.o not found under ${CACHE_OBJ}." >&2
    echo "Build the module first (make -j\$(nproc) in the nginx tree)." >&2
    exit 2
fi

cc -O -Wall -o "${BIN}" "${HERE}/test_cinfo.c" "${CACHE_OBJ}/cinfo.o"

"${BIN}"
rc=$?
rm -f "${BIN}"
exit "${rc}"
