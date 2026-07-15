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

# If the deployed module objects were built with ThreadSanitizer (the fleet is
# sometimes compiled -fsanitize=thread), they carry __tsan_* references that only
# resolve against the tsan runtime. Detect that and link the unit test the same
# way so the standalone binary resolves cleanly.
SAN_FLAGS=()
if nm "${CACHE_OBJ}/cinfo.o" 2>/dev/null | grep -q '__tsan'; then
    SAN_FLAGS=(-fsanitize=thread)
fi

cc -O -Wall "${SAN_FLAGS[@]}" -o "${BIN}" "${HERE}/test_cinfo.c" "${CACHE_OBJ}/cinfo.o" \
    "${OBJS_DIR}/addon/meta/xmeta.o" "${OBJS_DIR}/addon/meta/xmeta_path.o" \
    "${OBJS_DIR}/addon/meta/xmeta_decode.o" \
    "${OBJS_DIR}/addon/meta/xmeta_encode.o" \
    "${OBJS_DIR}/addon/meta/xmeta_carrier.o" \
    "${OBJS_DIR}/addon/compat/crc32c.o"

"${BIN}"
rc=$?
rm -f "${BIN}"
exit "${rc}"
