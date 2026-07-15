#!/usr/bin/env bash
#
# run_cache_lock_reclaim_tests.sh — compile + run the cache-fill lock dead-owner
# reclaim regression against the compiled lock.o.
#
# Proves an orphaned O_EXCL cache-fill lock left by a dead worker is reclaimed
# instead of stranding the entry forever ("workers stuck after many reboots").
# See tests/c/test_cache_lock_reclaim.c for the full rationale.
#
# Usage:  tests/c/run_cache_lock_reclaim_tests.sh [path-to-nginx-src-dir]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
NGX_SRC="${1:-/tmp/nginx-1.28.3}"
OBJS_DIR="${NGX_SRC}/objs"
LOCK_OBJ="${OBJS_DIR}/addon/cache/lock.o"
BIN="$(mktemp /tmp/test_cache_lock_reclaim.XXXXXX)"

if [[ ! -f "${LOCK_OBJ}" ]]; then
    echo "ERROR: ${LOCK_OBJ} not found. Build the module first (./configure && make)." >&2
    exit 2
fi

INCS=(-I "${NGX_SRC}/src/core" -I "${NGX_SRC}/src/event"
      -I "${NGX_SRC}/src/event/modules" -I "${NGX_SRC}/src/os/unix"
      -I "${OBJS_DIR}" -I "${NGX_SRC}/src/stream" -I "${NGX_SRC}/src/http"
      -I "${NGX_SRC}/src/http/modules" -I "${REPO}/src")

# Match the sanitizer the module object was built with. If lock.o was compiled
# with ThreadSanitizer (module built --with-debug/tsan), it carries unresolved
# __tsan_* references; the test binary must be linked with -fsanitize=thread too
# or the link fails. Detect the instrumentation directly from the object.
SAN_FLAGS=()
if nm "${LOCK_OBJ}" 2>/dev/null | grep -q '__tsan_'; then
    SAN_FLAGS+=(-fsanitize=thread)
fi

cc -O -Wall "${SAN_FLAGS[@]}" "${INCS[@]}" -o "${BIN}" \
    "${HERE}/test_cache_lock_reclaim.c" "${LOCK_OBJ}"

"${BIN}"
rc=$?
rm -f "${BIN}"
exit "${rc}"
