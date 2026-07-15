#!/usr/bin/env bash
#
# run_shm_mutex_recovery_tests.sh — compile + run the SHM table-mutex dead-holder
# recovery regression against the compiled shm_slots.o and nginx's ngx_shmtx.o.
#
# Proves that a module SHM-table mutex is recovered by nginx's per-zone
# force-unlock when the worker holding it dies — the "workers stuck after many
# reboots" bug. See tests/c/test_shm_mutex_recovery.c for the full rationale.
#
# Usage:  tests/c/run_shm_mutex_recovery_tests.sh [path-to-nginx-src-dir]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
NGX_SRC="${1:-/tmp/nginx-1.28.3}"
OBJS_DIR="${NGX_SRC}/objs"
SHM_OBJ="${OBJS_DIR}/addon/compat/shm_slots.o"
SHMTX_OBJ="${OBJS_DIR}/src/core/ngx_shmtx.o"
BIN="$(mktemp /tmp/test_shm_mutex_recovery.XXXXXX)"

for obj in "${SHM_OBJ}" "${SHMTX_OBJ}"; do
    if [[ ! -f "${obj}" ]]; then
        echo "ERROR: ${obj} not found. Build the module first (./configure && make)." >&2
        exit 2
    fi
done

# Include dirs mirror the module build's ALL_INCS (nginx core + our src/).
INCS=(-I "${NGX_SRC}/src/core" -I "${NGX_SRC}/src/event"
      -I "${NGX_SRC}/src/event/modules" -I "${NGX_SRC}/src/os/unix"
      -I "${OBJS_DIR}" -I "${REPO}/src")

# If the deployed objects were built with ThreadSanitizer (the fleet is sometimes
# compiled -fsanitize=thread), they carry __tsan_* references that only resolve
# against the tsan runtime. Detect that and link the unit test the same way.
SAN_FLAGS=()
if nm "${SHMTX_OBJ}" "${SHM_OBJ}" 2>/dev/null | grep -q '__tsan'; then
    SAN_FLAGS=(-fsanitize=thread)
fi

cc -O -Wall "${SAN_FLAGS[@]}" "${INCS[@]}" -o "${BIN}" \
    "${HERE}/test_shm_mutex_recovery.c" "${SHM_OBJ}" "${SHMTX_OBJ}" -pthread

"${BIN}"
rc=$?
rm -f "${BIN}"
exit "${rc}"
