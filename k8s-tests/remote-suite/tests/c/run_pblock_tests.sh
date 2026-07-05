#!/usr/bin/env bash
#
# run_pblock_tests.sh — compile and run the pblock backend's standalone unit
# tests: the SQLite metadata catalog (sd_pblock_catalog) and the full storage
# driver vtable (sd_pblock), including multi-thread + multi-process concurrency.
#
# Both build straight from source against libsqlite3 — no nginx, no objs tree,
# no running server. The driver test is compiled exactly as it builds in the
# module (BRIX_HAVE_SQLITE), with the ngx-free shim surface (XRDPROTO_NO_NGX)
# standing in for the nginx runtime it never touches.
#
# Usage:  tests/c/run_pblock_tests.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BACKEND="${HERE}/../../src/fs/backend"
CC="${CC:-cc}"

if ! pkg-config --exists sqlite3 2>/dev/null && [ ! -f /usr/include/sqlite3.h ]; then
    echo "SKIP run_pblock_tests: libsqlite3 development headers not found" >&2
    exit 0
fi
SQLITE_CFLAGS="$(pkg-config --cflags sqlite3 2>/dev/null || true)"
SQLITE_LIBS="$(pkg-config --libs sqlite3 2>/dev/null || echo -lsqlite3)"

CAT_BIN="$(mktemp /tmp/pb_cat_ut.XXXXXX)"
DRV_BIN="$(mktemp /tmp/pb_ut.XXXXXX)"
trap 'rm -f "${CAT_BIN}" "${DRV_BIN}"' EXIT

echo "== building + running sd_pblock_catalog_unittest =="
# shellcheck disable=SC2086
"${CC}" -O2 -Wall -Wextra -DBRIX_HAVE_SQLITE=1 \
    -I"${BACKEND}/pblock" -I"${BACKEND}" -I"${HERE}/../../src" ${SQLITE_CFLAGS} \
    "${BACKEND}/pblock/sd_pblock_catalog_unittest.c" \
    "${BACKEND}/pblock/sd_pblock_catalog.c" \
    ${SQLITE_LIBS} -o "${CAT_BIN}"
"${CAT_BIN}"

echo "== building + running sd_pblock_unittest (vtable + concurrency) =="
# shellcheck disable=SC2086
"${CC}" -O2 -Wall -Wextra -DBRIX_HAVE_SQLITE=1 -DXRDPROTO_NO_NGX \
    -I"${BACKEND}/pblock" -I"${BACKEND}" -I"${HERE}/../../src" ${SQLITE_CFLAGS} \
    "${BACKEND}/pblock/sd_pblock_unittest.c" \
    "${BACKEND}/pblock/sd_pblock.c" \
    "${BACKEND}/pblock/pblock_store.c" \
    "${BACKEND}/pblock/sd_pblock_catalog.c" \
    ${SQLITE_LIBS} -lpthread -o "${DRV_BIN}"
"${DRV_BIN}"

echo "run_pblock_tests: ALL PASS"
