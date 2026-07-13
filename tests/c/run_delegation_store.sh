#!/bin/sh
# run_delegation_store.sh — phase-3 T4 pending-delegation store unit tests
# (put/get/sweep/expire/evict/free-on-drop), mirroring run_ucred_tests.sh's
# link-against-built-objects pattern.
#
# The store functions are `static` to src/protocols/webdav/delegation.c (an
# internal implementation detail — see that file's module doc-block), so
# test_delegation_store.c #includes delegation.c directly rather than
# relaxing their linkage. delegation.c also pulls in webdav.h (the full
# nginx HTTP module surface) for its HTTP-handler functions, which the store
# logic itself does not touch — this script links the REAL sibling project
# objects delegation.c depends on (hex.o, ucred.o, store_policy.o,
# proxy_req.o); test_delegation_store.c itself stubs the small number of
# nginx core symbols (ngx_pcalloc/ngx_pnalloc/ngx_pstrdup/ngx_snprintf/
# ngx_log_error_core/ngx_cycle) and webdav/HTTP symbols ONLY the (untested
# here) HTTP-handler functions reference — linking the real ngx_cycle.o
# would drag in nginx's entire OS/process/shm/module-init surface for a
# global this test's call graph never dereferences.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd)
OBJS=/tmp/nginx-1.28.3/objs
BIN=/tmp/test_delegation_store

command -v cc >/dev/null 2>&1 || { echo "SKIP: no C compiler on PATH"; exit 0; }

need_obj() {
    local found
    found=$(find "$OBJS" -name "$1" | head -1)
    if [ -z "$found" ]; then
        echo "SKIP: build first (make) — missing $1"
        exit 0
    fi
    echo "$found"
}

DELEG_C="$REPO/src/protocols/webdav/delegation.c"
[ -f "$DELEG_C" ] || { echo "SKIP: $DELEG_C not found"; exit 0; }

HEX_O=$(need_obj hex.o)
UCRED_O=$(need_obj ucred.o)
STOREPOLICY_O=$(need_obj store_policy.o)
SIGNINGPOLICY_O=$(need_obj signing_policy.o)
PROXYREQ_O=$(need_obj proxy_req.o)

cc -O -Wall -Wno-unused-function -o "$BIN" "$HERE/test_delegation_store.c" \
    "$HEX_O" "$UCRED_O" "$STOREPOLICY_O" "$SIGNINGPOLICY_O" "$PROXYREQ_O" \
    -I "$REPO/src" -I /tmp/nginx-1.28.3/src/core -I /tmp/nginx-1.28.3/src/event \
    -I /tmp/nginx-1.28.3/src/os/unix -I /tmp/nginx-1.28.3/src/http \
    -I /tmp/nginx-1.28.3/src/http/modules -I "$OBJS" \
    -lcrypto -lssl \
    2>"$HERE/.delegation_store_build.log" \
    || { echo "FAIL: build error"; cat "$HERE/.delegation_store_build.log"; exit 1; }
rm -f "$HERE/.delegation_store_build.log"

"$BIN"
