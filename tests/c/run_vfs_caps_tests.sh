#!/bin/sh
# run_vfs_caps_tests.sh — phase-71 capability accessors (brix_sd_supports /
# brix_sd_cred_accept). Links the real sd_registry.o so the accessor bodies
# under test are the shipped ones. SKIPs (exit 0) until the module is built.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd)
OBJS=/tmp/nginx-1.28.3/objs
BIN=/tmp/test_vfs_caps

REG_OBJ=$(find "$OBJS/addon" -path '*/backend/sd_registry.o' 2>/dev/null | head -1)
[ -n "$REG_OBJ" ] || { echo "SKIP: build sd_registry.o first (make in /tmp/nginx-1.28.3)"; exit 0; }

cc -O -Wall -o "$BIN" "$HERE/test_vfs_caps.c" "$REG_OBJ" \
    -I "$REPO/src" -I /tmp/nginx-1.28.3/src/core -I /tmp/nginx-1.28.3/src/event \
    -I /tmp/nginx-1.28.3/src/event/modules -I /tmp/nginx-1.28.3/src/event/quic \
    -I /tmp/nginx-1.28.3/src/os/unix -I "$OBJS"
"$BIN"
