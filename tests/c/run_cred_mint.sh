#!/bin/sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd)
OBJS=/tmp/nginx-1.28.3/objs
BIN=/tmp/test_cred_mint

# openssl must be on PATH (needed to mint the throwaway test CA).
command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl not on PATH"; exit 0; }

CRED_MINT_OBJ=$(find "$OBJS/addon" -name 'cred_mint.o' | head -1)
[ -n "$CRED_MINT_OBJ" ] || { echo "SKIP: build cred_mint.o first (make)"; exit 1; }
cc -O -Wall -o "$BIN" "$HERE/test_cred_mint.c" "$CRED_MINT_OBJ" \
    -I "$REPO/src" -I /tmp/nginx-1.28.3/src/core -I /tmp/nginx-1.28.3/src/event \
    -I /tmp/nginx-1.28.3/src/os/unix -I "$OBJS" -lcrypto
"$BIN"
