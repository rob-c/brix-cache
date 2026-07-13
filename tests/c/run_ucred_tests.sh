#!/bin/sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd)
OBJS=/tmp/nginx-1.28.3/objs
BIN=/tmp/test_ucred

# openssl must be on PATH (needed by mint_pem for valid certs)
command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl not on PATH"; exit 0; }

# python3 cryptography is required to mint expired test PEMs
python3 -c "import cryptography" >/dev/null 2>&1 || { echo "SKIP: python3 cryptography unavailable (needed to mint an expired test PEM)"; exit 0; }

UCRED_OBJ=$(find "$OBJS/addon" -name 'ucred.o' | head -1)
[ -n "$UCRED_OBJ" ] || { echo "SKIP: build ucred.o first (make)"; exit 1; }
cc -O -Wall -o "$BIN" "$HERE/test_ucred.c" "$UCRED_OBJ" \
    -I "$REPO/src" -I /tmp/nginx-1.28.3/src/core -I /tmp/nginx-1.28.3/src/event \
    -I /tmp/nginx-1.28.3/src/os/unix -I "$OBJS" -lcrypto
"$BIN"
