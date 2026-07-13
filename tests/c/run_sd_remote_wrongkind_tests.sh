#!/bin/sh
# run_sd_remote_wrongkind_tests.sh — Phase-3 review defense-in-depth fix:
# sd_remote_open_cred must refuse (EACCES) a wrong-kind credential under
# fallback_deny instead of silently falling back to the export's static
# service credential. See test_sd_remote_wrongkind.c for the full rationale.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd)
OBJS=/tmp/nginx-1.28.3/objs
BIN=/tmp/test_sd_remote_wrongkind

SD_REMOTE_OBJ=$(find "$OBJS/addon" -path '*/remote/sd_remote.o' | head -1)
SD_S3_OBJ=$(find "$OBJS/addon" -path '*/s3/sd_s3.o' | head -1)
CRYPTO_OBJ=$(find "$OBJS/addon" -path '*/compat/crypto.o' | head -1)
HEX_OBJ=$(find "$OBJS/addon" -path '*/compat/hex.o' | head -1)
SIGV4_OBJ=$(find "$OBJS/addon" -path '*/compat/sigv4.o' | head -1)
URI_OBJ=$(find "$OBJS/addon" -path '*/compat/uri.o' | head -1)
HOSTFMT_OBJ=$(find "$OBJS/addon" -path '*/compat/host_format.o' | head -1)

for v in SD_REMOTE_OBJ SD_S3_OBJ CRYPTO_OBJ HEX_OBJ SIGV4_OBJ URI_OBJ HOSTFMT_OBJ; do
    eval "val=\${$v}"
    [ -n "$val" ] || { echo "SKIP: build $v.o first (make in /tmp/nginx-1.28.3)"; exit 0; }
done

cc -O -Wall -o "$BIN" "$HERE/test_sd_remote_wrongkind.c" \
    "$SD_REMOTE_OBJ" "$SD_S3_OBJ" "$CRYPTO_OBJ" "$HEX_OBJ" "$SIGV4_OBJ" \
    "$URI_OBJ" "$HOSTFMT_OBJ" \
    -I "$REPO/src" -I /tmp/nginx-1.28.3/src/core -I /tmp/nginx-1.28.3/src/event \
    -I /tmp/nginx-1.28.3/src/os/unix -I "$OBJS" -lssl -lcrypto
"$BIN"
