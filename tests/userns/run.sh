#!/usr/bin/env bash
#
# run.sh — manual runner for the phase-40 impersonation user-namespace test.
#
# Compiles tests/userns/c/userns_broker_test.c against the real broker/client/
# idmap sources and runs it directly (no pytest).  Useful for fast iteration and
# for seeing the full per-assertion PASS/FAIL trace on stderr.
#
# Requirements: a C compiler, the nginx source tree (TEST_NGINX_SRC), the
# setuid-root newuidmap/newgidmap helpers, and a /etc/subuid + /etc/subgid range
# for the invoking user.  Exits 0 + prints SKIP when any are missing.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
NGINX_SRC="${TEST_NGINX_SRC:-/tmp/nginx-1.28.3}"
CC="${CC:-cc}"
IMP="$REPO/src/auth/impersonate"
OUT="${OUT:-/tmp/userns_broker_test.bin}"

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "SKIP: no C compiler ($CC)"; exit 0
fi
if [[ ! -f "$NGINX_SRC/src/core/ngx_config.h" ]]; then
    echo "SKIP: nginx source not at $NGINX_SRC (set TEST_NGINX_SRC)"; exit 0
fi
if ! command -v newuidmap >/dev/null 2>&1 || ! command -v newgidmap >/dev/null 2>&1; then
    echo "SKIP: newuidmap/newgidmap not installed (uidmap package)"; exit 0
fi

INCS=(
    -I"$NGINX_SRC/src/core" -I"$NGINX_SRC/src/event"
    -I"$NGINX_SRC/src/event/modules" -I"$NGINX_SRC/src/os/unix"
    -I"$NGINX_SRC/objs" -I"$NGINX_SRC/src/protocols/root/stream" -I"$IMP"
)

echo "==> building $OUT"
"$CC" -O2 -D_GNU_SOURCE -Wall "${INCS[@]}" -o "$OUT" \
    "$HERE/c/userns_broker_test.c" \
    "$IMP/broker.c" "$IMP/client.c" "$IMP/idmap.c"

echo "==> running"
exec "$OUT"
