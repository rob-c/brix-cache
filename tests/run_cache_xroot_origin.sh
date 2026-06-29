#!/usr/bin/env bash
#
# run_cache_xroot_origin.sh — end-to-end proof of the remote root:// cache origin
# via the new sd_xroot driver (src/fs/backend/xroot/). A stream root:// cache node
# fronts a separate root:// origin server; a cache miss fills the object through
# the driver (open → kXR_read range loop → staged sink → commit-then-verify),
# byte-exact, including a multi-chunk object (> the 1 MiB fill chunk).
#
# Anonymous auth (the in-process driver's mode). Token/GSI root:// origins use the
# cache's native-client delegation, covered elsewhere.
#
# Usage: tests/run_cache_xroot_origin.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDFS="$HERE/client/bin/xrdfs"
ORIGIN_PORT=11636
NODE_PORT=11637
PFX="$(mktemp -d /tmp/cache_xr.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() {
    for r in o n; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done
    rm -rf "$PFX" /tmp/cache_xr_*.got
}
trap cleanup EXIT

mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/n/export" "$PFX/n/cache" "$PFX/n/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${ORIGIN_PORT}; xrootd on; xrootd_root $PFX/o/root;
    xrootd_auth none; } }
EOF

cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${NODE_PORT}; xrootd on; xrootd_root $PFX/n/export; xrootd_auth none;
    xrootd_cache on; xrootd_cache_root $PFX/n/cache;
    xrootd_cache_origin root://127.0.0.1:${ORIGIN_PORT};
} }
EOF

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "origin start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo "node start failed"; cat "$PFX/n/err"; exit 2; }
sleep 1

head -c 600000  /dev/urandom > "$PFX/o/root/small.bin"      # < 1 MiB fill chunk
head -c 2800000 /dev/urandom > "$PFX/o/root/big.bin"        # ~2.7 chunks

echo "== cold read: cache miss fills /small.bin from the root:// origin =="
"$XRDFS" root://127.0.0.1:${NODE_PORT} cat /small.bin > /tmp/cache_xr_s.got 2>"$PFX/n/logs/cat1.err"
cmp -s "$PFX/o/root/small.bin" /tmp/cache_xr_s.got && ok "root:// origin fill byte-exact (via sd_xroot)" \
    || { bad "root:// fill DIFFERS"; grep -iE 'root|origin|xroot|fill|error' "$PFX/n/logs/e.log" | tail -6; }
[ -f "$PFX/n/cache/small.bin" ] && ok "object landed in the local cache" || bad "no cache entry created"

echo "== warm read: served from cache =="
"$XRDFS" root://127.0.0.1:${NODE_PORT} cat /small.bin > /tmp/cache_xr_s2.got 2>/dev/null
cmp -s "$PFX/o/root/small.bin" /tmp/cache_xr_s2.got && ok "warm cache hit byte-exact" || bad "warm hit DIFFERS"

echo "== multi-chunk: fills across several kXR_read ranges (> 1 MiB) =="
"$XRDFS" root://127.0.0.1:${NODE_PORT} cat /big.bin > /tmp/cache_xr_b.got 2>/dev/null
cmp -s "$PFX/o/root/big.bin" /tmp/cache_xr_b.got && ok "multi-chunk root:// fill byte-exact" \
    || bad "multi-chunk fill DIFFERS (got=$(stat -c%s /tmp/cache_xr_b.got 2>/dev/null))"

[ "$fail" = 0 ] && echo "run_cache_xroot_origin: ALL PASS" || echo "run_cache_xroot_origin: FAILURES"
exit "$fail"
