#!/usr/bin/env bash
# run_cache_backend_source.sh — C-1 (phase-63): a read cache whose SOURCE is the
# export's registered remote backend (brix_storage_backend root://O), with NO
# separate brix_cache_origin. A miss fills FROM the backend (driver open/pread →
# staged sink), stores locally, serves byte-exact; a warm read is a cache hit.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"; XRDFS="$HERE/client/bin/xrdfs"
OPORT=11664; BPORT=11665; PFX="$(mktemp -d /tmp/cache_src.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o b; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/cache_src_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/b/export" "$PFX/b/cache" "$PFX/b/logs"
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; brix_root on; brix_auth none; brix_storage_backend posix:$PFX/o/root; brix_allow_write on; } }
EOF
cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${BPORT}; brix_root on; brix_auth none;
    brix_storage_backend root://127.0.0.1:${OPORT};   # the origin
    brix_cache_store posix:$PFX/b/cache;              # physical FSAL
    brix_cache_export /;                                 # advertised root
} }
EOF
# seed two files DIRECTLY on the origin O
head -c 500000  /dev/urandom > "$PFX/o/root/small.bin"
head -c 2600000 /dev/urandom > "$PFX/o/root/big.bin"
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B start failed"; cat "$PFX/b/err"; exit 2; }
sleep 1
echo "== cold read: cache MISS fills from the backend source =="
"$XRDFS" root://127.0.0.1:${BPORT} cat /small.bin > /tmp/cache_src_s.got 2>"$PFX/b/logs/cat.err"
cmp -s "$PFX/o/root/small.bin" /tmp/cache_src_s.got && ok "byte-exact serve (filled from backend)" \
  || { bad "differs"; grep -iE 'cache|source|xroot|backend|error' "$PFX/b/logs/e.log" | tail -8; }
[ -f "$PFX/b/cache/small.bin" ] && ok "object landed in the local cache (fill stored)" || bad "no cache entry created"
echo "== warm read: served from cache =="
"$XRDFS" root://127.0.0.1:${BPORT} cat /small.bin > /tmp/cache_src_s2.got 2>/dev/null
cmp -s "$PFX/o/root/small.bin" /tmp/cache_src_s2.got && ok "warm hit byte-exact" || bad "warm differs"
echo "== multi-chunk fill (> fetch chunk) =="
"$XRDFS" root://127.0.0.1:${BPORT} cat /big.bin > /tmp/cache_src_b.got 2>/dev/null
cmp -s "$PFX/o/root/big.bin" /tmp/cache_src_b.got && ok "multi-chunk byte-exact" \
  || bad "multi-chunk differs (got=$(stat -c%s /tmp/cache_src_b.got 2>/dev/null))"
[ "$fail" = 0 ] && echo "run_cache_backend_source: ALL PASS" || echo "run_cache_backend_source: FAILURES"
exit "$fail"
