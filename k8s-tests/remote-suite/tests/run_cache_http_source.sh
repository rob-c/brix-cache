#!/usr/bin/env bash
# run_cache_http_source.sh — C-4 (phase-63): a read cache whose SOURCE is a plain
# read-only HTTP(S) origin (brix_storage_backend http://H/base), served through
# the sd_http driver over the shared libcurl transport — NO separate cache_origin.
# A miss HEADs for the size then Range-GETs to fill (driver pread → staged sink),
# stores locally, serves byte-exact; a warm read is a cache hit. The HTTP origin is
# a stock `python3 -m http.server` (no XRootD), proving the source is generic HTTP.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"; XRDFS="$HERE/client/bin/xrdfs"
HPORT=11668; BPORT=11669; PFX="$(mktemp -d /tmp/cache_http.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){
    for r in o b; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done
    rm -rf "$PFX" /tmp/cache_http_*.got
}
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/b/export" "$PFX/b/cache" "$PFX/b/logs"

# seed two files DIRECTLY in the HTTP origin's docroot
head -c 500000  /dev/urandom > "$PFX/o/root/small.bin"
head -c 2600000 /dev/urandom > "$PFX/o/root/big.bin"

# plain static HTTP origin (the same nginx binary) — no XRootD on the source side.
# nginx serves static files with Range support, so cache fills hit real 206 GETs.
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
http {
    access_log off;
    server { listen 127.0.0.1:${HPORT}; location / { root $PFX/o/root; } }
}
EOF

cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${BPORT}; brix_root on; brix_auth none;
    brix_storage_backend http://127.0.0.1:${HPORT};
    brix_cache_store posix:$PFX/b/cache; brix_cache_export /;
} }
EOF

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B start failed"; cat "$PFX/b/err"; exit 2; }
sleep 1

echo "== cold read: cache MISS fills from the HTTP source (HEAD + Range GET) =="
"$XRDFS" root://127.0.0.1:${BPORT} cat /small.bin > /tmp/cache_http_s.got 2>"$PFX/b/logs/cat.err"
cmp -s "$PFX/o/root/small.bin" /tmp/cache_http_s.got && ok "byte-exact serve (filled from HTTP)" \
  || { bad "differs"; grep -iE 'cache|source|http|backend|error' "$PFX/b/logs/e.log" | tail -8; }
[ -f "$PFX/b/cache/small.bin" ] && ok "object landed in the local cache (fill stored)" || bad "no cache entry created"

echo "== warm read: served from cache =="
"$XRDFS" root://127.0.0.1:${BPORT} cat /small.bin > /tmp/cache_http_s2.got 2>/dev/null
cmp -s "$PFX/o/root/small.bin" /tmp/cache_http_s2.got && ok "warm hit byte-exact" || bad "warm differs"

echo "== multi-chunk fill (> fetch chunk) =="
"$XRDFS" root://127.0.0.1:${BPORT} cat /big.bin > /tmp/cache_http_b.got 2>/dev/null
cmp -s "$PFX/o/root/big.bin" /tmp/cache_http_b.got && ok "multi-chunk byte-exact" \
  || bad "multi-chunk differs (got=$(stat -c%s /tmp/cache_http_b.got 2>/dev/null))"

[ "$fail" = 0 ] && echo "run_cache_http_source: ALL PASS" || echo "run_cache_http_source: FAILURES"
exit "$fail"
