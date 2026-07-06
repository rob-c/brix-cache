#!/usr/bin/env bash
#
# run_root_slice_fill.sh — phase-64 §6.5: a root:// (stream) slice-cache read served
# through the unified sd_cache partial mechanism (not the legacy slice_read path).
# A cache node with the LEGACY config (brix_cache_origin + brix_cache_slice)
# fills per-slice from a root:// origin and serves byte-exact over root://. This is
# the parity gate for routing open_cache.c's slice branch onto sd_cache: a full read
# (cold fill + warm hit) and a multi-slice object must be byte-identical to the
# origin. (Sparse per-block fill is a property of sd_cache, proven for the same
# mechanism by tests/run_tier_slice_fill.sh.)
#
# Usage: tests/run_root_slice_fill.sh [nginx-binary]
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDFS="$HERE/client/bin/xrdfs"
OPORT=11752
CPORT=11753
PFX="$(mktemp -d /tmp/root_slice.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() {
    for r in o c; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done
    rm -rf "$PFX" /tmp/rsf_*.got
}
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/c/export" "$PFX/c/cache" "$PFX/c/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log error; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; brix_root on; brix_export $PFX/o/root; brix_auth none; } }
EOF

# Legacy slice-cache node: brix_cache_origin + brix_cache_slice (>= 1 MiB).
cat > "$PFX/c/nginx.conf" <<EOF
daemon on; error_log $PFX/c/logs/e.log info; pid $PFX/c/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream {
    server {
        listen 127.0.0.1:${CPORT};
        brix_root on;
        brix_export $PFX/c/export;
        brix_auth none;
        brix_storage_backend root://127.0.0.1:${OPORT};
        brix_cache_store posix:$PFX/c/cache; brix_cache_export /;
        brix_cache_slice_size 1m;
    }
}
EOF

head -c 900000  /dev/urandom > "$PFX/o/root/small.bin"    # < 1 slice
head -c 4194304 /dev/urandom > "$PFX/o/root/big.bin"      # 4 slices

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "origin start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/c" -c "$PFX/c/nginx.conf" 2>"$PFX/c/err" || { echo "cache start failed"; cat "$PFX/c/err"; exit 2; }
sleep 1

echo "== cold root:// read: slice-fills /small.bin from the origin =="
"$XRDFS" root://127.0.0.1:${CPORT} cat /small.bin > /tmp/rsf_s.got 2>"$PFX/c/logs/cat1.err"
cmp -s "$PFX/o/root/small.bin" /tmp/rsf_s.got \
  && ok "cold slice read byte-exact" \
  || { bad "cold slice read DIFFERS"; grep -iE 'slice|cache|origin|xroot|fill|error' "$PFX/c/logs/e.log" | tail -8; }
[ -f "$PFX/c/cache/small.bin" ] && ok "object cached under cache_root" || bad "no cache object created"

echo "== warm root:// read: served from cache =="
"$XRDFS" root://127.0.0.1:${CPORT} cat /small.bin > /tmp/rsf_s2.got 2>/dev/null
cmp -s "$PFX/o/root/small.bin" /tmp/rsf_s2.got && ok "warm slice hit byte-exact" || bad "warm hit DIFFERS"

echo "== multi-slice (4 blocks) root:// read byte-exact (read + ReadV) =="
"$XRDFS" root://127.0.0.1:${CPORT} cat /big.bin > /tmp/rsf_b.got 2>/dev/null
cmp -s "$PFX/o/root/big.bin" /tmp/rsf_b.got \
  && ok "multi-slice read byte-exact" \
  || bad "multi-slice DIFFERS (got=$(stat -c%s /tmp/rsf_b.got 2>/dev/null))"

echo "== warm multi-slice read (cache hit across all slices) =="
"$XRDFS" root://127.0.0.1:${CPORT} cat /big.bin > /tmp/rsf_b2.got 2>/dev/null
cmp -s "$PFX/o/root/big.bin" /tmp/rsf_b2.got && ok "warm multi-slice byte-exact" || bad "warm multi-slice DIFFERS"

[ "$fail" = 0 ] && echo "run_root_slice_fill: ALL PASS" || echo "run_root_slice_fill: FAILURES"
exit "$fail"
