#!/usr/bin/env bash
#
# run_cache_pblock_posix.sh — Test 1 of the exclusively-VFS caching layer:
# a pblock PRIMARY export with a POSIX read cache and a POSIX write-back staging
# cache. Verifies (a) a write to the pblock primary is mirrored to a root:// origin
# THROUGH the POSIX staging copy (byte-exact, multi-block), and (b) a read miss of
# an origin-only file fills the POSIX read cache and serves byte-exact.
#
# The origin runs as a SEPARATE nginx process (a sync-mode flush blocks the worker
# loop, so a same-worker origin would deadlock — real deployments have a distinct
# origin node).
#
# Usage: tests/run_cache_pblock_posix.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDCP="$HERE/client/bin/xrdcp"
XRDFS="$HERE/client/bin/xrdfs"
ORIGIN_PORT=11562
NODE_PORT=11563
PFX="$(mktemp -d /tmp/cache_pp.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }

mkdir -p "$PFX/o/root" "$PFX/o/logs" \
         "$PFX/n/root" "$PFX/n/cache" "$PFX/n/stage" "$PFX/n/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${ORIGIN_PORT}; xrootd on; xrootd_root $PFX/o/root;
    xrootd_auth none; xrootd_allow_write on; xrootd_upload_resume off; } }
EOF

cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/nginx.pid;
events { worker_connections 64; }
thread_pool default threads=2;
stream {
    server {
        listen 127.0.0.1:${NODE_PORT};
        xrootd on;
        xrootd_root $PFX/n/root;
        xrootd_auth none;
        xrootd_allow_write on;
        xrootd_upload_resume off;
        xrootd_storage_backend  pblock;          # pblock PRIMARY
        xrootd_pblock_block_size 1m;
        xrootd_cache on;                          # POSIX read cache
        xrootd_cache_root   $PFX/n/cache;
        xrootd_cache_origin 127.0.0.1:${ORIGIN_PORT};
        xrootd_write_through on;                  # POSIX write-back staging
        xrootd_wt_mode sync;
        xrootd_wt_origin 127.0.0.1:${ORIGIN_PORT};
        xrootd_cache_wt_stage_root $PFX/n/stage;
    }
}
EOF

cleanup() {
    for r in o n; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done
    rm -rf "$PFX" /tmp/cpp_*.bin
}
trap cleanup EXIT

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "origin failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo "node failed"; cat "$PFX/n/err"; exit 2; }
sleep 1

echo "== write to pblock primary → mirror to origin via the POSIX staging copy =="
head -c 2621440 /dev/urandom > /tmp/cpp_w.bin    # 2.5 pblock blocks
"$XRDCP" -f /tmp/cpp_w.bin "root://127.0.0.1:${NODE_PORT}//w.bin" >/dev/null 2>&1 \
    && ok "PUT to pblock primary" || bad "PUT to pblock primary"
sleep 1
if [ -f "$PFX/o/root/w.bin" ]; then
    cmp -s /tmp/cpp_w.bin "$PFX/o/root/w.bin" && ok "origin mirror byte-exact (multi-block, via stage)" \
        || bad "origin mirror DIFFERS"
else
    bad "origin file missing — write-through did not mirror"
    grep -iE 'wt: flush|stage' "$PFX/n/logs/e.log" | tail -2
fi
[ -d "$PFX/n/root/data" ] && ok "primary kept in pblock (data/)" || bad "no pblock primary data dir"
[ -n "$(find "$PFX/n/stage" -type f 2>/dev/null | head -1)" ] && ok "POSIX staging copy present" \
    || bad "no POSIX staging copy"

echo "== read miss of an origin-only file → fills the POSIX read cache =="
head -c 1500000 /dev/urandom > "$PFX/o/root/r.bin"   # origin-only
"$XRDFS" root://127.0.0.1:${NODE_PORT} cat /r.bin > /tmp/cpp_r.got 2>/dev/null
cmp -s "$PFX/o/root/r.bin" /tmp/cpp_r.got && ok "read-through fill byte-exact" || bad "read fill DIFFERS"
[ -f "$PFX/n/cache/r.bin" ] && ok "POSIX read cache file present" || bad "no POSIX read cache file"

[ "$fail" = 0 ] && echo "run_cache_pblock_posix: ALL PASS" || echo "run_cache_pblock_posix: FAILURES"
exit "$fail"
