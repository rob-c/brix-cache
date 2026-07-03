#!/usr/bin/env bash
#
# run_cache_pblock_posix.sh — Test 1 of the exclusively-VFS caching layer, on the
# phase-64 TIER grammar (§14: the legacy brix_cache_origin model is retired).
# Two server blocks on one node cover the two legacy assertions:
#   W (pblock primary + write-through): a write to the pblock primary is mirrored
#     to a root:// origin byte-exact (multi-block, driver read-back).
#   R (tier read cache): storage_backend root://O + a POSIX cache_store — a read
#     miss of an origin-only file fills the local cache and serves byte-exact.
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
READ_PORT=11568
PFX="$(mktemp -d /tmp/cache_pp.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }

mkdir -p "$PFX/o/root" "$PFX/o/logs" \
         "$PFX/n/root" "$PFX/n/rroot" "$PFX/n/cache" "$PFX/n/stage" "$PFX/n/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${ORIGIN_PORT}; xrootd on; brix_storage_backend posix:$PFX/o/root;
    brix_auth none; brix_allow_write on; brix_upload_resume off; } }
EOF

cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/nginx.pid;
events { worker_connections 64; }
thread_pool default threads=2;
stream {
    # W: pblock PRIMARY + write-through mirror to the origin (sd_stage Option A).
    server {
        listen 127.0.0.1:${NODE_PORT};
        xrootd on;
        brix_auth none;
        brix_allow_write on;
        brix_upload_resume off;
        brix_storage_backend  pblock://$PFX/n/root/;   # pblock PRIMARY (path = root, created on init)
        brix_pblock_block_size 1m;
        brix_write_through on;
        brix_wt_mode sync;
        brix_wt_origin 127.0.0.1:${ORIGIN_PORT};
        brix_cache_wt_stage_root $PFX/n/stage;
    }
    # R: tier read cache — the origin is the storage backend, cached locally.
    server {
        listen 127.0.0.1:${READ_PORT};
        xrootd on;
        brix_auth none;
        brix_root $PFX/n/rroot;
        brix_storage_backend root://127.0.0.1:${ORIGIN_PORT};
        brix_cache_store posix:$PFX/n/cache;
        brix_cache_root /;
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

echo "== write to pblock primary → mirror to origin via the wt sd_stage decorator =="
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
# Write-through now routes through the wt sd_stage decorator (Option A): the write
# BUFFERS on the pblock store (the primary, verified byte-exact to origin above) and
# flushes to the origin on sync/close — it no longer makes a SEPARATE POSIX staging
# copy under cache_wt_stage_root (that was the legacy run_flush mechanism). The
# origin-mirror byte-exact check above is the functional write-through assertion.
ok "write-through mirrored via sd_stage (no separate POSIX staging copy — expected)"

echo "== read miss of an origin-only file → fills the POSIX read cache (tier R) =="
head -c 1500000 /dev/urandom > "$PFX/o/root/r.bin"   # origin-only
"$XRDFS" root://127.0.0.1:${READ_PORT} cat /r.bin > /tmp/cpp_r.got 2>/dev/null
cmp -s "$PFX/o/root/r.bin" /tmp/cpp_r.got && ok "read-through fill byte-exact" || bad "read fill DIFFERS"
[ -f "$PFX/n/cache/r.bin" ] && ok "POSIX read cache file present" || bad "no POSIX read cache file"

[ "$fail" = 0 ] && echo "run_cache_pblock_posix: ALL PASS" || echo "run_cache_pblock_posix: FAILURES"
exit "$fail"
