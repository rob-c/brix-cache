#!/usr/bin/env bash
#
# run_cache_pblock_pblock.sh — Test 2 of the exclusively-VFS caching layer, on the
# phase-64 TIER grammar (§14: the legacy cache_origin/cache_storage_backend model
# is retired): every TIER store is a pblock catalog over a root:// backend.
#
#   backend                        root://O (the origin IS the storage backend)
#   cache tier  (cache_store)      pblock READ cache
#   stage tier  (stage_store)      pblock WRITE staging, sync flush
#
# Verifies the bytes of the cache and stage tiers land in pblock (data/ + catalog,
# NOT a plain POSIX file), a write is flushed to the root:// backend THROUGH the
# pblock staging copy (byte-exact), a read miss is served byte-exact from the
# pblock read cache, the cinfo rides IN the pblock catalog (no POSIX sidecar
# leak), and a warm hit serves with the backend file hidden (G3). The origin is a
# SEPARATE process (a sync flush blocks the worker loop).
#
# Usage: tests/run_cache_pblock_pblock.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDCP="$HERE/client/bin/xrdcp"
XRDFS="$HERE/client/bin/xrdfs"
ORIGIN_PORT=11564
NODE_PORT=11565
PFX="$(mktemp -d /tmp/cache_pb.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }

# is a pblock store? (a data/ subdir holding block files + a catalog db)
is_pblock() { [ -d "$1/data" ] && [ -n "$(find "$1" -name '*.db' -o -name 'catalog*' 2>/dev/null | head -1)$(find "$1/data" -type f 2>/dev/null | head -1)" ]; }

mkdir -p "$PFX/o/root" "$PFX/o/logs" \
         "$PFX/n/root" "$PFX/n/cacheB" "$PFX/n/stageC" "$PFX/n/state" "$PFX/n/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${ORIGIN_PORT}; brix_root on; brix_export $PFX/o/root;
    brix_auth none; brix_allow_write on; brix_upload_resume off; } }
EOF

cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/nginx.pid;
events { worker_connections 64; }
thread_pool default threads=2;
stream {
    server {
        listen 127.0.0.1:${NODE_PORT};
        brix_root on;
        brix_export $PFX/n/root;
        brix_auth none;
        brix_allow_write on;
        brix_upload_resume off;
        brix_storage_backend root://127.0.0.1:${ORIGIN_PORT};
        brix_cache_store pblock:$PFX/n/cacheB block_size=1m;
        brix_cache_export  /;
        brix_stage on;
        brix_stage_store pblock:$PFX/n/stageC block_size=1m;
        brix_stage_flush sync;
    }
}
EOF

cleanup() {
    for r in o n; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done
    rm -rf "$PFX" /tmp/cpb_*.bin /tmp/cpb_*.got
}
trap cleanup EXIT

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "origin failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo "node failed"; cat "$PFX/n/err"; exit 2; }
sleep 1

echo "== write → staged on the pblock stage tier, sync-flushed to the backend =="
head -c 2621440 /dev/urandom > /tmp/cpb_w.bin    # 2.5 blocks
"$XRDCP" -f /tmp/cpb_w.bin "root://127.0.0.1:${NODE_PORT}//w.bin" >/dev/null 2>&1 \
    && ok "PUT through the stage tier" || bad "PUT through the stage tier"
sleep 1
if [ -f "$PFX/o/root/w.bin" ]; then
    cmp -s /tmp/cpb_w.bin "$PFX/o/root/w.bin" && ok "backend copy byte-exact (via pblock stage)" \
        || bad "backend copy DIFFERS"
else
    bad "backend file missing — stage flush did not run"
    grep -iE 'stage' "$PFX/n/logs/e.log" | tail -3
fi
is_pblock "$PFX/n/stageC" && ok "stage tier is pblock"  || bad "stage tier not pblock"

echo "== read miss of a backend-only file → fills the pblock read cache =="
head -c 1500000 /dev/urandom > "$PFX/o/root/r.bin"   # backend-only
"$XRDFS" root://127.0.0.1:${NODE_PORT} cat /r.bin > /tmp/cpb_r.got 2>/dev/null
cmp -s "$PFX/o/root/r.bin" /tmp/cpb_r.got && ok "read-through fill byte-exact" || bad "read fill DIFFERS"
is_pblock "$PFX/n/cacheB" && ok "read cache is pblock" || bad "read cache not pblock"

echo "== cinfo rides IN the pblock catalog (no POSIX sidecar leak) + warm hit (G3) =="
[ -z "$(find "$PFX/n/cacheB" "$PFX/n/stageC" -name '*.meta' -o -name '*.cinfo' 2>/dev/null | head -1)" ] \
    && ok "no POSIX sidecars leaked into the pblock stores" || bad "sidecar leaked into a pblock store"
mv "$PFX/o/root/r.bin" "$PFX/o/root/r.bin.hidden"
"$XRDFS" root://127.0.0.1:${NODE_PORT} cat /r.bin > /tmp/cpb_r2.got 2>/dev/null
cmp -s "$PFX/o/root/r.bin.hidden" /tmp/cpb_r2.got \
    && ok "warm hit byte-exact with the backend file hidden (cinfo in-catalog)" \
    || bad "warm hit failed — cinfo not persisted in the pblock catalog"

[ "$fail" = 0 ] && echo "run_cache_pblock_pblock: ALL PASS" || echo "run_cache_pblock_pblock: FAILURES"
exit "$fail"
