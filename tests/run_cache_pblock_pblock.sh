#!/usr/bin/env bash
#
# run_cache_pblock_pblock.sh — Test 2 of the exclusively-VFS caching layer:
# every storage plane is a pblock backend, with the .meta/.cinfo sidecars on a
# separate POSIX state root.
#
#   loc A (xrootd_root)            pblock PRIMARY
#   loc B (cache_root)             pblock READ cache       (cache_storage_backend)
#   loc C (cache_wt_stage_root)    pblock WRITE staging    (cache_wt_stage_backend)
#   state (cache_state_root)       POSIX sidecars (.meta/.cinfo)
#
# Verifies the bytes of B and C land in pblock (data/ + catalog, NOT a plain POSIX
# file), the sidecars are POSIX under the state root, a write is mirrored to a
# root:// origin THROUGH the pblock staging copy (byte-exact), and a read miss is
# served byte-exact from the pblock read cache. The origin is a SEPARATE process
# (a sync flush blocks the worker loop).
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
        xrootd_storage_backend  pblock;              # loc A primary
        xrootd_pblock_block_size 1m;
        xrootd_cache on;
        xrootd_cache_root             $PFX/n/cacheB;  # loc B read cache (pblock)
        xrootd_cache_storage_backend  pblock;
        xrootd_cache_storage_block_size 1m;
        xrootd_cache_state_root       $PFX/n/state;   # POSIX sidecars
        xrootd_cache_origin 127.0.0.1:${ORIGIN_PORT};
        xrootd_write_through on;
        xrootd_wt_mode sync;
        xrootd_wt_origin 127.0.0.1:${ORIGIN_PORT};
        xrootd_cache_wt_stage_root       $PFX/n/stageC; # loc C write staging (pblock)
        xrootd_cache_wt_stage_backend    pblock;
        xrootd_cache_wt_stage_block_size 1m;
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

echo "== write to pblock primary → mirror to origin via the pblock staging copy =="
head -c 2621440 /dev/urandom > /tmp/cpb_w.bin    # 2.5 blocks
"$XRDCP" -f /tmp/cpb_w.bin "root://127.0.0.1:${NODE_PORT}//w.bin" >/dev/null 2>&1 \
    && ok "PUT to pblock primary" || bad "PUT to pblock primary"
sleep 1
if [ -f "$PFX/o/root/w.bin" ]; then
    cmp -s /tmp/cpb_w.bin "$PFX/o/root/w.bin" && ok "origin mirror byte-exact (via pblock stage)" \
        || bad "origin mirror DIFFERS"
else
    bad "origin file missing — write-through did not mirror"
    grep -iE 'wt: flush|stage' "$PFX/n/logs/e.log" | tail -3
fi
is_pblock "$PFX/n/root"   && ok "loc A primary is pblock"        || bad "loc A primary not pblock"
is_pblock "$PFX/n/stageC" && ok "loc C write-staging is pblock"  || bad "loc C staging not pblock"

echo "== read miss of an origin-only file → fills the pblock read cache (loc B) =="
head -c 1500000 /dev/urandom > "$PFX/o/root/r.bin"   # origin-only
"$XRDFS" root://127.0.0.1:${NODE_PORT} cat /r.bin > /tmp/cpb_r.got 2>/dev/null
cmp -s "$PFX/o/root/r.bin" /tmp/cpb_r.got && ok "read-through fill byte-exact" || bad "read fill DIFFERS"
is_pblock "$PFX/n/cacheB" && ok "loc B read cache is pblock" || bad "loc B read cache not pblock"

echo "== sidecars are POSIX under the state root, not in the pblock stores =="
[ -n "$(find "$PFX/n/state" -name '*.meta' -o -name '*.cinfo' 2>/dev/null | head -1)" ] \
    && ok "POSIX .meta/.cinfo sidecars under state root" || bad "no sidecars under state root"
[ -z "$(find "$PFX/n/cacheB" "$PFX/n/stageC" -name '*.meta' 2>/dev/null | head -1)" ] \
    && ok "no POSIX sidecars leaked into the pblock stores" || bad "sidecar leaked into a pblock store"

[ "$fail" = 0 ] && echo "run_cache_pblock_pblock: ALL PASS" || echo "run_cache_pblock_pblock: FAILURES"
exit "$fail"
