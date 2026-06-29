#!/usr/bin/env bash
#
# run_pblock_writethrough.sh — proves the cache fronts a driver-backed PRIMARY:
# a pblock-backed export with write-through mirrors a locally-written multi-block
# file to a root:// origin by reading it back THROUGH the pblock driver (block
# striped), not a raw POSIX read.
#
# The origin and the primary run as SEPARATE nginx processes (a sync-mode flush
# blocks the worker event loop, so an origin served by the SAME worker would
# deadlock — real deployments have a distinct origin node anyway).
#
# Usage: tests/run_pblock_writethrough.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDCP="$HERE/client/bin/xrdcp"
ORIGIN_PORT=11516
PRIMARY_PORT=11517
PFX="$(mktemp -d /tmp/pblock_wt.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }

mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/p/root" "$PFX/p/cache" "$PFX/p/logs"

# --- Origin: a separate plain POSIX root:// server (mirror target). ---
cat > "$PFX/o/nginx.conf" <<EOF
daemon on;
error_log $PFX/o/logs/error.log info;
pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream {
    server {
        listen 127.0.0.1:${ORIGIN_PORT};
        xrootd on;
        xrootd_root $PFX/o/root;
        xrootd_auth none;
        xrootd_allow_write on;
        xrootd_upload_resume off;
    }
}
EOF

# --- Primary: pblock storage + write-through to the origin. ---
cat > "$PFX/p/nginx.conf" <<EOF
daemon on;
error_log $PFX/p/logs/error.log info;
pid $PFX/p/nginx.pid;
events { worker_connections 64; }
thread_pool default threads=2;
stream {
    server {
        listen 127.0.0.1:${PRIMARY_PORT};
        xrootd on;
        xrootd_root $PFX/p/root;
        xrootd_auth none;
        xrootd_allow_write on;
        xrootd_upload_resume off;
        xrootd_storage_backend  pblock;
        xrootd_pblock_block_size 1m;
        xrootd_cache on;
        xrootd_cache_root   $PFX/p/cache;
        xrootd_cache_origin 127.0.0.1:${ORIGIN_PORT};
        xrootd_write_through on;
        xrootd_wt_mode sync;
        xrootd_wt_origin 127.0.0.1:${ORIGIN_PORT};
    }
}
EOF

cleanup() {
    for r in o p; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done
    rm -rf "$PFX" /tmp/pbwt_*.bin
}
trap cleanup EXIT

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/start.err" || { echo "origin nginx failed"; cat "$PFX/o/start.err"; exit 2; }
"$NGINX" -p "$PFX/p" -c "$PFX/p/nginx.conf" 2>"$PFX/p/start.err" || { echo "primary nginx failed"; cat "$PFX/p/start.err"; exit 2; }
sleep 1

head -c 2621440 /dev/urandom > /tmp/pbwt_src.bin    # 2.5 pblock blocks

echo "== write to pblock primary (write-through sync to origin on close) =="
"$XRDCP" -f /tmp/pbwt_src.bin "root://127.0.0.1:${PRIMARY_PORT}//m.bin" >/dev/null 2>&1 \
    && ok "PUT to pblock primary" || bad "PUT to pblock primary"

sleep 1   # sync-mode flush completes during close; let the origin settle

echo "== origin received the mirror (read THROUGH the pblock driver) =="
if [ -f "$PFX/o/root/m.bin" ]; then
    ok "origin file present"
    cmp -s /tmp/pbwt_src.bin "$PFX/o/root/m.bin" && ok "origin bytes match (multi-block, driver read-back)" \
        || bad "origin bytes DIFFER (driver read-back wrong)"
    SZ=$(stat -c %s "$PFX/o/root/m.bin" 2>/dev/null)
    [ "$SZ" = 2621440 ] && ok "origin size 2621440" || bad "origin size $SZ != 2621440"
else
    bad "origin file missing — write-through did not mirror"
    grep -iE 'wt: flush' "$PFX/p/logs/error.log" | tail -2
fi

echo "== primary kept it in pblock (block-striped, not a raw POSIX file) =="
[ -d "$PFX/p/root/data" ]    && ok "pblock data/ dir present"          || bad "no pblock data dir"
[ ! -f "$PFX/p/root/m.bin" ] && ok "no raw POSIX file at primary path" || bad "unexpected raw file at primary"

[ "$fail" = 0 ] && echo "run_pblock_writethrough: ALL PASS" || echo "run_pblock_writethrough: FAILURES"
exit "$fail"
