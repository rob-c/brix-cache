#!/usr/bin/env bash
#
# run_tier_instance_lifetime.sh — storage-driver instance LIFETIME through a
# composed tier stack (read-cache + write-stage over a remote root:// backend).
#
# Regression for the xrd1 crash-loop: tier composition runs during
# CONFIGURATION PARSE, when ngx_cycle still names nginx's transient init cycle
# — whose pool is destroyed as startup completes.  Storage-driver instances
# allocated from that pool (brix_sd_instance_create used ngx_cycle->pool)
# dangled, and the FIRST request through the tier dereferenced freed memory:
# every staged write / cache fill SIGSEGV'd the worker (crash-loop, client saw
# "file not found" when its upload resume raced the dead worker).  Fixed by
# giving the SD registry a private process-lifetime pool.
#
# The test runs the tier stack in PRODUCTION shape (master + multiple workers,
# exactly what crashed on xrd1) and checks every tier surface after startup,
# then again after a live reload (a second config parse over a running tree):
#   1. success   — staged write flushes to the origin byte-exact
#   2. success   — cold read fills the cache; warm read serves from it
#   3. reload    — SIGHUP re-parse, then the same paths again
#   4. invariant — ZERO workers died on a signal anywhere in the run
#
# Usage: tests/run_tier_instance_lifetime.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDCP="$HERE/client/bin/xrdcp"
XRDFS="$HERE/client/bin/xrdfs"
OPORT=11764
BPORT=11765
PFX="$(mktemp -d /tmp/tier_life.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() {
    for r in o b; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done
    rm -rf "$PFX"
}
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/b/export" "$PFX/b/cache" \
         "$PFX/b/stage" "$PFX/b/logs"

# Origin O — plain root:// server (auth is not what this test is about).
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; brix_root on; brix_export $PFX/o/root;
    brix_auth none; brix_allow_write on; } }
EOF

# Node B — the full composed stack over the remote backend, in PRODUCTION
# process shape: master + 2 workers (the config-parse composition happens in
# the master's init cycle; the request arrives in a forked worker — the exact
# sequence that dereferenced the destroyed init-cycle pool).
cat > "$PFX/b/nginx.conf" <<EOF
daemon on; master_process on; worker_processes 2;
error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${BPORT}; brix_root on; brix_export $PFX/b/export;
    brix_auth none; brix_allow_write on;
    brix_storage_backend root://127.0.0.1:${OPORT};
    brix_cache_store posix:$PFX/b/cache; brix_cache_export /;
    brix_stage on; brix_stage_store posix:$PFX/b/stage; brix_stage_flush async;
} }
EOF

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B start failed"; cat "$PFX/b/err"; exit 2; }
sleep 1

head -c 300000  /dev/urandom > "$PFX/small.bin"
head -c 2600000 /dev/urandom > "$PFX/big.bin"
head -c 500000  /dev/urandom > "$PFX/o/root/pre.bin"     # pre-seeded on the origin

wait_flush() { # <origin-file> <reference> <label>
    local i
    for i in $(seq 1 30); do
        cmp -s "$2" "$1" && { ok "$3"; return 0; }
        sleep 0.5
    done
    bad "$3 (flush never landed byte-exact)"; return 1
}

echo "== staged writes through the tier land on the origin (async flush) =="
"$XRDCP" -f "$PFX/small.bin" "root://127.0.0.1:${BPORT}//small.bin" >/dev/null 2>&1 \
    || bad "small write failed outright"
wait_flush "$PFX/o/root/small.bin" "$PFX/small.bin" "small staged write flushed byte-exact"
"$XRDCP" -f "$PFX/big.bin" "root://127.0.0.1:${BPORT}//big.bin" >/dev/null 2>&1 \
    || bad "multi-chunk write failed outright"
wait_flush "$PFX/o/root/big.bin" "$PFX/big.bin" "multi-chunk staged write flushed byte-exact"

echo "== cold read fills the cache; warm read serves from it =="
"$XRDFS" "root://127.0.0.1:${BPORT}" cat /pre.bin > "$PFX/cold.got" 2>/dev/null
cmp -s "$PFX/o/root/pre.bin" "$PFX/cold.got" && ok "cold read (cache fill) byte-exact" \
    || bad "cold read differs/empty (got=$(stat -c%s "$PFX/cold.got" 2>/dev/null))"
"$XRDFS" "root://127.0.0.1:${BPORT}" cat /pre.bin > "$PFX/warm.got" 2>/dev/null
cmp -s "$PFX/o/root/pre.bin" "$PFX/warm.got" && ok "warm read (cache hit) byte-exact" \
    || bad "warm read differs/empty"

echo "== live reload (second config parse over a running tree), then again =="
kill -HUP "$(cat "$PFX/b/nginx.pid")"
sleep 1.5
"$XRDCP" -f "$PFX/small.bin" "root://127.0.0.1:${BPORT}//post-reload.bin" >/dev/null 2>&1 \
    || bad "post-reload write failed outright"
wait_flush "$PFX/o/root/post-reload.bin" "$PFX/small.bin" "post-reload staged write flushed byte-exact"
"$XRDFS" "root://127.0.0.1:${BPORT}" cat /pre.bin > "$PFX/post.got" 2>/dev/null
cmp -s "$PFX/o/root/pre.bin" "$PFX/post.got" && ok "post-reload read byte-exact" \
    || bad "post-reload read differs/empty"

echo "== invariant: no worker died at any point =="
if grep -qE "exited on signal|exited with fatal" "$PFX/b/logs/e.log"; then
    bad "worker death in the error log (the lifetime bug is back)"
    grep -E "exited on signal|exited with fatal" "$PFX/b/logs/e.log" | head -3
else
    ok "zero worker deaths across writes, fills, hits, and a reload"
fi

[ $fail -eq 0 ] && echo "run_tier_instance_lifetime: ALL PASS" \
    || { echo "run_tier_instance_lifetime: FAILURES"; exit 1; }
