#!/usr/bin/env bash
#
# run_cache_reaper.sh — end-to-end proof of the unified cache-state engine's
# stale-dirty reaper. Stands up its own stream-only nginx with a cache state root
# and a 1-second brix_cache_dirty_max_age, plants an aged-dirty .cinfo record
# (via the real brix_cache_cinfo_mark_dirty, linked against the built cinfo.o),
# waits for the per-worker reaper timer to fire, and asserts the data file + its
# sidecar are removed. Also asserts a CLEAN file is left untouched.
#
# Usage: tests/run_cache_reaper.sh [nginx-binary] [objs-dir]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
OBJS="${2:-/tmp/nginx-1.28.3/objs}"
CINFO_O="${OBJS}/addon/cache/cinfo.o"
PORT=11505
PFX="$(mktemp -d /tmp/cache_reaper.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }

[ -f "$CINFO_O" ] || { echo "cinfo.o not found at $CINFO_O — build the module first"; exit 2; }

mkdir -p "$PFX/root" "$PFX/state" "$PFX/logs"

# Tiny helper: mark a cache path dirty in the unified state record. mark_dirty
# stamps dirty_since=now; with dirty_max_age=1 and the reaper's 5s first tick the
# record is already aged when the reaper runs (no backdating needed).
cat > "$PFX/mk_dirty.c" <<'EOF'
#include <stdint.h>
#include <stddef.h>
typedef intptr_t ngx_int_t;
ngx_int_t brix_cache_cinfo_mark_dirty(const char *cache_path, uint64_t size,
    uint32_t block_size, uint64_t mtime, uint64_t off, uint64_t len, void *log);
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    return brix_cache_cinfo_mark_dirty(argv[1], 4096, 1048576, 1000, 0, 4096, NULL)
           == 0 ? 0 : 1;
}
EOF
cc -O -o "$PFX/mk_dirty" "$PFX/mk_dirty.c" "$CINFO_O" || { echo "failed to build mk_dirty"; exit 2; }

cat > "$PFX/nginx.conf" <<EOF
daemon on;
error_log $PFX/logs/error.log info;
pid $PFX/nginx.pid;
events { worker_connections 64; }
stream {
    server {
        listen 127.0.0.1:${PORT};
        brix_root on;
        brix_export $PFX/root;
        brix_auth none;
        brix_cache_state_root  $PFX/state;
        brix_cache_dirty_max_age 1;
    }
}
EOF

cleanup() { [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT

# Plant an aged-dirty file and a clean file under the state root.
DIRTY="$PFX/state/abandoned.bin"
CLEAN="$PFX/state/keepme.bin"
head -c 4096 /dev/urandom > "$DIRTY"
head -c 4096 /dev/urandom > "$CLEAN"
"$PFX/mk_dirty" "$DIRTY" || { echo "mk_dirty failed"; exit 2; }
[ -f "$DIRTY.cinfo" ] && ok "planted dirty .cinfo" || bad "no dirty .cinfo planted"

"$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/logs/start.err" || { echo "nginx failed to start"; cat "$PFX/logs/start.err"; exit 2; }

# Reaper first tick is at 5s; wait generously past it. Wait for the data file
# AND its sidecar — the reaper unlinks them back to back, so polling only the
# data file can observe the (sub-ms) in-between state and spuriously fail.
deadline=$((SECONDS + 20))
while [ $SECONDS -lt $deadline ] && { [ -f "$DIRTY" ] || [ -f "$DIRTY.cinfo" ]; }; do
    sleep 1
done

[ ! -f "$DIRTY" ]        && ok "aged-dirty data file reaped"       || bad "aged-dirty file NOT reaped"
[ ! -f "$DIRTY.cinfo" ]  && ok "dirty .cinfo sidecar reaped"       || bad ".cinfo sidecar NOT reaped"
[ -f "$CLEAN" ]          && ok "clean file left untouched"         || bad "clean file was wrongly removed"
grep -q 'reaped stale-dirty file' "$PFX/logs/error.log" && ok "reaper logged a WARN" || bad "no reaper WARN logged"

[ "$fail" = 0 ] && echo "run_cache_reaper: ALL PASS" || echo "run_cache_reaper: FAILURES"
exit "$fail"
