#!/usr/bin/env bash
#
# run_cache_watermark.sh — end-to-end proof of the watermark-driven LRU reaper
# (Phase B, Tasks B3+B4). The HIGH/LOW watermarks are a fraction of the *whole*
# filesystem occupancy (statvfs), which cannot be forced to 90% on a shared /tmp,
# so the test sets the watermarks RELATIVE to the live filesystem usage:
#
#   "purge" instance:  HIGH/LOW just BELOW current usage  → the timer must purge
#                      (occupancy already exceeds HIGH; a tiny cache cannot reach
#                      LOW, so it evicts every eligible file) — and a DIRTY
#                      write-back file must SURVIVE (never reaped).
#   "calm"  instance:  HIGH just ABOVE current usage       → the timer must NOT
#                      purge (occupancy is below HIGH); planted files survive.
#
# Usage: tests/run_cache_watermark.sh [nginx-binary] [objs-dir]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
OBJS="${2:-/tmp/nginx-1.28.3/objs}"
CINFO_O="${OBJS}/addon/cache/cinfo.o"
PFX="$(mktemp -d /tmp/cache_wm.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() {
    for p in "$PFX"/*/nginx.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done
    rm -rf "$PFX"
}
trap cleanup EXIT

[ -f "$CINFO_O" ] || { echo "cinfo.o not found at $CINFO_O — build the module first"; exit 2; }

# Live filesystem usage % of the device holding the cache tree.
USED="$(df --output=pcent "$PFX" 2>/dev/null | tail -1 | tr -dc '0-9')"
[ -n "$USED" ] || { echo "could not read df usage"; exit 2; }
if [ "$USED" -lt 10 ] || [ "$USED" -gt 96 ]; then
    echo "run_cache_watermark: SKIP (filesystem usage ${USED}% outside testable 10-96% band)"
    exit 0
fi
HIGH_PURGE=$((USED - 2)); LOW_PURGE=$((USED - 5)); [ "$LOW_PURGE" -lt 1 ] && LOW_PURGE=1
HIGH_CALM=$((USED + 2));  [ "$HIGH_CALM" -gt 99 ] && HIGH_CALM=99
LOW_CALM=$((HIGH_CALM - 3))
echo "  (filesystem usage ${USED}% → purge ${HIGH_PURGE}/${LOW_PURGE}%, calm ${HIGH_CALM}/${LOW_CALM}%)"

# mk_dirty: stamp a dirty .cinfo so the candidate collector skips the data file.
cat > "$PFX/mk_dirty.c" <<'EOF'
#include <stdint.h>
#include <stddef.h>
typedef intptr_t ngx_int_t;
ngx_int_t xrootd_cache_cinfo_mark_dirty(const char *cache_path, uint64_t size,
    uint32_t block_size, uint64_t mtime, uint64_t off, uint64_t len, void *log);
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    return xrootd_cache_cinfo_mark_dirty(argv[1], 65536, 1048576, 1000, 0, 65536, NULL) == 0 ? 0 : 1;
}
EOF
cc -O -o "$PFX/mk_dirty" "$PFX/mk_dirty.c" "$CINFO_O" || { echo "failed to build mk_dirty"; exit 2; }

# Build one cache instance. $1=name $2=port $3=high% $4=low% $5=metrics_port(opt)
spawn() {
    local name="$1" port="$2" high="$3" low="$4" mport="${5:-}" d="$PFX/$1" http_blk=""
    mkdir -p "$d/root" "$d/cache" "$d/logs"
    [ -n "$mport" ] && http_blk="http { server { listen 127.0.0.1:${mport}; location /metrics { xrootd_metrics on; } } }"
    cat > "$d/nginx.conf" <<EOF
daemon on; error_log $d/logs/e.log info; pid $d/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${port}; xrootd on; xrootd_root $d/root; xrootd_auth none;
    xrootd_cache on; xrootd_cache_root $d/cache; xrootd_cache_origin 127.0.0.1:1;
    xrootd_cache_high_watermark ${high}%;
    xrootd_cache_low_watermark  ${low}%;
    xrootd_cache_reap_interval 1;
} }
${http_blk}
EOF
    # Plant 4 plain files (oldest→newest) + 1 dirty file that must survive.
    for i in 1 2 3 4; do
        head -c 65536 /dev/urandom > "$d/cache/plain_${i}.bin"
        touch -d "$((10 - i)) hours ago" "$d/cache/plain_${i}.bin"   # plain_1 oldest
    done
    head -c 65536 /dev/urandom > "$d/cache/keep_dirty.bin"
    "$PFX/mk_dirty" "$d/cache/keep_dirty.bin" || return 2
    "$NGINX" -p "$d" -c "$d/nginx.conf" 2>"$d/logs/start.err" || { echo "start failed ($name)"; cat "$d/logs/start.err"; return 2; }
}

spawn purge 11606 "$HIGH_PURGE" "$LOW_PURGE" 11608 || exit 2
spawn calm  11607 "$HIGH_CALM"  "$LOW_CALM"        || exit 2

# First reaper tick is ~5s + jitter; reap_interval 1s thereafter. Wait for the
# purge instance to remove its plain files.
deadline=$((SECONDS + 25))
while [ $SECONDS -lt $deadline ] && ls "$PFX/purge/cache"/plain_*.bin >/dev/null 2>&1; do sleep 1; done

# --- purge instance assertions ---
if ls "$PFX/purge/cache"/plain_*.bin >/dev/null 2>&1; then
    bad "purge: plain files NOT reaped"; ls "$PFX/purge/cache"
else
    ok "purge: all plain files reaped (timer drove watermark purge)"
fi
[ -f "$PFX/purge/cache/keep_dirty.bin" ] && ok "purge: DIRTY write-back file survived (never reaped)" \
    || bad "purge: dirty file was wrongly reaped"
# Its .cinfo must persist too — evicting the sidecar would un-protect the data on
# the next tick (~15 ticks have run by now), so survival proves durable protection.
[ -f "$PFX/purge/cache/keep_dirty.bin.cinfo" ] && ok "purge: dirty .cinfo sidecar persisted (durable protection)" \
    || bad "purge: dirty .cinfo was reaped (un-protects data on next tick)"
grep -q 'watermark reaper purged' "$PFX/purge/logs/e.log" && ok "purge: watermark NOTICE logged" \
    || bad "purge: no watermark NOTICE"

# --- B5 metrics: dedicated watermark-reaper family on /metrics ---
M="$(curl -s --max-time 5 "http://127.0.0.1:11608/metrics" 2>/dev/null)"
echo "$M" | grep -q '^xrootd_cache_usage_ratio ' && ok "metrics: cache_usage_ratio gauge present" \
    || bad "metrics: no cache_usage_ratio gauge"
wm_files="$(echo "$M" | awk '/^xrootd_cache_watermark_evicted_files_total /{print $2}')"
[ -n "$wm_files" ] && [ "${wm_files%.*}" -gt 0 ] 2>/dev/null \
    && ok "metrics: watermark_evicted_files_total > 0 ($wm_files)" \
    || bad "metrics: watermark_evicted_files_total not positive ($wm_files)"
echo "$M" | awk '/^xrootd_cache_watermark_purges_total /{exit ($2>0)?0:1}' \
    && ok "metrics: watermark_purges_total > 0" || bad "metrics: watermark_purges_total not positive"

# --- calm instance assertions (give it the same wall time; it must NOT purge) ---
n_calm=$(ls "$PFX/calm/cache"/plain_*.bin 2>/dev/null | wc -l)
[ "$n_calm" -eq 4 ] && ok "calm: all 4 plain files survived (below HIGH → no purge)" \
    || bad "calm: $n_calm/4 plain files survived (unexpected purge)"
grep -q 'watermark reaper purged' "$PFX/calm/logs/e.log" && bad "calm: purged despite being below HIGH" \
    || ok "calm: no purge below HIGH watermark"

[ "$fail" = 0 ] && echo "run_cache_watermark: ALL PASS" || echo "run_cache_watermark: FAILURES"
exit "$fail"
