#!/usr/bin/env bash
#
# run_cache_stage_throttle.sh — end-to-end proof of the two-tier write-back-
# staging backpressure gate (Phase C). The staging watermarks are a fraction of
# the staging *filesystem* occupancy (statvfs), which cannot be forced on a shared
# /tmp, so the watermarks are set RELATIVE to live `df` usage:
#
#   "reject" instance: HIGH just BELOW usage  → a root:// write-open is REJECTED
#                      (kXR_Overloaded); the client write fails; reads still work.
#   "wait"   instance: LOW below / HIGH above usage → a write-open is DELAYED
#                      (kXR_wait); the server records a wait.
#
# Reads are never throttled by staging fullness. Asserts via client behavior +
# the /metrics counters.
#
# Usage: tests/run_cache_stage_throttle.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDCP="$HERE/client/bin/xrdcp"
XRDFS="$HERE/client/bin/xrdfs"
PFX="$(mktemp -d /tmp/stage_thr.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() {
    for p in "$PFX"/*/nginx.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done
    rm -rf "$PFX" /tmp/stage_thr_*.bin
}
trap cleanup EXIT

USED="$(df --output=pcent "$PFX" 2>/dev/null | tail -1 | tr -dc '0-9')"
[ -n "$USED" ] || { echo "could not read df usage"; exit 2; }
if [ "$USED" -lt 10 ] || [ "$USED" -gt 94 ]; then
    echo "run_cache_stage_throttle: SKIP (filesystem usage ${USED}% outside testable 10-94% band)"
    exit 0
fi
RJ_HIGH=$((USED - 2)); RJ_LOW=$((USED - 5)); [ "$RJ_LOW" -lt 1 ] && RJ_LOW=1
WT_HIGH=$((USED + 3)); [ "$WT_HIGH" -gt 99 ] && WT_HIGH=99; WT_LOW=$((USED - 3)); [ "$WT_LOW" -lt 1 ] && WT_LOW=1
echo "  (filesystem usage ${USED}% → reject ${RJ_HIGH}/${RJ_LOW}%, wait ${WT_HIGH}/${WT_LOW}%)"

# $1=name $2=port $3=high% $4=low% $5=metrics_port
spawn() {
    local name="$1" port="$2" high="$3" low="$4" mport="$5" d="$PFX/$1"
    mkdir -p "$d/root" "$d/stage" "$d/logs"
    echo "readable-content-$name" > "$d/root/readme.txt"   # a file reads can fetch
    cat > "$d/nginx.conf" <<EOF
daemon on; error_log $d/logs/e.log info; pid $d/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${port}; xrootd on; brix_auth none;
    brix_storage_backend posix:$d/root;
    brix_allow_write on; brix_upload_resume off;
    brix_write_through on; brix_wt_mode sync; brix_wt_origin 127.0.0.1:1;
    brix_cache_wt_stage_root $d/stage;
    brix_wt_stage_high_watermark ${high}%;
    brix_wt_stage_low_watermark  ${low}%;
} }
http { server { listen 127.0.0.1:${mport}; location /metrics { brix_metrics on; } } }
EOF
    "$NGINX" -p "$d" -c "$d/nginx.conf" 2>"$d/logs/start.err" || { echo "start failed ($name)"; cat "$d/logs/start.err"; return 2; }
}

spawn reject 11616 "$RJ_HIGH" "$RJ_LOW" 11618 || exit 2
spawn wait   11617 "$WT_HIGH" "$WT_LOW" 11619 || exit 2
sleep 1
head -c 4096 /dev/urandom > /tmp/stage_thr_w.bin

echo "== reject instance: write rejected, read still works =="
"$XRDCP" -f /tmp/stage_thr_w.bin "root://127.0.0.1:11616//w.bin" >/tmp/stage_thr_rj.out 2>&1
if [ $? -ne 0 ]; then ok "reject: root:// write failed (staging full)"; else bad "reject: write unexpectedly succeeded"; fi
[ ! -f "$PFX/reject/root/w.bin" ] && ok "reject: no file created (shed before any write)" || bad "reject: file was created despite reject"
got="$("$XRDFS" root://127.0.0.1:11616 cat /readme.txt 2>/dev/null)"
[ "$got" = "readable-content-reject" ] && ok "reject: READ still works (reads never throttled)" || bad "reject: read was wrongly blocked (got '$got')"
MR="$(curl -s --max-time 5 http://127.0.0.1:11618/metrics 2>/dev/null)"
echo "$MR" | awk '/^brix_wt_stage_throttled_total\{action="reject"\}/{exit ($2>0)?0:1}' \
    && ok "reject: throttled_total{reject} > 0" || bad "reject: reject counter not incremented"
echo "$MR" | grep -q '^brix_wt_stage_usage_ratio ' && ok "reject: wt_stage_usage_ratio gauge present" || bad "reject: no usage_ratio gauge"

echo "== wait instance: write delayed (kXR_wait) =="
# A write in the soft band gets kXR_wait; the client sleeps + retries. Run it in
# the background and sample the metric, then stop it (don't wait out the retries).
timeout 8 "$XRDCP" -f /tmp/stage_thr_w.bin "root://127.0.0.1:11617//w.bin" >/tmp/stage_thr_wt.out 2>&1 &
wpid=$!
deadline=$((SECONDS + 6)); waited=0
while [ $SECONDS -lt $deadline ]; do
    MW="$(curl -s --max-time 3 http://127.0.0.1:11619/metrics 2>/dev/null)"
    if echo "$MW" | awk '/^brix_wt_stage_throttled_total\{action="wait"\}/{exit ($2>0)?0:1}'; then waited=1; break; fi
    sleep 1
done
kill "$wpid" 2>/dev/null; wait "$wpid" 2>/dev/null
[ "$waited" -eq 1 ] && ok "wait: throttled_total{wait} > 0 (server issued kXR_wait)" || bad "wait: no wait recorded"

[ "$fail" = 0 ] && echo "run_cache_stage_throttle: ALL PASS" || echo "run_cache_stage_throttle: FAILURES"
exit "$fail"
