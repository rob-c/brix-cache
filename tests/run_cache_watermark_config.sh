#!/usr/bin/env bash
#
# run_cache_watermark_config.sh — config-validation tests for the watermark
# reaper directives (Phase B, Task B2). Asserts a valid high/low pair passes
# `nginx -t`, an inverted pair (low >= high) is rejected with the EMERG message,
# and a bare cache_eviction_threshold still works (back-compat: high derives from
# it, low from high).
#
# Usage: tests/run_cache_watermark_config.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
PFX="$(mktemp -d /tmp/wm_cfg.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
mkdir -p "$PFX/root" "$PFX/cache" "$PFX/logs"
trap 'rm -rf "$PFX"' EXIT

emit() {  # $1 = high, $2 = low (omit low to leave it defaulted)
    cat > "$PFX/nginx.conf" <<EOF
daemon off; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:11620; brix_root on; brix_auth none;
    brix_storage_backend root://127.0.0.1:1;
    brix_cache on; brix_cache_export $PFX/cache; ${3:-}
    $1 $2
} }
EOF
}

# 1. valid pair passes
emit "brix_cache_high_watermark 90%;" "brix_cache_low_watermark 80%;"
"$NGINX" -t -c "$PFX/nginx.conf" >"$PFX/o1" 2>&1
grep -q 'syntax is ok' "$PFX/o1" && ok "valid 90/80 pair accepted" || { bad "valid pair rejected"; grep emerg "$PFX/o1"; }

# 2. inverted pair (low >= high) rejected with the watermark message
emit "brix_cache_high_watermark 70%;" "brix_cache_low_watermark 80%;"
"$NGINX" -t -c "$PFX/nginx.conf" >"$PFX/o2" 2>&1
grep -qi 'low_watermark must be greater than 0 and less than' "$PFX/o2" \
    && ok "inverted pair rejected with EMERG" || { bad "inverted pair not rejected"; tail -2 "$PFX/o2"; }

# 3. back-compat: bare eviction_threshold still loads (watermarks derive)
emit "brix_cache_eviction_threshold 0.85;" ""
"$NGINX" -t -c "$PFX/nginx.conf" >"$PFX/o3" 2>&1
grep -q 'syntax is ok' "$PFX/o3" && ok "back-compat eviction_threshold loads" || { bad "back-compat broken"; grep emerg "$PFX/o3"; }

# 4. decimal form of the watermark parser accepted
emit "brix_cache_high_watermark 0.95;" "brix_cache_low_watermark 0.90;"
"$NGINX" -t -c "$PFX/nginx.conf" >"$PFX/o4" 2>&1
grep -q 'syntax is ok' "$PFX/o4" && ok "decimal watermark form accepted" || bad "decimal form rejected"

# --- staging backpressure watermarks (Phase C) ---
emit_stage() {  # $1 = extra staging directives
    cat > "$PFX/nginx.conf" <<EOF
daemon off; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:11621; brix_root on; brix_auth none;
    brix_storage_backend posix:$PFX/root;
    brix_allow_write on; brix_write_through on; brix_wt_origin 127.0.0.1:1;
    $1
} }
EOF
}

# 5. staging high watermark without a stage root → rejected
emit_stage "brix_wt_stage_high_watermark 90%; brix_wt_stage_low_watermark 80%;"
"$NGINX" -t -c "$PFX/nginx.conf" >"$PFX/o5" 2>&1
grep -qi 'wt_stage_high_watermark requires .*wt_stage_root' "$PFX/o5" \
    && ok "staging watermark without stage_root rejected" || { bad "missing stage_root not rejected"; tail -2 "$PFX/o5"; }

# 6. staging valid pair with a stage root → accepted
mkdir -p "$PFX/stage"
emit_stage "brix_cache_wt_stage_root $PFX/stage; brix_wt_stage_high_watermark 90%; brix_wt_stage_low_watermark 80%;"
"$NGINX" -t -c "$PFX/nginx.conf" >"$PFX/o6" 2>&1
grep -q 'syntax is ok' "$PFX/o6" && ok "staging valid pair accepted" || { bad "staging valid pair rejected"; grep emerg "$PFX/o6"; }

# 7. staging inverted pair (low >= high) → rejected
emit_stage "brix_cache_wt_stage_root $PFX/stage; brix_wt_stage_high_watermark 70%; brix_wt_stage_low_watermark 80%;"
"$NGINX" -t -c "$PFX/nginx.conf" >"$PFX/o7" 2>&1
grep -qi 'wt_stage_low_watermark must be greater than 0' "$PFX/o7" \
    && ok "staging inverted pair rejected" || { bad "staging inverted pair not rejected"; tail -2 "$PFX/o7"; }

[ "$fail" = 0 ] && echo "run_cache_watermark_config: ALL PASS" || echo "run_cache_watermark_config: FAILURES"
exit "$fail"
