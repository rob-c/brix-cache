#!/usr/bin/env bash
# tests/run_cvmfs_upstream_metrics.sh — per-upstream (Stratum-1) Prometheus
# attribution + the optional file/upstream trace logging (phase-68).
#
#   1 a fill from the "RAL" mock attributes to brix_cvmfs_upstream_*{upstream=RAL}
#     (requests/fills/origin_bytes) AND a fill-duration histogram bucket+count+sum
#   2 a fill that fails over to the fallback bumps _failovers_total on the
#     answering upstream (and _fill_failures on the dead one)
#   3 no path/repo leaks into the upstream label (cardinality is host:port only)
#   4 brix_cvmfs_trace on: the client-op AND upstream-request lines appear at INFO
#   5 trace off + error_log info: NEITHER line appears
#   6 trace off + error_log debug: BOTH lines appear (debug-level path)
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MRAL=12901; MALT=12902; CPORT=12903; XPORT=12904; DEAD=12909
PFX="$(mktemp -d /tmp/cvmfs_upm.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MRALPID" "$MALTPID" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"

python3 "$HERE/cvmfs/mock_stratum1.py" --port $MRAL --objects 8 --seed 41 & MRALPID=$!
python3 "$HERE/cvmfs/mock_stratum1.py" --port $MALT --objects 8 --seed 41 & MALTPID=$!
sleep 0.5
OBJ0="$(curl -s "http://127.0.0.1:$MRAL/ctl/objects" | python3 -c \
       'import json,sys; print(json.load(sys.stdin)[0])')"
OBJ1="$(curl -s "http://127.0.0.1:$MRAL/ctl/objects" | python3 -c \
       'import json,sys; print(json.load(sys.stdin)[1])')"

# $1 = backend URL list, $2 = extra location lines, $3 = error_log level
mkconf() {
cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log ${3:-info}; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off;
    server { listen 127.0.0.1:$CPORT;
        location /cvmfs/ {
            brix_cvmfs_storage_backend "$1";
            brix_cvmfs_cache_store posix:$PFX/cache;
            brix_cvmfs on;
${2:-}
        } }
    server { listen 127.0.0.1:$XPORT; location = /metrics { brix_metrics on; } }
}
EOF
}
restart() {
    if [ -f "$PFX/nginx.pid" ]; then
        local pid; pid="$(cat "$PFX/nginx.pid")"; kill "$pid" 2>/dev/null
        for _ in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    fi
    rm -rf "$PFX/cache"; mkdir -p "$PFX/cache"; : > "$PFX/logs/e.log"
    "$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.7
}
metric() { curl -s "http://127.0.0.1:$XPORT/metrics" | grep -F "$1" | head -1; }
mval()   { metric "$1" | awk '{print $NF}'; }

# --- 1: attribution to the RAL upstream -------------------------------------
mkconf "http://127.0.0.1:$MRAL" ""
restart
curl -s "http://127.0.0.1:$CPORT$OBJ0" -o /dev/null
RAL="127.0.0.1:$MRAL"
R="$(mval "brix_cvmfs_upstream_requests_total{upstream=\"$RAL\"}")"
F="$(mval "brix_cvmfs_upstream_fills_total{upstream=\"$RAL\"}")"
B="$(mval "brix_cvmfs_upstream_origin_bytes_total{upstream=\"$RAL\"}")"
[ "${R:-0}" -ge 1 ] 2>/dev/null && [ "${F:-0}" -ge 1 ] 2>/dev/null \
    && [ "${B:-0}" -ge 1 ] 2>/dev/null \
    && ok "fill attributed to upstream RAL (req=$R fills=$F bytes=$B)" \
    || bad "RAL attribution: req=$R fills=$F bytes=$B"

HC="$(mval "brix_cvmfs_upstream_fill_duration_seconds_count{upstream=\"$RAL\"}")"
HB="$(mval "brix_cvmfs_upstream_fill_duration_seconds_bucket{upstream=\"$RAL\",le=\"+Inf\"}")"
curl -s "http://127.0.0.1:$XPORT/metrics" \
    | grep -q "brix_cvmfs_upstream_fill_duration_seconds_sum{upstream=\"$RAL\"}" \
    && [ "${HC:-0}" -ge 1 ] 2>/dev/null && [ "${HB:-0}" -ge 1 ] 2>/dev/null \
    && ok "fill-duration histogram present (count=$HC +Inf=$HB)" \
    || bad "histogram: count=$HC +Inf=$HB"

# --- 3: cardinality — the upstream label is host:port only, no path/repo ----
if curl -s "http://127.0.0.1:$XPORT/metrics" \
     | grep -E "brix_cvmfs_upstream_.*upstream=\"[^\"]*(/|data/|\.cvmfs)" >/dev/null; then
    bad "path/repo leaked into the upstream label"
else
    ok "upstream label is bounded host:port (no path/repo leak)"
fi

# --- 2: failover attribution — dead primary, fills served by the fallback ---
mkconf "http://127.0.0.1:$DEAD|http://127.0.0.1:$MALT" ""
restart
curl -s "http://127.0.0.1:$CPORT$OBJ1" -o /dev/null
ALT="127.0.0.1:$MALT"
FO="$(mval "brix_cvmfs_upstream_failovers_total{upstream=\"$ALT\"}")"
FA="$(mval "brix_cvmfs_upstream_fills_total{upstream=\"$ALT\"}")"
[ "${FO:-0}" -ge 1 ] 2>/dev/null && [ "${FA:-0}" -ge 1 ] 2>/dev/null \
    && ok "failover fill attributed to the fallback upstream (failovers=$FO)" \
    || bad "failover attribution: failovers=$FO fills=$FA"

# --- 4: trace ON → client + upstream lines at INFO --------------------------
mkconf "http://127.0.0.1:$MRAL" "            brix_cvmfs_trace on;" info
restart
curl -s "http://127.0.0.1:$CPORT$OBJ0" -o /dev/null
sleep 0.3
grep -q "cvmfs-trace: client .*class=cas .*cache=fill" "$PFX/logs/e.log" \
    && ok "trace on: client-op line at INFO" \
    || bad "trace on: no client-op line"
# the fill issues a HEAD (size) then a Range GET (206) — match either 2xx
grep -qE "cvmfs-trace: upstream (GET|HEAD) http://127.0.0.1:$MRAL.*status=2[0-9][0-9]" "$PFX/logs/e.log" \
    && ok "trace on: upstream-request line at INFO" \
    || bad "trace on: no upstream-request line"

# --- 5: trace OFF + info level → neither line -------------------------------
mkconf "http://127.0.0.1:$MRAL" "" info
restart
curl -s "http://127.0.0.1:$CPORT$OBJ1" -o /dev/null
sleep 0.3
grep -q "cvmfs-trace:" "$PFX/logs/e.log" \
    && bad "trace off/info: trace line leaked at INFO" \
    || ok "trace off + error_log info: no trace lines"

# --- 6: trace OFF + debug level → both lines (debug path) -------------------
mkconf "http://127.0.0.1:$MRAL" "" debug
restart
curl -s "http://127.0.0.1:$CPORT$OBJ0" -o /dev/null
sleep 0.3
grep -q "cvmfs-trace: client " "$PFX/logs/e.log" \
    && grep -q "cvmfs-trace: upstream GET" "$PFX/logs/e.log" \
    && ok "trace off + error_log debug: both lines at DEBUG" \
    || bad "trace off/debug: missing a trace line"

exit $fail
