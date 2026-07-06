#!/usr/bin/env bash
# tests/cvmfs/run_matrix.sh — the phase-68 comparison matrix. For each cache
# implementation x netem profile: fresh lab, mock inside the impaired ns,
# cache on the host, one harness run, one JSON. Renders RESULTS.md at the end.
# Requires root (netem). Skips squid/varnish when not installed.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"
NGINX="${NGINX:-/tmp/nginx-1.28.3/objs/nginx}"
LAB="$HERE/netem_lab.sh"; NIP=10.199.0.2
MPORT=12881; CPORT=12882; PPORT=12883
OUT="$REPO/deploy/cvmfs/baselines"
PROFILES="clean loss reorder corrupt jitter site"
CACHES="module-reverse module-proxy stock-nginx squid varnish"
[ "$(id -u)" = 0 ] || { echo "must run as root (netem)"; exit 2; }

start_mock() {
    ip netns exec cvmfslab python3 "$HERE/mock_stratum1.py" \
        --bind "$NIP" --port $MPORT --objects 16 --seed 68 & MOCK=$!
    sleep 0.5
}

start_cache() {   # $1 = cache name, $2 = workdir; sets CACHEBASE and STOP
    local w="$2"
    case "$1" in
    module-reverse)
        cat > "$w/nginx.conf" <<EOF
daemon on; error_log $w/e.log warn; pid $w/nginx.pid;
thread_pool default threads=4;
events { worker_connections 512; }
http { access_log off;
    keepalive_timeout 3600s; keepalive_requests 1000000;
    send_timeout 300s; client_header_timeout 300s;
    reset_timedout_connection off;
    server {
    listen 127.0.0.1:$CPORT so_keepalive=60s:10s:6 backlog=2048;
    location /cvmfs/ {
        brix_storage_backend http://$NIP:$MPORT;
        brix_cache_store posix:$w/cache;
        brix_cache_verify cvmfs-cas;
        brix_cvmfs on;
        brix_cvmfs_client_hold 25;
    }
} }
EOF
        mkdir -p "$w/cache" "$w/logs"
        "$NGINX" -c "$w/nginx.conf" -p "$w"
        STOP="kill \$(cat $w/nginx.pid)"; CACHEBASE="http://127.0.0.1:$CPORT"
        unset http_proxy ;;
    module-proxy)
        cat > "$w/nginx.conf" <<EOF
daemon on; error_log $w/e.log warn; pid $w/nginx.pid;
thread_pool default threads=4;
events { worker_connections 512; }
http { access_log off;
    keepalive_timeout 3600s; keepalive_requests 1000000;
    send_timeout 300s; client_header_timeout 300s;
    reset_timedout_connection off;
    server {
    listen 127.0.0.1:$PPORT so_keepalive=60s:10s:6 backlog=2048;
    location / {
        brix_cache_store posix:$w/cache;
        brix_cache_verify cvmfs-cas;
        brix_cvmfs on;
        brix_cvmfs_client_hold 25;
        brix_cvmfs_upstream_allow $NIP;
    }
} }
EOF
        mkdir -p "$w/cache" "$w/logs"
        "$NGINX" -c "$w/nginx.conf" -p "$w"
        STOP="kill \$(cat $w/nginx.pid)"
        export http_proxy="http://127.0.0.1:$PPORT"
        CACHEBASE="http://$NIP:$MPORT" ;;
    stock-nginx)
        sed -e "s/@PORT@/$CPORT/" -e "s/@PPORT@/$PPORT/" -e "s#@CACHEDIR@#$w#" \
            -e "s/@ORIGIN@/$NIP:$MPORT/" -e "s/@ORIGINHOST@/$NIP/g" \
            -e "s/@ORIGINPORT@/$MPORT/" \
            "$REPO/deploy/cvmfs/nginx-proxy-cache.conf" > "$w/nginx.conf"
        mkdir -p "$w/store" "$w/logs"
        "$NGINX" -c "$w/nginx.conf" -p "$w"
        STOP="kill \$(cat $w/nginx.pid)"; CACHEBASE="http://127.0.0.1:$CPORT"
        unset http_proxy ;;
    squid|varnish)
        # delegate to the Task-4 runner; it sets its own proxy env/base
        SKIP_DELEGATE=1 ;;
    esac
}

: > "$OUT/matrix_rows.tsv"
for cache in $CACHES; do
    for prof in $PROFILES; do
        "$LAB" down >/dev/null 2>&1 || true
        "$LAB" up >/dev/null; "$LAB" profile "$prof" >/dev/null
        start_mock
        W="$(mktemp -d /tmp/cvmfs_matrix.XXXXXX)"
        SKIP_DELEGATE=0; start_cache "$cache" "$W"
        if [ "$SKIP_DELEGATE" = 1 ]; then
            "$HERE/run_baselines.sh" "$cache" $CPORT "$NIP:$MPORT" \
                && J="baseline_${cache}.json" || J=""
        else
            J="$OUT/results_${cache}_${prof}.json"
            python3 "$HERE/harness.py" --cache "$CACHEBASE" \
                --mock "http://$NIP:$MPORT" --out "$J" || J=""
            eval "$STOP" || true
        fi
        [ -n "$J" ] && printf '%s\t%s\t%s\n' "$cache" "$prof" "$J" \
            >> "$OUT/matrix_rows.tsv"
        kill "$MOCK" 2>/dev/null || true
        rm -rf "$W"
    done
done
"$LAB" down >/dev/null

python3 - "$OUT" <<'EOF'
import json, sys, os, datetime
out = sys.argv[1]
rows = [l.split("\t") for l in open(f"{out}/matrix_rows.tsv").read().splitlines()]
K = ["cold_ttfb_p50_ms","cold_ttfb_p99_ms","warm_ttfb_p50_ms",
     "error_rate","stampede_origin_fetches","corrupt_served"]
today = datetime.date.today().isoformat()
lines = []
for cache, prof, path in rows:
    try:
        d = json.load(open(path if os.path.isabs(path) else f"{out}/{path}"))
    except Exception:
        continue
    cells = [f"{d.get(k, ''):.1f}" if isinstance(d.get(k), float) else str(d.get(k, ""))
             for k in K]
    note = f"conn_failures={d.get('conn_failures', '?')}"
    lines.append(f"| {cache} | {prof} | " + " | ".join(cells)
                 + f" | {today} | {note} |")
with open(f"{out}/RESULTS.md", "a") as f:
    f.write("\n".join(lines) + "\n")
print(f"appended {len(lines)} rows to RESULTS.md")
EOF
