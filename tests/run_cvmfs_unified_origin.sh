#!/usr/bin/env bash
# tests/run_cvmfs_unified_origin.sh — xrootd_cvmfs_unified_origin (2026-07-03).
# In forward-proxy mode, unified_origin serves EVERY client-named Stratum-1 from
# ONE ranked multi-endpoint origin backend (xrootd_cvmfs_storage_backend), so a
# dead origin is hidden by internal failover and the client keeps getting 200
# from the host it named — it never marks the proxy bad or wanders to a mirror.
# Two mocks, SAME seed = the same object on both "Stratum-1s".
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
M1=12891; M2=12892; CPORT=12893
PFX="$(mktemp -d /tmp/cvmfs_unified.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCK1" "$MOCK2" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"

python3 "$HERE/cvmfs/mock_stratum1.py" --port $M1 --objects 4 --seed 55 & MOCK1=$!
python3 "$HERE/cvmfs/mock_stratum1.py" --port $M2 --objects 4 --seed 55 & MOCK2=$!
sleep 0.6

# storage_backend = ranked set: M1 (primary) then M2 (failover). unified_origin
# serves both client-named authorities from it. allowlist covers 127.0.0.1.
cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
worker_processes 1; thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location / {
        xrootd_cvmfs_storage_backend "http://127.0.0.1:$M1|http://127.0.0.1:$M2";
        xrootd_cvmfs_cache_store posix:$PFX/cache;
        xrootd_cvmfs on;
        xrootd_cvmfs_upstream_allow 127.0.0.1;
        xrootd_cvmfs_unified_origin on;
        xrootd_cvmfs_origin_connect_timeout 1;
        xrootd_cvmfs_origin_attempt_timeout 2;
        xrootd_cvmfs_client_hold 4;
    }
} }
EOF
"$NGINX" -t -c "$PFX/nginx.conf" -p "$PFX" 2>/dev/null \
    && ok "unified_origin + multi-endpoint storage_backend parse" \
    || { bad "nginx -t rejected"; "$NGINX" -t -c "$PFX/nginx.conf" -p "$PFX"; }

O="$(curl -s "http://127.0.0.1:$M1/ctl/objects" | python3 -c \
    'import json,sys; print(json.load(sys.stdin)[0])')"
curl -s "http://127.0.0.1:$M1$O" -o "$PFX/ref.bin"

# ---- B: two client-named authorities → ONE origin fetch (unified backend) ---
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5
# Baseline AFTER the direct ref fetch above (which itself hit an origin), so we
# count only the fetches the two PROXY requests cause.
B1="$(curl -s "http://127.0.0.1:$M1/ctl/log" | grep -oF "$O" | wc -l)"
B2="$(curl -s "http://127.0.0.1:$M2/ctl/log" | grep -oF "$O" | wc -l)"
curl -s -x "http://127.0.0.1:$CPORT" "http://127.0.0.1:$M1$O" -o "$PFX/g1.bin"
curl -s -x "http://127.0.0.1:$CPORT" "http://127.0.0.1:$M2$O" -o "$PFX/g2.bin"
F1="$(curl -s "http://127.0.0.1:$M1/ctl/log" | grep -oF "$O" | wc -l)"
F2="$(curl -s "http://127.0.0.1:$M2/ctl/log" | grep -oF "$O" | wc -l)"
DELTA="$(( (F1 - B1) + (F2 - B2) ))"
cmp -s "$PFX/g1.bin" "$PFX/ref.bin" && cmp -s "$PFX/g2.bin" "$PFX/ref.bin" \
    && ok "both client-named authorities serve byte-exact 200" || bad "bytes differ"
[ "$DELTA" -eq 1 ] \
    && ok "unified: M1-named + M2-named = ONE origin fetch total (delta=$DELTA)" \
    || bad "unified: expected 1 origin fetch, got $DELTA (F1=$F1/$B1 F2=$F2/$B2)"
kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; sleep 0.3

# ---- A: primary origin DOWN → request naming it still 200 (failover hidden) --
rm -rf "$PFX/cache"/*; kill "$MOCK1" 2>/dev/null; MOCK1=""; sleep 0.3
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5
# client names the DEAD primary (M1); unified must fail over to M2 invisibly.
CODE="$(curl -s -m 8 -o "$PFX/ha.bin" -w '%{http_code}' \
        -x "http://127.0.0.1:$CPORT" "http://127.0.0.1:$M1$O")"
if [ "$CODE" = 200 ] && cmp -s "$PFX/ha.bin" "$PFX/ref.bin"; then
    ok "primary origin DOWN: request naming it still returns 200 (failover hidden)"
else
    bad "dead-primary failover: code=$CODE (expected 200 byte-exact from backup)"
fi

# ---- config guard: unified_origin without an http storage_backend is rejected
cat > "$PFX/bad.conf" <<EOF
daemon off; events { worker_connections 32; }
http { server { listen 127.0.0.1:$CPORT; location / {
    xrootd_cvmfs_cache_store posix:$PFX/cache;
    xrootd_cvmfs on; xrootd_cvmfs_upstream_allow 127.0.0.1;
    xrootd_cvmfs_unified_origin on;
} } }
EOF
"$NGINX" -t -c "$PFX/bad.conf" -p "$PFX" 2>/dev/null \
    && bad "unified_origin without http backend should be rejected" \
    || ok "config guard: unified_origin without http storage_backend rejected"

exit $fail
