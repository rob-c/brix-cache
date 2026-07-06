#!/usr/bin/env bash
# tests/run_cvmfs_shared_cache.sh — brix_cvmfs_shared_cache (2026-07-03).
# In forward-proxy mode a CVMFS client fails a slow object over from one
# Stratum-1 to the next; because CAS objects are content-addressed (identical
# across replicas), a shared cache turns that failover into a HIT instead of a
# fresh cold fill. Two mocks with the SAME seed = the same object on both
# "Stratum-1s"; a fill via one must serve a request naming the other.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
M1=12881; M2=12882; CPORT=12883
PFX="$(mktemp -d /tmp/cvmfs_shared.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCK1" "$MOCK2" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"

# SAME seed => the two upstreams serve byte-identical objects at the same paths.
python3 "$HERE/cvmfs/mock_stratum1.py" --port $M1 --objects 4 --seed 77 & MOCK1=$!
python3 "$HERE/cvmfs/mock_stratum1.py" --port $M2 --objects 4 --seed 77 & MOCK2=$!
sleep 0.6

mk_conf() {  # $1 = on|off
cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
worker_processes 1; thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location / {
        brix_cache_store posix:$PFX/cache;
        brix_cvmfs on;
        brix_cvmfs_upstream_allow 127.0.0.1;
        brix_cvmfs_shared_cache $1;
    }
} }
EOF
}

O="$(curl -s "http://127.0.0.1:$M1/ctl/objects" | python3 -c \
    'import json,sys; print(json.load(sys.stdin)[0])')"
# sanity: the same path exists byte-identical on both upstreams
curl -s "http://127.0.0.1:$M1$O" -o "$PFX/a.bin"; curl -s "http://127.0.0.1:$M2$O" -o "$PFX/b.bin"
cmp -s "$PFX/a.bin" "$PFX/b.bin" && ok "same-seed mocks serve identical object" \
    || bad "mocks differ (test precondition)"

# ---- shared_cache ON: fill via M1, request via M2 → HIT (M2 never fetched) --
mk_conf on
"$NGINX" -t -c "$PFX/nginx.conf" -p "$PFX" 2>/dev/null \
    && ok "brix_cvmfs_shared_cache directive parses" || bad "nginx -t rejected"
rm -rf "$PFX/cache"/*; "$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5
curl -s -x "http://127.0.0.1:$CPORT" "http://127.0.0.1:$M1$O" -o "$PFX/got1.bin"
M2_BEFORE="$(curl -s "http://127.0.0.1:$M2/ctl/log" | grep -oF "$O" | wc -l)"
curl -s -x "http://127.0.0.1:$CPORT" "http://127.0.0.1:$M2$O" -o "$PFX/got2.bin"
M2_AFTER="$(curl -s "http://127.0.0.1:$M2/ctl/log" | grep -oF "$O" | wc -l)"
cmp -s "$PFX/got1.bin" "$PFX/got2.bin" && cmp -s "$PFX/got1.bin" "$PFX/a.bin" \
    && ok "shared: both upstreams serve byte-exact object" || bad "shared: bytes differ"
[ "$M2_AFTER" = "$M2_BEFORE" ] \
    && ok "shared ON: fill via M1 → request via M2 is a HIT (M2 fetched 0×)" \
    || bad "shared ON: M2 went to origin ($M2_BEFORE→$M2_AFTER)"
kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; sleep 0.3

# ---- shared_cache OFF (default): per-upstream isolation preserved -----------
mk_conf off
rm -rf "$PFX/cache"/*; "$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5
curl -s -x "http://127.0.0.1:$CPORT" "http://127.0.0.1:$M1$O" -o /dev/null
N2B="$(curl -s "http://127.0.0.1:$M2/ctl/log" | grep -oF "$O" | wc -l)"
curl -s -x "http://127.0.0.1:$CPORT" "http://127.0.0.1:$M2$O" -o /dev/null
N2A="$(curl -s "http://127.0.0.1:$M2/ctl/log" | grep -oF "$O" | wc -l)"
[ "$N2A" -gt "$N2B" ] \
    && ok "shared OFF: per-upstream isolation preserved (M2 fetched its own copy)" \
    || bad "shared OFF: M2 did not fetch ($N2B→$N2A) — isolation broken"

exit $fail
