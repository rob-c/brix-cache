#!/usr/bin/env bash
# tests/run_cvmfs_conn_reuse.sh — origin connection reuse (2026-07-03).
# The origin transport keeps ONE long-lived keep-alive connection per fill
# thread and reuses it across requests (curl handle reuse), instead of opening
# and tearing down a fresh TCP connection per object — the fix for a
# high-latency link where every object otherwise paid a full handshake +
# slow-start. With one fill thread, N object fills (each a HEAD + GET) must
# share a handful of connections, not ~2N.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MPORT=12895; CPORT=12896
PFX="$(mktemp -d /tmp/cvmfs_reuse.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           [ -n "${MOCK:-}" ] && kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"

# --keepalive => the mock serves HTTP/1.1 persistent connections, so reuse is
# even possible; /ctl/connections reports distinct TCP connections accepted.
python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 8 --seed 31 \
    --keepalive & MOCK=$!
sleep 0.6

# ONE fill thread → all fills funnel through one persistent handle.
cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
worker_processes 1; thread_pool default threads=1;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location /cvmfs/ {
        xrootd_cvmfs_storage_backend http://127.0.0.1:$MPORT;
        xrootd_cvmfs_cache_store posix:$PFX/cache;
        xrootd_cvmfs on;
    }
} }
EOF
"$NGINX" -t -c "$PFX/nginx.conf" -p "$PFX" 2>/dev/null \
    && ok "config parses" || { bad "nginx -t rejected"; exit 1; }
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5

mapfile -t OBJS < <(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
    'import json,sys; [print(o) for o in json.load(sys.stdin)]')

# One reference copy for the byte check, fetched BEFORE the baseline so its
# direct connection is not counted against the cache.
curl -s "http://127.0.0.1:$MPORT${OBJS[0]}" -o "$PFX/ref0.bin"

conns(){ curl -s "http://127.0.0.1:$MPORT/ctl/connections" | python3 -c \
    'import json,sys; print(json.load(sys.stdin)["connections"])'; }
gets(){ curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -oF '/cvmfs/' | wc -l; }

B_CONNS="$(conns)"; B_GETS="$(gets)"          # count only what the cache causes

# cold-fill every object through the cache (each = HEAD + GET at the origin)
for O in "${OBJS[@]}"; do
    curl -s "http://127.0.0.1:$CPORT$O" -o /dev/null
done

D_CONNS=$(( $(conns) - B_CONNS ))
D_GETS=$(( $(gets) - B_GETS ))
echo "  ..   cache→origin: $D_GETS GET(s) over $D_CONNS new TCP connection(s)"

# byte check via a cache HIT (already filled → no origin fetch, no pollution)
curl -s "http://127.0.0.1:$CPORT${OBJS[0]}" -o "$PFX/c0.bin"
cmp -s "$PFX/c0.bin" "$PFX/ref0.bin" && ok "cache serves byte-exact object" \
    || bad "cache byte mismatch"

# Decisive: ${#OBJS[@]} fills (>=8 GETs, plus a HEAD each ⇒ ~16 requests) rode a
# handful of reused connections. Without reuse it would be ~16 connections; with
# reuse it's a small number. Assert well below the request count.
[ "$D_GETS" -ge 8 ] && [ "$D_CONNS" -le 6 ] \
    && ok "origin connection reused: $D_GETS fills over $D_CONNS connection(s)" \
    || bad "no reuse: $D_GETS fills opened $D_CONNS connections"