#!/usr/bin/env bash
# tests/run_cvmfs_keepalive.sh — connection durability on the wire:
#   1 accepted socket has a kernel keepalive timer (ss shows timer:(keepalive))
#   2 neg-control listener WITHOUT so_keepalive shows no keepalive timer
#   3 200 sequential requests over ONE socket, zero reconnects
#   4 a 403 reject does NOT terminate the connection (error-then-success reuse)
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MPORT=12896; CPORT=12897; NPORT=12898
PFX="$(mktemp -d /tmp/cvmfs_ka.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"
python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 4 --seed 44 &
MOCK=$!; sleep 0.5

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 256; }
http {
    access_log off;
    keepalive_timeout 3600s; keepalive_requests 1000000;
    send_timeout 300s; client_header_timeout 300s;
    reset_timedout_connection off;
    server {
        listen 127.0.0.1:$CPORT so_keepalive=60s:10s:6 backlog=2048;
        location /cvmfs/ {
            brix_storage_backend http://127.0.0.1:$MPORT;
            brix_cache_store posix:$PFX/cache;
            brix_cvmfs on;
        }
        location / { return 403; }
    }
    server {   # negative control: same handler, NO so_keepalive
        listen 127.0.0.1:$NPORT;
        location /cvmfs/ {
            brix_storage_backend http://127.0.0.1:$MPORT;
            brix_cache_store posix:$PFX/cache;
            brix_cvmfs on;
        }
    }
}
EOF
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.3
OBJ="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[0])')"

# 1+2: kernel keepalive timer present on CPORT, absent on NPORT
python3 - "$CPORT" "$NPORT" "$OBJ" <<'EOF' & HOLD=$!
import http.client, sys, time
for port in (int(sys.argv[1]), int(sys.argv[2])):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", sys.argv[3]); c.getresponse().read()
    globals()[f"c{port}"] = c          # keep both sockets open
time.sleep(5)
EOF
sleep 1.5
ss -tno state established "( sport = :$CPORT )" | grep -q 'timer:(keepalive' \
    && ok "keepalive timer armed on cvmfs listener" || bad "no keepalive timer"
ss -tno state established "( sport = :$NPORT )" | grep -q 'timer:(keepalive' \
    && bad "neg-control unexpectedly has keepalive" \
    || ok "neg-control has no keepalive (assert is not vacuous)"
wait $HOLD 2>/dev/null

# 3+4: one socket, 200 requests + an error mid-stream, zero reconnects
python3 - "$CPORT" "$OBJ" <<'EOF' && ok "200 reqs + 403 on one socket" || bad "reuse broken"
import http.client, sys
c = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=30)
for i in range(200):
    c.request("GET", sys.argv[2]); r = c.getresponse(); r.read()
    assert r.status == 200, f"req {i}: {r.status}"
c.request("GET", "/etc/passwd"); r = c.getresponse(); r.read()
assert r.status in (403, 405), f"reject: {r.status}"
c.request("GET", sys.argv[2]); r = c.getresponse(); r.read()   # raises if closed
assert r.status == 200, f"post-error: {r.status}"
print("keepalive python OK")
EOF
exit $fail
