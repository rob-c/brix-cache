#!/usr/bin/env bash
# tests/run_cvmfs_failover.sh — two mock origins; primary stalls/dies →
#   1 fills transparently from the secondary (client sees success)
#   2 primary recovers → traffic returns (health decay)
#   3 error-neg: BOTH origins down → clean 502, no worker stall
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
M1=12851; M2=12852; CPORT=12853
PFX="$(mktemp -d /tmp/cvmfs_fo.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCK1" "$MOCK2" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"

# identical repos (same seed) on both origins
python3 "$HERE/cvmfs/mock_stratum1.py" --port $M1 --objects 6 --seed 5 & MOCK1=$!
python3 "$HERE/cvmfs/mock_stratum1.py" --port $M2 --objects 6 --seed 5 & MOCK2=$!
sleep 0.5

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location /cvmfs/ {
        brix_cvmfs_storage_backend "http://127.0.0.1:$M1|http://127.0.0.1:$M2";
        brix_cvmfs_cache_store posix:$PFX/cache;
        brix_cvmfs on;
        brix_cvmfs_client_hold 3;
    }
} }
EOF
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5

OBJS=($(curl -s "http://127.0.0.1:$M1/ctl/objects" | python3 -c \
       'import json,sys; print(" ".join(json.load(sys.stdin)))'))

# 1: kill primary → fill must come from secondary
kill "$MOCK1"; sleep 0.2
curl -s --max-time 25 "http://127.0.0.1:$CPORT${OBJS[0]}" -o "$PFX/a.bin"
curl -s "http://127.0.0.1:$M2${OBJS[0]}" -o "$PFX/ref.bin"
cmp -s "$PFX/a.bin" "$PFX/ref.bin" && ok "failover fill from secondary" \
    || bad "failover fill failed"
N2="$(curl -s "http://127.0.0.1:$M2/ctl/log" | grep -oF "${OBJS[0]}" | wc -l)"
[ "$N2" -ge 1 ] && ok "secondary actually served it" || bad "secondary untouched"

# 2: primary back → eventually reused (health decay). Restart it on same port.
python3 "$HERE/cvmfs/mock_stratum1.py" --port $M1 --objects 6 --seed 5 & MOCK1=$!
sleep 0.5
for u in "${OBJS[@]:1:4}"; do curl -s "http://127.0.0.1:$CPORT$u" -o /dev/null; done
NP="$(curl -s "http://127.0.0.1:$M1/ctl/log" | grep -oF '/data/' | wc -l || true)"
[ "$NP" -ge 1 ] && ok "primary reused after recovery ($NP fills)" \
    || bad "primary never reused"

# 3: both down → held for client_hold, then a clean keep-alive 504
# ("still trying, come back" — convention #6; 502 is reserved for
# definitive origin badness like a CAS mismatch)
kill "$MOCK1" "$MOCK2"; sleep 0.2
C="$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' \
     "http://127.0.0.1:$CPORT${OBJS[5]}")"
[ "$C" = 504 ] && ok "both-down → held then clean 504" || bad "both-down: $C"
exit $fail
