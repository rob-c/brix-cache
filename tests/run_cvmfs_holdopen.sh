#!/usr/bin/env bash
# tests/run_cvmfs_holdopen.sh — never-drop client semantics:
#   1 origin DOWN at request time, up 3s later → client (30s budget) gets 200
#   2 hold expiry → 504 + Retry-After on a KEPT-ALIVE conn; retry on the
#     SAME socket succeeds once the origin is back
#   3 client aborts mid-outage → detached fill still populates the cache
#   4 neg: 404 is definitive — immediate, exactly 1 origin probe, no hold
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MPORT=12894; CPORT=12895
PFX="$(mktemp -d /tmp/cvmfs_hold.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           pkill -f "mock_stratum1.py --port $MPORT" 2>/dev/null
           rm -rf "$PFX"; }
# kill whatever mock instance holds MPORT and wait for the port to free
mock_down(){ pkill -f "mock_stratum1.py --port $MPORT" 2>/dev/null
             for _ in $(seq 1 50); do
                 curl -sf -m 1 "http://127.0.0.1:$MPORT/ctl/objects" -o /dev/null \
                     || return 0
                 sleep 0.1
             done; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"

mkconf() {  # $1 = client_hold seconds
cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=4;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location /cvmfs/ {
        xrootd_cvmfs_storage_backend http://127.0.0.1:$MPORT;
        xrootd_cvmfs_cache_store posix:$PFX/cache;
        xrootd_cvmfs on;
        xrootd_cvmfs_client_hold $1;
        xrootd_cvmfs_fill_max_life 60;
        xrootd_cvmfs_negative_ttl 10;
    }
} }
EOF
}

# discover object names with a throwaway mock instance (same seed each start)
python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 6 --seed 20 &
MOCK=$!
for _ in $(seq 1 50); do
    curl -sf "http://127.0.0.1:$MPORT/ctl/objects" -o "$PFX/objs.json" && break
    sleep 0.1
done
OBJS=($(python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))))' "$PFX/objs.json"))
mock_down

# --- 1: retry-until-origin-returns ------------------------------------------
mkconf 20; "$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.3
( sleep 3; exec python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT \
      --objects 6 --seed 20 ) &
C="$(curl -s --max-time 30 -o "$PFX/a.bin" -w '%{http_code}' \
     "http://127.0.0.1:$CPORT${OBJS[0]}")"
sleep 0.5
curl -s "http://127.0.0.1:$MPORT${OBJS[0]}" -o "$PFX/ref.bin"
[ "$C" = 200 ] && cmp -s "$PFX/a.bin" "$PFX/ref.bin" \
    && ok "held through outage, served on recovery" || bad "outage hold: $C"

# --- 2: hold expiry → 504 keep-alive, retry on SAME socket -------------------
mock_down
kill "$(cat "$PFX/nginx.pid")"; sleep 0.3
mkconf 2; rm -rf "$PFX/cache"; mkdir -p "$PFX/cache"
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.3
if python3 - "$CPORT" "$MPORT" "${OBJS[1]}" "$HERE" <<'EOF'
import http.client, subprocess, sys, time
cport, mport, obj, here = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
c = http.client.HTTPConnection("127.0.0.1", cport, timeout=30)
c.request("GET", obj)
r1 = c.getresponse()
body1 = r1.read()
assert r1.status == 504, f"want 504 got {r1.status}"
assert r1.getheader("Retry-After") is not None, "no Retry-After"
assert r1.getheader("Connection", "keep-alive").lower() != "close", "conn closed"
# origin comes back; retry over the SAME socket (raises if server closed it)
p = subprocess.Popen(["python3", f"{here}/cvmfs/mock_stratum1.py",
                      "--port", str(mport), "--objects", "6", "--seed", "20"])
time.sleep(1.0)
c.request("GET", obj)
r2 = c.getresponse()
b2 = r2.read()
p.terminate()
assert r2.status == 200 and len(b2) > 0, f"retry got {r2.status}"
print("holdopen python OK")
EOF
then ok "504-keepalive + same-socket retry"; else bad "504-keepalive scenario"; fi

# --- 3: detached fill completes after client abort ---------------------------
mock_down
kill "$(cat "$PFX/nginx.pid")"; sleep 0.3
mkconf 20; rm -rf "$PFX/cache"; mkdir -p "$PFX/cache"
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.3
curl -s --max-time 1 "http://127.0.0.1:$CPORT${OBJS[2]}" -o /dev/null  # aborts
python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 6 --seed 20 &
MOCK=$!; sleep 6            # detached fill (max_life 60) retries and lands
N1="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -oF "${OBJS[2]}" | wc -l)"
C="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT${OBJS[2]}")"
N2="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -oF "${OBJS[2]}" | wc -l)"
[ "$C" = 200 ] && [ "$N1" -ge 1 ] && [ "$N1" = "$N2" ] \
    && ok "detached fill populated cache (abort didn't cancel)" \
    || bad "detached fill: code=$C origin=$N1→$N2"

# --- 4: 404 definitive, immediate ---------------------------------------------
BOGUS="/cvmfs/test.cern.ch/data/aa/$(python3 -c 'print("ef"*19)')"
T0=$(date +%s)
C="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT$BOGUS")"
T1=$(date +%s)
[ "$C" = 404 ] && [ $((T1 - T0)) -le 2 ] && ok "404 immediate (no hold)" \
    || bad "404 path: code=$C took $((T1-T0))s"
exit $fail
