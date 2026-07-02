#!/usr/bin/env bash
# tests/run_cvmfs_select.sh — origin selection policies:
#   0 standalone unit: haversine + stable argsort
#   1 static: first-listed origin serves the fill (failover untouched)
#   2 geo: nearer origin wins although listed second
#   3 rtt: refused first-listed endpoint is pre-ranked out by the probe
#   4 security/error-neg: geo without coords/here → nginx -t rejects
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
MA=12891; MB=12892; CPORT=12893
PFX="$(mktemp -d /tmp/cvmfs_sel.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCKA" "$MOCKB" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"

# --- 0: pure-C unit (no nginx) ---------------------------------------------
cat > "$PFX/u.c" <<'EOF'
#include "protocols/cvmfs/origin_geo.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    /* Edinburgh <-> CERN is ~1180 km great-circle */
    double d = xrootd_cvmfs_haversine_km(55.95, -3.19, 46.23, 6.05);
    assert(d > 1000.0 && d < 1300.0);
    /* argsort with a tie: ties keep input order (stability) */
    double m[4] = { 9.0, 1.0, 9.0, 4.0 };
    int r[4];
    xrootd_cvmfs_rank_by_metric(m, 4, r);
    assert(r[1] == 0 && r[3] == 1 && r[0] == 2 && r[2] == 3);
    printf("origin_geo unit OK\n");
    return 0;
}
EOF
gcc -Wall -Werror -I"$REPO/src" -o "$PFX/u" "$PFX/u.c" \
    "$REPO/src/protocols/cvmfs/origin_geo.c" -lm && "$PFX/u" \
    && ok "unit: haversine+argsort" || bad "unit test"

python3 "$HERE/cvmfs/mock_stratum1.py" --port $MA --objects 4 --seed 31 & MOCKA=$!
python3 "$HERE/cvmfs/mock_stratum1.py" --port $MB --objects 4 --seed 31 & MOCKB=$!
sleep 0.5
OBJ="$(curl -s "http://127.0.0.1:$MA/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[0])')"

mkconf() {  # $1 = select-specific directive lines, $2 = backend URL list
cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location /cvmfs/ {
        xrootd_cvmfs_storage_backend "$2";
        xrootd_cvmfs_cache_store posix:$PFX/cache;
        xrootd_cvmfs on;
$1
    }
} }
EOF
}
restart() { if [ -f "$PFX/nginx.pid" ]; then
                local pid; pid="$(cat "$PFX/nginx.pid")"
                kill "$pid" 2>/dev/null
                for _ in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || break
                                         sleep 0.1; done
            fi
            rm -rf "$PFX/cache"; mkdir -p "$PFX/cache"
            : > "$PFX/logs/e.log"
            "$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.7; }

# --- 1: static — first-listed (A) serves ------------------------------------
mkconf "        xrootd_cvmfs_origin_select static;" \
       "http://127.0.0.1:$MA|http://127.0.0.1:$MB"
restart
curl -s "http://127.0.0.1:$CPORT$OBJ" -o /dev/null
NA="$(curl -s "http://127.0.0.1:$MA/ctl/log" | grep -oF "$OBJ" | wc -l)"
NB="$(curl -s "http://127.0.0.1:$MB/ctl/log" | grep -oF "$OBJ" | wc -l)"
[ "$NA" = 1 ] && [ "$NB" = 0 ] && ok "static: first-listed served" \
    || bad "static: A=$NA B=$NB"

# --- 2: geo — nearer origin (B=Edinburgh) wins although listed second -------
mkconf "        xrootd_cvmfs_origin_select geo;
        xrootd_cvmfs_here 55.95:-3.19;
        xrootd_cvmfs_origin_coords 127.0.0.1:$MA 46.23:6.05;
        xrootd_cvmfs_origin_coords 127.0.0.1:$MB 55.95:-3.19;" \
       "http://127.0.0.1:$MA|http://127.0.0.1:$MB"
restart
curl -s "http://127.0.0.1:$CPORT$OBJ" -o /dev/null
NB="$(curl -s "http://127.0.0.1:$MB/ctl/log" | grep -oF "$OBJ" | wc -l)"
[ "$NB" = 1 ] && ok "geo: nearer origin served" || bad "geo: B=$NB"

# --- 3: rtt — refused endpoint pre-ranked out (not failed-over-from) --------
mkconf "        xrootd_cvmfs_origin_select rtt;
        xrootd_cvmfs_rtt_interval 1;" \
       "http://127.0.0.1:1|http://127.0.0.1:$MB"
restart
sleep 1.5                       # let the first probe run and rank
NB0="$(curl -s "http://127.0.0.1:$MB/ctl/log" | grep -oF "$OBJ" | wc -l)"
curl -s "http://127.0.0.1:$CPORT$OBJ" -o /dev/null
NB1="$(curl -s "http://127.0.0.1:$MB/ctl/log" | grep -oF "$OBJ" | wc -l)"
grep -q 'cvmfs rtt ranks:' "$PFX/logs/e.log" \
    && [ "$((NB1 - NB0))" = 1 ] && ok "rtt: probe pre-ranked live origin first" \
    || bad "rtt selection (log=$(grep -c 'cvmfs rtt ranks:' "$PFX/logs/e.log" || true) fills=$((NB1-NB0)))"

# --- 4: config-error negatives ----------------------------------------------
mkconf "        xrootd_cvmfs_origin_select geo;" \
       "http://127.0.0.1:$MA|http://127.0.0.1:$MB"
"$NGINX" -t -c "$PFX/nginx.conf" -p "$PFX" 2>/dev/null \
    && bad "geo without here/coords accepted" || ok "geo misconfig rejected"
exit $fail
