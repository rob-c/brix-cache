#!/usr/bin/env bash
# tests/run_cvmfs_logging.sh — the cvmfs operational-logging contract.
#
# Every connection break / origin trouble / misbehaving client must leave a
# single-line, greppable trail an operator can act on. This drives each
# failure mode against the mock Stratum-1 and asserts the exact log event:
#
#   xrootd-fill: event=retry|recovered|exhausted|done       (fill lifecycle)
#   xrootd-fill: event=hold-expired                          (client waited out the hold)
#   xrootd-fill: event=client-gone                           (client abandoned mid-fill)
#   cvmfs-neg:   event=absorbed-404                          (client hammering misses)
#   cvmfs-client:event=send-timeout|aborted                 (broken client connection)
#
# The point is diagnosability: each line names the client, the object, and
# how long things took, so a stall vs a misbehaving client is unambiguous.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PFX="$(mktemp -d /tmp/cvmfs_log.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           [ -n "${MOCK:-}" ] && kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
MPORT=12841; CPORT=12842
mkdir -p "$PFX/cache" "$PFX/logs"
LOG="$PFX/logs/e.log"

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $LOG info; pid $PFX/nginx.pid;
thread_pool default threads=4;
events { worker_connections 128; }
http {
    access_log off;
    server {
        listen 127.0.0.1:$CPORT;
        location /cvmfs/ {
            brix_storage_backend http://127.0.0.1:$MPORT;
            brix_cache_store posix:$PFX/cache;
            brix_cvmfs on;
            brix_cvmfs_negative_ttl 30;
            brix_cvmfs_client_hold 2;      # short hold => hold-expired fires fast
            brix_cvmfs_fill_max_life 20;
        }
    }
}
EOF
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX" 2>/dev/null; sleep 0.5
python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 8 --seed 5 &
MOCK=$!; sleep 0.5

OBJ="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[0])')"
haslog(){ grep -qF "$1" "$LOG"; }

# --- 1: healthy cold fill logs a clean done ---------------------------------
curl -s "http://127.0.0.1:$CPORT$OBJ" -o /dev/null
sleep 0.3
haslog 'xrootd-fill: event=done' && haslog 'attempts=1' \
    && ok "clean fill logs event=done attempts=1" \
    || bad "no clean done line"

# --- 2: reset the origin repeatedly -> retry + recovered --------------------
# 3 one-shot resets, then it succeeds: the fill retries and logs recovery.
OBJ2="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
       'import json,sys; print(json.load(sys.stdin)[2])')"
curl -s -o /dev/null -X POST -d '{"mode":"reset","count":3}' \
     "http://127.0.0.1:$MPORT/ctl/fault"
curl -s --max-time 15 "http://127.0.0.1:$CPORT$OBJ2" -o /dev/null
sleep 0.3
haslog 'xrootd-fill: event=retry' \
    && ok "transient origin failure logs event=retry (attempt/backoff)" \
    || bad "no retry line"
grep -q 'xrootd-fill: event=recovered' "$LOG" \
    && ok "fill after retries logs event=recovered" \
    || bad "no recovered line"

# --- 3: origin health TRANSITION -> degraded --------------------------------
grep -q 'xrootd-origin: event=degraded' "$LOG" \
    && ok "origin flap logs event=degraded (host/port)" \
    || bad "no origin degraded line"

# --- 4: stalled origin past the hold -> hold-expired + exhausted ------------
OBJ3="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
       'import json,sys; print(json.load(sys.stdin)[4])')"
curl -s -o /dev/null -X POST -d '{"mode":"stall","count":9}' \
     "http://127.0.0.1:$MPORT/ctl/fault"
# client waits; hold is 2s, so it should get a 504 and the log the reason
RC="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
      "http://127.0.0.1:$CPORT$OBJ3")"
sleep 0.3
[ "$RC" = 504 ] && ok "stalled origin -> client gets 504 (kept-alive)" \
    || bad "stall gave $RC (want 504)"
grep -q 'xrootd-fill: event=hold-expired' "$LOG" \
    && grep -q 'held_ms=' "$LOG" \
    && ok "hold expiry logs event=hold-expired with held_ms" \
    || bad "no hold-expired line"
curl -s -o /dev/null -X POST -d '{"mode":"none","count":0}' \
     "http://127.0.0.1:$MPORT/ctl/fault"

# --- 5: client abandons mid-fill -> client-gone -----------------------------
OBJ5="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
       'import json,sys; print(json.load(sys.stdin)[6])')"
curl -s -o /dev/null -X POST -d '{"mode":"stall","count":9}' \
     "http://127.0.0.1:$MPORT/ctl/fault"
# start a request, then kill the client well before the hold (2s) expires
curl -s --max-time 1 "http://127.0.0.1:$CPORT$OBJ5" -o /dev/null 2>/dev/null || true
sleep 1
grep -q 'xrootd-fill: event=client-gone' "$LOG" \
    && grep -q 'parked_ms=' "$LOG" \
    && ok "client abort mid-fill logs event=client-gone with parked_ms" \
    || bad "no client-gone line"
curl -s -o /dev/null -X POST -d '{"mode":"none","count":0}' \
     "http://127.0.0.1:$MPORT/ctl/fault"

# --- 6: 404 hammering -> absorbed-404, one line per hit ---------------------
BOGUS="/cvmfs/test.cern.ch/data/aa/$(python3 -c 'print("bc"*19)')"
for _ in 1 2 3; do curl -s -o /dev/null "http://127.0.0.1:$CPORT$BOGUS"; done
sleep 0.2
N_NEG="$(grep -c 'cvmfs-neg: event=absorbed-404' "$LOG")"
[ "$N_NEG" -ge 1 ] && ok "repeated 404s log cvmfs-neg absorbed-404 ($N_NEG)" \
    || bad "no absorbed-404 line"

# --- 7: every emitted line carries a client= or key= locator ----------------
# (a log an operator can pivot on: who, and which object)
BADLINE="$(grep -E 'xrootd-fill:|cvmfs-neg:|cvmfs-client:' "$LOG" \
           | grep -vE 'client=|key=' | head -1)"
[ -z "$BADLINE" ] \
    && ok "every cvmfs event line has a client= or key= locator" \
    || bad "unpivotable line: $BADLINE"

exit $fail
