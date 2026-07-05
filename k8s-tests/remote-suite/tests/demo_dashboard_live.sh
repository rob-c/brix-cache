#!/usr/bin/env bash
#
# demo_dashboard_live.sh — live web-monitoring-portal demo (sustained load).
#
# Launches the nginx-xrootd gateway (root:// stream + the web dashboard), does
# one 100 MB IN (xrdcp PUT) + OUT (xrdcp GET) round-trip and verifies it
# byte-exact, then drives SUSTAINED multi-stream traffic so you can watch the
# dashboard in use: NSTREAMS parallel xrdcp streams (default 5) continuously
# moving the 100 MB file in and out, each throttled to RATE (default 100 kB/s)
# so every transfer lingers as a slowly-progressing row in the portal.
#
# Pipe-throttle THROUGHOUT: every xrdcp in this demo — the opening round-trip,
# the stream seeding, and the sustained streams — is piped through a tiny
# rate-limiter so the wire rate is smooth and the dashboard never shows a
# full-speed burst.  The round-trip + seeding use the faster SEED_RATE_BPS so
# setup stays quick; the long-lived streams use the slow per-stream RATE_BPS.
#
# Usage:
#   tests/demo_dashboard_live.sh [LIVE_MINUTES]       # default 20 min of traffic
#   NSTREAMS=5 RATE_BPS=100000 tests/demo_dashboard_live.sh 30
#   SEED_RATE_BPS=5000000 tests/demo_dashboard_live.sh        # faster/slower setup
#
# Stop the live traffic:  kill -- -"$(cat /tmp/xrd-dash-demo.pid)"   # whole group
# Stop the gateway:       tests/manage_test_servers.sh stop
#
set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ROOT_URL="root://localhost:11094"          # anonymous root:// (read + write)
DASH_HOST_PORT="localhost:8445"            # dedicated dashboard portal (no client-cert prompt)
DASH_URL="https://${DASH_HOST_PORT}/brix/"
DASH_PASS="testpassword"                   # from the test config
DEMO_OBJ="dashboard_demo_100mb.bin"
SIZE_BYTES=$((100 * 1024 * 1024))          # 100 MiB
LIVE_MINUTES="${1:-20}"
NSTREAMS="${NSTREAMS:-5}"                   # parallel xrdcp streams kept in flight
RATE_BPS="${RATE_BPS:-100000}"             # bytes/sec per sustained stream (slow)
SEED_RATE_BPS="${SEED_RATE_BPS:-5000000}"  # bytes/sec for round-trip + seeding
                                           # (faster so setup is smooth but quick)
XFER_BYTES="${XFER_BYTES:-$((8 * 1024 * 1024))}"  # bytes per SUSTAINED transfer
                                           # (~84s at 100 kB/s) — bounded so each
                                           # completes and is replaced, giving a
                                           # constant churn of rows in the portal
GEN_PIDFILE="/tmp/xrd-dash-demo.pid"
WSL_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

say(){ printf '\n\033[1;36m%s\033[0m\n' "$*"; }
die(){ printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

command -v xrdcp >/dev/null || die "xrdcp not found (install xrootd-client)"

# 1) Ensure the gateway (root:// + dashboard) is up --------------------------
# The demo only needs the main test config (11094 root:// + 8443 dashboard).
# Prefer starting that standalone — robust — and only fall back to the full
# fleet setup when the prepared config/PKI is not present yet.
NGINX_BIN="${NGINX_BIN:-/tmp/nginx-1.28.3/objs/nginx}"
TEST_CONF="/tmp/xrd-test/conf/nginx.conf"
if ! ss -tln 2>/dev/null | grep -q ':11094 '; then
    if [ -x "$NGINX_BIN" ] && [ -f "$TEST_CONF" ] \
       && [ -f /tmp/xrd-test/pki/server/hostcert.pem ]; then
        say "Starting nginx-xrootd (root:// + dashboard) from $TEST_CONF …"
        "$NGINX_BIN" -p /tmp/xrd-test -c "$TEST_CONF" \
            || die "nginx failed to start (see /tmp/xrd-test/logs/error.log)"
    else
        say "Preparing test environment + servers (first run)…"
        "$SCRIPT_DIR/manage_test_servers.sh" start || true   # full-fleet extras
    fi                                                       # may fail; we gate
fi                                                           # on the ports below
sleep 1
ss -tln 2>/dev/null | grep -q ':11094 ' || die "root:// (:11094) not listening"
ss -tln 2>/dev/null | grep -q ':8443 '  || die "dashboard (:8443) not listening"

# 2) Sanity-check the dashboard portal + login -------------------------------
code=$(curl -sk -o /dev/null -w '%{http_code}' "$DASH_URL")
[ "$code" != "000" ] || die "dashboard not reachable at $DASH_URL"
cookie=$(curl -sk -i -X POST -d "password=${DASH_PASS}" \
              "https://${DASH_HOST_PORT}/brix/login" 2>/dev/null \
         | awk 'tolower($1)=="set-cookie:"{print $2; exit}' | tr -d ';\r')
snap=$(curl -sk -o /dev/null -w '%{http_code}' --cookie "$cookie" \
            "https://${DASH_HOST_PORT}/brix/api/v1/snapshot")
say "Dashboard OK  (portal http=$code, api/v1/snapshot http=$snap)"

# 3) Make a 100 MB source file ----------------------------------------------
# SRC is persistent (fixed path, NOT removed on exit) because the detached
# multi-stream generator below keeps reading it after this script returns.
SRC="/tmp/xrd-dash-demo-src-100mb.bin"
OUT="$(mktemp /tmp/xrd-dash-demo-out.XXXXXX.bin)"
trap 'rm -f "$OUT"' EXIT
if [ ! -s "$SRC" ]; then
    say "Generating 100 MB test file…"
    head -c "$SIZE_BYTES" /dev/urandom > "$SRC"
fi

# 4) Set up the pipe-throttle used by EVERY transfer in this demo -----------
# xrdcp's own --xrate pre-paces a whole 8 MiB copy-chunk before it moves any
# data, so at low rates it stalls then bursts — useless for a live view.
# Instead we pipe every xrdcp through a tiny rate-limiter: backpressure on the
# pipe paces the wire to a smooth rate.  Two helpers, used throughout below:
#   thr_put RATE SRC OBJ : throttled PUT  (throttle < SRC | xrdcp - OBJ)
#   thr_get RATE OBJ DST : throttled GET  (xrdcp OBJ -    | throttle > DST)
THR="/tmp/xrd-dash-throttle.py"
cat > "$THR" <<'PY'
import sys, time
RATE = int(sys.argv[1]); CH = 8192
i = sys.stdin.buffer; o = sys.stdout.buffer
t0 = time.time(); sent = 0
while True:
    b = i.read(CH)
    if not b:
        break
    o.write(b); o.flush(); sent += len(b)
    dt = sent / RATE - (time.time() - t0)
    if dt > 0:
        time.sleep(dt)
PY
thr_put(){ python3 "$THR" "$1" < "$2" 2>/dev/null | xrdcp -f - "${ROOT_URL}//$3" 2>/dev/null; }
thr_get(){ xrdcp -f "${ROOT_URL}//$2" - 2>/dev/null | python3 "$THR" "$1" > "$3" 2>/dev/null; }

# 5) Transfer IN (PUT) and OUT (GET) over root:// — both pipe-throttled ------
seed_mbs=$(( SEED_RATE_BPS / 1000000 ))
say "IN   →  throttled PUT 100 MB (~${seed_mbs} MB/s)  $SRC  →  ${ROOT_URL}//${DEMO_OBJ}"
t0=$(date +%s%3N)
thr_put "$SEED_RATE_BPS" "$SRC" "$DEMO_OBJ"  || die "PUT failed"
say "OUT  ←  throttled GET 100 MB (~${seed_mbs} MB/s)  ${ROOT_URL}//${DEMO_OBJ}  →  $OUT"
thr_get "$SEED_RATE_BPS" "$DEMO_OBJ" "$OUT"  || die "GET failed"
t1=$(date +%s%3N)

# 6) Verify the round-trip is byte-exact ------------------------------------
cmp -s "$SRC" "$OUT" || die "round-trip MISMATCH"
say "✔ Round-trip byte-exact (100 MB in + out in $((t1 - t0)) ms)"

# 7) Seed one bounded read-source object (pipe-throttled) -------------------
# The sustained READ streams all pull from this single object; WRITE streams
# create their own per-stream targets.  Sized XFER_BYTES so every sustained
# transfer completes in about XFER_BYTES/RATE_BPS seconds — after which the
# generator immediately starts the next one (continuous churn of rows).
xfer_mb=$(( XFER_BYTES / 1024 / 1024 ))
say "Seeding read-source object (${xfer_mb} MiB, pipe-throttled, ~${seed_mbs} MB/s)…"
head -c "$XFER_BYTES" "$SRC" 2>/dev/null \
    | python3 "$THR" "$SEED_RATE_BPS" 2>/dev/null \
    | xrdcp -f - "${ROOT_URL}//dash_read_src.bin" 2>/dev/null \
    || die "seeding read-source object failed"

# 8) Sustained multi-stream live traffic — continuous churn, all throttled ---
# NSTREAMS worker loops run under one setsid process group (so it outlives this
# script and stops with a single group kill).  Odd workers READ the shared
# read-source, even workers WRITE a per-stream object — a steady mix of both.
# Each transfer moves only XFER_BYTES (paced to RATE_BPS via the THR throttle),
# so it completes in ~XFER_BYTES/RATE_BPS seconds; the worker then IMMEDIATELY
# launches the next one.  Net effect: as every transfer finishes a fresh one
# takes its place, so the portal always shows ~NSTREAMS live, smoothly
# progressing rows — a constant flow of new transfers for the whole demo.
#   OUT (read):  xrdcp read_src -        | throttle > /dev/null
#   IN  (write): head -c XB SRC | throttle | xrdcp - obj

# Stop any previous generator group (pidfile holds the group-leader PID).
if [ -f "$GEN_PIDFILE" ]; then
    old="$(cat "$GEN_PIDFILE" 2>/dev/null)"
    [ -n "$old" ] && { kill -- "-$old" 2>/dev/null; kill "$old" 2>/dev/null; }
fi

setsid bash -c '
    ROOT="'"$ROOT_URL"'"; SRC="'"$SRC"'"; THR="'"$THR"'"
    R='"$RATE_BPS"'; XB='"$XFER_BYTES"'; N='"$NSTREAMS"'
    end=$(( $(date +%s) + '"$LIVE_MINUTES"' * 60 ))
    for n in $(seq 1 "$N"); do
        (
            while [ "$(date +%s)" -lt "$end" ]; do
                if [ $((n % 2)) -eq 1 ]; then   # OUT: read XB from the shared source
                    xrdcp -f "${ROOT}//dash_read_src.bin" - 2>/dev/null \
                        | python3 "$THR" "$R" >/dev/null 2>&1
                else                            # IN: write XB to a per-stream object
                    head -c "$XB" "$SRC" 2>/dev/null \
                        | python3 "$THR" "$R" 2>/dev/null \
                        | xrdcp -f - "${ROOT}//dash_stream_${n}.bin" 2>/dev/null
                fi
            done
        ) &
    done
    wait
    rm -f "'"$GEN_PIDFILE"'"
' >/dev/null 2>&1 &
GEN_PID=$!
echo "$GEN_PID" > "$GEN_PIDFILE"

# 9) Point the user at the LIVE portal --------------------------------------
cat <<EOF

============================================================================
  ✅  THE WEB MONITORING PORTAL IS LIVE — open it in your browser now:

         ${DASH_URL}
         (if localhost doesn't resolve from Windows:
          https://${WSL_IP}:8443/brix/ )

  🔑  Login password:  ${DASH_PASS}
  ⚠   Self-signed TLS cert — accept the browser's security warning.

  Every transfer is pipe-throttled for a smooth wire rate (no bursts):
    • the opening round-trip + seeding ran at ~${seed_mbs} MB/s,
    • ${NSTREAMS} parallel xrdcp workers (alternating in/out) now run at
      $((RATE_BPS / 1000)) kB/s each, every transfer moving ${xfer_mb} MiB
      (~$((XFER_BYTES / RATE_BPS))s) for ${LIVE_MINUTES} min.
  As each transfer completes the worker immediately starts the next, so the
  Transfers view always shows ~${NSTREAMS} live rows (reads + writes) with a
  constant flow of fresh transfers arriving — never an empty dashboard.
  Stream-group leader pid: ${GEN_PID}

  Stop the live traffic:   kill -- -${GEN_PID}    (or: kill -- -\$(cat ${GEN_PIDFILE}))
  Stop the gateway:        ${SCRIPT_DIR}/manage_test_servers.sh stop
============================================================================
EOF
