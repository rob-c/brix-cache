#!/usr/bin/env bash
# tests/run_cvmfs_selectlog.sh — the origin-SELECTION diagnostic trail.
#
# Proves the error log explains WHY the cvmfs cache changed origin server:
#   1 success:  geo ranks are logged at config time (RAL preferred over CERN
#               from a UK site) AND a live failover emits the driver's
#               per-attempt failure + "origin switched ... SKIPPED" evidence.
#   2 error:    both origins down → the attempt trail + a give-up line, then a
#               clean keep-alive 504 (no worker stall).
#   3 sec-neg:  a percent-encoded CRLF in the request path cannot forge a log
#               record — the key is sanitised before it reaches the log.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
# RAL (near) and CERN (far) mock origins; coordinates below match.
RAL=12861; CERN=12862; CPORT=12863
PFX="$(mktemp -d /tmp/cvmfs_sl.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }
bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCK_RAL" "$MOCK_CERN" 2>/dev/null
           [ -n "${KEEP:-}" ] && { echo "  (kept $PFX)"; return; }; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"

# identical repos (same seed) on both origins so a fill can come from either
python3 "$HERE/cvmfs/mock_stratum1.py" --port $RAL  --objects 6 --seed 9 & MOCK_RAL=$!
python3 "$HERE/cvmfs/mock_stratum1.py" --port $CERN --objects 6 --seed 9 & MOCK_CERN=$!
sleep 0.5

# "here" = a UK site (near RAL, 51.57:-1.31; far from CERN, 46.23:6.05).
cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location /cvmfs/ {
        xrootd_cvmfs_storage_backend "http://127.0.0.1:$RAL|http://127.0.0.1:$CERN";
        xrootd_cvmfs_cache_store posix:$PFX/cache;
        xrootd_cvmfs_origin_select geo;
        xrootd_cvmfs_here 51.57:-1.31;
        xrootd_cvmfs_origin_coords 127.0.0.1:$RAL  51.57:-1.31;
        xrootd_cvmfs_origin_coords 127.0.0.1:$CERN 46.23:6.05;
        xrootd_cvmfs on;
        xrootd_cvmfs_client_hold 3;
    }
} }
EOF
# The config-time geo "selection report" is emitted during parse, when the
# active log is still the prefix log on stderr — capture it separately.
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX" 2>"$PFX/logs/start.err"; sleep 0.5

E="$PFX/logs/e.log"
SE="$PFX/logs/start.err"
OBJS=($(curl -s "http://127.0.0.1:$RAL/ctl/objects" | python3 -c \
       'import json,sys; print(" ".join(json.load(sys.stdin)))'))

# --- 1a: geo ranking table logged at config time, RAL preferred -------------
grep -q "selection report.*127.0.0.1:$RAL .*rank 0 (preferred" "$SE" \
    && ok "config-time geo table: RAL ranked preferred" \
    || bad "config-time geo table missing RAL-preferred line"
grep -q "selection report.*127.0.0.1:$CERN .*rank 1" "$SE" \
    && ok "config-time geo table: CERN ranked behind" \
    || bad "config-time geo table missing CERN rank line"

# warm the cache from the preferred origin (RAL)
curl -s --max-time 20 "http://127.0.0.1:$CPORT${OBJS[0]}" -o /dev/null

# --- 1b: kill RAL, request an UNCACHED object → failover to CERN, logged ----
kill "$MOCK_RAL"; sleep 0.3
curl -s --max-time 25 "http://127.0.0.1:$CPORT${OBJS[1]}" -o "$PFX/a.bin"
curl -s "http://127.0.0.1:$CERN${OBJS[1]}" -o "$PFX/ref.bin"
cmp -s "$PFX/a.bin" "$PFX/ref.bin" && ok "served via failover to CERN" \
    || bad "failover fill failed"
# driver logged the RAL transport failure with detail
grep -q "http origin 127.0.0.1:$RAL failed" "$E" \
    && ok "driver logged RAL transport failure (per-attempt WARN)" \
    || bad "no per-attempt RAL failure line"
# driver logged the failover hop and/or the origin switch with SKIPPED reason
grep -Eq "http origin (failover for|switched to 127.0.0.1:$CERN)" "$E" \
    && ok "driver logged the origin switch to CERN" \
    || bad "no origin-switch line"
grep -q "SKIPPED" "$E" \
    && ok "switch line explains preferred RAL was SKIPPED" \
    || bad "switch line missing the SKIPPED reason"

# --- 2: both down → attempt trail + give-up, clean 504 ----------------------
kill "$MOCK_CERN"; sleep 0.3
C="$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' \
     "http://127.0.0.1:$CPORT${OBJS[4]}")"
[ "$C" = 504 ] && ok "both-down → clean keep-alive 504" || bad "both-down: $C"
grep -q "http origin request exhausted all endpoints" "$E" \
    && ok "driver logged endpoint exhaustion" \
    || bad "no exhaustion line"
grep -q "xrootd-fill: event=retry" "$E" \
    && ok "fill layer logged the per-attempt retry trail" \
    || bad "no fill retry trail"

# --- 3: sec-neg — encoded CRLF in the path cannot inject a log line ---------
# %0d%0a<fake> would, unsanitised, split the log into a forged record.
curl -s --max-time 10 -o /dev/null \
    "http://127.0.0.1:$CPORT/cvmfs/data/%0d%0aFORGED-ORIGIN-SWITCH" || true
if grep -q '^FORGED-ORIGIN-SWITCH' "$E"; then
    bad "CRLF injection forged a log line"
else
    ok "CRLF in path did not forge a log record (key sanitised)"
fi
# If the wire path reached the log at all, its CR/LF must appear hex-escaped
# (\x0D\x0A) — never as raw bytes that would split the record.
if grep -aq 'FORGED-ORIGIN-SWITCH' "$E"; then
    if grep -aiq '\\x0d\\x0a *FORGED-ORIGIN-SWITCH' "$E"; then
        ok "wire path logged with CRLF hex-escaped"
    else
        bad "wire path reached the log with un-escaped control bytes"
    fi
else
    ok "wire path never logged (rejected before any origin log line)"
fi

exit $fail
