#!/bin/bash
#
# run_valgrind.sh — Valgrind Memcheck memory-safety harness for nginx-xrootd.
#
# WHAT: Launches a single nginx instance (from nginx.conf.in) under Valgrind
# Memcheck, drives every external-handle code path (GSI/TLS x509, bearer JWT,
# macaroon, libcurl TPC, S3 SigV4), shuts nginx down gracefully, then greps the
# per-pid valgrind logs for leaks / uninitialised reads / invalid accesses /
# leaked fds in MODULE frames and writes a triage summary.
#
# WHY a worker (not master_process off): TLS only serves with a real worker; with
# --trace-children=yes valgrind follows the worker (where requests are handled)
# and writes its report to vg.<workerpid>.log when the worker exits on SIGQUIT.
#
# TOOLING CAVEAT (WSL2 / sandboxed shells): some shells block foreground `sleep`
# and kill `&`-backgrounded long-lived processes when the calling tool returns,
# so valgrind never gets to write its log. Launch this script FULLY DETACHED and
# poll its marker file from a separate shell invocation:
#
#     setsid bash tests/valgrind/run_valgrind.sh </dev/null >/dev/null 2>&1 & disown
#     # … later, in a separate call:
#     grep FINISHED "$VG_WORK/results.txt"      # default VG_WORK=/tmp/xrd-vg
#
# Requires the test PKI + token fixtures to already exist (run the fleet once:
# `tests/manage_test_servers.sh start-all`, or any pytest session). The harness
# does NOT regenerate certs/JWKS.

set -u

# ---- Configuration (override via environment) ----
NGINX_BIN="${NGINX_BIN:-/tmp/nginx-1.28.3/objs/nginx}"
TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"
PKI_DIR="${PKI_DIR:-$TEST_ROOT/pki}"
TOKEN_DIR="${TOKEN_DIR:-$TEST_ROOT/tokens}"
VG_WORK="${VG_WORK:-/tmp/xrd-vg}"
SUPP="${SUPP:-$(cd "$(dirname "$0")" && pwd)/valgrind.supp}"
TEMPLATE="${TEMPLATE:-$(cd "$(dirname "$0")" && pwd)/nginx.conf.in}"

GSI_TLS_PORT="${GSI_TLS_PORT:-28444}"
HTTP_PORT="${HTTP_PORT:-28080}"
S3_PORT="${S3_PORT:-29051}"
METRICS_PORT="${METRICS_PORT:-29100}"

CA_DIR="$PKI_DIR/ca"
CA_CERT="$PKI_DIR/ca/ca.pem"
SERVER_CERT="$PKI_DIR/server/hostcert.pem"
SERVER_KEY="$PKI_DIR/server/hostkey.pem"
CLIENT_CERT="$PKI_DIR/user/usercert.pem"
CLIENT_KEY="$PKI_DIR/user/userkey.pem"

LOGDIR="$VG_WORK/logs"
RESULTS="$VG_WORK/results.txt"

# ---- Preflight ----
mkdir -p "$VG_WORK"/{logs,tmp,data,conf}
exec >"$VG_WORK/run.trace" 2>&1
echo "STARTED $(date +%s)"
: >"$RESULTS"

command -v valgrind >/dev/null || { echo "MISSING valgrind" >>"$RESULTS"; echo "FINISHED $(date +%s)"; exit 1; }
[[ -x "$NGINX_BIN" ]] || { echo "MISSING nginx binary $NGINX_BIN" >>"$RESULTS"; echo "FINISHED $(date +%s)"; exit 1; }
for f in "$CA_CERT" "$SERVER_CERT" "$SERVER_KEY" "$TOKEN_DIR/jwks.json"; do
    [[ -e "$f" ]] || { echo "MISSING fixture $f (run tests/manage_test_servers.sh start-all first)" >>"$RESULTS"; echo "FINISHED $(date +%s)"; exit 1; }
done

# A file to GET/COPY as a TPC source.
echo "valgrind harness payload $(date +%s)" >"$VG_WORK/data/vgtest.txt"

# ---- Render config from template ----
CONF="$VG_WORK/conf/nginx.conf"
sed -e "s|{WORK}|$VG_WORK|g" \
    -e "s|{CA_DIR}|$CA_DIR|g" \
    -e "s|{CA_CERT}|$CA_CERT|g" \
    -e "s|{SERVER_CERT}|$SERVER_CERT|g" \
    -e "s|{SERVER_KEY}|$SERVER_KEY|g" \
    -e "s|{CLIENT_CERT}|$CLIENT_CERT|g" \
    -e "s|{CLIENT_KEY}|$CLIENT_KEY|g" \
    -e "s|{TOKEN_DIR}|$TOKEN_DIR|g" \
    -e "s|{GSI_TLS_PORT}|$GSI_TLS_PORT|g" \
    -e "s|{HTTP_PORT}|$HTTP_PORT|g" \
    -e "s|{S3_PORT}|$S3_PORT|g" \
    -e "s|{METRICS_PORT}|$METRICS_PORT|g" \
    "$TEMPLATE" >"$CONF"

"$NGINX_BIN" -t -p "$VG_WORK" -c "$CONF" || { echo "CONFIG INVALID" >>"$RESULTS"; echo "FINISHED $(date +%s)"; exit 1; }

# ---- Clean any prior harness procs, launch under valgrind ----
# NOTE: valgrind's visible cmdline is the nginx invocation (not "memcheck"), so
# match prior runs on the unique config path, not the process name.
pkill -9 -f "$VG_WORK/conf/nginx.conf" 2>/dev/null
sleep 2
rm -f "$LOGDIR"/vg.*.log

valgrind --leak-check=full --show-leak-kinds=definite,indirect \
    --track-fds=yes --trace-children=yes --child-silent-after-fork=no \
    --error-exitcode=0 --num-callers=30 \
    --suppressions="$SUPP" \
    --log-file="$LOGDIR/vg.%p.log" \
    "$NGINX_BIN" -p "$VG_WORK" -c "$CONF" &
VG=$!
echo "valgrind launcher pid=$VG"

# Wait for the worker to accept connections (valgrind is ~20x slower to boot).
for i in $(seq 1 120); do
    (exec 3<>/dev/tcp/127.0.0.1/$HTTP_PORT) 2>/dev/null && { exec 3<&-; echo "up after ${i}s" >>"$RESULTS"; break; }
    sleep 1
done

# ---- Exercise every external-handle path ----
JWT=""; [[ -f "$TOKEN_DIR/upstream.jwt" ]] && JWT="$(cat "$TOKEN_DIR/upstream.jwt")"
{
    # JWT / jansson / EVP (plain HTTP, auth optional → invalid falls to anon).
    echo -n "jwt valid=";   curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $JWT" "http://127.0.0.1:$HTTP_PORT/vgtest.txt"
    echo -n " garbage=";    curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer aa.bb.cc" "http://127.0.0.1:$HTTP_PORT/vgtest.txt"
    echo -n " malformed=";  curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer xyz" "http://127.0.0.1:$HTTP_PORT/vgtest.txt"
    echo -n " put=";        curl -s -o /dev/null -w "%{http_code}" -T "$VG_WORK/data/vgtest.txt" -H "Authorization: Bearer $JWT" "http://127.0.0.1:$HTTP_PORT/put.txt"
    echo

    # GSI / x509 proxy-cert over TLS → OpenSSL chain verify + VOMS.
    echo -n "gsi usercert="; curl -s -k -o /dev/null -w "%{http_code}" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" --cacert "$CA_CERT" "https://127.0.0.1:$GSI_TLS_PORT/vgtest.txt"
    if [[ -f "$PKI_DIR/user/proxy.pem" && -f "$PKI_DIR/user/proxykey.pem" ]]; then
        echo -n " proxycert="; curl -s -k -o /dev/null -w "%{http_code}" --cert "$PKI_DIR/user/proxy.pem" --key "$PKI_DIR/user/proxykey.pem" --cacert "$CA_CERT" "https://127.0.0.1:$GSI_TLS_PORT/vgtest.txt"
    fi
    echo -n " noclientcert="; curl -s -k -o /dev/null -w "%{http_code}" "https://127.0.0.1:$GSI_TLS_PORT/vgtest.txt"
    echo

    # Macaroon mint (POST /.oauth2/token) → HMAC chain; then use it → verify path.
    MAC="$(curl -s -X POST \
        -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange&scope=storage.read:/ storage.write:/&expires_in=600' \
        "http://127.0.0.1:$HTTP_PORT/.oauth2/token" 2>/dev/null)"
    echo -n "macaroon mint_bytes=${#MAC}"
    MACTOK="$(printf '%s' "$MAC" | sed -n 's/.*"macaroon"[: ]*"\([^"]*\)".*/\1/p')"
    [[ -z "$MACTOK" ]] && MACTOK="$(printf '%s' "$MAC" | sed -n 's/.*"access_token"[: ]*"\([^"]*\)".*/\1/p')"
    if [[ -n "$MACTOK" ]]; then
        echo -n " use="; curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $MACTOK" "http://127.0.0.1:$HTTP_PORT/vgtest.txt"
    fi
    echo

    # libcurl TPC on the x509 block (client cert passes auth/write gate → reaches
    # curl): a pull COPY from our own TLS port (curl perform + TLS), and a push to
    # an unreachable host (curl failure-cleanup path).
    echo -n "tpc pull="; curl -s -k -o /dev/null -w "%{http_code}" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" --cacert "$CA_CERT" -X COPY \
        -H "Source: https://127.0.0.1:$GSI_TLS_PORT/vgtest.txt" \
        "https://127.0.0.1:$GSI_TLS_PORT/tpc_pulled.txt"
    echo -n " push_unreach="; curl -s -k -o /dev/null -w "%{http_code}" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" --cacert "$CA_CERT" -X COPY \
        -H "Destination: https://127.0.0.1:1/dead.txt" \
        "https://127.0.0.1:$GSI_TLS_PORT/vgtest.txt"
    echo

    # S3 SigV4 reject + anonymous + metrics.
    echo -n "s3 badsig="; curl -s -o /dev/null -w "%{http_code}" -H "Authorization: AWS4-HMAC-SHA256 Credential=x/y, SignedHeaders=host, Signature=dead" "http://127.0.0.1:$S3_PORT/testbucket/vgtest.txt"
    echo -n " anon=";     curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$S3_PORT/testbucket/vgtest.txt"
    echo -n " | metrics="; curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$METRICS_PORT/metrics"
    echo
} >>"$RESULTS" 2>&1

# ---- Shutdown: stop the WORKER gracefully (it handled the requests, so its
# report is the one we want), then SIGKILL the master. The master is killed —
# not asked to quit — on purpose: on shutdown nginx's master reaps the worker
# and runs ngx_unlock_mutexes()->ngx_shmtx_force_unlock() over the (single-worker,
# uninitialised) accept mutex, which NULL-derefs under valgrind. That crash is
# nginx-CORE only (ngx_shmtx.c / ngx_process.c — off-limits to edit and benign
# without valgrind), but a graceful master exit would fill its log with that
# core-shutdown noise. SIGKILL skips the master's signal handler entirely, so the
# clean signal is the worker's report. ----
sleep 2
MASTER_PID="$(cat "$LOGDIR/nginx.pid" 2>/dev/null || true)"
# The worker is the valgrind-traced nginx process that is NOT the master. Match
# on the config path — valgrind's cmdline is the nginx invocation, not "memcheck".
WORKER_PID="$(pgrep -f "$VG_WORK/conf/nginx.conf" 2>/dev/null | grep -vx "$VG" | grep -vx "$MASTER_PID" | head -1)"
# SIGQUIT the MASTER (graceful): the master tells the worker to finish and quit,
# so the worker exits cleanly and its valgrind dumps a COMPLETE leak report.
# (Do NOT kill the master first — nginx workers self-terminate the instant the
# master vanishes, exiting abnormally before valgrind can dump.) The master's own
# reap of the worker may NULL-deref in ngx_unlock_mutexes under valgrind, but
# that lands only in the master's log, which we discard below.
[[ -n "$MASTER_PID" ]] && kill -QUIT "$MASTER_PID" 2>/dev/null
# Wait for the worker valgrind to finish flushing its report.
if [[ -n "$WORKER_PID" ]]; then
    for i in $(seq 1 180); do kill -0 "$WORKER_PID" 2>/dev/null || break; sleep 1; done
fi
sleep 2
# Force-reap anything still bound to this harness (master valgrind post-crash, or
# a worker that ignored SIGQUIT) so the ports are free for the next run.
for p in $(pgrep -f "$VG_WORK/conf/nginx.conf" 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
[[ -n "$VG" ]] && kill -9 "$VG" 2>/dev/null
sleep 1
# Discard the master's log (graceful-exit reap noise / core crash) so triage sees
# only the clean worker report.
if [[ -n "$MASTER_PID" && -f "$LOGDIR/vg.$MASTER_PID.log" ]]; then
    mv "$LOGDIR/vg.$MASTER_PID.log" "$LOGDIR/vg.master-$MASTER_PID.discarded" 2>/dev/null
fi

# ---- Triage: module frames only (exclude nginx core) ----
echo "---- vg logs ----" >>"$RESULTS"
for f in "$LOGDIR"/vg.*.log; do
    [[ -e "$f" ]] || continue
    lost="$(grep -cE "definitely lost|indirectly lost|Invalid (read|write)|uninitialised" "$f" 2>/dev/null)"
    err="$(grep -E "ERROR SUMMARY" "$f" | tail -1)"
    echo "$(basename "$f"): leakish=$lost  $err" >>"$RESULTS"
done
echo "---- MODULE-FRAME HITS (should be empty) ----" >>"$RESULTS"
grep -nE "in (xrootd_|ngx_http_xrootd|ngx_stream_xrootd)|/src/(token|webdav|s3|gsi|crypto|dashboard|read|session|cache|metrics|aio|path|fattr|tpc)/" "$LOGDIR"/vg.*.log 2>/dev/null \
    | grep -v "src/core" >>"$RESULTS" || echo "(none)" >>"$RESULTS"

echo "DONE logs=$(ls "$LOGDIR"/vg.*.log 2>/dev/null | wc -l)" >>"$RESULTS"
echo "FINISHED $(date +%s)"
