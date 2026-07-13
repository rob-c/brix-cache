#!/usr/bin/env bash
# run_cred_metrics.sh — Phase-2 Task-3: Prometheus counters for credential outcomes.
#
# WHAT: Verifies that brix_cred_select_user_total, brix_cred_select_fallback_total,
#       and brix_cred_select_deny_total are exported on /metrics and move when the
#       corresponding credential outcomes fire at the VFS credential gate.
#
# WHY:  Task 3 adds three per-proto Prometheus counters in ngx_brix_unified_metrics_t
#       (mirroring brix_metric_cache_result).  This test is the TDD gate: it MUST
#       fail before implementation (families absent) and pass after (families present
#       and each counter incremented by the correct trigger).
#
# HOW:  Topology = GSI-auth root:// origin O (port CMOP) + davs:// frontend F (port
#       CMFP) + plain HTTP listener M (port CMMP) that serves /metrics.  Three PUT
#       scenarios drive each outcome:
#         1  user A (cred provisioned, fallback=deny) → BRIX_CRED_OUTCOME_USER
#         2  user B (no cred, fallback=allow)         → BRIX_CRED_OUTCOME_FALLBACK
#         3  user B (no cred, fallback=deny)          → BRIX_CRED_OUTCOME_DENY
#       After each scenario we scrape /metrics and assert the respective counter
#       moved by at least 1.
#
# SAFETY: Uses ONLY own ports (CMOP=11199, CMFP=18465, CMMP=18466).  Teardown
#         kills ONLY PIDs from our own pidfiles.  Never runs pkill nginx or
#         manage_test_servers.sh.  Workdir is /tmp/ucredm-e2e (entirely ours).
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
NGINX=${NGINX:-/tmp/nginx-1.28.3/objs/nginx}
TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"

# ---- private workdir (entirely ours) ----------------------------------------
PFX=/tmp/ucredm-e2e
rm -rf "$PFX"
mkdir -p "$PFX/o/logs"  "$PFX/o/root" \
         "$PFX/f/logs"  "$PFX/f/export" "$PFX/f/stage" "$PFX/f/journal" \
         "$PFX/creds"   "$PFX/b"
chmod 777 "$PFX/creds"

# ---- choose ports -----------------------------------------------------------
CMOP=${CMOP:-11199}
CMFP=${CMFP:-18465}
CMMP=${CMMP:-18466}
for p in "$CMOP" "$CMFP" "$CMMP"; do
    if ss -tlnp 2>/dev/null | grep -q ":${p} "; then
        echo "SKIP: port $p already in use — choose different CMOP/CMFP/CMMP"
        exit 0
    fi
done

# ---- helpers ----------------------------------------------------------------
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; FAILED=1; }
FAILED=0

count_grep(){ grep -c "$1" "$2" 2>/dev/null || true; }

# Extract a numeric counter value from Prometheus text output.
# Usage: metric_value "family_name" <metrics_text>
# Returns the first numeric value for the given family (any label set).
metric_value(){
    local family="$1" text="$2"
    printf '%s' "$text" | grep "^${family}" | head -1 | awk '{print $NF}' | tr -d '\n'
}

# Sum all lines for a given metric family (handles multiple label rows).
metric_sum(){
    local family="$1" text="$2"
    printf '%s' "$text" | grep "^${family}" | awk '{s+=$NF} END{printf "%d",s}'
}

origin_stop(){
    if [ -f "$PFX/o/nginx.pid" ]; then
        kill "$(cat "$PFX/o/nginx.pid")" 2>/dev/null
        sleep 0.5
    fi
}
front_stop(){
    if [ -f "$PFX/f/nginx.pid" ]; then
        local pid; pid=$(cat "$PFX/f/nginx.pid" 2>/dev/null)
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
        sleep 1
    fi
}
cleanup(){
    front_stop
    origin_stop
    rm -rf "$PFX" /tmp/ucredm_payload.bin 2>/dev/null
}
trap cleanup EXIT

# ---- PKI provisioning -------------------------------------------------------
CA_CERT="$TEST_ROOT/pki/ca/ca.pem"
CA_DIR="$TEST_ROOT/pki/ca"
CA_KEY="$TEST_ROOT/pki/ca/ca.key"
SERVER_CERT="$TEST_ROOT/pki/server/hostcert.pem"
SERVER_KEY="$TEST_ROOT/pki/server/hostkey.pem"
PROXY_A="$TEST_ROOT/pki/user/proxy_std.pem"

need_pki=0
[ ! -f "$CA_CERT" ] && need_pki=1
[ ! -f "$CA_KEY" ]  && need_pki=1
[ ! -f "$PROXY_A" ] && need_pki=1
if [ "$need_pki" = 0 ]; then
    openssl x509 -in "$PROXY_A" -noout -checkend 300 >/dev/null 2>&1 || need_pki=1
fi
if [ "$need_pki" = 1 ]; then
    echo "Provisioning test PKI (blitz_test_pki)..."
    ( cd "$HERE/tests" && PYTHONPATH=. python3 -c \
        "import pki_helpers; pki_helpers.blitz_test_pki()" ) \
        >"$PFX/o/logs/pki.log" 2>&1 \
        || { echo "SKIP: PKI provisioning failed"; cat "$PFX/o/logs/pki.log"; exit 0; }
fi
[ -f "$CA_KEY" ] || { echo "SKIP: CA key not found ($CA_KEY)"; exit 0; }

# ---- mint user B cert from the same CA (plain end-entity cert) ----
openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$PFX/b/key.pem" \
    -subj "/DC=test/DC=xrootd/CN=Cred Metrics User B/CN=99998" \
    -out "$PFX/b/req.pem" >/dev/null 2>&1
openssl x509 -req \
    -in "$PFX/b/req.pem" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -set_serial "0x$(openssl rand -hex 8)" \
    -days 2 \
    -out "$PFX/b/cert.pem" >/dev/null 2>&1 \
    || { echo "SKIP: user-B cert mint failed"; exit 0; }
B_CERT="$PFX/b/cert.pem"
B_KEY="$PFX/b/key.pem"

# Small test payload.
head -c 4096 /dev/urandom > /tmp/ucredm_payload.bin

# ---- origin: GSI-only root:// server ----------------------------------------
cat > "$PFX/o/nginx.conf" <<EOF
daemon on;
error_log $PFX/o/logs/e.log info;
pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${CMOP};
    brix_root on;
    brix_export $PFX/o/root;
    brix_allow_write on;
    brix_auth gsi;
    brix_certificate     $SERVER_CERT;
    brix_certificate_key $SERVER_KEY;
    brix_trusted_ca      $CA_CERT;
} }
EOF
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/start.err" \
    || { echo "SKIP: origin start failed"; cat "$PFX/o/start.err"; exit 0; }
sleep 0.5

# ---- frontend builder --------------------------------------------------------
# $1 = deny|allow   $2 = extra main-context lines (optional)
mkfront(){
    local fallback="$1" extra="${2:-}"
    cat > "$PFX/f/nginx.conf" <<EOF
daemon on;
error_log $PFX/f/logs/e.log info;
pid $PFX/f/nginx.pid;
env BRIX_STAGE_JOURNAL_DIR=$PFX/f/journal;
${extra}
worker_processes 1;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    access_log $PFX/f/logs/access.log;
    client_body_temp_path $PFX/f/export;
    brix_credential origin { x509_proxy $PROXY_A; ca_dir $CA_DIR; }
    server {
        listen 127.0.0.1:${CMFP} ssl;
        ssl_certificate     $SERVER_CERT;
        ssl_certificate_key $SERVER_KEY;
        ssl_client_certificate $CA_CERT;
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;
        location / {
            brix_webdav on;
            brix_allow_write on;
            brix_export $PFX/f/export;
            brix_webdav_cafile $CA_CERT;
            brix_webdav_auth required;
            brix_storage_backend root://127.0.0.1:${CMOP};
            brix_storage_credential origin;
            brix_storage_credential_dir $PFX/creds;
            brix_storage_credential_fallback $fallback;
            brix_stage on;
            brix_stage_store posix:$PFX/f/stage;
            brix_stage_flush sync;
        }
    }
    server {
        listen 127.0.0.1:${CMMP};
        location /metrics { brix_metrics on; }
    }
}
EOF
}
front_start(){
    mkfront "$@"
    "$NGINX" -p "$PFX/f" -c "$PFX/f/nginx.conf" 2>"$PFX/f/start.err" \
        || { echo "SKIP: frontend start failed ($*)"; cat "$PFX/f/start.err"; exit 0; }
    sleep 0.5
}
wait_ready(){
    local i
    for i in $(seq 1 20); do
        curl -sk -o /dev/null --max-time 1 "https://127.0.0.1:${CMFP}/" 2>/dev/null && return 0
        sleep 0.2
    done
    return 1
}
scrape_metrics(){
    curl -s --max-time 5 "http://127.0.0.1:${CMMP}/metrics" 2>/dev/null
}

CURL_A="curl -sk --cert $PROXY_A --key $PROXY_A"
CURL_B="curl -sk --cert $B_CERT --key $B_KEY"
URLF="https://127.0.0.1:${CMFP}"

# ===========================================================================
# STEP 0 — Learn the derived key for user A (so we can provision a cred file).
# ===========================================================================
echo "--- step 0: learning derived key for user A ---"
front_start deny
wait_ready
$CURL_A -o /dev/null -w '%{http_code}' \
    -T /tmp/ucredm_payload.bin "$URLF/probe_key.bin" >/dev/null 2>&1 || true
sleep 0.3
A_KEY=$(grep -oE 'key=x5h-[0-9a-f]+|key=[A-Za-z0-9@._-]+' "$PFX/f/logs/e.log" 2>/dev/null \
        | head -1 | cut -d= -f2)
if [ -z "$A_KEY" ]; then
    A_DN_TMP=$(openssl x509 -in "$PROXY_A" -noout -subject -nameopt oneline 2>/dev/null \
               | sed 's/subject= *//')
    A_KEY="x5h-$(printf '%s' "$A_DN_TMP" | openssl dgst -sha256 -hex 2>/dev/null \
               | awk '{print $2}' | head -c 32)"
fi
[ -n "$A_KEY" ] || { bad "could not derive key for user A"; exit 1; }
echo "  user-A credential stem: $A_KEY"
install -m 644 "$PROXY_A" "$PFX/creds/$A_KEY.pem"
front_stop

# ===========================================================================
# ASSERTION 1 — User A with provisioned cred (deny mode) → cred_select_user_total++
# ===========================================================================
echo "--- assertion 1: user A with cred → cred_select_user_total increments ---"
front_start deny
wait_ready

M_BEFORE=$(scrape_metrics)

# Confirm metric families are present; if not, this is the expected TDD red state.
if ! printf '%s' "$M_BEFORE" | grep -q '^brix_cred_select_user_total'; then
    bad "1: brix_cred_select_user_total family absent from /metrics (expected before implementation)"
    # Flush all three failures to show the red state clearly.
    bad "2: brix_cred_select_fallback_total family absent"
    bad "3: brix_cred_select_deny_total family absent"
    echo ""
    echo "run_cred_metrics: FAIL (expected — families not yet implemented)"
    exit 1
fi

USER_BEFORE=$(metric_sum "brix_cred_select_user_total" "$M_BEFORE")
CODE=$($CURL_A -o /dev/null -w '%{http_code}' \
       -T /tmp/ucredm_payload.bin "$URLF/cm1.bin" 2>/dev/null)
{ [ "$CODE" = "201" ] || [ "$CODE" = "204" ]; } \
    && ok "1a: A PUT accepted (code=$CODE)" \
    || bad "1a: A PUT → $CODE (want 201/204)"
sleep 0.3
M_AFTER=$(scrape_metrics)
USER_AFTER=$(metric_sum "brix_cred_select_user_total" "$M_AFTER")
[ "${USER_AFTER:-0}" -gt "${USER_BEFORE:-0}" ] \
    && ok "1b: cred_select_user_total incremented ($USER_BEFORE → $USER_AFTER)" \
    || bad "1b: cred_select_user_total did not increment ($USER_BEFORE → $USER_AFTER)"
front_stop

# ===========================================================================
# ASSERTION 2 — User B, no cred, fallback=allow → cred_select_fallback_total++
# ===========================================================================
echo "--- assertion 2: user B (no cred), allow → cred_select_fallback_total increments ---"
front_start allow
wait_ready

M_BEFORE=$(scrape_metrics)
FALLBACK_BEFORE=$(metric_sum "brix_cred_select_fallback_total" "$M_BEFORE")
CODE=$($CURL_B -o /dev/null -w '%{http_code}' \
       -T /tmp/ucredm_payload.bin "$URLF/cm2.bin" 2>/dev/null)
{ [ "$CODE" = "201" ] || [ "$CODE" = "204" ]; } \
    && ok "2a: B PUT allowed via fallback (code=$CODE)" \
    || bad "2a: B PUT fallback → $CODE (want 201/204)"
sleep 0.3
M_AFTER=$(scrape_metrics)
FALLBACK_AFTER=$(metric_sum "brix_cred_select_fallback_total" "$M_AFTER")
[ "${FALLBACK_AFTER:-0}" -gt "${FALLBACK_BEFORE:-0}" ] \
    && ok "2b: cred_select_fallback_total incremented ($FALLBACK_BEFORE → $FALLBACK_AFTER)" \
    || bad "2b: cred_select_fallback_total did not increment ($FALLBACK_BEFORE → $FALLBACK_AFTER)"
front_stop

# ===========================================================================
# ASSERTION 3 — User B, no cred, fallback=deny → cred_select_deny_total++
# ===========================================================================
echo "--- assertion 3: user B (no cred), deny → cred_select_deny_total increments ---"
front_start deny
wait_ready

M_BEFORE=$(scrape_metrics)
DENY_BEFORE=$(metric_sum "brix_cred_select_deny_total" "$M_BEFORE")
CODE=$($CURL_B -o /dev/null -w '%{http_code}' \
       -T /tmp/ucredm_payload.bin "$URLF/cm3.bin" 2>/dev/null)
[ "$CODE" = "403" ] \
    && ok "3a: B PUT denied (403)" \
    || bad "3a: B PUT → $CODE (want 403)"
sleep 0.3
M_AFTER=$(scrape_metrics)
DENY_AFTER=$(metric_sum "brix_cred_select_deny_total" "$M_AFTER")
[ "${DENY_AFTER:-0}" -gt "${DENY_BEFORE:-0}" ] \
    && ok "3b: cred_select_deny_total incremented ($DENY_BEFORE → $DENY_AFTER)" \
    || bad "3b: cred_select_deny_total did not increment ($DENY_BEFORE → $DENY_AFTER)"

# Show sample /metrics lines for the report.
echo ""
echo "--- sample /metrics output ---"
printf '%s' "$M_AFTER" | grep '^brix_cred_select_' || echo "  (no cred_select_ lines)"
front_stop

# ===========================================================================
echo ""
[ "$FAILED" = 0 ] \
    && echo "run_cred_metrics: ALL PASS" \
    || echo "run_cred_metrics: FAILURES"
exit "$FAILED"
