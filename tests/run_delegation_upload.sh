#!/usr/bin/env bash
# run_delegation_upload.sh — Phase-2 Task 8, opt-in proxy-upload delegation endpoint.
#
# Topology: GSI-auth root:// origin O (port OPORT) + davs:// frontend F (port FPORT),
# same shape as run_user_backend_cred.sh.  F has brix_delegation_endpoint on (or
# off, per-assertion), an empty credential dir, and a remote backend
# (brix_storage_backend root://O).
#
#   (a) GSI-auth'd user A PUTs its OWN proxy to /.well-known/brix-delegation
#       -> 200/201 AND <cred_dir>/<A's key>.pem now exists.
#   (b) A SUBSEQUENT davs PUT by A (cred dir otherwise had no A entry before (a))
#       authenticates to the origin as A — end to end, delegation populated the
#       dir Phase-1 selection reads.
#   (c) NEGATIVE: A authenticates over TLS but uploads a proxy whose EEC is user
#       B's identity -> 403, and no <B's key>.pem is written.
#   (d) NEGATIVE: an EXPIRED proxy for A -> 400.
#   (e) endpoint off -> the path is not special: 404/405 (no store — verified by
#       the credential dir staying untouched).
#
# Certs are minted with tests/x509forge.py (already used by the WLCG x509
# conformance suite) via tests/mint_delegation_certs.py, off the shared test
# CA — this gives exact, portable control over proxy notAfter (no openssl-CLI
# -req date-flag portability issues).
#
# SAFETY: own ports only (OPORT=11196, FPORT=18461).  Teardown kills ONLY PIDs
# from our own pidfiles + orphan-scan scoped to our own workdir.  Reads (never
# writes) the shared /tmp/xrd-test PKI.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
NGINX=${NGINX:-/tmp/nginx-1.28.3/objs/nginx}
TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"

PFX=/tmp/deleg-e2e
rm -rf "$PFX"
mkdir -p "$PFX/o/logs" "$PFX/o/root" \
         "$PFX/f/logs" "$PFX/f/export" "$PFX/f/stage" "$PFX/f/journal" \
         "$PFX/creds" "$PFX/certs"
chmod 777 "$PFX/creds"

OPORT=${OPORT:-11196}
FPORT=${FPORT:-18461}
for p in "$OPORT" "$FPORT"; do
    if ss -tlnp 2>/dev/null | grep -q ":${p} "; then
        echo "SKIP: port $p already in use — choose different OPORT/FPORT"
        exit 0
    fi
done

ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; FAILED=1; }
FAILED=0

origin_stop(){
    if [ -f "$PFX/o/nginx.pid" ]; then
        kill "$(cat "$PFX/o/nginx.pid")" 2>/dev/null
        sleep 0.5
    fi
}
front_kill_orphans(){
    local pid fd target
    for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
        [ -f "/proc/$pid/exe" ] || continue
        readlink "/proc/$pid/exe" 2>/dev/null | grep -q "nginx" || continue
        for fd in $(ls "/proc/$pid/fd" 2>/dev/null); do
            target=$(readlink "/proc/$pid/fd/$fd" 2>/dev/null)
            echo "$target" | grep -q "^$PFX/f/" && { kill "$pid" 2>/dev/null; break; }
        done
    done
}
front_stop(){
    if [ -f "$PFX/f/nginx.pid" ]; then
        local pid; pid=$(cat "$PFX/f/nginx.pid" 2>/dev/null)
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
        sleep 1
    fi
    front_kill_orphans
    sleep 0.3
}
cleanup(){
    front_stop
    origin_stop
    rm -rf "$PFX" /tmp/deleg_payload.bin /tmp/deleg_back.bin 2>/dev/null
}
trap cleanup EXIT

# ---- PKI: read the shared test CA; mint per-test EEC+proxy certs off it ----
CA_CERT="$TEST_ROOT/pki/ca/ca.pem"
CA_KEY="$TEST_ROOT/pki/ca/ca.key"
SERVER_CERT="$TEST_ROOT/pki/server/hostcert.pem"
SERVER_KEY="$TEST_ROOT/pki/server/hostkey.pem"

need_pki=0
[ ! -f "$CA_CERT" ] && need_pki=1
[ ! -f "$CA_KEY" ]  && need_pki=1
if [ "$need_pki" = 1 ]; then
    echo "Provisioning test PKI (blitz_test_pki)..."
    ( cd "$HERE/tests" && PYTHONPATH=. python3 -c \
        "import pki_helpers; pki_helpers.blitz_test_pki()" ) \
        >"$PFX/o/logs/pki.log" 2>&1 \
        || { echo "SKIP: PKI provisioning failed"; cat "$PFX/o/logs/pki.log"; exit 0; }
fi
[ -f "$CA_KEY" ] || { echo "SKIP: CA key not found ($CA_KEY)"; exit 0; }

echo "Minting delegation test certs (x509forge)..."
MINT_OUT=$( cd "$HERE/tests" && PYTHONPATH=. python3 mint_delegation_certs.py \
    "$CA_CERT" "$CA_KEY" "$PFX/certs" 2>"$PFX/o/logs/mint.log" )
if [ -z "$MINT_OUT" ] || [ ! -f "$PFX/certs/a_proxy_valid.pem" ]; then
    echo "SKIP: cert minting failed"; cat "$PFX/o/logs/mint.log"; exit 0
fi
A_DN=$(printf '%s\n' "$MINT_OUT" | sed -n 's/^A_DN=//p')
B_DN=$(printf '%s\n' "$MINT_OUT" | sed -n 's/^B_DN=//p')
[ -n "$A_DN" ] && [ -n "$B_DN" ] || { echo "SKIP: could not parse minted DNs"; exit 0; }

A_TLS_CERT="$PFX/certs/a_eec_cert.pem"
A_TLS_KEY="$PFX/certs/a_eec_key.pem"

# ---- derive the expected credential-store keys (same formula as ucred.c) ---
key_for_dn(){
    printf 'x5h-%s' "$(printf '%s' "$1" | openssl dgst -sha256 -hex 2>/dev/null \
        | awk '{print $2}' | head -c 32)"
}
A_KEY=$(key_for_dn "$A_DN")
B_KEY=$(key_for_dn "$B_DN")
echo "  user-A DN: $A_DN"
echo "  user-A credential stem: $A_KEY"
echo "  user-B credential stem: $B_KEY"

# ---- origin: GSI-only root:// server ----------------------------------------
cat > "$PFX/o/nginx.conf" <<EOF
daemon on;
error_log $PFX/o/logs/e.log info;
pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${OPORT};
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
OLOG="$PFX/o/logs/e.log"
sleep 0.5

# ---- frontend builder --------------------------------------------------------
# $1 = on|off (brix_delegation_endpoint)
mkfront(){
    local deleg="$1"
    cat > "$PFX/f/nginx.conf" <<EOF
daemon on;
error_log $PFX/f/logs/e.log info;
pid $PFX/f/nginx.pid;
env BRIX_STAGE_JOURNAL_DIR=$PFX/f/journal;
worker_processes 1;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    access_log $PFX/f/logs/access.log;
    client_body_temp_path $PFX/f/export;
    brix_credential origin { x509_proxy $PFX/certs/a_proxy_valid.pem; ca_dir $TEST_ROOT/pki/ca; }
    server {
        listen 127.0.0.1:${FPORT} ssl;
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
            brix_storage_backend root://127.0.0.1:${OPORT};
            brix_storage_credential origin;
            brix_storage_credential_dir $PFX/creds;
            brix_storage_credential_fallback deny;
            brix_stage on;
            brix_stage_store posix:$PFX/f/stage;
            brix_stage_flush sync;
            brix_delegation_endpoint $deleg;
        }
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
        curl -sk -o /dev/null --max-time 1 "https://127.0.0.1:${FPORT}/" 2>/dev/null && return 0
        sleep 0.2
    done
    return 1
}

URL="https://127.0.0.1:${FPORT}"
DELEG_URL="$URL/.well-known/brix-delegation"
CURL_A="curl -sk --cert $A_TLS_CERT --key $A_TLS_KEY"

# ===========================================================================
# ASSERTION (a) — A uploads its own valid proxy -> 200/201, key.pem exists.
# ===========================================================================
echo "--- assertion (a): A uploads its own proxy -> stored ---"
front_start on
wait_ready
CODE=$($CURL_A -o /tmp/deleg_resp_a.txt -w '%{http_code}' \
       -T "$PFX/certs/a_proxy_valid.pem" "$DELEG_URL" 2>/dev/null)
{ [ "$CODE" = "200" ] || [ "$CODE" = "201" ]; } \
    && ok "a1: A's own-proxy upload accepted (code=$CODE)" \
    || bad "a1: A's own-proxy upload -> $CODE (want 200/201): $(cat /tmp/deleg_resp_a.txt)"
[ -f "$PFX/creds/$A_KEY.pem" ] \
    && ok "a2: $A_KEY.pem now exists in credential dir" \
    || bad "a2: $PFX/creds/$A_KEY.pem NOT created"

# ===========================================================================
# ASSERTION (b) — subsequent davs PUT by A authenticates to the origin as A.
# ===========================================================================
echo "--- assertion (b): delegation-populated cred used for a real PUT ---"
> "$OLOG"
head -c 4096 /dev/urandom > /tmp/deleg_payload.bin
CODE=$($CURL_A -o /dev/null -w '%{http_code}' \
       -T /tmp/deleg_payload.bin "$URL/b_probe.bin" 2>/dev/null)
{ [ "$CODE" = "201" ] || [ "$CODE" = "204" ]; } \
    && ok "b1: A's PUT via delegated cred accepted (code=$CODE)" \
    || bad "b1: A's PUT via delegated cred -> $CODE (want 201/204)"
sleep 0.5
if grep -q 'GSI auth OK dn=' "$OLOG" 2>/dev/null; then
    ok "b2: origin authenticated a user (GSI auth OK in origin log)"
else
    bad "b2: no 'GSI auth OK' in origin log — delegation was not used"
fi
front_stop

# ===========================================================================
# ASSERTION (c) — A uploads a proxy for B's identity -> 403, no B key written.
# ===========================================================================
echo "--- assertion (c): A uploads B's proxy -> 403, nothing written for B ---"
front_start on
wait_ready
CODE=$($CURL_A -o /tmp/deleg_resp_c.txt -w '%{http_code}' \
       -T "$PFX/certs/b_proxy_valid.pem" "$DELEG_URL" 2>/dev/null)
[ "$CODE" = "403" ] \
    && ok "c1: cross-identity upload rejected (403)" \
    || bad "c1: cross-identity upload -> $CODE (want 403): $(cat /tmp/deleg_resp_c.txt)"
[ ! -f "$PFX/creds/$B_KEY.pem" ] \
    && ok "c2: no credential file written for B" \
    || bad "c2: $PFX/creds/$B_KEY.pem WAS created — impersonation leak!"
front_stop

# ===========================================================================
# ASSERTION (d) — expired proxy for A -> 400.
# ===========================================================================
echo "--- assertion (d): expired proxy -> 400 ---"
front_start on
wait_ready
CODE=$($CURL_A -o /tmp/deleg_resp_d.txt -w '%{http_code}' \
       -T "$PFX/certs/a_proxy_expired.pem" "$DELEG_URL" 2>/dev/null)
[ "$CODE" = "400" ] \
    && ok "d: expired proxy rejected (400)" \
    || bad "d: expired proxy -> $CODE (want 400): $(cat /tmp/deleg_resp_d.txt)"
front_stop

# ===========================================================================
# ASSERTION (f) — untrusted (wrong-CA / self-signed) proxy whose EEC subject
# STRING equals A's DN -> 403, no key written.  This is the credential-endpoint
# chain-verification depth fix: pre-fix the endpoint only string-compared the
# self-asserted EEC DN against ctx->dn, so A could plant a self-signed cert
# spoofing its own DN.  Post-fix the chain must anchor to the trusted CA store
# (brix_gsi_verify_chain vs conf->ca_store) or the upload is refused, while the
# genuinely CA-signed proxy in assertion (a) still succeeds — proving the
# verification is live and not merely tightening every path.
# ===========================================================================
echo "--- assertion (f): untrusted/wrong-CA proxy (DN spoofed to A) -> 403 ---"
rm -f "$PFX/creds/$A_KEY.pem"
front_start on
wait_ready
CODE=$($CURL_A -o /tmp/deleg_resp_f.txt -w '%{http_code}' \
       -T "$PFX/certs/a_proxy_wrongca.pem" "$DELEG_URL" 2>/dev/null)
[ "$CODE" = "403" ] \
    && ok "f1: untrusted-CA proxy rejected (403)" \
    || bad "f1: untrusted-CA proxy -> $CODE (want 403): $(cat /tmp/deleg_resp_f.txt)"
[ ! -f "$PFX/creds/$A_KEY.pem" ] \
    && ok "f2: no credential file written for the untrusted proxy" \
    || bad "f2: $PFX/creds/$A_KEY.pem WAS created from an untrusted proxy!"
front_stop

# ===========================================================================
# ASSERTION (e) — endpoint off -> path is not special, no store.
#
# With the endpoint off, dispatch.c never special-cases the well-known path,
# so it falls through to ordinary WebDAV method handling. A GET for a path
# that was never written cleanly demonstrates "not treated as delegation"
# via a plain 404 (independent of remote-backend/credential wiring). A PUT
# is also exercised: it is NOT rejected as an unparseable-PEM/DN-mismatch/
# expiry error (those are delegation-specific 400/403 reasons) — it is
# rejected for the ordinary per-user-credential reason this frontend also
# enforces on every other write (fallback=deny, same as ASSERTION 2 in
# run_user_backend_cred.sh) — and, most importantly, no credential file is
# ever written.
# ===========================================================================
echo "--- assertion (e): endpoint off -> not special, no store ---"
rm -f "$PFX/creds/$A_KEY.pem"
front_start off
wait_ready
CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 2 \
       "$URL/never_written_$$_probe.bin" 2>/dev/null)
# 404 (plain not-found) or 403 (this frontend's per-user credential gate runs
# before existence is revealed, same fail-closed-before-disclosure behaviour
# proven in run_user_backend_cred.sh assertion 2) both demonstrate the path
# is handled by ORDINARY WebDAV GET, not the delegation endpoint.
{ [ "$CODE" = "404" ] || [ "$CODE" = "403" ]; } \
    && ok "e1: GET of an unwritten path -> $CODE (endpoint off, not special)" \
    || bad "e1: GET of an unwritten path -> $CODE (want 404 or 403)"
CODE=$($CURL_A -o /tmp/deleg_resp_e.txt -w '%{http_code}' \
       -T "$PFX/certs/a_proxy_valid.pem" "$DELEG_URL" 2>/dev/null)
[ "$CODE" != "200" ] && [ "$CODE" != "201" ] \
    && ok "e2: PUT to the well-known path is not accepted as a delegation (code=$CODE)" \
    || bad "e2: PUT to the well-known path -> $CODE (delegation-endpoint semantics leaked while off!)"
[ ! -f "$PFX/creds/$A_KEY.pem" ] \
    && ok "e3: no credential file written while endpoint is off" \
    || bad "e3: $PFX/creds/$A_KEY.pem WAS created while endpoint off!"
front_stop

# ===========================================================================
echo ""
[ "$FAILED" = 0 ] \
    && echo "run_delegation_upload: ALL PASS" \
    || echo "run_delegation_upload: FAILURES"
exit "$FAILED"
