#!/usr/bin/env bash
# run_delegation_twostep.sh — Phase-3 Task 4, standard GridSite two-step
# getProxyReq/putProxy REST flow, alongside the T8 proxy-upload form
# (run_delegation_upload.sh, unaffected by this file).
#
# Topology: same shape as run_delegation_upload.sh — a GSI-auth root://
# origin O (port OPORT) + a davs:// frontend F (port FPORT) with
# brix_delegation_endpoint on (or off, per-assertion), an empty credential
# dir, and a remote backend (brix_storage_backend root://O).
#
#   (a) GSI-auth'd user A: GET /.well-known/brix-delegation/request -> 200,
#       X-Brix-Delegation-Id header + a CSR PEM body.
#   (b) A signs that CSR with its OWN EEC key (openssl x509 -req -CA/-CAkey,
#       chosen over a from-scratch ASN.1 tool since A already HAS a normal
#       EEC cert+key from mint_delegation_certs.py and the CSR's subject/
#       extensions are exactly what a plain `openssl x509 -req` signing
#       step reproduces faithfully for this RFC-3820 shape), PUTs the
#       signed proxy (+ its own EEC chain appended) to
#       /.well-known/brix-delegation/<id> -> 200/201, and
#       <cred_dir>/<A's key>.pem now exists.
#   (c) NEGATIVE: user B (different identity, own valid TLS session) PUTs
#       to A's id -> 403, and A's cred file is NOT created by B's attempt
#       (proven by deleting it first and confirming it stays absent).
#   (d) NEGATIVE: PUT to an unknown/garbage id -> 404.
#   (e) NEGATIVE: PUT with a garbage (non-PEM, unsigned) body to a FRESH,
#       valid id -> 400.
#   (f) NEGATIVE (C unit test only — see tests/c/run_delegation_store.sh):
#       an expired id -> 410. Proven with a synthetic expires_at there
#       rather than waiting out a real 600s TTL in this shell script.
#   (g) endpoint off -> both new routes are not special: GET .../request
#       falls through to ordinary WebDAV GET (404/403), and PUT .../<id>
#       is not accepted as a delegation (no credential file written).
#
# Certs: reuses tests/mint_delegation_certs.py's A/B EEC certs+keys (the
# SAME test-cert minting T8 already uses) — the two-step flow only needs a
# client's own EEC cert+key (to authenticate the GET/PUT and sign the CSR),
# not a pre-built proxy chain, so a_proxy_valid.pem/b_proxy_valid.pem are
# unused here.
#
# SAFETY: own ports only (OPORT=21430, FPORT=21431, both pre-flight-
# checked and free as of authoring — override via env if busy). Teardown
# kills ONLY PIDs from our own pidfiles + orphan-scan scoped to our own
# workdir (front_kill_orphans, mirrored verbatim from run_delegation_upload.sh).
# Reads (never writes) the shared /tmp/xrd-test PKI.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
NGINX=${NGINX:-/tmp/nginx-1.28.3/objs/nginx}
TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"

PFX=/tmp/deleg2-e2e
rm -rf "$PFX"
mkdir -p "$PFX/o/logs" "$PFX/o/root" \
         "$PFX/f/logs" "$PFX/f/export" "$PFX/f/stage" "$PFX/f/journal" \
         "$PFX/creds" "$PFX/certs"
chmod 777 "$PFX/creds"

OPORT=${OPORT:-21430}
FPORT=${FPORT:-21431}
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
    rm -rf "$PFX" /tmp/deleg2_csr_a.pem /tmp/deleg2_signed_a.pem /tmp/deleg2_body_a.pem 2>/dev/null
}
trap cleanup EXIT

# ---- PKI: read the shared test CA; mint per-test EEC certs off it ----------
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

echo "Minting delegation test certs (x509forge, shared with run_delegation_upload.sh)..."
MINT_OUT=$( cd "$HERE/tests" && PYTHONPATH=. python3 mint_delegation_certs.py \
    "$CA_CERT" "$CA_KEY" "$PFX/certs" 2>"$PFX/o/logs/mint.log" )
if [ -z "$MINT_OUT" ] || [ ! -f "$PFX/certs/a_eec_cert.pem" ]; then
    echo "SKIP: cert minting failed"; cat "$PFX/o/logs/mint.log"; exit 0
fi
A_DN=$(printf '%s\n' "$MINT_OUT" | sed -n 's/^A_DN=//p')
B_DN=$(printf '%s\n' "$MINT_OUT" | sed -n 's/^B_DN=//p')
[ -n "$A_DN" ] && [ -n "$B_DN" ] || { echo "SKIP: could not parse minted DNs"; exit 0; }

A_TLS_CERT="$PFX/certs/a_eec_cert.pem"
A_TLS_KEY="$PFX/certs/a_eec_key.pem"
B_TLS_CERT="$PFX/certs/b_eec_cert.pem"
B_TLS_KEY="$PFX/certs/b_eec_key.pem"

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
REQ_URL="$URL/.well-known/brix-delegation/request"
CURL_A="curl -sk --cert $A_TLS_CERT --key $A_TLS_KEY"
CURL_B="curl -sk --cert $B_TLS_CERT --key $B_TLS_KEY"

# ===========================================================================
# ASSERTION (a) — A GETs a CSR + delegation-id.
# ===========================================================================
echo "--- assertion (a): A GETs getProxyReq -> CSR + id ---"
front_start on
wait_ready
HDRS=/tmp/deleg2_hdrs_a.txt
CODE=$($CURL_A -D "$HDRS" -o /tmp/deleg2_csr_a.pem -w '%{http_code}' \
       "$REQ_URL" 2>/dev/null)
[ "$CODE" = "200" ] \
    && ok "a1: getProxyReq accepted (code=$CODE)" \
    || bad "a1: getProxyReq -> $CODE (want 200): $(cat /tmp/deleg2_csr_a.pem 2>/dev/null)"
DELEG_ID=$(grep -i '^X-Brix-Delegation-Id:' "$HDRS" | tr -d '\r' | sed 's/^[^:]*: *//')
[ -n "$DELEG_ID" ] \
    && ok "a2: X-Brix-Delegation-Id header present ($DELEG_ID)" \
    || bad "a2: X-Brix-Delegation-Id header missing"
grep -q 'BEGIN CERTIFICATE REQUEST' /tmp/deleg2_csr_a.pem \
    && ok "a3: response body is a PEM CSR" \
    || bad "a3: response body is not a PEM CSR: $(head -c 200 /tmp/deleg2_csr_a.pem)"

# ===========================================================================
# ASSERTION (b) — A signs the CSR with its own EEC key, PUTs it back.
# ===========================================================================
echo "--- assertion (b): A signs + PUTs the proxy -> stored ---"
rm -f "$PFX/creds/$A_KEY.pem"
if [ -n "$DELEG_ID" ] && [ -s /tmp/deleg2_csr_a.pem ]; then
    # Sign the CSR with A's own EEC cert+key as issuer — the openssl CLI's
    # `x509 -req -CA/-CAkey` path reproduces exactly the RFC-3820-shaped
    # signature brix_gsi_sign_pxyreq would also produce (subject preserved
    # from the request, issued off the signer's cert/key), and is far more
    # portable across CI environments than hand-rolling one via ctypes/
    # cryptography here.  `-copy_extensions copy` is REQUIRED: the CSR's
    # critical proxyCertInfo extension (what makes this an RFC-3820 proxy
    # rather than an ordinary leaf cert — the server's brix_px_classify()
    # relies on it to tell a proxy apart from an end-entity cert) is NOT
    # copied by default; without this flag the signed cert loses
    # proxyCertInfo, brix_px_classify misclassifies IT as the end-entity
    # cert (its subject carries the extra "/CN=<serial>" the request added),
    # and the server-side DN check then fails even for A's own valid
    # delegation (caught by testing: assertion b initially failed with
    # "assembled proxy identity does not match authenticated client").
    openssl x509 -req -in /tmp/deleg2_csr_a.pem \
        -CA "$A_TLS_CERT" -CAkey "$A_TLS_KEY" -CAcreateserial \
        -days 1 -copy_extensions copy -out /tmp/deleg2_signed_a.pem 2>/tmp/deleg2_sign.log
    if [ -s /tmp/deleg2_signed_a.pem ]; then
        ok "b1: A signed its own CSR"
        # Body = signed proxy + A's EEC chain (the split
        # delegation_split_first_pem_block on the server expects).
        cat /tmp/deleg2_signed_a.pem "$A_TLS_CERT" > /tmp/deleg2_body_a.pem
        CODE=$($CURL_A -o /tmp/deleg2_resp_b.txt -w '%{http_code}' \
               -T /tmp/deleg2_body_a.pem "$URL/.well-known/brix-delegation/$DELEG_ID" \
               2>/dev/null)
        { [ "$CODE" = "200" ] || [ "$CODE" = "201" ]; } \
            && ok "b2: putProxy accepted (code=$CODE)" \
            || bad "b2: putProxy -> $CODE (want 200/201): $(cat /tmp/deleg2_resp_b.txt)"
        [ -f "$PFX/creds/$A_KEY.pem" ] \
            && ok "b3: $A_KEY.pem now exists in credential dir" \
            || bad "b3: $PFX/creds/$A_KEY.pem NOT created"
    else
        bad "b1: A failed to sign its own CSR: $(cat /tmp/deleg2_sign.log)"
        bad "b2: skipped (no signed proxy to PUT)"
        bad "b3: skipped (no signed proxy to PUT)"
    fi
else
    bad "b1: skipped (no delegation-id/CSR from assertion a)"
    bad "b2: skipped (no delegation-id/CSR from assertion a)"
    bad "b3: skipped (no delegation-id/CSR from assertion a)"
fi
front_stop

# ===========================================================================
# ASSERTION (c) — B (different identity) PUTs to A's id -> 403, A's file
# untouched (proven by deleting it first, confirming it's regenerated only
# via A's own successful putProxy, never via B's attempt).
# ===========================================================================
echo "--- assertion (c): B PUTs to A's (fresh) id -> 403, no impersonation ---"
front_start on
wait_ready
CODE=$($CURL_A -D /tmp/deleg2_hdrs_c.txt -o /tmp/deleg2_csr_c.pem -w '%{http_code}' \
       "$REQ_URL" 2>/dev/null)
DELEG_ID_C=$(grep -i '^X-Brix-Delegation-Id:' /tmp/deleg2_hdrs_c.txt | tr -d '\r' | sed 's/^[^:]*: *//')
if [ "$CODE" = "200" ] && [ -n "$DELEG_ID_C" ]; then
    rm -f "$PFX/creds/$A_KEY.pem"
    # B does not need a validly-signed body for this assertion — the DN
    # check happens before assembly, so any authenticated-as-B PUT to A's
    # id must be rejected regardless of body validity.
    CODE=$($CURL_B -o /tmp/deleg2_resp_c.txt -w '%{http_code}' \
           -T "$A_TLS_CERT" "$URL/.well-known/brix-delegation/$DELEG_ID_C" \
           2>/dev/null)
    [ "$CODE" = "403" ] \
        && ok "c1: B's putProxy to A's id rejected (403)" \
        || bad "c1: B's putProxy to A's id -> $CODE (want 403): $(cat /tmp/deleg2_resp_c.txt)"
    [ ! -f "$PFX/creds/$A_KEY.pem" ] \
        && ok "c2: A's credential file NOT created by B's attempt" \
        || bad "c2: $PFX/creds/$A_KEY.pem WAS created by B — cross-client leak!"
else
    bad "c1: skipped (could not obtain a fresh id for this assertion, code=$CODE)"
    bad "c2: skipped (could not obtain a fresh id for this assertion)"
fi
front_stop

# ===========================================================================
# ASSERTION (d) — PUT to an unknown/garbage id -> 404.
# ===========================================================================
echo "--- assertion (d): unknown delegation id -> 404 ---"
front_start on
wait_ready
CODE=$($CURL_A -o /tmp/deleg2_resp_d.txt -w '%{http_code}' \
       -T "$A_TLS_CERT" "$URL/.well-known/brix-delegation/0000000000000000000000000000dead" \
       2>/dev/null)
[ "$CODE" = "404" ] \
    && ok "d: unknown id rejected (404)" \
    || bad "d: unknown id -> $CODE (want 404): $(cat /tmp/deleg2_resp_d.txt)"
front_stop

# ===========================================================================
# ASSERTION (e) — garbage (non-PEM, unsigned) body to a FRESH valid id -> 400.
# ===========================================================================
echo "--- assertion (e): garbage body to a fresh valid id -> 400 ---"
front_start on
wait_ready
CODE=$($CURL_A -D /tmp/deleg2_hdrs_e.txt -o /tmp/deleg2_csr_e.pem -w '%{http_code}' \
       "$REQ_URL" 2>/dev/null)
DELEG_ID_E=$(grep -i '^X-Brix-Delegation-Id:' /tmp/deleg2_hdrs_e.txt | tr -d '\r' | sed 's/^[^:]*: *//')
if [ "$CODE" = "200" ] && [ -n "$DELEG_ID_E" ]; then
    echo "this is not a PEM certificate, just garbage bytes" > /tmp/deleg2_garbage.txt
    CODE=$($CURL_A -o /tmp/deleg2_resp_e.txt -w '%{http_code}' \
           -T /tmp/deleg2_garbage.txt "$URL/.well-known/brix-delegation/$DELEG_ID_E" \
           2>/dev/null)
    [ "$CODE" = "400" ] \
        && ok "e: garbage body rejected (400)" \
        || bad "e: garbage body -> $CODE (want 400): $(cat /tmp/deleg2_resp_e.txt)"
else
    bad "e: skipped (could not obtain a fresh id for this assertion, code=$CODE)"
fi
front_stop

# ===========================================================================
# ASSERTION (f) — untrusted EEC chain: A authenticates normally (trusted EEC),
# gets a fresh CSR+id, but signs the CSR with its WRONG-CA EEC (subject string
# == A's DN, issuer NOT in the trust store) and appends that untrusted EEC as
# the chain.  Proof-of-possession still succeeds (the CSR's server-generated
# key is preserved through signing), and the assembled proxy's EEC subject
# still string-matches ctx->dn — so ONLY the chain-of-trust verification against
# conf->ca_store can catch this.  Expect 403, A's cred file untouched, while
# the trusted-EEC path in assertion (b) still succeeds — proving the fix is
# live and specific to untrusted issuers, not a blanket tightening.
# ===========================================================================
echo "--- assertion (f): A signs CSR with a wrong-CA EEC (DN spoofed) -> 403 ---"
front_start on
wait_ready
CODE=$($CURL_A -D /tmp/deleg2_hdrs_f.txt -o /tmp/deleg2_csr_f.pem -w '%{http_code}' \
       "$REQ_URL" 2>/dev/null)
DELEG_ID_F=$(grep -i '^X-Brix-Delegation-Id:' /tmp/deleg2_hdrs_f.txt | tr -d '\r' | sed 's/^[^:]*: *//')
if [ "$CODE" = "200" ] && [ -n "$DELEG_ID_F" ] && [ -s /tmp/deleg2_csr_f.pem ]; then
    rm -f "$PFX/creds/$A_KEY.pem"
    # Sign the server CSR with the UNTRUSTED (rogue-CA) EEC that carries A's
    # exact subject string, and append that same rogue EEC as the chain.
    openssl x509 -req -in /tmp/deleg2_csr_f.pem \
        -CA "$PFX/certs/a_eec_wrongca_cert.pem" \
        -CAkey "$PFX/certs/a_eec_wrongca_key.pem" -CAcreateserial \
        -days 1 -copy_extensions copy -out /tmp/deleg2_signed_f.pem 2>/tmp/deleg2_sign_f.log
    if [ -s /tmp/deleg2_signed_f.pem ]; then
        cat /tmp/deleg2_signed_f.pem "$PFX/certs/a_eec_wrongca_cert.pem" \
            > /tmp/deleg2_body_f.pem
        CODE=$($CURL_A -o /tmp/deleg2_resp_f.txt -w '%{http_code}' \
               -T /tmp/deleg2_body_f.pem "$URL/.well-known/brix-delegation/$DELEG_ID_F" \
               2>/dev/null)
        [ "$CODE" = "403" ] \
            && ok "f1: untrusted-EEC signed proxy rejected (403)" \
            || bad "f1: untrusted-EEC signed proxy -> $CODE (want 403): $(cat /tmp/deleg2_resp_f.txt)"
        [ ! -f "$PFX/creds/$A_KEY.pem" ] \
            && ok "f2: no credential file written for the untrusted proxy" \
            || bad "f2: $PFX/creds/$A_KEY.pem WAS created from an untrusted EEC!"
    else
        bad "f1: could not sign CSR with rogue EEC: $(cat /tmp/deleg2_sign_f.log)"
        bad "f2: skipped (no signed proxy to PUT)"
    fi
else
    bad "f1: skipped (could not obtain a fresh id for this assertion, code=$CODE)"
    bad "f2: skipped (could not obtain a fresh id for this assertion)"
fi
front_stop

# ===========================================================================
# ASSERTION (g) — endpoint off -> both new routes are not special.
# ===========================================================================
echo "--- assertion (g): endpoint off -> not special, no store ---"
rm -f "$PFX/creds/$A_KEY.pem"
front_start off
wait_ready
CODE=$($CURL_A -o /tmp/deleg2_resp_g1.txt -w '%{http_code}' --max-time 2 \
       "$REQ_URL" 2>/dev/null)
# 404 (never-written ordinary WebDAV path) or 403 (per-user credential gate
# runs before existence is revealed — same fail-closed-before-disclosure
# behaviour proven in run_user_backend_cred.sh / run_delegation_upload.sh
# assertion e) both demonstrate the path is handled by ORDINARY WebDAV GET,
# not the delegation endpoint.
{ [ "$CODE" = "404" ] || [ "$CODE" = "403" ]; } \
    && ok "g1: GET .../request -> $CODE (endpoint off, not special)" \
    || bad "g1: GET .../request -> $CODE (want 404 or 403)"
CODE=$($CURL_A -o /tmp/deleg2_resp_g2.txt -w '%{http_code}' \
       -T "$A_TLS_CERT" "$URL/.well-known/brix-delegation/somefakeid0000000000000000000000" \
       2>/dev/null)
[ "$CODE" != "200" ] && [ "$CODE" != "201" ] \
    && ok "g2: PUT .../<id> not accepted as a delegation (code=$CODE)" \
    || bad "g2: PUT .../<id> -> $CODE (delegation-endpoint semantics leaked while off!)"
[ ! -f "$PFX/creds/$A_KEY.pem" ] \
    && ok "g3: no credential file written while endpoint is off" \
    || bad "g3: $PFX/creds/$A_KEY.pem WAS created while endpoint off!"
front_stop

# ===========================================================================
echo ""
echo "NOTE: the expired-id -> 410 case is proven in"
echo "      tests/c/run_delegation_store.sh (synthetic expires_at) rather"
echo "      than waiting out a real 600s TTL in this shell script."
echo ""
[ "$FAILED" = 0 ] \
    && echo "run_delegation_twostep: ALL PASS" \
    || echo "run_delegation_twostep: FAILURES"
exit "$FAILED"
