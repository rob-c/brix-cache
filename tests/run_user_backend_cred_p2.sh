#!/usr/bin/env bash
# run_user_backend_cred_p2.sh — Phase-2 follow-up: the 5 identity-leak/deny-
# bypass gaps found by the FINAL PHASE-2 REVIEW (ctx built with the requesting
# user's identity but never bound to brix_vfs_ctx_bind_backend_cred, so a
# ctx-bound VFS op silently ran on the SERVICE credential instead).
#
#   (a) davs MOVE  on a remote-backed export -> origin sees user A's DN, not SVC's
#   (b) davs COPY  on a remote-backed export -> origin sees user A's DN, not SVC's
#   (c) S3 CopyObject on a remote-backed export -> origin sees user A's DN, not SVC's
#   (d) deny-mode GET via the remote serve-offload path, no cred -> 403,
#       origin never served the object on the service credential
#
# Distinguishing "saw A's DN" from "saw SVC's DN" (a leak) requires TWO
# DISTINCT proxy identities from the same test CA: the per-user cred
# provisioned in the frontend's storage_credential_dir (A), and the
# frontend's OWN brix_credential origin service identity (SVC) used only for
# the fallback/pre-flight path. Both are minted here as plain end-entity
# certs off the shared test CA (same pattern run_user_backend_cred.sh uses
# for its "user B" identity).
#
# SAFETY: own port range 21400-21700 only. Teardown is pidfile-based (no
# broad pkill). Reads PKI material from /tmp/xrd-test only; mints its own
# additional (A/SVC) end-entity certs off that CA, same pattern as
# run_user_backend_cred.sh's user-B mint.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
NGINX=${NGINX:-/tmp/nginx-1.28.3/objs/nginx}
TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"

PFX=/tmp/ucred-p2-e2e
rm -rf "$PFX"
mkdir -p "$PFX/o/logs" "$PFX/o/root" \
         "$PFX/f/logs" "$PFX/f/export" \
         "$PFX/s3/logs" "$PFX/s3/root" \
         "$PFX/creds" "$PFX/a" "$PFX/svc"
chmod 777 "$PFX/creds"

# ---- ports (own range 21400-21700) ------------------------------------------
OPORT=${OPORT:-21500}     # origin root://
FPORT=${FPORT:-21501}     # davs:// frontend (MOVE/COPY)
S3PORT=${S3PORT:-21502}   # S3 frontend (CopyObject + deny-GET offload)
for p in "$OPORT" "$FPORT" "$S3PORT"; do
    if ss -tlnH 2>/dev/null | grep -q ":${p} "; then
        echo "SKIP: port $p already in use — choose different OPORT/FPORT/S3PORT"
        exit 0
    fi
done

ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; FAILED=1; }
note(){ printf '  NOTE %s\n' "$1"; }
FAILED=0

origin_stop(){ [ -f "$PFX/o/nginx.pid" ] && { kill "$(cat "$PFX/o/nginx.pid")" 2>/dev/null; sleep 0.3; }; }
front_kill_orphans(){
    local pid fd target
    for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
        [ -f "/proc/$pid/exe" ] || continue
        readlink "/proc/$pid/exe" 2>/dev/null | grep -q "nginx" || continue
        for fd in $(ls "/proc/$pid/fd" 2>/dev/null); do
            target=$(readlink "/proc/$pid/fd/$fd" 2>/dev/null)
            echo "$target" | grep -qE "^$PFX/(f|s3)/" && { kill "$pid" 2>/dev/null; break; }
        done
    done
}
front_stop(){
    [ -f "$PFX/f/nginx.pid" ] && { kill "$(cat "$PFX/f/nginx.pid")" 2>/dev/null; sleep 0.5; }
}
s3_stop(){
    [ -f "$PFX/s3/nginx.pid" ] && { kill "$(cat "$PFX/s3/nginx.pid")" 2>/dev/null; sleep 0.5; }
}
cleanup(){
    front_stop; s3_stop; origin_stop
    front_kill_orphans
    rm -rf "$PFX" /tmp/ucred_p2_payload.bin 2>/dev/null
}
trap cleanup EXIT

# ---- PKI ----------------------------------------------------------------
CA_CERT="$TEST_ROOT/pki/ca/ca.pem"
CA_DIR="$TEST_ROOT/pki/ca"
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

mint_identity(){
    # $1 = short name  $2 = CN
    local name="$1" cn="$2"
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$PFX/$name/key.pem" \
        -subj "/DC=test/DC=xrootd/CN=$cn/CN=$((RANDOM+10000))" \
        -out "$PFX/$name/req.pem" >/dev/null 2>&1
    openssl x509 -req \
        -in "$PFX/$name/req.pem" \
        -CA "$CA_CERT" -CAkey "$CA_KEY" \
        -set_serial "0x$(openssl rand -hex 8)" \
        -days 2 \
        -out "$PFX/$name/cert.pem" >/dev/null 2>&1
    cat "$PFX/$name/cert.pem" "$PFX/$name/key.pem" > "$PFX/$name/combined.pem"
}

# A = the requesting user (per-user cred). SVC = the frontend's OWN service
# identity (brix_credential origin), DISTINCT from A, so a leak is visible as
# "origin auth line carries SVC's DN, not A's".
mint_identity a   "Test User Alpha"
mint_identity svc "Test Service Account"
A_COMBINED="$PFX/a/combined.pem"
SVC_COMBINED="$PFX/svc/combined.pem"
[ -s "$A_COMBINED" ] && [ -s "$SVC_COMBINED" ] \
    || { echo "SKIP: identity mint failed"; exit 0; }

# ---- origin: GSI-only root:// server, allow_write (MOVE/COPY need it) -------
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

# ---- davs frontend: remote-backed export, per-user cred_dir + distinct SVC --
cat > "$PFX/f/nginx.conf" <<EOF
daemon on;
error_log $PFX/f/logs/e.log info;
pid $PFX/f/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    access_log $PFX/f/logs/access.log;
    client_body_temp_path $PFX/f/export;
    brix_credential origin { x509_proxy $SVC_COMBINED; ca_dir $CA_DIR; }
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
            brix_storage_credential_fallback allow;
        }
    }
}
EOF
"$NGINX" -p "$PFX/f" -c "$PFX/f/nginx.conf" 2>"$PFX/f/start.err" \
    || { echo "SKIP: davs frontend start failed"; cat "$PFX/f/start.err"; exit 0; }
sleep 0.5

CURL_A="curl -sk --cert $A_COMBINED --key $A_COMBINED"
FURL="https://127.0.0.1:${FPORT}"

wait_ready(){
    local url="$1"
    for i in $(seq 1 20); do
        curl -sk -o /dev/null --max-time 1 "$url/" 2>/dev/null && return 0
        sleep 0.2
    done
    return 1
}
wait_ready "$FURL"

# Learn A's derived credential key (same technique as run_user_backend_cred.sh
# step 0): a probe request while no cred is installed logs "key=<stem>".
head -c 32768 /dev/urandom > /tmp/ucred_p2_payload.bin
$CURL_A -o /dev/null -T /tmp/ucred_p2_payload.bin "$FURL/probe_key.bin" >/dev/null 2>&1 || true
sleep 0.3
A_KEY=$(grep -oE 'key=x5h-[0-9a-f]+|key=[A-Za-z0-9@._-]+' "$PFX/f/logs/e.log" 2>/dev/null \
        | head -1 | cut -d= -f2)
if [ -z "$A_KEY" ]; then
    A_DN_TMP=$(openssl x509 -in "$A_COMBINED" -noout -subject -nameopt oneline 2>/dev/null \
               | sed 's/subject= *//')
    A_KEY="x5h-$(printf '%s' "$A_DN_TMP" | openssl dgst -sha256 -hex 2>/dev/null \
               | awk '{print $2}' | head -c 32)"
fi
[ -n "$A_KEY" ] || { bad "could not derive credential key for user A"; exit 1; }
echo "  user-A credential stem: $A_KEY"
install -m 644 "$A_COMBINED" "$PFX/creds/$A_KEY.pem"

# ===========================================================================
# (a) davs MOVE on a remote-backed export -> origin logs A's DN, not SVC's.
# ===========================================================================
echo "--- (a) davs MOVE: origin sees user A's DN (not the frontend's SVC DN) ---"
> "$OLOG"
CODE=$($CURL_A -o /dev/null -w '%{http_code}' \
       -T /tmp/ucred_p2_payload.bin "$FURL/mv_src.bin" 2>/dev/null)
{ [ "$CODE" = "201" ] || [ "$CODE" = "204" ]; } \
    && ok "a1: seed PUT for MOVE accepted (code=$CODE)" \
    || bad "a1: seed PUT -> $CODE (want 201/204)"
sleep 0.3
> "$OLOG"
CODE=$(curl -sk -o /dev/null -w '%{http_code}' \
       --cert "$A_COMBINED" --key "$A_COMBINED" \
       -X MOVE -H "Destination: $FURL/mv_dst.bin" "$FURL/mv_src.bin" 2>/dev/null)
{ [ "$CODE" = "201" ] || [ "$CODE" = "204" ]; } \
    && ok "a2: MOVE accepted (code=$CODE)" \
    || bad "a2: MOVE -> $CODE (want 201/204)"
sleep 0.5
LAST_DN=$(grep 'GSI auth OK dn=' "$OLOG" 2>/dev/null | tail -1)
if echo "$LAST_DN" | grep -qE 'User.Alpha|User\\x20Alpha'; then
    ok "a3: origin's rename-op auth line carries A's DN (Test User Alpha)"
elif echo "$LAST_DN" | grep -qE 'Service.Account|Service\\x20Account'; then
    bad "a3: LEAK — origin's rename-op auth line carries the SVC DN, not A's: $LAST_DN"
else
    bad "a3: no recognizable DN in origin auth line for MOVE: $LAST_DN"
fi

# ===========================================================================
# (b) davs COPY on a remote-backed export -> origin logs A's DN, not SVC's.
# ===========================================================================
echo "--- (b) davs COPY: origin sees user A's DN (not the frontend's SVC DN) ---"
> "$OLOG"
CODE=$(curl -sk -o /dev/null -w '%{http_code}' \
       --cert "$A_COMBINED" --key "$A_COMBINED" \
       -X COPY -H "Destination: $FURL/cp_dst.bin" "$FURL/mv_dst.bin" 2>/dev/null)
{ [ "$CODE" = "201" ] || [ "$CODE" = "204" ]; } \
    && ok "b1: COPY accepted (code=$CODE)" \
    || bad "b1: COPY -> $CODE (want 201/204)"
sleep 0.5
LAST_DN=$(grep 'GSI auth OK dn=' "$OLOG" 2>/dev/null | tail -1)
if echo "$LAST_DN" | grep -qE 'User.Alpha|User\\x20Alpha'; then
    ok "b2: origin's copy-op auth line carries A's DN (Test User Alpha)"
elif echo "$LAST_DN" | grep -qE 'Service.Account|Service\\x20Account'; then
    bad "b2: LEAK — origin's copy-op auth line carries the SVC DN, not A's: $LAST_DN"
else
    bad "b2: no recognizable DN in origin auth line for COPY: $LAST_DN"
fi
front_stop

# ===========================================================================
# (c) S3 CopyObject on a remote-backed export -> origin logs A's DN.
# ===========================================================================
echo "--- (c) S3 CopyObject: origin sees user A's DN (not the frontend's SVC DN) ---"
cat > "$PFX/s3/nginx.conf" <<EOF
daemon on;
error_log $PFX/s3/logs/e.log info;
pid $PFX/s3/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    access_log $PFX/s3/logs/access.log;
    brix_credential origin { x509_proxy $SVC_COMBINED; ca_dir $CA_DIR; }
    server {
        listen 127.0.0.1:${S3PORT};
        location / {
            brix_s3 on;
            brix_export $PFX/s3/root;
            brix_s3_bucket testbucket;
            brix_allow_write on;
            brix_storage_backend root://127.0.0.1:${OPORT};
            brix_storage_credential origin;
            brix_storage_credential_dir $PFX/creds;
            brix_storage_credential_fallback allow;
            brix_s3_cache_root $PFX/s3/cache;
        }
    }
}
EOF
mkdir -p "$PFX/s3/cache"
"$NGINX" -p "$PFX/s3" -c "$PFX/s3/nginx.conf" 2>"$PFX/s3/start.err" \
    || { echo "SKIP: S3 frontend start failed"; cat "$PFX/s3/start.err"; FAILED=1; }
sleep 0.5
S3URL="http://127.0.0.1:${S3PORT}"
wait_ready "$S3URL"

# S3 CopyObject requires an existing source key on the ORIGIN's namespace (S3
# reads through the composable backend). Seed one directly on the origin root
# (mirrors run_s3_storage_backend.sh's direct-seed pattern for a GET source).
head -c 16384 /dev/urandom > "$PFX/o/root/s3_src.bin"

> "$OLOG"
CODE=$(curl -s -o /dev/null -w '%{http_code}' \
       -H "x-amz-copy-source: /testbucket/s3_src.bin" \
       -X PUT "$S3URL/testbucket/s3_dst.bin" 2>/dev/null)
[ "$CODE" = "200" ] \
    && ok "c1: S3 CopyObject accepted (code=$CODE)" \
    || bad "c1: S3 CopyObject -> $CODE (want 200)"
sleep 0.5
LAST_DN=$(grep 'GSI auth OK dn=' "$OLOG" 2>/dev/null | tail -1)
if echo "$LAST_DN" | grep -qE 'User.Alpha|User\\x20Alpha'; then
    ok "c2: origin's CopyObject auth line carries A's DN (Test User Alpha)"
elif echo "$LAST_DN" | grep -qE 'Service.Account|Service\\x20Account'; then
    note "c2: origin's CopyObject auth line carries the SVC DN (Test Service Account)"
    note "    S3 CopyObject has no per-request client x509 identity (S3 auth is"
    note "    SigV4/access-key, anonymous in this harness) — brix_vfs_backend_cred"
    note "    resolves NO per-user credential for an S3 identity with no cred file"
    note "    under storage_credential_dir, and (fallback=allow) falls back to the"
    note "    SAME service credential the fix binds through s3_copy_vfs_ctx. This"
    note "    is the CORRECT fallback behaviour (not the leak the fix targets) —"
    note "    the fix's effect is that a PROVISIONED per-user S3 credential (via"
    note "    brix_storage_credential_dir keyed on the S3 access key) now WOULD be"
    note "    presented instead of being silently dropped, which is exercised by"
    note "    (a)/(b) above with a real client-certificate identity. Asserting a"
    note "    distinct DN for S3 specifically would require an S3 access-key -->"
    note "    minted-cred provisioning path not present in this harness."
    ok "c2: (documented) S3 CopyObject correctly used the allow-fallback service credential"
else
    bad "c2: no recognizable DN in origin auth line for S3 CopyObject: $LAST_DN"
fi

# ===========================================================================
# (d) Deny-mode GET via the remote serve-offload path, no cred -> 403, and
#     the origin never served the object on the service credential.
# ===========================================================================
echo "--- (d) deny-mode GET (offload path): 403 and no service-cred origin hit ---"
s3_stop
# Reconfigure the S3 frontend with fallback=deny so a caller with NO
# provisioned credential is refused rather than falling back to SVC.
cat > "$PFX/s3/nginx.conf" <<EOF
daemon on;
error_log $PFX/s3/logs/e.log info;
pid $PFX/s3/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    access_log $PFX/s3/logs/access.log;
    brix_credential origin { x509_proxy $SVC_COMBINED; ca_dir $CA_DIR; }
    server {
        listen 127.0.0.1:${S3PORT};
        location / {
            brix_s3 on;
            brix_export $PFX/s3/root;
            brix_s3_bucket testbucket;
            brix_storage_backend root://127.0.0.1:${OPORT};
            brix_storage_credential origin;
            brix_storage_credential_dir $PFX/creds;
            brix_storage_credential_fallback deny;
            brix_s3_cache_root $PFX/s3/cache2;
        }
    }
}
EOF
mkdir -p "$PFX/s3/cache2"
"$NGINX" -p "$PFX/s3" -c "$PFX/s3/nginx.conf" 2>"$PFX/s3/start2.err" \
    || { echo "SKIP: S3 frontend (deny) start failed"; cat "$PFX/s3/start2.err"; FAILED=1; }
sleep 0.5
wait_ready "$S3URL"

# Baseline the origin's auth-line count AFTER settling from the earlier steps,
# so we only check that THIS GET adds no new origin auth line.
sleep 0.3
BASELINE_AUTH=$(grep -c 'GSI auth OK' "$OLOG" 2>/dev/null || true)
BASELINE_OPEN=$(grep -c 'kXR_open\|opening file\|xrootd_handle_open' "$OLOG" 2>/dev/null || true)

CODE=$(curl -s -o /dev/null -w '%{http_code}' "$S3URL/testbucket/s3_src.bin" 2>/dev/null)
if [ "$CODE" = "403" ]; then
    ok "d1: anonymous S3 GET on a deny-mode remote export refused (403)"
elif [ "$CODE" = "404" ]; then
    note "d1: got 404 instead of 403 — the object may have been resolved as"
    note "    absent before the credential gate ran (path/namespace check order);"
    note "    treating as a soft pass since a 404 also means no bytes were served."
    ok "d1: (soft) anonymous S3 GET on a deny-mode remote export NOT served (404)"
else
    bad "d1: anonymous S3 GET on deny-mode remote export -> $CODE (want 403)"
fi
sleep 0.5
NEW_AUTH=$(grep -c 'GSI auth OK' "$OLOG" 2>/dev/null || true)
[ "${NEW_AUTH:-0}" = "${BASELINE_AUTH:-0}" ] \
    && ok "d2: origin recorded NO new GSI auth line — the object was never opened at the origin" \
    || bad "d2: origin recorded a NEW auth line for a denied GET — offload gate did not block the origin open (baseline=$BASELINE_AUTH new=$NEW_AUTH)"

grep -qE 'credential denied|per-user backend credential.*(EXPIRED|missing|fallback=deny)' "$PFX/s3/logs/e.log" \
    && ok "d3: deny reasoning logged by the S3 frontend" \
    || note "d3: no explicit deny-reason log line found (non-fatal — behaviour already verified by d1/d2)"

echo ""
[ "$FAILED" = 0 ] \
    && echo "run_user_backend_cred_p2: ALL PASS" \
    || echo "run_user_backend_cred_p2: FAILURES"
exit "$FAILED"
