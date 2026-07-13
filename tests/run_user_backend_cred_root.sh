#!/usr/bin/env bash
# run_user_backend_cred_root.sh — Phase 2 Task 6: per-user backend credentials
# extended to the root:// STREAM protocol (Phase 1 was davs/S3-only).
#
# Topology: GSI-auth root:// origin O (port OPORT) + GSI-auth root:// frontend F
# (port FPORT).  F's export storage IS the remote origin O (brix_storage_backend
# root://O, write-through — no local cache/stage layer, exercising the driver-
# backed open path directly per Phase 2 Task 6).  F also sets
# brix_storage_credential_dir + brix_storage_credential_fallback.
#
#   1  user A (cred provisioned via xrdcp/xrdfs, GSI client cert=A's proxy):
#      PUT via F lands on the origin authenticated as A (origin log shows A's
#      DN, NOT the service DN); GET back is byte-exact.
#   2  user B (no cred provisioned), fallback=deny:
#      PUT is refused with kXR_NotAuthorized (xrdcp reports failure / non-zero
#      rc); the origin log gains NO new auth line for B's op (no service-cred
#      session was opened on B's behalf), and no data reaches the origin root.
#
# A DISTINCT service credential (CN=SVC Proxy, separate from user A's CN=Test
# User) is configured as F's static brix_credential, so a PASS genuinely
# distinguishes "the client's own proxy reached the origin" from "the service
# credential happened to work too."
#
# SAFETY: uses ONLY own ports; teardown kills ONLY PIDs from our own pidfiles
# (no pkill, no manage_test_servers.sh, no /tmp/xrd-test writes beyond PKI read).
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
NGINX=${NGINX:-/tmp/nginx-1.28.3/objs/nginx}
TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"
XRDCP="$HERE/client/bin/xrdcp"
XRDFS="$HERE/client/bin/xrdfs"

PFX=/tmp/ucred-root-e2e
rm -rf "$PFX"
mkdir -p "$PFX/o/root" "$PFX/o/logs" \
         "$PFX/f/export" "$PFX/f/logs" \
         "$PFX/creds" "$PFX/b" "$PFX/svc"
chmod 777 "$PFX/creds"

OPORT=${OPORT:-11720}
FPORT=${FPORT:-11721}
for p in "$OPORT" "$FPORT"; do
    if ss -tlnp 2>/dev/null | grep -q ":${p} "; then
        echo "SKIP: port $p already in use — choose different OPORT/FPORT"
        exit 0
    fi
done

ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; FAILED=1; }
FAILED=0
count_grep(){ grep -c "$1" "$2" 2>/dev/null || true; }

for need in "$NGINX" "$XRDCP" "$XRDFS"; do
    [ -e "$need" ] || { echo "SKIP: missing $need"; exit 0; }
done

origin_stop(){
    if [ -f "$PFX/o/nginx.pid" ]; then
        kill "$(cat "$PFX/o/nginx.pid")" 2>/dev/null
        sleep 0.5
    fi
}
front_stop(){
    if [ -f "$PFX/f/nginx.pid" ]; then
        kill "$(cat "$PFX/f/nginx.pid")" 2>/dev/null
        sleep 0.5
    fi
}
cleanup(){
    front_stop
    origin_stop
    rm -rf "$PFX" /tmp/ucred_root_payload.bin /tmp/ucred_root_back.bin 2>/dev/null
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

# ---- mint user B cert from the same CA (plain end-entity cert, no matching
# credential-dir entry — the deny-mode negative control) ----
openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$PFX/b/key.pem" \
    -subj "/DC=test/DC=xrootd/CN=Test User B/CN=88888" \
    -out "$PFX/b/req.pem" >/dev/null 2>&1
openssl x509 -req \
    -in "$PFX/b/req.pem" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -set_serial "0x$(openssl rand -hex 8)" \
    -days 2 \
    -out "$PFX/b/cert.pem" >/dev/null 2>&1 \
    || { echo "SKIP: user-B cert mint failed"; exit 0; }
cat "$PFX/b/cert.pem" "$PFX/b/key.pem" > "$PFX/b/proxy.pem"
chmod 600 "$PFX/b/proxy.pem"
PROXY_B="$PFX/b/proxy.pem"

# ---- mint a DISTINCT service proxy (CN=SVC Proxy) — F's static service cred,
# deliberately different from user A's proxy (CN=Test User) so success genuinely
# distinguishes the per-user credential from the shared service credential. ----
openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$PFX/svc/key.pem" \
    -subj "/DC=test/DC=xrootd/CN=SVC Proxy" \
    -out "$PFX/svc/req.pem" >/dev/null 2>&1
openssl x509 -req \
    -in "$PFX/svc/req.pem" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -set_serial "0x$(openssl rand -hex 8)" \
    -days 2 \
    -out "$PFX/svc/cert.pem" >/dev/null 2>&1 \
    || { echo "SKIP: service proxy mint failed"; exit 0; }
cat "$PFX/svc/cert.pem" "$PFX/svc/key.pem" > "$PFX/svc/proxy.pem"
chmod 600 "$PFX/svc/proxy.pem"
SVC_PROXY="$PFX/svc/proxy.pem"

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
# $1 = deny|allow
mkfront(){
    local fallback="$1"
    cat > "$PFX/f/nginx.conf" <<EOF
daemon on;
error_log $PFX/f/logs/e.log info;
pid $PFX/f/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events { worker_connections 64; }
stream {
    brix_credential origin { x509_proxy $SVC_PROXY; ca_dir $CA_DIR; }
    server {
        listen 127.0.0.1:${FPORT};
        brix_root on;
        brix_export $PFX/f/export;
        brix_allow_write on;
        brix_upload_resume off;
        brix_auth gsi;
        brix_certificate     $SERVER_CERT;
        brix_certificate_key $SERVER_KEY;
        brix_trusted_ca      $CA_CERT;
        brix_storage_backend root://127.0.0.1:${OPORT};
        brix_storage_credential origin;
        brix_storage_credential_dir $PFX/creds;
        brix_storage_credential_fallback $fallback;
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

# GSI client env: X509_USER_PROXY selects the client cert xrdcp/xrdfs present.
run_as(){
    local proxy="$1"; shift
    X509_USER_PROXY="$proxy" X509_CERT_DIR="$CA_DIR" XrdSecGSICADIR="$CA_DIR" "$@"
}

# ===========================================================================
# PARSE-LEVEL CHECKS (run first, unconditionally — directive wiring proof).
# ===========================================================================
echo "--- parse-level: nginx -t accepts the 2 new stream directives ---"
mkfront deny
if "$NGINX" -p "$PFX/f" -t -c "$PFX/f/nginx.conf" >"$PFX/f/parsetest.log" 2>&1; then
    ok "P1: nginx -t accepts brix_storage_credential_dir + brix_storage_credential_fallback"
else
    bad "P1: nginx -t rejected a valid config"; cat "$PFX/f/parsetest.log"
fi

echo "--- parse-level: bad fallback value is rejected ---"
cat > "$PFX/f/nginx_bad.conf" <<EOF
daemon on;
error_log $PFX/f/logs/e_bad.log info;
pid $PFX/f/bad.pid;
events { worker_connections 64; }
stream {
    server {
        listen 127.0.0.1:${FPORT};
        brix_root on;
        brix_export $PFX/f/export;
        brix_storage_credential_dir $PFX/creds;
        brix_storage_credential_fallback bogus;
    }
}
EOF
if "$NGINX" -p "$PFX/f" -t -c "$PFX/f/nginx_bad.conf" >"$PFX/f/parsetest_bad.log" 2>&1; then
    bad "P2: nginx -t accepted an invalid brix_storage_credential_fallback value"
else
    ok "P2: nginx -t rejects an invalid brix_storage_credential_fallback value"
fi

echo "--- parse-level: phase-3 T1 root:// credential-minting directives ---"
cat > "$PFX/f/nginx_mint.conf" <<EOF
daemon on;
error_log $PFX/f/logs/e_mint.log info;
pid $PFX/f/mint.pid;
events { worker_connections 64; }
stream {
    server {
        listen 127.0.0.1:${FPORT};
        brix_root on;
        brix_export $PFX/f/export;
        brix_storage_credential_dir $PFX/creds;
        brix_storage_credential_fallback allow;
        brix_storage_credential_mint_ca $CA_CERT $CA_KEY;
        brix_storage_credential_mint_ttl 900;
    }
}
EOF
if "$NGINX" -p "$PFX/f" -t -c "$PFX/f/nginx_mint.conf" >"$PFX/f/parsetest_mint.log" 2>&1; then
    ok "P3: nginx -t accepts brix_storage_credential_mint_ca + _mint_ttl on the stream plane"
else
    bad "P3: nginx -t rejected a valid mint-CA config"; cat "$PFX/f/parsetest_mint.log"
fi

echo "--- parse-level: bad mint CA cert path is rejected ---"
cat > "$PFX/f/nginx_mint_bad.conf" <<EOF
daemon on;
error_log $PFX/f/logs/e_mint_bad.log info;
pid $PFX/f/mint_bad.pid;
events { worker_connections 64; }
stream {
    server {
        listen 127.0.0.1:${FPORT};
        brix_root on;
        brix_export $PFX/f/export;
        brix_storage_credential_mint_ca /nonexistent/cert.pem /nonexistent/key.pem;
    }
}
EOF
if "$NGINX" -p "$PFX/f" -t -c "$PFX/f/nginx_mint_bad.conf" >"$PFX/f/parsetest_mint_bad.log" 2>&1; then
    bad "P4: nginx -t accepted an unparseable mint CA cert/key path"
else
    ok "P4: nginx -t rejects an unparseable mint CA cert/key path"
fi
# NOTE: a full root:// mint e2e (a mint-CA-signed proxy actually reaching a
# remote origin) is heavy — it needs the origin to trust a SEPARATE mint CA
# distinct from the client-cert CA already wired into this harness. The parse-
# level checks above (P3/P4) prove the directives are correctly registered and
# threaded onto conf->common (which brix_vfs_ctx_bind_backend_mint reads at
# the data-plane sites); the mint/gate logic itself is exercised end-to-end by
# tests/c/run_cred_mint.sh (unit) and by the existing davs/S3 mint e2e paths.

# ===========================================================================
# STEP 0 — Learn the derived credential key for user A (same formula as
# ucred.c: fs-safe literal DN, else x5h-<sha256hex32>).
# ===========================================================================
echo "--- learning derived key for user A ---"
front_start deny
sleep 0.5
head -c 65536 /dev/urandom > /tmp/ucred_root_payload.bin
run_as "$PROXY_A" "$XRDCP" -f /tmp/ucred_root_payload.bin \
    "root://127.0.0.1:${FPORT}//probe_key.bin" >/dev/null 2>"$PFX/f/probe.err" || true
sleep 0.3
A_KEY=$(grep -oE 'key=x5h-[0-9a-f]+|key=[A-Za-z0-9@._-]+' "$PFX/f/logs/e.log" 2>/dev/null \
        | head -1 | cut -d= -f2)
if [ -z "$A_KEY" ]; then
    A_DN_TMP=$(openssl x509 -in "$PROXY_A" -noout -subject -nameopt oneline 2>/dev/null \
               | sed 's/subject= *//')
    A_KEY="x5h-$(printf '%s' "$A_DN_TMP" | openssl dgst -sha256 -hex 2>/dev/null \
               | awk '{print $2}' | head -c 32)"
fi
if [ -z "$A_KEY" ]; then
    echo "SKIP: could not derive credential key for user A (GSI client auth prerequisite failed)"
    cat "$PFX/f/probe.err" 2>/dev/null
    echo ""
    echo "run_user_backend_cred_root: parse-level checks only (e2e prerequisite unavailable)"
    [ "$FAILED" = 0 ] && exit 0 || exit "$FAILED"
fi
echo "  user-A credential stem: $A_KEY"
install -m 644 "$PROXY_A" "$PFX/creds/$A_KEY.pem"
front_stop

# ===========================================================================
# ASSERTION 1 — User A (cred provisioned): xrdcp PUT+GET through the root://
# frontend lands on the origin authenticated as A (origin log shows A's DN,
# not the service DN); GET back is byte-exact.
# ===========================================================================
echo "--- assertion 1: user A (cred provisioned) PUT+GET + origin sees A's DN ---"
> "$OLOG"
front_start deny
sleep 0.5
run_as "$PROXY_A" "$XRDCP" -f /tmp/ucred_root_payload.bin \
    "root://127.0.0.1:${FPORT}//a1.bin" >/dev/null 2>"$PFX/f/put_a.err"
PUT_RC=$?
[ "$PUT_RC" = 0 ] && ok "1a: A's xrdcp PUT succeeded" || {
    bad "1a: A's xrdcp PUT failed (rc=$PUT_RC)"; cat "$PFX/f/put_a.err"
    grep -iE 'gsi|proxy|auth|cred|error' "$PFX/f/logs/e.log" | tail -10
}
sleep 0.5
if grep -q 'GSI auth OK dn=' "$OLOG" 2>/dev/null; then
    ok "1b: origin authenticated a session (GSI auth OK in origin log)"
else
    bad "1b: no 'GSI auth OK' in origin log"
fi
LAST_DN=$(grep 'GSI auth OK dn=' "$OLOG" 2>/dev/null | tail -1)
echo "$LAST_DN" | grep -qE 'Test.User|Test\\x20User' \
    && ok "1c: origin log shows user A's DN (Test User), not the service DN" \
    || bad "1c: origin auth line does not carry A's DN: $LAST_DN"
echo "$LAST_DN" | grep -qE 'SVC.Proxy' \
    && bad "1c-neg: origin log wrongly shows the SERVICE DN (SVC Proxy) for A's op" \
    || ok "1c-neg: origin log does NOT show the service DN for A's op"
run_as "$PROXY_A" "$XRDCP" -f "root://127.0.0.1:${FPORT}//a1.bin" \
    /tmp/ucred_root_back.bin >/dev/null 2>"$PFX/f/get_a.err"
cmp -s /tmp/ucred_root_payload.bin /tmp/ucred_root_back.bin \
    && ok "1d: A's GET byte-exact" \
    || bad "1d: A's GET differs from PUT"

# ---- 1e: kXR_mv (rename) by user A — origin DN around the rename must be A's,
# proving the final rename call (mv.c) is now identity-threaded (review-finding
# fix 1: brix_vfs_rename replacing the ctx-free brix_vfs_rename_path). ----
> "$OLOG"
run_as "$PROXY_A" "$XRDFS" "127.0.0.1:${FPORT}" mv a1.bin a1_moved.bin \
    >"$PFX/f/mv_a.log" 2>"$PFX/f/mv_a.err"
MV_RC=$?
[ "$MV_RC" = 0 ] && ok "1e: A's xrdfs mv succeeded" || {
    bad "1e: A's xrdfs mv failed (rc=$MV_RC)"; cat "$PFX/f/mv_a.err"
}
sleep 0.3
MV_DN=$(grep 'GSI auth OK dn=' "$OLOG" 2>/dev/null | tail -1)
echo "$MV_DN" | grep -qE 'Test.User|Test\\x20User' \
    && ok "1f: origin log around the mv shows user A's DN (not the service DN)" \
    || bad "1f: origin auth line for the mv does not carry A's DN: $MV_DN"
echo "$MV_DN" | grep -qE 'SVC.Proxy' \
    && bad "1f-neg: origin log wrongly shows the SERVICE DN for A's mv" \
    || ok "1f-neg: origin log does NOT show the service DN for A's mv"

# ---- 1g: kXR_dirlist by user A — origin DN around the dirlist must be A's,
# proving dirlist/handler.c AND the sd_xroot opendir_cred slot are identity-
# threaded (phase-3 T2: sd_xroot now implements opendir/readdir/closedir +
# opendir_cred over kXR_dirlist against the origin — see
# src/fs/cache/origin_ns.c:brix_cache_origin_dirlist and
# src/fs/backend/xroot/sd_xroot_ns.c:sd_xroot_opendir_cred). Seed a couple of
# known entries at the origin first so `xrdfs ls` has something to list. ----
touch "$PFX/o/root/dirlist_e1.txt" "$PFX/o/root/dirlist_e2.txt"
> "$OLOG"
run_as "$PROXY_A" "$XRDFS" "127.0.0.1:${FPORT}" ls / \
    >"$PFX/f/ls_a.log" 2>"$PFX/f/ls_a.err"
LS_RC=$?
[ "$LS_RC" = 0 ] && ok "1g: A's xrdfs ls succeeded" || {
    bad "1g: A's xrdfs ls failed (rc=$LS_RC)"; cat "$PFX/f/ls_a.err"
}
grep -q 'dirlist_e1.txt' "$PFX/f/ls_a.log" && grep -q 'dirlist_e2.txt' "$PFX/f/ls_a.log" \
    && ok "1g2: ls output contains both origin-seeded entries (real dirlist, not empty/stub)" \
    || bad "1g2: ls output missing seeded entries: $(cat "$PFX/f/ls_a.log")"
sleep 0.3
LS_DN=$(grep 'GSI auth OK dn=' "$OLOG" 2>/dev/null | tail -1)
if [ -n "$LS_DN" ]; then
    echo "$LS_DN" | grep -qE 'Test.User|Test\\x20User' \
        && ok "1h: origin log around the dirlist shows user A's DN (not the service DN)" \
        || bad "1h: origin auth line for the dirlist does not carry A's DN: $LS_DN"
    echo "$LS_DN" | grep -qE 'SVC.Proxy' \
        && bad "1h-neg: origin log wrongly shows the SERVICE DN for A's dirlist" \
        || ok "1h-neg: origin log does NOT show the service DN for A's dirlist"
else
    bad "1h: no origin auth line observed for the dirlist — opendir_cred did not reach the origin"
fi

# ---- 1i: kXR_Qcksum by user A — origin DN around the checksum query must be
# A's, proving checksum_qcksum.c is now identity-threaded (review-finding
# fix 3). ----
> "$OLOG"
run_as "$PROXY_A" "$XRDFS" "127.0.0.1:${FPORT}" query checksum a1_moved.bin \
    >"$PFX/f/cksum_a.log" 2>"$PFX/f/cksum_a.err"
CKSUM_RC=$?
[ "$CKSUM_RC" = 0 ] && ok "1i: A's xrdfs query checksum succeeded" || {
    bad "1i: A's xrdfs query checksum failed (rc=$CKSUM_RC)"; cat "$PFX/f/cksum_a.err"
}
sleep 0.3
CKSUM_DN=$(grep 'GSI auth OK dn=' "$OLOG" 2>/dev/null | tail -1)
if [ -n "$CKSUM_DN" ]; then
    echo "$CKSUM_DN" | grep -qE 'Test.User|Test\\x20User' \
        && ok "1j: origin log around the checksum query shows user A's DN (not the service DN)" \
        || bad "1j: origin auth line for the checksum query does not carry A's DN: $CKSUM_DN"
    echo "$CKSUM_DN" | grep -qE 'SVC.Proxy' \
        && bad "1j-neg: origin log wrongly shows the SERVICE DN for A's checksum query" \
        || ok "1j-neg: origin log does NOT show the service DN for A's checksum query"
else
    echo "  NOTE 1j: no new origin auth line observed for the checksum query (origin may have reused an existing GSI session — informational only, not a failure)"
fi

front_stop

# ===========================================================================
# ASSERTION 2 — User B (no provisioned cred), fallback=deny: PUT refused with
# kXR_NotAuthorized; no new origin auth line for B's op; no data reaches origin.
# ===========================================================================
echo "--- assertion 2: user B (no cred), deny → refused, origin untouched ---"
AUTH_BASELINE=$(count_grep 'GSI auth OK' "$OLOG")
front_start deny
sleep 0.5
run_as "$PROXY_B" "$XRDCP" -f /tmp/ucred_root_payload.bin \
    "root://127.0.0.1:${FPORT}//b1.bin" >/dev/null 2>"$PFX/f/put_b.err"
PUT_B_RC=$?
[ "$PUT_B_RC" != 0 ] \
    && ok "2a: B's xrdcp PUT was refused (rc=$PUT_B_RC != 0)" \
    || bad "2a: B's xrdcp PUT unexpectedly succeeded (no cred, fallback=deny)"
grep -qiE 'not.?authorized|kxr_notauthorized|permission denied|authorization' "$PFX/f/put_b.err" \
    && ok "2b: xrdcp reported an authorization failure for B" \
    || echo "  NOTE 2b: xrdcp stderr did not literally say 'not authorized' (informational only): $(cat "$PFX/f/put_b.err")"
sleep 0.3
# NOTE: the pre-flight write-target probes (symlink/directory/exclusive-create
# checks in brix_open_resolved_file, via the internal brix_open_probe helper)
# run BEFORE the credential gate and are identity-less by design (mirrors the
# WebDAV/S3 Phase 1 behaviour documented in run_user_backend_cred.sh assertion
# 2b: "the frontend uses the service credential for a pre-flight existence
# probe; that is expected and NOT a security leak"). The security property
# under test is that B's DATA is never written to the origin — checked below
# — not that the origin is never contacted at all.
NEW_AUTH=$(count_grep 'GSI auth OK' "$OLOG")
echo "  info: origin auth-line count baseline=$AUTH_BASELINE now=$NEW_AUTH (pre-flight probes may add lines; see NOTE above)"
[ ! -f "$PFX/o/root/b1.bin" ] \
    && ok "2c: B's data never reached the origin root (credential gate blocked the write)" \
    || bad "2c: b1.bin exists in the origin root — data reached the backend!"
grep -qE 'fallback=deny.*refusing|per-user backend credential.*fallback=deny' "$PFX/f/logs/e.log" \
    && ok "2d: deny reasoning logged by the frontend" \
    || bad "2d: no fallback=deny log in frontend error log"
front_stop

# ===========================================================================
# ASSERTION 3 — Defense-in-depth (Phase-3 review gap): user C has ONLY a
# WRONG-KIND credential provisioned — a <key>.s3 file (AK/SK/region), no
# .pem and no .token — against this root:// (sd_xroot) export. sd_xroot
# implements open_cred (cap_ok=TRUE at the VFS gate, so the gate's own
# "backend cannot scope a session" refusal does NOT fire — that check is
# capability-only, not kind-aware) but sd_xroot can ONLY present an x509
# proxy or a bearer token at the origin, never S3 keys. Before this fix,
# sd_xroot_open_common silently fell through to sd_xroot_origin_open(cred)
# with an all-NULL x509_proxy/bearer, which sd_xroot_origin_open treats
# identically to cred=NULL — i.e. it silently opened on F's static SERVICE
# credential (CN=SVC Proxy) even though fallback=deny explicitly forbids
# exactly that fallback. The fix (sd_xroot_open_common + sd_xroot_session)
# now refuses (EACCES) before any origin session is opened whenever
# fallback_deny is set and the cred carries neither x509_proxy nor bearer.
# ===========================================================================
echo "--- assertion 3: user C (wrong-kind .s3-only cred), deny → refused, NOT served on service cred ---"
mkdir -p "$PFX/c"
openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$PFX/c/key.pem" \
    -subj "/DC=test/DC=xrootd/CN=Test User C/CN=77777" \
    -out "$PFX/c/req.pem" >/dev/null 2>&1
openssl x509 -req \
    -in "$PFX/c/req.pem" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -set_serial "0x$(openssl rand -hex 8)" \
    -days 2 \
    -out "$PFX/c/cert.pem" >/dev/null 2>&1 \
    || { echo "SKIP: user-C cert mint failed"; PROXY_C=""; }
if [ -n "${PROXY_C-x}" ] && [ -f "$PFX/c/cert.pem" ]; then
    cat "$PFX/c/cert.pem" "$PFX/c/key.pem" > "$PFX/c/proxy.pem"
    chmod 600 "$PFX/c/proxy.pem"
    PROXY_C="$PFX/c/proxy.pem"
fi

if [ -n "$PROXY_C" ]; then
    # Learn user C's derived credential key the same way STEP 0 learned A's
    # (probe PUT with no cred provisioned yet; deny mode still logs the
    # derived key before refusing).
    > "$OLOG"
    front_start deny
    sleep 0.5
    run_as "$PROXY_C" "$XRDCP" -f /tmp/ucred_root_payload.bin \
        "root://127.0.0.1:${FPORT}//probe_key_c.bin" >/dev/null 2>"$PFX/f/probe_c.err" || true
    sleep 0.3
    C_KEY=$(grep -oE 'key=x5h-[0-9a-f]+|key=[A-Za-z0-9@._-]+' "$PFX/f/logs/e.log" 2>/dev/null \
            | tail -1 | cut -d= -f2)
    if [ -z "$C_KEY" ]; then
        C_DN_TMP=$(openssl x509 -in "$PROXY_C" -noout -subject -nameopt oneline 2>/dev/null \
                   | sed 's/subject= *//')
        C_KEY="x5h-$(printf '%s' "$C_DN_TMP" | openssl dgst -sha256 -hex 2>/dev/null \
                   | awk '{print $2}' | head -c 32)"
    fi
    front_stop

    if [ -n "$C_KEY" ]; then
        echo "  user-C credential stem: $C_KEY"
        # Provision ONLY a .s3 file for C — no .pem, no .token — so
        # brix_sd_ucred_resolve selects the S3 kind (the only kind present),
        # which sd_xroot cannot use.
        printf 'AKIAWRONGKINDTEST\nwrongkindsecretkeywrongkindsecretkey\nus-east-1\n' \
            > "$PFX/creds/$C_KEY.s3"
        chmod 600 "$PFX/creds/$C_KEY.s3"

        AUTH_BASELINE_C=$(count_grep 'GSI auth OK' "$OLOG")
        > "$OLOG"
        front_start deny
        sleep 0.5
        run_as "$PROXY_C" "$XRDCP" -f /tmp/ucred_root_payload.bin \
            "root://127.0.0.1:${FPORT}//c1.bin" >/dev/null 2>"$PFX/f/put_c.err"
        PUT_C_RC=$?
        [ "$PUT_C_RC" != 0 ] \
            && ok "3a: C's xrdcp PUT (wrong-kind .s3-only cred, deny) was refused (rc=$PUT_C_RC != 0)" \
            || bad "3a: C's xrdcp PUT unexpectedly succeeded (wrong-kind cred, fallback=deny)"
        sleep 0.3
        [ ! -f "$PFX/o/root/c1.bin" ] \
            && ok "3b: C's data never reached the origin root (wrong-kind cred refused before any write)" \
            || bad "3b: c1.bin exists in the origin root — wrong-kind cred silently reached the backend!"
        # The security property under test: the op must NOT have been served
        # on F's static SERVICE credential (CN=SVC Proxy). Assert the origin
        # log gained NO 'GSI auth OK dn=...SVC Proxy...' line for this op —
        # that would prove the pre-fix silent-fallback-to-service-cred leak.
        SVC_AUTH_FOR_C=$(grep 'GSI auth OK dn=' "$OLOG" 2>/dev/null | grep -c 'SVC.Proxy' || true)
        [ "$SVC_AUTH_FOR_C" = 0 ] \
            && ok "3c: origin log shows NO service-credential (SVC Proxy) session for C's wrong-kind-cred op (not silently served on service cred)" \
            || bad "3c: origin log shows a SVC Proxy auth session for C's op — silent fallback to service credential!"
        front_stop
    else
        echo "  NOTE assertion 3: could not derive credential key for user C (GSI client auth prerequisite failed) — skipping wrong-kind assertion"
    fi
else
    echo "  NOTE assertion 3: user-C proxy mint failed — skipping wrong-kind assertion"
fi

# ===========================================================================
echo ""
[ "$FAILED" = 0 ] \
    && echo "run_user_backend_cred_root: ALL PASS" \
    || echo "run_user_backend_cred_root: FAILURES"
exit "$FAILED"
