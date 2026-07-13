#!/usr/bin/env bash
# run_credential_xroot_gsi.sh — C-3 GSI half (phase-63): the §14 brix_credential
# threads an X.509 proxy into the sd_xroot source driver, which authenticates to a
# GSI (XrdSecgsi) root:// origin IN-PROCESS — the two-round certreq/cert handshake
# via the shared gsi_core kernel (no xrdcp subprocess). Origin O requires GSI auth;
# node B caches over root://O with an x509_proxy credential. A read miss fills only
# when the proxy authenticates the origin. Negative: a node without it is rejected.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"; XRDFS="$HERE/client/bin/xrdfs"
OPORT=11704; BPORT=11705; NPORT=11706; VPORT=11707; CPORT=11708; PFX="$(mktemp -d /tmp/cred_gsi.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o b n v c; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/cred_gsi_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/b/export" "$PFX/b/cache" "$PFX/b/logs" \
         "$PFX/n/export" "$PFX/n/cache" "$PFX/n/logs" \
         "$PFX/v/export" "$PFX/v/cache" "$PFX/v/logs" "$PFX/badca" \
         "$PFX/c/export" "$PFX/c/cache" "$PFX/c/logs"

TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"
CA_CERT="$TEST_ROOT/pki/ca/ca.pem"; CA_DIR="$TEST_ROOT/pki/ca"
SERVER_CERT="$TEST_ROOT/pki/server/hostcert.pem"; SERVER_KEY="$TEST_ROOT/pki/server/hostkey.pem"
PROXY_STD="$TEST_ROOT/pki/user/proxy_std.pem"

# Provision (or refresh) the CA-signed PKI: server cert + a user proxy the CA trusts.
if [ ! -f "$CA_CERT" ] || [ ! -f "$SERVER_CERT" ] || [ ! -f "$PROXY_STD" ] \
   || ! openssl x509 -in "$PROXY_STD" -noout -checkend 300 >/dev/null 2>&1; then
    ( cd "$HERE/tests" && PYTHONPATH=. python3 -c "import pki_helpers; pki_helpers.blitz_test_pki()" ) \
        >"$PFX/o/logs/pki.log" 2>&1 || { echo "SKIP: PKI provisioning failed"; cat "$PFX/o/logs/pki.log"; exit 0; }
fi

# Origin O — root:// server requiring GSI auth.
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${OPORT}; brix_root on; brix_export $PFX/o/root;
    brix_auth gsi;
    brix_certificate     $SERVER_CERT;
    brix_certificate_key $SERVER_KEY;
    brix_trusted_ca      $CA_CERT;
    brix_allow_write on;
} }
EOF
# Node B — cache over root://O, authenticating in-process with the X.509 proxy.
cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream {
    brix_credential origin { x509_proxy $PROXY_STD; ca_dir $CA_DIR; }
    server {
        listen 127.0.0.1:${BPORT}; brix_root on; brix_export $PFX/b/export; brix_auth none;
        brix_storage_backend root://127.0.0.1:${OPORT};
        brix_storage_credential origin;
        brix_cache on; brix_cache_export $PFX/b/cache;
    }
}
EOF
# Node V — MITM negative: same proxy but a WRONG (empty) CA dir, so the origin's
# server cert cannot be verified and the GSI handshake must refuse.
cat > "$PFX/v/nginx.conf" <<EOF
daemon on; error_log $PFX/v/logs/e.log info; pid $PFX/v/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream {
    brix_credential origin { x509_proxy $PROXY_STD; ca_dir $PFX/badca; }
    server {
        listen 127.0.0.1:${VPORT}; brix_root on; brix_export $PFX/v/export; brix_auth none;
        brix_storage_backend root://127.0.0.1:${OPORT};
        brix_storage_credential origin;
        brix_cache on; brix_cache_export $PFX/v/cache;
    }
}
EOF
# Node C — SEPARATE x509_cert + x509_key (not a combined proxy).  Split the standard
# proxy PEM into its cert chain and its private key; brix must reassemble them into a
# GSI credential.  Before the cert/key plumbing fix these fields were silently dead, so
# this node would fall back to anonymous and the GSI origin would reject the fill.
CERT_PART="$PFX/c/cert.pem"; KEY_PART="$PFX/c/key.pem"
awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' "$PROXY_STD" > "$CERT_PART"
awk '/-----BEGIN[A-Z ]*PRIVATE KEY-----/,/-----END[A-Z ]*PRIVATE KEY-----/' "$PROXY_STD" > "$KEY_PART"
chmod 600 "$KEY_PART"
cat > "$PFX/c/nginx.conf" <<EOF
daemon on; error_log $PFX/c/logs/e.log info; pid $PFX/c/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream {
    brix_credential origin { x509_cert $CERT_PART; x509_key $KEY_PART; ca_dir $CA_DIR; }
    server {
        listen 127.0.0.1:${CPORT}; brix_root on; brix_export $PFX/c/export; brix_auth none;
        brix_storage_backend root://127.0.0.1:${OPORT};
        brix_storage_credential origin;
        brix_cache on; brix_cache_export $PFX/c/cache;
    }
}
EOF
# Node N — no credential (negative control: anonymous login rejected by the GSI origin).
cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${NPORT}; brix_root on; brix_export $PFX/n/export; brix_auth none;
    brix_storage_backend root://127.0.0.1:${OPORT};
    brix_cache on; brix_cache_export $PFX/n/cache;
} }
EOF

head -c 500000  /dev/urandom > "$PFX/o/root/small.bin"
head -c 2600000 /dev/urandom > "$PFX/o/root/big.bin"
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B start failed"; cat "$PFX/b/err"; exit 2; }
"$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo "N start failed"; cat "$PFX/n/err"; exit 2; }
"$NGINX" -p "$PFX/v" -c "$PFX/v/nginx.conf" 2>"$PFX/v/err" || { echo "V start failed"; cat "$PFX/v/err"; exit 2; }
"$NGINX" -p "$PFX/c" -c "$PFX/c/nginx.conf" 2>"$PFX/c/err" || { echo "C start failed"; cat "$PFX/c/err"; exit 2; }
sleep 1

echo "== with X.509 proxy + the right CA: GSI verifies the origin cert AND fills =="
"$XRDFS" root://127.0.0.1:${BPORT} cat /small.bin > /tmp/cred_gsi_s.got 2>"$PFX/b/logs/cat.err"
cmp -s "$PFX/o/root/small.bin" /tmp/cred_gsi_s.got && ok "byte-exact serve (GSI-authenticated fill)" \
  || { bad "differs/empty"; grep -iE 'gsi|proxy|auth|origin|cache|error' "$PFX/b/logs/e.log" | tail -10; }
"$XRDFS" root://127.0.0.1:${BPORT} cat /big.bin > /tmp/cred_gsi_b.got 2>/dev/null
cmp -s "$PFX/o/root/big.bin" /tmp/cred_gsi_b.got && ok "multi-chunk GSI-authenticated fill byte-exact" \
  || bad "multi-chunk differs (got=$(stat -c%s /tmp/cred_gsi_b.got 2>/dev/null))"

echo "== separate x509_cert + x509_key (no combined proxy): GSI fills =="
"$XRDFS" root://127.0.0.1:${CPORT} cat /small.bin > /tmp/cred_gsi_c.got 2>"$PFX/c/logs/cat.err"
cmp -s "$PFX/o/root/small.bin" /tmp/cred_gsi_c.got && ok "cert+key credential authenticated the GSI fill" \
  || { bad "cert+key fill differs/empty (x509_cert/x509_key not wired to GSI)"; grep -iE 'gsi|proxy|auth|origin|cache|error' "$PFX/c/logs/e.log" | tail -10; }

echo "== negative control: no credential ⇒ anonymous login rejected by the GSI origin =="
"$XRDFS" root://127.0.0.1:${NPORT} cat /small.bin > /tmp/cred_gsi_n.got 2>/dev/null
if [ -s /tmp/cred_gsi_n.got ] && cmp -s "$PFX/o/root/small.bin" /tmp/cred_gsi_n.got; then
    bad "UNAUTHENTICATED fill unexpectedly succeeded (GSI not enforced!)"
else
    ok "unauthenticated fill correctly failed (origin required GSI)"
fi

echo "== MITM negative: a WRONG CA ⇒ the origin's server cert fails verification =="
"$XRDFS" root://127.0.0.1:${VPORT} cat /small.bin > /tmp/cred_gsi_v.got 2>/dev/null
if [ -s /tmp/cred_gsi_v.got ] && cmp -s "$PFX/o/root/small.bin" /tmp/cred_gsi_v.got; then
    bad "fill with an UNVERIFIABLE origin cert unexpectedly succeeded (MITM not blocked!)"
else
    ok "fill correctly refused (origin cert not verifiable against the wrong CA)"
fi

[ "$fail" = 0 ] && echo "run_credential_xroot_gsi: ALL PASS" || echo "run_credential_xroot_gsi: FAILURES"
exit "$fail"
