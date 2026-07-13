#!/usr/bin/env bash
# run_credential_xroot_gsi_writeback.sh — the WRITE-BACK half of C-3 GSI: a
# storage_backend + cache + stage node writing THROUGH to a GSI root:// origin,
# authenticating the outbound flush with a brix_credential.
#
# This exercises the sd_xroot BACKEND/TIER credential path (create_origin built
# from the composed cache/stage tier), which is DISTINCT from the legacy cache
# fetch path in run_credential_xroot_gsi.sh.  It is the exact shape that failed on
# a real deployment: a plain host cert + key (x509_cert + x509_key, not a combined
# x509_proxy) was silently dropped on the tier path, so the origin flush failed
# with "cache origin requires authentication (no credential set)".
#
# Node W: brix_credential origin { x509_cert; x509_key } + storage_backend
# root://O + cache + stage.  A client PUT lands in the stage, the async flush
# writes through to O; we assert the bytes appear on O's export.  Negative: a
# node with NO credential must fail the flush (origin rejects anonymous write).
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDCP="$HERE/client/bin/xrdcp"; XRDFS="$HERE/client/bin/xrdfs"
OPORT=11714; WPORT=11715; NPORT=11716; PFX="$(mktemp -d /tmp/cred_gsi_wb.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o w n; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/cred_gsi_wb_*.bin; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" \
         "$PFX/w/export" "$PFX/w/cache" "$PFX/w/staging" "$PFX/w/logs" \
         "$PFX/n/export" "$PFX/n/cache" "$PFX/n/staging" "$PFX/n/logs"

TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"
CA_CERT="$TEST_ROOT/pki/ca/ca.pem"; CA_DIR="$TEST_ROOT/pki/ca"
SERVER_CERT="$TEST_ROOT/pki/server/hostcert.pem"; SERVER_KEY="$TEST_ROOT/pki/server/hostkey.pem"
PROXY_STD="$TEST_ROOT/pki/user/proxy_std.pem"
if [ ! -f "$CA_CERT" ] || [ ! -f "$SERVER_CERT" ] || [ ! -f "$PROXY_STD" ] \
   || ! openssl x509 -in "$PROXY_STD" -noout -checkend 300 >/dev/null 2>&1; then
    ( cd "$HERE/tests" && PYTHONPATH=. python3 -c "import pki_helpers; pki_helpers.blitz_test_pki()" ) \
        >"$PFX/o/logs/pki.log" 2>&1 || { echo "SKIP: PKI provisioning failed"; cat "$PFX/o/logs/pki.log"; exit 0; }
fi

# Split the standard proxy into a SEPARATE cert chain + key (the plain-cert+key case).
CERT_PART="$PFX/w/cert.pem"; KEY_PART="$PFX/w/key.pem"
awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' "$PROXY_STD" > "$CERT_PART"
awk '/-----BEGIN[A-Z ]*PRIVATE KEY-----/,/-----END[A-Z ]*PRIVATE KEY-----/' "$PROXY_STD" > "$KEY_PART"
chmod 600 "$KEY_PART"

# Origin O — GSI root:// server, writable.
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
# Node W — storage_backend root://O + cache + stage, cert+key credential.
cat > "$PFX/w/nginx.conf" <<EOF
daemon on; error_log $PFX/w/logs/e.log info; pid $PFX/w/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream {
    brix_credential origin { x509_cert $CERT_PART; x509_key $KEY_PART; ca_dir $CA_DIR; }
    server {
        listen 127.0.0.1:${WPORT}; brix_root on; brix_export $PFX/w/export; brix_auth none;
        brix_allow_write on;
        brix_storage_backend root://127.0.0.1:${OPORT};
        brix_storage_credential origin;
        brix_cache_store posix:$PFX/w/cache;
        brix_stage on; brix_stage_store posix:$PFX/w/staging; brix_stage_flush async;
    }
}
EOF
# Node N — no credential (negative control: origin rejects the anonymous flush).
cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${NPORT}; brix_root on; brix_export $PFX/n/export; brix_auth none;
    brix_allow_write on;
    brix_storage_backend root://127.0.0.1:${OPORT};
    brix_cache_store posix:$PFX/n/cache;
    brix_stage on; brix_stage_store posix:$PFX/n/staging; brix_stage_flush async;
} }
EOF

head -c 400000 /dev/urandom > /tmp/cred_gsi_wb_src.bin
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/w" -c "$PFX/w/nginx.conf" 2>"$PFX/w/err" || { echo "W start failed"; cat "$PFX/w/err"; exit 2; }
"$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo "N start failed"; cat "$PFX/n/err"; exit 2; }
sleep 1

echo "== cert+key credential: write through to the GSI origin (flush authenticates) =="
"$XRDCP" -f /tmp/cred_gsi_wb_src.bin root://127.0.0.1:${WPORT}//wb.bin >/dev/null 2>"$PFX/w/logs/cp.err"
# wait for the async flush to reach the origin
landed=0
for _ in $(seq 1 20); do
    [ -f "$PFX/o/root/wb.bin" ] && cmp -s /tmp/cred_gsi_wb_src.bin "$PFX/o/root/wb.bin" && { landed=1; break; }
    sleep 0.5
done
if [ "$landed" = 1 ]; then
    ok "flush authenticated + wrote through to the GSI origin byte-exact"
else
    bad "flush did NOT reach the origin (size=$(stat -c%s "$PFX/o/root/wb.bin" 2>/dev/null || echo missing))"
    grep -iE "sd_xroot: origin|no credential|gsi|staged_open|auth|require" "$PFX/w/logs/e.log" | tail -8
fi

echo "== negative control: no credential ⇒ the origin rejects the anonymous flush =="
"$XRDCP" -f /tmp/cred_gsi_wb_src.bin root://127.0.0.1:${NPORT}//nb.bin >/dev/null 2>/dev/null
nlanded=0
for _ in $(seq 1 10); do
    [ -f "$PFX/o/root/nb.bin" ] && cmp -s /tmp/cred_gsi_wb_src.bin "$PFX/o/root/nb.bin" && { nlanded=1; break; }
    sleep 0.5
done
if [ "$nlanded" = 1 ]; then
    bad "UNAUTHENTICATED flush unexpectedly reached the origin (GSI not enforced!)"
else
    ok "anonymous flush correctly rejected by the GSI origin"
fi

[ "$fail" = 0 ] && echo "run_credential_xroot_gsi_writeback: ALL PASS" || echo "run_credential_xroot_gsi_writeback: FAILURES"
exit "$fail"
