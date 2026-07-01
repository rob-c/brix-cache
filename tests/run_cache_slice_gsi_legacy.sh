#!/usr/bin/env bash
# run_cache_slice_gsi_legacy.sh — regression guard for the cache-config credential-field
# reconciliation (phase-64 cluster). A LEGACY xrootd_cache_origin config (host:port +
# xrootd_cache_origin_proxy/_cadir GSI directives) WITH xrootd_cache_slice must fill each
# slice through a GSI-authenticated origin session. The slice decorator builds its origin
# via the SHARED xrootd_cache_build_origin, which reads the read-origin credentials
# (cache_origin_proxy/cadir), NOT the write-back C-3 fields (cache_origin_x509_proxy/…)
# it wrongly read before — that bug left slice fills logging in ANONYMOUSLY, which a GSI
# origin rejects. Pre-fix: this FAILS (empty/rejected). Post-fix: byte-exact.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"; XRDFS="$HERE/client/bin/xrdfs"
OPORT=11762; BPORT=11763; NPORT=11764; PFX="$(mktemp -d /tmp/slice_gsi.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o b n; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/slice_gsi_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/b/export" "$PFX/b/cache" "$PFX/b/logs" \
         "$PFX/n/export" "$PFX/n/cache" "$PFX/n/logs"

TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"
CA_CERT="$TEST_ROOT/pki/ca/ca.pem"; CA_DIR="$TEST_ROOT/pki/ca"
SERVER_CERT="$TEST_ROOT/pki/server/hostcert.pem"; SERVER_KEY="$TEST_ROOT/pki/server/hostkey.pem"
PROXY_STD="$TEST_ROOT/pki/user/proxy_std.pem"

# Provision (or refresh) the CA-signed PKI (shared with run_credential_xroot_gsi.sh).
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
    listen 127.0.0.1:${OPORT}; xrootd on; xrootd_root $PFX/o/root;
    xrootd_auth gsi;
    xrootd_certificate     $SERVER_CERT;
    xrootd_certificate_key $SERVER_KEY;
    xrootd_trusted_ca      $CA_CERT;
    xrootd_allow_write on;
} }
EOF
# Node B — LEGACY slice cache over root://O, GSI via the cache_origin directives.
cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${BPORT}; xrootd on; xrootd_root $PFX/b/export; xrootd_auth none;
    xrootd_cache on;
    xrootd_cache_root  $PFX/b/cache;
    xrootd_cache_origin       127.0.0.1:${OPORT};
    xrootd_cache_origin_proxy $PROXY_STD;
    xrootd_cache_origin_cadir $CA_DIR;
    xrootd_cache_slice 1m;
} }
EOF
# Node N — legacy slice cache but NO proxy (negative control: anonymous → GSI rejects).
cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${NPORT}; xrootd on; xrootd_root $PFX/n/export; xrootd_auth none;
    xrootd_cache on;
    xrootd_cache_root  $PFX/n/cache;
    xrootd_cache_origin 127.0.0.1:${OPORT};
    xrootd_cache_slice 1m;
} }
EOF

head -c 2600000 /dev/urandom > "$PFX/o/root/big.bin"     # 3 slices @ 1 MiB
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B start failed"; cat "$PFX/b/err"; exit 2; }
"$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo "N start failed"; cat "$PFX/n/err"; exit 2; }
sleep 1

echo "== legacy cache_origin + proxy + slice: each slice fills through a GSI-auth origin =="
"$XRDFS" root://127.0.0.1:${BPORT} cat /big.bin > /tmp/slice_gsi_b.got 2>"$PFX/b/logs/cat.err"
cmp -s "$PFX/o/root/big.bin" /tmp/slice_gsi_b.got \
  && ok "multi-slice GSI-authenticated fill byte-exact" \
  || { bad "slice fill differs/empty (got=$(stat -c%s /tmp/slice_gsi_b.got 2>/dev/null)) — slice used the wrong credential?"; grep -iE 'gsi|proxy|auth|origin|slice|login|error' "$PFX/b/logs/e.log" | tail -12; }

echo "== warm read served from the sliced cache (no re-auth) =="
"$XRDFS" root://127.0.0.1:${BPORT} cat /big.bin > /tmp/slice_gsi_b2.got 2>/dev/null
cmp -s "$PFX/o/root/big.bin" /tmp/slice_gsi_b2.got && ok "warm multi-slice byte-exact" || bad "warm slice differs"

echo "== negative control: no proxy ⇒ anonymous slice fill rejected by the GSI origin =="
"$XRDFS" root://127.0.0.1:${NPORT} cat /big.bin > /tmp/slice_gsi_n.got 2>/dev/null
if [ -s /tmp/slice_gsi_n.got ] && cmp -s "$PFX/o/root/big.bin" /tmp/slice_gsi_n.got; then
    bad "UNAUTHENTICATED slice fill unexpectedly succeeded (GSI not enforced!)"
else
    ok "unauthenticated slice fill correctly failed (origin required GSI)"
fi

[ "$fail" = 0 ] && echo "run_cache_slice_gsi_legacy: ALL PASS" || echo "run_cache_slice_gsi_legacy: FAILURES"
exit "$fail"
