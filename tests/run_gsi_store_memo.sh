#!/usr/bin/env bash
# run_gsi_store_memo.sh — regression guard for slow restart caused by rebuilding
# the (expensive) IGTF CA/CRL X509_STORE once PER GSI server block.
#
# Loading a real grid CA distribution's hundreds of *.r0 CRLs takes ~1s. brix
# used to pay that once for EACH brix_auth-gsi server block (root://, davs://,
# …) at config load, adding seconds of dead time to every restart. The fix
# memoises the built store by its inputs (brix_build_ca_store_cached), so blocks
# that share the same trusted_ca/CRL dir build it once and share it; the
# per-worker CRL hot-reload timer still rebuilds from fresh CRLs (uncached).
#
# This test stands up TWO stream GSI server blocks with the SAME trusted CA and
# asserts, from `nginx -t`, that the store is built ONCE and the second block
# REUSES it. Pure config load, fast, no fleet.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
PFX="$(mktemp -d /tmp/gsi_memo.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/logs" "$PFX/e1" "$PFX/e2"

TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"
CA_CERT="$TEST_ROOT/pki/ca/ca.pem"
SC="$TEST_ROOT/pki/server/hostcert.pem"; SK="$TEST_ROOT/pki/server/hostkey.pem"
if [ ! -f "$CA_CERT" ] || [ ! -f "$SC" ]; then
    ( cd "$HERE/tests" && PYTHONPATH=. python3 -c "import pki_helpers; pki_helpers.blitz_test_pki()" ) \
        >"$PFX/logs/pki.log" 2>&1 || { echo "SKIP: PKI provisioning failed"; exit 0; }
fi

# Two GSI server blocks, IDENTICAL trusted CA (a single-file CA here; the same
# memo path applies to a hashed CA directory, only slower to build).
cat > "$PFX/nginx.conf" <<EOF
daemon off; error_log stderr info; pid $PFX/nginx.pid;
events { worker_connections 64; }
stream {
    server {
        listen 127.0.0.1:15701; brix_root on; brix_export $PFX/e1;
        brix_auth gsi; brix_certificate $SC; brix_certificate_key $SK;
        brix_trusted_ca $CA_CERT;
    }
    server {
        listen 127.0.0.1:15702; brix_root on; brix_export $PFX/e2;
        brix_auth gsi; brix_certificate $SC; brix_certificate_key $SK;
        brix_trusted_ca $CA_CERT;
    }
}
EOF

out="$("$NGINX" -t -c "$PFX/nginx.conf" 2>&1)"
printf '%s' "$out" | grep -q "test is successful" \
  || { bad "config did not load"; printf '%s\n' "$out" | tail -8; echo "run_gsi_store_memo: FAILURES"; exit 1; }

# The memo fires when the SECOND GSI block reuses the store the first built —
# that is the guarantee that the expensive CRL directory is loaded once, not
# once per block. (Note: the "GSI trust store built ... in <N>us" line is logged
# per configure call regardless of reuse — on a reuse <N> is ~0 — so it is NOT a
# build count; the "reusing the CA/CRL store" NOTICE is the real signal.)
reused=$(printf '%s\n' "$out" | grep -c "reusing the CA/CRL store")

echo "== two GSI blocks, same trusted CA: the store is built once and reused =="
[ "$reused" -ge 1 ] && ok "second block reused the memoised CA/CRL store (no per-block rebuild)" \
  || { bad "second GSI block did NOT reuse the store — the expensive CRL load runs once per block (slow-restart regression)"; printf '%s\n' "$out" | grep -iE "trust store|reusing|CA/CRL"; }

[ "$fail" = 0 ] && echo "run_gsi_store_memo: ALL PASS" || echo "run_gsi_store_memo: FAILURES"
exit "$fail"
