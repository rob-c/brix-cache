#!/usr/bin/env bash
# Phase-4b end-to-end: a delegating GSI client -> our terminating tap proxy
# (brix_tap_proxy_auth gsi, delegation capture) -> a GSI-only upstream. The
# proxy logs into the upstream AS THE USER with the delegated proxy and forwards;
# the read must be byte-exact and the tap must log the opcodes.
#
# Client note: X.509 proxy delegation on a *plain read* is armed by THIS repo's
# xrdcp via XRDC_GSI_DELEGATE=1.  The stock /usr/bin/xrdcp only arms delegation
# for a `--tpc delegate` operation (the env var alone leaves dlgpxy=0), so a stock
# plain read cannot delegate — it is exercised here as a clean-decline negative.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUR_XRDCP="${OUR_XRDCP:-$HERE/client/bin/xrdcp}"
STOCK_XRDCP="/usr/bin/xrdcp"
OP=11970; PP=11971
PFX="$(mktemp -d /tmp/tapgsi.XXXXXX)"
fail=0
ok(){ printf '  ok   %s\n' "$1"; }
bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o n; do [ -f "$PFX/$r/pid" ] && kill "$(cat "$PFX/$r/pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/tapgsi_*.got; }
trap cleanup EXIT

[ -x "$STOCK_XRDCP" ] || { echo "SKIP: stock xrdcp not installed"; exit 0; }

TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"
CA_CERT="$TEST_ROOT/pki/ca/ca.pem"; CA_DIR="$TEST_ROOT/pki/ca"
SERVER_CERT="$TEST_ROOT/pki/server/hostcert.pem"; SERVER_KEY="$TEST_ROOT/pki/server/hostkey.pem"
PROXY_STD="$TEST_ROOT/pki/user/proxy_std.pem"
if [ ! -f "$CA_CERT" ] || [ ! -f "$SERVER_CERT" ] || [ ! -f "$PROXY_STD" ] \
   || ! openssl x509 -in "$PROXY_STD" -noout -checkend 300 >/dev/null 2>&1; then
    ( cd "$HERE/tests" && PYTHONPATH=. python3 -c "import pki_helpers; pki_helpers.blitz_test_pki()" ) \
        >"$PFX/pki.log" 2>&1 || { echo "SKIP: PKI provisioning failed"; cat "$PFX/pki.log"; exit 0; }
fi

mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/n/logs"

# Origin O — GSI-only root:// upstream (accepts the delegated user proxy).
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${OP}; xrootd on; brix_root $PFX/o/root;
    brix_auth gsi;
    brix_certificate     $SERVER_CERT;
    brix_certificate_key $SERVER_KEY;
    brix_trusted_ca      $CA_CERT;
} }
EOF

# Tap proxy — GSI inbound + delegation capture, GSI-as-user upstream.
cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/pid;
thread_pool default threads=4;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${PP}; xrootd on;
    brix_auth gsi;
    brix_gsi_signed_dh require;
    brix_tpc_delegate on;
    brix_certificate     $SERVER_CERT;
    brix_certificate_key $SERVER_KEY;
    brix_trusted_ca      $CA_CERT;
    brix_tap_proxy on;
    brix_tap_proxy_upstream 127.0.0.1:${OP};
    brix_tap_proxy_auth gsi;
} }
EOF

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo origin-fail; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo proxy-fail; cat "$PFX/n/err"; exit 2; }
sleep 1
head -c 400000 /dev/urandom > "$PFX/o/root/f.bin"

export X509_USER_PROXY="$PROXY_STD" X509_CERT_DIR="$CA_DIR" XrdSecGSICADIR="$CA_DIR"
# connect by the cert-CN name (localhost) so the client does not "use DNS"

# --- positive: THIS repo's delegating client -> tap proxy -> GSI upstream ---
if [ -x "$OUR_XRDCP" ]; then
    XRDC_GSI_DELEGATE=1 "$OUR_XRDCP" -f "root://localhost:${PP}//f.bin" \
        "/tmp/tapgsi_a.got" >"$PFX/n/logs/xrdcp.log" 2>&1
    rc=$?
    if [ $rc -eq 0 ] && cmp -s "$PFX/o/root/f.bin" /tmp/tapgsi_a.got; then
        ok "GSI delegation: repo client -> tap proxy -> GSI upstream byte-exact"
    else
        bad "GSI delegation read failed (rc=$rc) — see proxy log below"
    fi
    # the upstream must have authenticated the PROXY's pull as the delegated USER
    grep -q "GSI auth OK dn=\"/DC=test/DC=xrootd/CN=Test" "$PFX/o/logs/e.log" \
        && ok "upstream authenticated the forward as the delegated user" \
        || bad "upstream did not authenticate as the delegated user"
    grep -q '"op":"open"' "$PFX/n/logs/e.log" && ok "tap logged open" \
        || bad "tap did not log open"
else
    echo "  SKIP repo-client delegation (build client first: make -C client xrdcp)"
fi

# --- negative: stock plain read cannot delegate → clean decline, NO crash ---
XrdSecGSIDELEGPROXY=2 "$STOCK_XRDCP" -f "root://localhost:${PP}//f.bin" \
    "/tmp/tapgsi_b.got" >"$PFX/n/logs/xrdcp_stock.log" 2>&1
grep -q 'declined to delegate' "$PFX/n/logs/e.log" \
    && ok "stock plain-read client declines delegation cleanly" \
    || bad "stock client did not produce the expected clean decline"
grep -q 'signal 11' "$PFX/n/logs/e.log" \
    && bad "proxy CRASHED on the stock non-delegating client" \
    || ok "proxy survived the stock non-delegating client (no crash)"

# diagnostics on failure
if [ $fail -ne 0 ]; then
    echo "--- proxy error.log (tail) ---"; tail -25 "$PFX/n/logs/e.log"
    echo "--- xrdcp.log (tail) ---"; tail -15 "$PFX/n/logs/xrdcp.log"
fi
exit $fail
