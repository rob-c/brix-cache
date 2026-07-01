#!/usr/bin/env bash
# Phase-4b HYBRID end-to-end: a delegating GSI client -> our nginx terminating
# tap proxy (xrootd_tap_proxy_auth gsi, delegation capture) -> an OFFICIAL
# `xrootd` upstream. Unlike run_tap_proxy_gsi.sh (nginx upstream), this proves the
# proxy's OUTBOUND GSI login — presenting the captured user proxy — interoperates
# with a real XRootD server, which maps the delegated DN and logs the proxy's pull
# in AS THE USER. GSI auth ONLY on every hop.
#
# Clients: THIS repo's xrdcp arms plain-read delegation via XRDC_GSI_DELEGATE=1
# (positive). The stock /usr/bin/xrdcp cannot delegate on a plain read (only via
# `--tpc delegate`), so it is the clean-decline negative.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUR_XRDCP="${OUR_XRDCP:-$HERE/client/bin/xrdcp}"
STOCK_XRDCP="/usr/bin/xrdcp"
XO=12070; PP=12071
PFX="$(mktemp -d /tmp/taphybrid.XXXXXX)"
fail=0
ok(){ printf '  ok   %s\n' "$1"; }
bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){
    [ -f "$PFX/up.pid" ] && kill "$(cat "$PFX/up.pid")" 2>/dev/null
    fuser -k ${XO}/tcp ${PP}/tcp 2>/dev/null
    [ -f "$PFX/n.pid" ] && kill "$(cat "$PFX/n.pid")" 2>/dev/null
    rm -rf "$PFX" /tmp/taphybrid_*.got
}
trap cleanup EXIT

command -v xrootd >/dev/null 2>&1 || { echo "SKIP: official xrootd not installed"; exit 0; }
[ -x "$STOCK_XRDCP" ] || { echo "SKIP: stock xrdcp not installed"; exit 0; }
[ -x "$NGINX" ] || { echo "SKIP: nginx not built"; exit 0; }

TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"
CA="$TEST_ROOT/pki/ca/ca.pem"; CADIR="$TEST_ROOT/pki/ca"
SC="$TEST_ROOT/pki/server/hostcert.pem"; SK="$TEST_ROOT/pki/server/hostkey.pem"
PROXY_STD="$TEST_ROOT/pki/user/proxy_std.pem"; USERCERT="$TEST_ROOT/pki/user/usercert.pem"
if [ ! -f "$CA" ] || [ ! -f "$SC" ] || [ ! -f "$PROXY_STD" ] \
   || ! openssl x509 -in "$PROXY_STD" -noout -checkend 300 >/dev/null 2>&1; then
    ( cd "$HERE/tests" && PYTHONPATH=. python3 -c "import pki_helpers; pki_helpers.blitz_test_pki()" ) \
        >"$PFX/pki.log" 2>&1 || { echo "SKIP: PKI provisioning failed"; cat "$PFX/pki.log"; exit 0; }
fi

mkdir -p "$PFX/data" "$PFX/n"
head -c 400000 /dev/urandom > "$PFX/data/f.bin"
cp "$SK" "$PFX/hostkey.pem"; chmod 600 "$PFX/hostkey.pem"

# gridmap the user's END-ENTITY DN (xrootd strips proxy CNs down to it).
ME="$(id -un)"
EEC_DN="$(openssl x509 -in "$USERCERT" -noout -subject -nameopt compat 2>/dev/null | sed 's/^subject= *//')"
printf '"%s" %s\n' "$EEC_DN" "$ME" > "$PFX/gridmap"

# --- OFFICIAL xrootd GSI-only upstream ---
cat > "$PFX/xrootd.cfg" <<EOF
xrd.port $XO
all.export /data
oss.localroot $PFX
xrootd.seclib libXrdSec.so
sec.protocol /usr/lib64 gsi -certdir:$CADIR -cert:$SC -key:$PFX/hostkey.pem -gridmap:$PFX/gridmap -d:1 -crl:0 -gmapopt:2
sec.protbind * only gsi
EOF
fuser -k ${XO}/tcp 2>/dev/null; sleep 0.3
xrootd -c "$PFX/xrootd.cfg" -l "$PFX/xrootd.log" -n up >/dev/null 2>&1 &
echo $! > "$PFX/up.pid"
for _ in $(seq 1 50); do ss -tln | grep -q ":$XO " && break; sleep 0.1; done
ss -tln | grep -q ":$XO " || { echo "SKIP: official xrootd upstream did not start"; exit 0; }

# --- our nginx tap proxy: GSI in + delegation capture, GSI-as-user upstream ---
cat > "$PFX/n.conf" <<EOF
daemon on; error_log $PFX/n/e.log info; pid $PFX/n.pid;
thread_pool default threads=4;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:$PP; xrootd on;
  xrootd_auth gsi; xrootd_gsi_signed_dh require; xrootd_tpc_delegate on;
  xrootd_certificate $SC; xrootd_certificate_key $SK; xrootd_trusted_ca $CA;
  xrootd_tap_proxy on; xrootd_tap_proxy_upstream 127.0.0.1:$XO; xrootd_tap_proxy_auth gsi; } }
EOF
fuser -k ${PP}/tcp 2>/dev/null; sleep 0.3
"$NGINX" -p "$PFX/n" -c "$PFX/n.conf" 2>"$PFX/n.err" || { echo "proxy-fail"; cat "$PFX/n.err"; exit 2; }
for _ in $(seq 1 30); do ss -tln | grep -q ":$PP " && break; sleep 0.1; done

export X509_USER_PROXY="$PROXY_STD" X509_CERT_DIR="$CADIR" XrdSecGSICADIR="$CADIR"

# --- positive: repo delegating client -> nginx tap proxy -> OFFICIAL xrootd ---
# xrootd -n up writes its log under the instance subdir (…/up/xrootd.log).
UPLOG="$PFX/up/xrootd.log"
if [ -x "$OUR_XRDCP" ]; then
    : > "$UPLOG"
    XRDC_GSI_DELEGATE=1 "$OUR_XRDCP" -f "root://localhost:${PP}//data/f.bin" \
        /tmp/taphybrid_a.got >"$PFX/n/xrdcp.log" 2>&1
    rc=$?
    if [ $rc -eq 0 ] && cmp -s "$PFX/data/f.bin" /tmp/taphybrid_a.got; then
        ok "repo client -> nginx tap proxy -> OFFICIAL xrootd byte-exact"
    else
        bad "hybrid delegated read failed (rc=$rc)"; tail -15 "$PFX/n/e.log"
    fi
    grep -q "login as ${ME}" "$UPLOG" \
        && ok "official xrootd mapped the delegated proxy + logged the pull in as the user" \
        || bad "official xrootd did not log the proxy's pull in as the user"
    grep -q '"op":"open"' "$PFX/n/e.log" && ok "tap logged open" || bad "tap did not log open"
else
    echo "  SKIP repo-client delegation (build: make -C client xrdcp)"
fi

# --- negative: stock plain read cannot delegate → clean decline, NO crash ---
XrdSecGSIDELEGPROXY=2 "$STOCK_XRDCP" -f "root://localhost:${PP}//data/f.bin" \
    /tmp/taphybrid_b.got >"$PFX/n/xrdcp_stock.log" 2>&1
grep -q 'declined to delegate' "$PFX/n/e.log" \
    && ok "stock plain-read client declines delegation cleanly" \
    || bad "stock client did not produce the expected clean decline"
grep -q 'signal 11' "$PFX/n/e.log" \
    && bad "proxy CRASHED on the stock non-delegating client" \
    || ok "proxy survived the stock non-delegating client (no crash)"

[ $fail -eq 0 ] && echo "run_tap_proxy_gsi_hybrid: ALL PASS" || echo "run_tap_proxy_gsi_hybrid: FAILURES"
exit $fail
