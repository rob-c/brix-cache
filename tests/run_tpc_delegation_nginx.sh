#!/usr/bin/env bash
# GSI X.509 proxy delegation for third-party copy with our nginx as a real
# FILESERVER on BOTH ends (source + destination), distinct from the tap/MITM
# proxy.  A delegating client (`xrdcp --tpc delegate`) hands its proxy to the
# nginx destination, which captures it and pulls the file from the nginx source
# AS THE USER.  Verified with both the official and this repo's xrdcp; GSI only.
#
# What this exercises that the tap-proxy tests do not:
#   * nginx as a delegation-capturing TPC *destination* that writes to its store;
#   * nginx as a TPC *source* that (a) advertises TPC to the client's CheckTPCLite
#     pre-flight and (b) authenticates the destination's delegated pull as the
#     USER (the pull DN carries the delegated proxy layer, not a gateway).
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUR_XRDCP="${OUR_XRDCP:-$HERE/client/bin/xrdcp}"
STOCK_XRDCP="/usr/bin/xrdcp"
SRCP=12080; DSTP=12081
PFX="$(mktemp -d /tmp/ngxtpcdlg.XXXXXX)"
fail=0
ok(){ printf '  ok   %s\n' "$1"; }
bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){
    for r in src dst; do [ -f "$PFX/$r.pid" ] && kill "$(cat "$PFX/$r.pid")" 2>/dev/null; done
    fuser -k ${SRCP}/tcp ${DSTP}/tcp 2>/dev/null
    rm -rf "$PFX"
}
trap cleanup EXIT

[ -x "$NGINX" ] || { echo "SKIP: nginx not built"; exit 0; }

TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"
CA="$TEST_ROOT/pki/ca/ca.pem"; CADIR="$TEST_ROOT/pki/ca"
SC="$TEST_ROOT/pki/server/hostcert.pem"; SK="$TEST_ROOT/pki/server/hostkey.pem"
PROXY_STD="$TEST_ROOT/pki/user/proxy_std.pem"
if [ ! -f "$CA" ] || [ ! -f "$SC" ] || [ ! -f "$PROXY_STD" ] \
   || ! openssl x509 -in "$PROXY_STD" -noout -checkend 300 >/dev/null 2>&1; then
    ( cd "$HERE/tests" && PYTHONPATH=. python3 -c "import pki_helpers; pki_helpers.blitz_test_pki()" ) \
        >"$PFX/pki.log" 2>&1 || { echo "SKIP: PKI provisioning failed"; cat "$PFX/pki.log"; exit 0; }
fi

mkdir -p "$PFX/src/root" "$PFX/dst/root" "$PFX/src/logs" "$PFX/dst/logs"
head -c 400000 /dev/urandom > "$PFX/src/root/f.bin"

# nginx SOURCE — GSI fileserver (read-only; must still advertise TPC as a source)
cat > "$PFX/src.conf" <<EOF
daemon on; error_log $PFX/src/logs/e.log info; pid $PFX/src.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:$SRCP; xrootd on; xrootd_root $PFX/src/root;
  xrootd_auth gsi; xrootd_certificate $SC; xrootd_certificate_key $SK; xrootd_trusted_ca $CA; } }
EOF
# nginx DEST — GSI fileserver + delegation-capturing TPC pull
cat > "$PFX/dst.conf" <<EOF
daemon on; error_log $PFX/dst/logs/e.log info; pid $PFX/dst.pid;
thread_pool default threads=4;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:$DSTP; xrootd on; xrootd_root $PFX/dst/root;
  xrootd_auth gsi; xrootd_gsi_signed_dh require; xrootd_allow_write on;
  xrootd_tpc_allow_local on; xrootd_tpc_allow_private on; xrootd_tpc_delegate on;
  xrootd_certificate $SC; xrootd_certificate_key $SK; xrootd_trusted_ca $CA; } }
EOF
fuser -k ${SRCP}/tcp ${DSTP}/tcp 2>/dev/null; sleep 0.3
"$NGINX" -p "$PFX/src" -c "$PFX/src.conf" 2>"$PFX/src.err" || { echo src-fail; cat "$PFX/src.err"; exit 2; }
"$NGINX" -p "$PFX/dst" -c "$PFX/dst.conf" 2>"$PFX/dst.err" || { echo dst-fail; cat "$PFX/dst.err"; exit 2; }
for _ in $(seq 1 30); do ss -tln | grep -q ":$SRCP " && ss -tln | grep -q ":$DSTP " && break; sleep 0.1; done

export X509_USER_PROXY="$PROXY_STD" X509_CERT_DIR="$CADIR" XrdSecGSICADIR="$CADIR"

# run one delegated TPC. $1=label $2=xrdcp $3=extra-env $4=out $5..=tpc args
run_case(){
    local label="$1" xrdcp="$2" env_extra="$3" out="$4"; shift 4
    : > "$PFX/src/logs/e.log"; rm -f "$PFX/dst/root/$out"
    env $env_extra "$xrdcp" -f "$@" \
        "root://localhost:${SRCP}//f.bin" "root://localhost:${DSTP}//$out" \
        >"$PFX/${label}.log" 2>&1
    local rc=$?
    if [ $rc -eq 0 ] && cmp -s "$PFX/src/root/f.bin" "$PFX/dst/root/$out"; then
        ok "$label: nginx source -> nginx dest delegated TPC byte-exact"
    else
        bad "$label: delegated TPC failed (rc=$rc)"; tail -6 "$PFX/${label}.log"
        return
    fi
    # the destination's pull must authenticate to the source as the delegated
    # USER — its DN carries an EXTRA proxy layer (two trailing numeric CNs: the
    # client's own proxy + the destination's delegated proxy).
    if grep -Eq 'GSI auth OK dn=".*CN=12345/CN=[0-9]+/CN=[0-9]+"' "$PFX/src/logs/e.log"; then
        ok "$label: source authenticated the pull as the delegated user"
    else
        bad "$label: source did not see the delegated (multi-hop) pull identity"
    fi
    [ "$(grep -c 'signal 11' "$PFX/dst/logs/e.log")" = 0 ] || bad "$label: dest crashed"
}

# stock syntax: `--tpc delegate only`; this repo's xrdcp: `--tpc delegate`.
run_case official "$STOCK_XRDCP" "" out_official.bin --tpc delegate only
[ -x "$OUR_XRDCP" ] && run_case repo "$OUR_XRDCP" "XRDC_GSI_DELEGATE=1" out_repo.bin --tpc delegate \
    || echo "  SKIP repo client (build: make -C client xrdcp)"

[ $fail -eq 0 ] && echo "run_tpc_delegation_nginx: ALL PASS" || echo "run_tpc_delegation_nginx: FAILURES"
exit $fail
