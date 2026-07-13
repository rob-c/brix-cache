#!/usr/bin/env bash
# run_gsi_intermediate_ca.sh — GSI against a REAL-WORLD CA topology: the server
# certificate hangs off an INTERMEDIATE CA (root -> issuing CA -> host cert, the
# UK eScience / IGTF shape) and the trust anchor is a hashed CA DIRECTORY, not a
# single bundle file.
#
# Regression for the xrd1 deployment failure: the kXGS_init sec token used to
# advertise ca:00000000 (the hash computation PEM-parsed brix_trusted_ca, which
# is silently empty when the directive names a DIRECTORY), and stock XrdSecgsi
# clients abort with "unknown CA: cannot verify server certificate" before the
# handshake proper.  The fix derives the ca: list from the server certificate's
# verified chain (intermediate + root subject hashes).
#
# Checks (against the STOCK system client, which enforces the ca: list):
#   1. wire      — the advertised sec token carries the real chain hashes
#   2. success   — stock xrdcp authenticates + transfers byte-exact
#   3. security  — a client with an empty CA dir refuses the server (MITM negative)
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDCP_STOCK="${XRDCP_STOCK:-/usr/bin/xrdcp}"
PORT=11712
PFX="$(mktemp -d /tmp/gsi_ica.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT

[ -x "$XRDCP_STOCK" ] || { echo "SKIP: stock xrootd client not installed ($XRDCP_STOCK)"; exit 0; }

mkdir -p "$PFX"/{pki/user,cadir,badca,root,logs}
cd "$PFX/pki"

# --- PKI: root CA -> intermediate CA -> server leaf; user EEC under the root ---
osl(){ openssl "$@" >>"$PFX/logs/pki.log" 2>&1 || { echo "SKIP: openssl PKI build failed ($*)"; exit 0; }; }
cat > ca.ext <<'E'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
E
cat > srv.ext <<'E'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
subjectAltName=DNS:localhost,IP:127.0.0.1
E
cat > usr.ext <<'E'
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
E
osl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 2 \
    -subj "/O=BrixTest/CN=Test Root CA" -addext basicConstraints=critical,CA:TRUE
osl req -newkey rsa:2048 -nodes -keyout inter.key -out inter.csr \
    -subj "/O=BrixTest/CN=Test Issuing CA 2B"
osl x509 -req -in inter.csr -CA root.pem -CAkey root.key -set_serial 101 \
    -days 2 -extfile ca.ext -out inter.pem
osl req -newkey rsa:2048 -nodes -keyout host.key -out host.csr \
    -subj "/O=BrixTest/CN=localhost"
osl x509 -req -in host.csr -CA inter.pem -CAkey inter.key -set_serial 202 \
    -days 2 -extfile srv.ext -out host.pem
osl req -newkey rsa:2048 -nodes -keyout user/userkey.pem -out user.csr \
    -subj "/O=BrixTest/CN=Test User"
osl x509 -req -in user.csr -CA root.pem -CAkey root.key -set_serial 303 \
    -days 2 -extfile usr.ext -out user/usercert.pem
chmod 0600 user/userkey.pem host.key

# RFC 3820 proxy for the stock client (it refuses bare EEC credentials).
python3 "$HERE/utils/make_proxy.py" "$PFX/pki" >>"$PFX/logs/pki.log" 2>&1 \
    || { echo "SKIP: make_proxy.py failed"; tail -3 "$PFX/logs/pki.log"; exit 0; }

# Hashed CA DIRECTORY (grid /etc/grid-security/certificates shape): both CAs.
for ca in root inter; do
    cp "$ca.pem" "$PFX/cadir/$(openssl x509 -in "$ca.pem" -noout -subject_hash).0"
done
INTER_HASH="$(openssl x509 -in inter.pem -noout -subject_hash)"
ROOT_HASH="$(openssl x509 -in root.pem -noout -subject_hash)"

# --- GSI server: leaf-only cert (as deployed hosts keep it), CA DIR trust ---
cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log notice; pid $PFX/nginx.pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${PORT}; brix_root on; brix_export $PFX/root;
    brix_auth gsi;
    brix_certificate     $PFX/pki/host.pem;
    brix_certificate_key $PFX/pki/host.key;
    brix_trusted_ca      $PFX/cadir;
    brix_allow_write on;
} }
EOF
"$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/logs/start.err" \
    || { echo "SKIP: server start failed"; cat "$PFX/logs/start.err"; exit 0; }
sleep 1

stock_cp(){ # <certdir> <proxy> <dst> <log>
    env -i PATH=/usr/bin:/bin HOME="$PFX" XRD_LOGLEVEL=Debug \
        X509_CERT_DIR="$1" X509_USER_PROXY="$2" \
        "$XRDCP_STOCK" -f "$PFX/src.bin" "root://localhost:${PORT}//$3" \
        >"$PFX/logs/$4" 2>&1
}

head -c 300000 /dev/urandom > "$PFX/src.bin"

echo "== STOCK client GSI handshake + transfer through the intermediate chain =="
stock_cp "$PFX/cadir" "$PFX/pki/user/proxy_std.pem" stock.bin cp.log
if cmp -s "$PFX/src.bin" "$PFX/root/stock.bin"; then
    ok "stock xrdcp wrote byte-exact through GSI (was: unknown CA / kXGS_init abort)"
else
    bad "stock xrdcp transfer failed"; grep -iE "secgsi|Error" "$PFX/logs/cp.log" | head -4
fi

echo "== advertised ca: list on the wire is the real issuer chain =="
if grep -q "ca:${INTER_HASH}|${ROOT_HASH}" "$PFX/logs/cp.log"; then
    ok "sec token advertises ca:${INTER_HASH}|${ROOT_HASH}"
else
    bad "token hash list wrong"; grep -o "ca:[0-9a-f|]*" "$PFX/logs/cp.log" | head -1
fi
grep -q "ca:00000000" "$PFX/logs/cp.log" \
    && bad "placeholder 00000000 advertised" || ok "no 00000000 placeholder"

echo "== MITM negative: client with an EMPTY CA dir must refuse the server =="
stock_cp "$PFX/badca" "$PFX/pki/user/proxy_std.pem" mitm.bin neg.log
if [ -e "$PFX/root/mitm.bin" ]; then
    bad "transfer succeeded against an unverifiable server cert"
else
    ok "client correctly refused the unverifiable server"
fi

[ $fail -eq 0 ] && echo "run_gsi_intermediate_ca: ALL PASS" || { echo "run_gsi_intermediate_ca: FAILURES"; exit 1; }
