#!/usr/bin/env bash
# run_credential_xroot_ztn.sh — C-3 (token half, phase-63): the §14 brix_credential
# threads a WLCG/SciToken bearer into the sd_xroot source driver, which presents it to
# a token-auth root:// origin via XrdSecztn (kXR_login → kXR_authmore → ztn kXR_auth).
# Origin O REQUIRES token auth (brix_auth token); node B caches over root://O with a
# token_file credential. A read miss fills only when the token authenticates the
# origin session. Negative control: a node without the credential is rejected.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"; XRDFS="$HERE/client/bin/xrdfs"
OPORT=11692; BPORT=11693; NPORT=11694; PFX="$(mktemp -d /tmp/cred_ztn.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o b n; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/cred_ztn_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/b/export" "$PFX/b/cache" "$PFX/b/logs" \
         "$PFX/n/export" "$PFX/n/cache" "$PFX/n/logs"

# Local signing authority + a read token (WLCG profile).
if ! python3 "$HERE/utils/make_token.py" init "$PFX/tok" >/dev/null 2>"$PFX/mk.err"; then
    echo "SKIP: make_token.py init failed (cryptography missing?)"; cat "$PFX/mk.err"; exit 0
fi
python3 "$HERE/utils/make_token.py" gen --scope "storage.read:/ storage.modify:/" \
        --output "$PFX/token.jwt" "$PFX/tok" >/dev/null 2>&1 \
    || { echo "SKIP: token gen failed"; exit 0; }

# Origin O — root:// server that REQUIRES token auth.
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${OPORT}; brix_root on; brix_export $PFX/o/root;
    brix_auth token;
    brix_token_jwks     $PFX/tok/jwks.json;
    brix_token_issuer   https://test.example.com;
    brix_token_audience nginx-xrootd;
    brix_allow_write on;
} }
EOF
# Node B — cache over root://O, authenticating with the token (sd_xroot ztn).
cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream {
    brix_credential origin { token_file $PFX/token.jwt; }
    server {
        listen 127.0.0.1:${BPORT}; brix_root on; brix_export $PFX/b/export; brix_auth none;
        brix_storage_backend root://127.0.0.1:${OPORT};
        brix_storage_credential origin;
        brix_cache on; brix_cache_export $PFX/b/cache;
    }
}
EOF
# Node N — same, but NO credential (negative control: anonymous login rejected).
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
sleep 1

echo "== with token credential: sd_xroot authenticates the origin via ztn, cache fills =="
"$XRDFS" root://127.0.0.1:${BPORT} cat /small.bin > /tmp/cred_ztn_s.got 2>"$PFX/b/logs/cat.err"
cmp -s "$PFX/o/root/small.bin" /tmp/cred_ztn_s.got && ok "byte-exact serve (ztn-authenticated fill)" \
  || { bad "differs/empty"; grep -iE 'ztn|token|auth|origin|cache|error' "$PFX/b/logs/e.log" | tail -10; }
"$XRDFS" root://127.0.0.1:${BPORT} cat /big.bin > /tmp/cred_ztn_b.got 2>/dev/null
cmp -s "$PFX/o/root/big.bin" /tmp/cred_ztn_b.got && ok "multi-chunk ztn-authenticated fill byte-exact" \
  || bad "multi-chunk differs (got=$(stat -c%s /tmp/cred_ztn_b.got 2>/dev/null))"

echo "== negative control: no credential ⇒ anonymous login rejected ⇒ fill fails =="
"$XRDFS" root://127.0.0.1:${NPORT} cat /small.bin > /tmp/cred_ztn_n.got 2>/dev/null
if [ -s /tmp/cred_ztn_n.got ] && cmp -s "$PFX/o/root/small.bin" /tmp/cred_ztn_n.got; then
    bad "UNAUTHENTICATED fill unexpectedly succeeded (token not enforced!)"
else
    ok "unauthenticated fill correctly failed (origin required a token)"
fi

[ "$fail" = 0 ] && echo "run_credential_xroot_ztn: ALL PASS" || echo "run_credential_xroot_ztn: FAILURES"
exit "$fail"
