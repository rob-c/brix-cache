#!/usr/bin/env bash
# run_credential_wt_ztn.sh — authenticated write-back (phase-63 C-3-token + C-5 + §14).
# A local POSIX export with write-through flushes dirty data to a TOKEN-AUTH root://
# origin through the sd_xroot driver, authenticating via ztn with an xrootd_credential
# named by xrootd_wt_credential. Completes the authenticated round-trip: the same
# JWT that authenticates a read fill (run_credential_xroot_ztn) now authenticates the
# write-back. Verifies the flush lands byte-exact on the token origin; a node without
# the credential cannot flush (negative control).
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"; XRDCP="$HERE/client/bin/xrdcp"
OPORT=11698; BPORT=11699; NPORT=11700; PFX="$(mktemp -d /tmp/cred_wt.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o b n; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/cred_wt_*.bin; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/b/export" "$PFX/b/logs" "$PFX/n/export" "$PFX/n/logs"

if ! python3 "$HERE/utils/make_token.py" init "$PFX/tok" >/dev/null 2>"$PFX/mk.err"; then
    echo "SKIP: make_token.py init failed"; cat "$PFX/mk.err"; exit 0
fi
python3 "$HERE/utils/make_token.py" gen --scope "storage.read:/ storage.modify:/ storage.create:/" \
        --output "$PFX/token.jwt" "$PFX/tok" >/dev/null 2>&1 || { echo "SKIP: token gen failed"; exit 0; }

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${OPORT}; xrootd on; xrootd_root $PFX/o/root;
    xrootd_auth token; xrootd_token_jwks $PFX/tok/jwks.json;
    xrootd_token_issuer https://test.example.com; xrootd_token_audience nginx-xrootd;
    xrootd_allow_write on; xrootd_upload_resume off;
} }
EOF
cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream {
    xrootd_credential origin { token_file $PFX/token.jwt; }
    server {
        listen 127.0.0.1:${BPORT}; xrootd on; xrootd_root $PFX/b/export; xrootd_auth none;
        xrootd_allow_write on; xrootd_upload_resume off;
        xrootd_write_through on; xrootd_wt_mode sync;
        xrootd_wt_origin     root://127.0.0.1:${OPORT};
        xrootd_wt_credential origin;
    }
}
EOF
cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${NPORT}; xrootd on; xrootd_root $PFX/n/export; xrootd_auth none;
    xrootd_allow_write on; xrootd_upload_resume off;
    xrootd_write_through on; xrootd_wt_mode sync;
    xrootd_wt_origin root://127.0.0.1:${OPORT};
} }
EOF

head -c 300000  /dev/urandom > /tmp/cred_wt_small.bin
head -c 2600000 /dev/urandom > /tmp/cred_wt_big.bin
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B start failed"; cat "$PFX/b/err"; exit 2; }
"$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo "N start failed"; cat "$PFX/n/err"; exit 2; }
sleep 1

echo "== authenticated write-back: write to B flushes to the TOKEN origin via sd_xroot ztn =="
"$XRDCP" -f /tmp/cred_wt_small.bin "root://127.0.0.1:${BPORT}//w.bin" >/dev/null 2>"$PFX/b/logs/put.err"
cmp -s /tmp/cred_wt_small.bin "$PFX/o/root/w.bin" && ok "flushed byte-exact to token origin (ztn write-back)" \
  || { bad "origin differs/missing"; grep -iE 'ztn|token|auth|wt:|origin|error' "$PFX/b/logs/e.log" | tail -8; }

echo "== multi-chunk authenticated write-back =="
"$XRDCP" -f /tmp/cred_wt_big.bin "root://127.0.0.1:${BPORT}//wbig.bin" >/dev/null 2>/dev/null
cmp -s /tmp/cred_wt_big.bin "$PFX/o/root/wbig.bin" && ok "multi-chunk ztn write-back byte-exact" \
  || bad "multi-chunk differs (origin=$(stat -c%s "$PFX/o/root/wbig.bin" 2>/dev/null))"

echo "== negative control: no wt_credential ⇒ write-back to token origin fails =="
"$XRDCP" -f /tmp/cred_wt_small.bin "root://127.0.0.1:${NPORT}//nw.bin" >/dev/null 2>/dev/null
if [ -f "$PFX/o/root/nw.bin" ] && cmp -s /tmp/cred_wt_small.bin "$PFX/o/root/nw.bin"; then
    bad "UNAUTHENTICATED write-back unexpectedly reached the token origin!"
else
    ok "unauthenticated write-back correctly failed to reach the token origin"
fi

[ "$fail" = 0 ] && echo "run_credential_wt_ztn: ALL PASS" || echo "run_credential_wt_ztn: FAILURES"
exit "$fail"
