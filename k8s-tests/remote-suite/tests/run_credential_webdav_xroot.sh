#!/usr/bin/env bash
# run_credential_webdav_xroot.sh — §14 http-scope parity (phase-63): the
# brix_credential block + brix_webdav_storage_credential work at HTTP (WebDAV)
# scope, sharing the same process-wide credential registry as the stream scope. A
# WebDAV export whose PRIMARY is a TOKEN-AUTH root:// origin authenticates via the
# sd_xroot ztn path (C-3 token half) using the named credential. GET byte-exact with
# the credential; a node without it is rejected (negative control).
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OPORT=11696; WPORT=8472; NPORT=8473; PFX="$(mktemp -d /tmp/cred_dav.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o w n; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/cred_dav_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/w/export" "$PFX/w/logs" "$PFX/n/export" "$PFX/n/logs"

if ! python3 "$HERE/utils/make_token.py" init "$PFX/tok" >/dev/null 2>"$PFX/mk.err"; then
    echo "SKIP: make_token.py init failed"; cat "$PFX/mk.err"; exit 0
fi
python3 "$HERE/utils/make_token.py" gen --scope "storage.read:/ storage.modify:/" \
        --output "$PFX/token.jwt" "$PFX/tok" >/dev/null 2>&1 || { echo "SKIP: token gen failed"; exit 0; }

# Token-auth root:// origin.
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${OPORT}; xrootd on; brix_root $PFX/o/root;
    brix_auth token; brix_token_jwks $PFX/tok/jwks.json;
    brix_token_issuer https://test.example.com; brix_token_audience nginx-xrootd;
    brix_allow_write on;
} }
EOF
# WebDAV node W — http-scope credential block + reference.
cat > "$PFX/w/nginx.conf" <<EOF
daemon on; error_log $PFX/w/logs/e.log info; pid $PFX/w/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    brix_credential origin { token_file $PFX/token.jwt; }
    server {
        listen 127.0.0.1:${WPORT};
        location / {
            brix_webdav on; brix_webdav_root $PFX/w/export; brix_webdav_auth none;
            brix_webdav_storage_backend    root://127.0.0.1:${OPORT};
            brix_webdav_storage_credential origin;
        }
    }
}
EOF
# Node N — no credential (negative control).
cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http { server { listen 127.0.0.1:${NPORT}; location / {
    brix_webdav on; brix_webdav_root $PFX/n/export; brix_webdav_auth none;
    brix_webdav_storage_backend root://127.0.0.1:${OPORT};
} } }
EOF

head -c 250000  /dev/urandom > "$PFX/o/root/a.bin"
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/w" -c "$PFX/w/nginx.conf" 2>"$PFX/w/err" || { echo "W start failed"; cat "$PFX/w/err"; exit 2; }
"$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo "N start failed"; cat "$PFX/n/err"; exit 2; }
sleep 1

echo "== WebDAV GET over a token-auth origin: sd_xroot ztn with the http-scope credential =="
code=$(curl -s -o /tmp/cred_dav_a.got -w '%{http_code}' "http://127.0.0.1:${WPORT}/a.bin")
if [ "$code" = 200 ] && cmp -s "$PFX/o/root/a.bin" /tmp/cred_dav_a.got; then
    ok "GET byte-exact (ztn-authenticated via http-scope credential)"
else
    bad "GET failed (code=$code)"; grep -iE 'ztn|token|auth|origin|error' "$PFX/w/logs/e.log" | tail -8
fi

echo "== negative control: no credential ⇒ origin token auth rejects the read =="
ncode=$(curl -s -o /tmp/cred_dav_n.got -w '%{http_code}' "http://127.0.0.1:${NPORT}/a.bin")
if [ "$ncode" = 200 ] && cmp -s "$PFX/o/root/a.bin" /tmp/cred_dav_n.got; then
    bad "UNAUTHENTICATED GET unexpectedly succeeded (token not enforced!)"
else
    ok "unauthenticated GET correctly failed (code=$ncode)"
fi

[ "$fail" = 0 ] && echo "run_credential_webdav_xroot: ALL PASS" || echo "run_credential_webdav_xroot: FAILURES"
exit "$fail"
