#!/usr/bin/env bash
# run_credential_http_bearer.sh — §14 (phase-63): the brix_credential block +
# brix_storage_credential reference thread a BEARER token into the sd_http source
# driver. The HTTP origin REQUIRES `Authorization: Bearer <tok>` (401 otherwise), so
# the cache can only fill when the credential is wired. Proves: (1) with the right
# credential the fill succeeds byte-exact; (2) a token_file is read the same way;
# (3) WITHOUT the credential the same origin returns 401 → the fill fails (negative).
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"; XRDFS="$HERE/client/bin/xrdfs"
HPORT=11688; BPORT=11689; NPORT=11690; PFX="$(mktemp -d /tmp/cred_http.XXXXXX)"; fail=0
TOK="s3cr3t-bearer-tok-42"
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o b n; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/cred_http_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/b/export" "$PFX/b/cache" "$PFX/b/logs" \
         "$PFX/n/export" "$PFX/n/cache" "$PFX/n/logs"
printf '%s' "$TOK" > "$PFX/token_file"

# Bearer-gated static HTTP origin (plain nginx): 401 unless the exact Bearer arrives.
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
http {
    access_log off;
    server {
        listen 127.0.0.1:${HPORT};
        location / {
            if (\$http_authorization != "Bearer ${TOK}") { return 401; }
            root $PFX/o/root;
        }
    }
}
EOF
# Node B — cache over the bearer HTTP source, credential by INLINE token.
cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream {
    brix_credential web { token ${TOK}; }
    server {
        listen 127.0.0.1:${BPORT}; xrootd on; brix_root $PFX/b/export; brix_auth none;
        brix_storage_backend http://127.0.0.1:${HPORT};
        brix_storage_credential web;
        brix_cache on; brix_cache_root $PFX/b/cache;
    }
}
EOF
# Node N — same, but NO credential (negative control: fills must 401-fail).
cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${NPORT}; xrootd on; brix_root $PFX/n/export; brix_auth none;
    brix_storage_backend http://127.0.0.1:${HPORT};
    brix_cache on; brix_cache_root $PFX/n/cache;
} }
EOF

head -c 500000  /dev/urandom > "$PFX/o/root/small.bin"
head -c 2600000 /dev/urandom > "$PFX/o/root/big.bin"
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B start failed"; cat "$PFX/b/err"; exit 2; }
"$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo "N start failed"; cat "$PFX/n/err"; exit 2; }
sleep 1

echo "== with credential: cache fills through sd_http with Authorization: Bearer =="
"$XRDFS" root://127.0.0.1:${BPORT} cat /small.bin > /tmp/cred_http_s.got 2>"$PFX/b/logs/cat.err"
cmp -s "$PFX/o/root/small.bin" /tmp/cred_http_s.got && ok "byte-exact serve (authenticated fill)" \
  || { bad "differs/empty"; grep -iE 'cache|http|backend|auth|401|error' "$PFX/b/logs/e.log" | tail -8; }
"$XRDFS" root://127.0.0.1:${BPORT} cat /big.bin > /tmp/cred_http_b.got 2>/dev/null
cmp -s "$PFX/o/root/big.bin" /tmp/cred_http_b.got && ok "multi-chunk authenticated fill byte-exact" \
  || bad "multi-chunk differs (got=$(stat -c%s /tmp/cred_http_b.got 2>/dev/null))"

echo "== negative control: no credential ⇒ origin 401 ⇒ fill fails (no bytes) =="
"$XRDFS" root://127.0.0.1:${NPORT} cat /small.bin > /tmp/cred_http_n.got 2>/dev/null
if [ -s /tmp/cred_http_n.got ] && cmp -s "$PFX/o/root/small.bin" /tmp/cred_http_n.got; then
    bad "UNAUTHENTICATED fill unexpectedly succeeded (bearer not enforced!)"
else
    ok "unauthenticated fill correctly failed (401 enforced upstream)"
fi

echo "== token_file form: a node reading the bearer from a file works too =="
# reuse node B's conf shape but with token_file; restart B with a token_file credential
kill "$(cat "$PFX/b/nginx.pid")" 2>/dev/null; sleep 0.3; rm -f "$PFX/b/cache"/* 2>/dev/null
sed "s|token ${TOK};|token_file $PFX/token_file;|" "$PFX/b/nginx.conf" > "$PFX/b/nginx2.conf"
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx2.conf" 2>"$PFX/b/err2" || { bad "B(token_file) start failed"; cat "$PFX/b/err2"; }
sleep 1
"$XRDFS" root://127.0.0.1:${BPORT} cat /small.bin > /tmp/cred_http_tf.got 2>/dev/null
cmp -s "$PFX/o/root/small.bin" /tmp/cred_http_tf.got && ok "token_file credential authenticated fill byte-exact" \
  || bad "token_file fill differs/empty"

[ "$fail" = 0 ] && echo "run_credential_http_bearer: ALL PASS" || echo "run_credential_http_bearer: FAILURES"
exit "$fail"
