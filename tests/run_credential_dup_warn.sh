#!/usr/bin/env bash
# run_credential_dup_warn.sh — regression guard for the "silent duplicate
# brix_credential" class of bug (the 2026-07-08 origin-write saga, see
# docs/09-developer-guide/postmortem-origin-credential-shadowing.md).
#
# brix_credential is ONE global, name-keyed registry shared across stream{} and
# http{}. Defining the SAME name twice (e.g. a stream block with x509_proxy and
# an http/conf.d block with x509_cert+x509_key) silently last-wins: the second
# block zeroes and overrides the first, so the effective credential is whichever
# parsed last — with NO error. On a real deployment this made every worker
# resolve the wrong (shadowing) credential and broke GSI auth to the origin for
# hours. The fix makes config-load emit a clear WARNING on a same-config
# redefinition (but NOT on a benign reload re-parse).
#
# This test asserts:
#   1. two brix_credential blocks of the SAME name in one config  -> WARN
#   2. a single brix_credential block                              -> NO warn
#   3. two blocks with DISTINCT names                              -> NO warn
# It is pure `nginx -t` (config load only) — no fleet, fast, deterministic.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
PFX="$(mktemp -d /tmp/cred_dup.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/logs" "$PFX/export"

WARN_RE='brix_credential "origin" is defined more than once'

# Emit a stream-only config; $1 = body of the stream{} block.
mkconf(){
    cat > "$PFX/nginx.conf" <<EOF
daemon off; error_log stderr info; pid $PFX/nginx.pid;
events { worker_connections 64; }
stream {
$1
    server {
        listen 127.0.0.1:15599; brix_root on; brix_export $PFX/export; brix_auth none;
    }
}
EOF
}

echo "== 1. duplicate 'origin' (proxy block + cert/key block) -> WARN =="
mkconf '
    brix_credential origin { x509_proxy /tmp/p.pem; }
    brix_credential origin { x509_cert /tmp/c.pem; x509_key /tmp/k.pem; }'
out="$("$NGINX" -t -c "$PFX/nginx.conf" 2>&1)"
if printf '%s' "$out" | grep -qF "brix_credential \"origin\" is defined more than once"; then
    ok "duplicate same-name credential warned at config load"
else
    bad "duplicate credential did NOT warn"; printf '%s\n' "$out" | grep -i credential
fi
# a warning must NOT be a hard error — the config must still load
printf '%s' "$out" | grep -q "test is successful" \
  && ok "config with the duplicate still loads (warning, not error)" \
  || bad "duplicate credential wrongly made the config fail to load"

echo "== 2. single 'origin' block -> NO warn =="
mkconf '    brix_credential origin { x509_proxy /tmp/p.pem; }'
out="$("$NGINX" -t -c "$PFX/nginx.conf" 2>&1)"
printf '%s' "$out" | grep -qF "defined more than once" \
  && { bad "single credential wrongly warned"; printf '%s\n' "$out" | grep -i credential; } \
  || ok "single credential block: no false warning"

echo "== 3. two DISTINCT names -> NO warn =="
mkconf '
    brix_credential origin  { x509_proxy /tmp/p.pem; }
    brix_credential origin2 { x509_cert /tmp/c.pem; x509_key /tmp/k.pem; }'
out="$("$NGINX" -t -c "$PFX/nginx.conf" 2>&1)"
printf '%s' "$out" | grep -qF "defined more than once" \
  && { bad "distinct-name credentials wrongly warned"; } \
  || ok "distinct credential names: no false warning"

[ "$fail" = 0 ] && echo "run_credential_dup_warn: ALL PASS" || echo "run_credential_dup_warn: FAILURES"
exit "$fail"
