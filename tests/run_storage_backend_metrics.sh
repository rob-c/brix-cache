#!/usr/bin/env bash
# run_storage_backend_metrics.sh — phase-63 C-7: the /metrics endpoint exposes the
# composed storage stack per export as `xrootd_storage_backend_info{...}` (backend,
# origin, auth, staging). Proves the registry introspection + the info gauge reflect
# config: a WebDAV export backed by root://O with a token credential and write-back
# staging shows backend="xroot", auth="token", staging="1".
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
MPORT=9111; WPORT=8480; PFX="$(mktemp -d /tmp/sb_metrics.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/export" "$PFX/logs"

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    xrootd_credential origin { token s3cr3t-tok; }
    server {
        listen 127.0.0.1:${WPORT};
        location / {
            xrootd_webdav on; xrootd_webdav_root $PFX/export; xrootd_webdav_auth none;
            xrootd_webdav_allow_write on;
            xrootd_webdav_storage_backend    root://127.0.0.1:19999;
            xrootd_webdav_storage_credential origin;
            xrootd_webdav_storage_staging    on;
        }
        location /metrics { xrootd_metrics on; }
    }
}
EOF

"$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/err" || { echo "start failed"; cat "$PFX/err"; exit 2; }
sleep 1

echo "== /metrics exposes xrootd_storage_backend_info for the composed export =="
out=$(curl -s "http://127.0.0.1:${WPORT}/metrics")
line=$(printf '%s\n' "$out" | grep '^xrootd_storage_backend_info' | head -1)
[ -n "$line" ] && ok "info gauge present" || { bad "no xrootd_storage_backend_info line"; printf '%s\n' "$out" | grep -i storage | head; }
printf '%s\n' "$line" | grep -q 'backend="xroot"'  && ok 'backend="xroot"'   || bad "backend label wrong: $line"
printf '%s\n' "$line" | grep -q 'auth="token"'     && ok 'auth="token"'      || bad "auth label wrong: $line"
printf '%s\n' "$line" | grep -q 'staging="1"'      && ok 'staging="1"'       || bad "staging label wrong: $line"
printf '%s\n' "$line" | grep -q 'origin="127.0.0.1:19999"' && ok 'origin host:port' || bad "origin label wrong: $line"

[ "$fail" = 0 ] && echo "run_storage_backend_metrics: ALL PASS" || echo "run_storage_backend_metrics: FAILURES"
exit "$fail"
