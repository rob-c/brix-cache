#!/usr/bin/env bash
#
# run_remote_backend_staging.sh — Phase 4: write-back (Mode B). A WebDAV export
# with a remote root:// backend AND brix_webdav_storage_staging on stages each
# upload to the LOCAL export (fast, atomic), then PROMOTES it to the origin on
# commit and drops the local temp. Verifies: origin byte-exact, local store empty
# after commit (temp reclaimed), and read-back through the remote.
#
# Usage: tests/run_remote_backend_staging.sh [nginx-binary]
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
OPORT=11657; WPORT=8476
PFX="$(mktemp -d /tmp/remote_stg.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() { for r in o w; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/remote_stg_*.bin /tmp/remote_stg_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/w/export" "$PFX/w/logs" "$PFX/w/stage"
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; brix_root on; brix_export $PFX/o/root; brix_auth none; brix_allow_write on; brix_upload_resume off; } }
EOF
cat > "$PFX/w/nginx.conf" <<EOF
daemon on; error_log $PFX/w/logs/e.log info; pid $PFX/w/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http { client_max_body_size 50m; server { listen 127.0.0.1:${WPORT}; location / {
  brix_webdav on; brix_export $PFX/w/export; brix_webdav_auth none;
  brix_allow_write on;
  brix_storage_backend root://127.0.0.1:${OPORT};
  brix_webdav_storage_staging on;
} } }
EOF
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "origin start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/w" -c "$PFX/w/nginx.conf" 2>"$PFX/w/err" || { echo "node start failed"; cat "$PFX/w/err"; exit 2; }
sleep 1
head -c 700000 /dev/urandom > /tmp/remote_stg_a.bin
echo "== PUT with staging on: stage local -> promote to origin =="
code=$(curl -s -o /dev/null -w '%{http_code}' -T /tmp/remote_stg_a.bin "http://127.0.0.1:${WPORT}/a.bin")
{ [ "$code" = 201 ] || [ "$code" = 200 ] || [ "$code" = 204 ]; } && ok "PUT accepted ($code)" || bad "PUT status $code"
cmp -s /tmp/remote_stg_a.bin "$PFX/o/root/a.bin" && ok "promoted to ORIGIN byte-exact" \
  || { bad "origin differs/missing"; grep -iE 'promote|staged|xroot|error' "$PFX/w/logs/e.log" | tail -6; }
n=$(find "$PFX/w/export" -type f | wc -l)
[ "$n" = 0 ] && ok "local staging reclaimed (export empty after promote)" || bad "local temp left behind ($n file(s))"
echo "== GET reads back from the remote =="
curl -s "http://127.0.0.1:${WPORT}/a.bin" -o /tmp/remote_stg_a.got
cmp -s /tmp/remote_stg_a.bin /tmp/remote_stg_a.got && ok "GET byte-exact" || bad "GET differs"
[ "$fail" = 0 ] && echo "run_remote_backend_staging: ALL PASS" || echo "run_remote_backend_staging: FAILURES"
exit "$fail"
