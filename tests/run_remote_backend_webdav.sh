#!/usr/bin/env bash
#
# run_remote_backend_webdav.sh — Phase 3: the generic SD staged-write seam over a
# remote root:// backend. A WebDAV (HTTP) export whose PRIMARY storage is a remote
# root:// server (`brix_storage_backend root://O`). A WebDAV PUT runs
# through brix_vfs_staged_* → sd_xroot.staged_open/write/commit, streaming the
# body straight to the origin (transparent write-through); GET reads it back.
#
# Usage: tests/run_remote_backend_webdav.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
OPORT=11650
WPORT=8470
PFX="$(mktemp -d /tmp/remote_dav.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() {
    for r in o w; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done
    rm -rf "$PFX" /tmp/remote_dav_*.bin /tmp/remote_dav_*.got
}
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/w/export" "$PFX/w/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; brix_root on; brix_export $PFX/o/root;
    brix_auth none; brix_allow_write on; brix_upload_resume off; } }
EOF

cat > "$PFX/w/nginx.conf" <<EOF
daemon on; error_log $PFX/w/logs/e.log info; pid $PFX/w/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    client_max_body_size 50m;
    server {
        listen 127.0.0.1:${WPORT};
        location / {
            brix_webdav              on;
            brix_export         $PFX/w/export;
            brix_webdav_auth         none;
            brix_allow_write  on;
            brix_storage_backend root://127.0.0.1:${OPORT};
        }
    }
}
EOF

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "origin start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/w" -c "$PFX/w/nginx.conf" 2>"$PFX/w/err" || { echo "webdav start failed"; cat "$PFX/w/err"; exit 2; }
sleep 1

head -c 250000  /dev/urandom > /tmp/remote_dav_a.bin
head -c 1800000 /dev/urandom > /tmp/remote_dav_b.bin

echo "== WebDAV PUT streams through the staged seam to the origin =="
code=$(curl -s -o /dev/null -w '%{http_code}' -T /tmp/remote_dav_a.bin "http://127.0.0.1:${WPORT}/a.bin")
[ "$code" = 201 ] || [ "$code" = 200 ] || [ "$code" = 204 ] && ok "PUT accepted ($code)" || bad "PUT status $code"
if cmp -s /tmp/remote_dav_a.bin "$PFX/o/root/a.bin"; then
    ok "PUT body landed byte-exact on the ORIGIN (via sd_xroot staged-write)"
else
    bad "origin file differs / missing"; grep -iE 'xroot|origin|staged|write|error' "$PFX/w/logs/e.log" | tail -8
fi
[ ! -e "$PFX/w/export/a.bin" ] && ok "no local copy on the WebDAV node (passthrough)" || bad "unexpected local copy"

echo "== WebDAV GET reads it back through the remote backend =="
curl -s "http://127.0.0.1:${WPORT}/a.bin" -o /tmp/remote_dav_a.got
cmp -s /tmp/remote_dav_a.bin /tmp/remote_dav_a.got && ok "GET byte-exact" || bad "GET differs"

echo "== larger PUT (multi-chunk staged-write) =="
code=$(curl -s -o /dev/null -w '%{http_code}' -T /tmp/remote_dav_b.bin "http://127.0.0.1:${WPORT}/b.bin")
cmp -s /tmp/remote_dav_b.bin "$PFX/o/root/b.bin" && ok "multi-chunk PUT byte-exact on origin ($code)" \
    || bad "multi-chunk differs (origin=$(stat -c%s "$PFX/o/root/b.bin" 2>/dev/null))"

[ "$fail" = 0 ] && echo "run_remote_backend_webdav: ALL PASS" || echo "run_remote_backend_webdav: FAILURES"
exit "$fail"
