#!/usr/bin/env bash
# run_remote_backend_meta.sh — sd_xroot namespace/metadata ops as a PRIMARY remote
# backend: xattr (get/set/list/rm via kXR_fattr), rename (kXR_mv), and server_copy
# (WebDAV COPY) all forwarded to the origin. Node B (stream) + node W (webdav) are
# both backed by remote root:// origin O.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDFS="$HERE/client/bin/xrdfs"; XRDCP="$HERE/client/bin/xrdcp"
OPORT=11658; BPORT=11659; WPORT=8477
PFX="$(mktemp -d /tmp/remote_meta.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o b w; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/remote_meta_*.bin; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/b/export" "$PFX/b/logs" "$PFX/w/export" "$PFX/w/logs"
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; brix_root on; brix_export $PFX/o/root; brix_auth none; brix_allow_write on; brix_upload_resume off; } }
EOF
cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${BPORT}; brix_root on; brix_export $PFX/b/export; brix_auth none; brix_allow_write on; brix_upload_resume off; brix_storage_backend root://127.0.0.1:${OPORT}; } }
EOF
cat > "$PFX/w/nginx.conf" <<EOF
daemon on; error_log $PFX/w/logs/e.log info; pid $PFX/w/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http { client_max_body_size 20m; server { listen 127.0.0.1:${WPORT}; location / {
  brix_webdav on; brix_export $PFX/w/export; brix_webdav_auth none; brix_allow_write on;
  brix_storage_backend root://127.0.0.1:${OPORT}; } } }
EOF
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O fail"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B fail"; cat "$PFX/b/err"; exit 2; }
"$NGINX" -p "$PFX/w" -c "$PFX/w/nginx.conf" 2>"$PFX/w/err" || { echo "W fail"; cat "$PFX/w/err"; exit 2; }
sleep 1
head -c 4096 /dev/urandom > /tmp/remote_meta_a.bin
B="root://127.0.0.1:${BPORT}"
"$XRDCP" -f /tmp/remote_meta_a.bin "$B//f.bin" >/dev/null 2>&1
echo "== XATTR set/get/ls forwarded to origin (kXR_fattr) =="
"$XRDFS" "$B" xattr set /f.bin user.color blue >/dev/null 2>&1 && ok "xattr set" || bad "xattr set"
v=$("$XRDFS" "$B" xattr get /f.bin user.color 2>/dev/null)
echo "$v" | grep -q blue && ok "xattr get round-trips (blue)" || bad "xattr get ('$v')"
ov=$("$XRDFS" root://127.0.0.1:${OPORT} xattr get /f.bin user.color 2>/dev/null)
echo "$ov" | grep -q blue && ok "DIRECT-origin query finds it (no double-map; interoperable)" || bad "direct-origin interop ('$ov')"
getfattr -d "$PFX/o/root/f.bin" 2>/dev/null | grep -q 'user.U.user.U' && bad "on-disk DOUBLE-prefixed" || ok "on-disk single-prefixed (user.U.<name>)"
"$XRDFS" "$B" xattr ls /f.bin 2>/dev/null | grep -q 'user.color' && ok "xattr ls lists it" || bad "xattr ls"
echo "== RENAME forwarded to origin (kXR_mv) =="
"$XRDFS" "$B" mv /f.bin /g.bin >/dev/null 2>&1 && [ -f "$PFX/o/root/g.bin" ] && [ ! -f "$PFX/o/root/f.bin" ] && ok "rename → origin renamed" || bad "rename"
echo "== SERVER_COPY via WebDAV COPY (origin→origin relay) =="
curl -s -o /dev/null -X COPY -H "Destination: http://127.0.0.1:${WPORT}/copy.bin" "http://127.0.0.1:${WPORT}/g.bin"
cmp -s "$PFX/o/root/g.bin" "$PFX/o/root/copy.bin" 2>/dev/null && ok "server_copy → origin copy byte-exact" \
  || { bad "server_copy"; grep -iE 'copy|xroot|error' "$PFX/w/logs/e.log" | tail -5; }
[ "$fail" = 0 ] && echo "run_remote_backend_meta: ALL PASS" || echo "run_remote_backend_meta: FAILURES"
exit "$fail"
