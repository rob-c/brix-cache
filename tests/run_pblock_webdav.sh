#!/usr/bin/env bash
#
# run_pblock_webdav.sh — end-to-end WebDAV-on-pblock matrix: data movement
# (PUT/GET single + multi-block, byte-exact), metadata (HEAD/PROPFIND), and
# namespace mutation (MKCOL/MOVE/COPY/DELETE). Stands up its own nginx on a
# pblock-backed export, asserts each op, and verifies the on-disk catalog.
#
# Usage: tests/run_pblock_webdav.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
PORT=8493
PFX="$(mktemp -d /tmp/pblock_webdav.XXXXXX)"
U="http://127.0.0.1:${PORT}"
fail=0
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }
chk()  { [ "$2" = "$3" ] && ok "$1 ($2)" || bad "$1: got '$2' want '$3'"; }

mkdir -p "$PFX/root" "$PFX/tmp" "$PFX/logs"
cat > "$PFX/nginx.conf" <<EOF
daemon on;
error_log $PFX/logs/error.log info;
pid $PFX/nginx.pid;
events { worker_connections 64; }
http {
    client_body_temp_path $PFX/tmp;
    client_max_body_size 200m;
    server {
        listen 127.0.0.1:${PORT};
        location / {
            dav_methods PUT DELETE MKCOL MOVE COPY;
            xrootd_webdav on;
            xrootd_webdav_root $PFX/root;
            xrootd_webdav_auth none;
            xrootd_webdav_allow_write on;
            xrootd_webdav_storage_backend  pblock;
            xrootd_webdav_pblock_block_size 1m;
        }
    }
}
EOF

cleanup() { [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; rm -rf "$PFX" /tmp/pbw_*.bin; }
trap cleanup EXIT

"$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>/dev/null || { echo "nginx failed to start"; exit 2; }
sleep 1

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "== data movement =="
head -c 700000  /dev/urandom > /tmp/pbw_small.bin     # < 1 block
head -c 2621440 /dev/urandom > /tmp/pbw_multi.bin     # 2.5 blocks
chk "PUT small (1 block)"     "$(code -T /tmp/pbw_small.bin $U/s.bin)" 201
chk "PUT multi (3 blocks)"    "$(code -T /tmp/pbw_multi.bin $U/m.bin)" 201
curl -s -o /tmp/pbw_s.got "$U/s.bin"; curl -s -o /tmp/pbw_m.got "$U/m.bin"
cmp -s /tmp/pbw_small.bin /tmp/pbw_s.got && ok "GET small byte-exact"  || bad "GET small differs"
cmp -s /tmp/pbw_multi.bin /tmp/pbw_m.got && ok "GET multi byte-exact"  || bad "GET multi differs"
RB=$(curl -s -r 1048570-1048580 "$U/m.bin" | cmp -s - <(dd if=/tmp/pbw_multi.bin bs=1 skip=1048570 count=11 2>/dev/null) && echo ok || echo no)
chk "Range GET across block boundary" "$RB" ok

echo "== metadata =="
chk "HEAD existing"           "$(curl -s -I -o /dev/null -w '%{http_code}' $U/s.bin)" 200
chk "HEAD missing"            "$(curl -s -I -o /dev/null -w '%{http_code}' $U/none)"  404
chk "PROPFIND root depth1"    "$(code -X PROPFIND -H 'Depth: 1' $U/)" 207

echo "== namespace mutation =="
chk "MKCOL /d"                "$(code -X MKCOL $U/d)" 201
chk "PUT  /d/x.bin"           "$(code -T /tmp/pbw_small.bin $U/d/x.bin)" 201
chk "MOVE /s.bin -> /s2.bin"  "$(code -X MOVE -H "Destination: $U/s2.bin" $U/s.bin)" 201
chk "HEAD moved-from (gone)"  "$(curl -s -I -o /dev/null -w '%{http_code}' $U/s.bin)" 404
chk "HEAD moved-to"           "$(curl -s -I -o /dev/null -w '%{http_code}' $U/s2.bin)" 200
chk "COPY /s2.bin -> /cp.bin" "$(code -X COPY -H "Destination: $U/cp.bin" $U/s2.bin)" 201
curl -s -o /tmp/pbw_cp.got "$U/cp.bin"
cmp -s /tmp/pbw_small.bin /tmp/pbw_cp.got && ok "GET copy byte-exact" || bad "copy differs"
chk "DELETE /d (non-empty)"   "$(code -X DELETE $U/d)" 409
chk "DELETE /d/x.bin (file)"  "$(code -X DELETE $U/d/x.bin)" 204
chk "DELETE /d (now empty)"   "$(code -X DELETE $U/d)" 204
chk "HEAD deleted dir"        "$(curl -s -I -o /dev/null -w '%{http_code}' $U/d)" 404

echo "== on-disk =="
[ -f "$PFX/root/catalog.db" ] && ok "catalog.db present" || bad "no catalog.db"
[ -d "$PFX/root/data" ]       && ok "data/ block dir present" || bad "no data/"

[ "$fail" = 0 ] && echo "run_pblock_webdav: ALL PASS" || echo "run_pblock_webdav: FAILURES"
exit "$fail"
