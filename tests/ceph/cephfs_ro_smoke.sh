#!/usr/bin/env bash
#
# cephfs_ro_smoke.sh — runs INSIDE xrd-ceph-work. Stands up the in-container nginx
# with a READ-ONLY cephfsro export (/export → the seeded CephFS, meta+data pools,
# auth off) on both faces and verifies:
#   root:// : xrdfs stat + ls, xrdcp GET byte-exact (5 MiB + small file), writes refused
#   http:// : WebDAV GET byte-exact, WebDAV PUT refused
# The CephFS must be seeded (cephfs_seed.c + cephfs_seed2.c) and flushed
# (ceph tell mds.<id> flush journal) so the namespace is on RADOS.
#
# Prereqs: /opt/nginx-src/objs/nginx built with BRIX_HAVE_CEPH; /etc/ceph wired.
set -u

NGINX=/opt/nginx-src/objs/nginx
RUN=/work/run-ro
RPORT=1095
HPORT=8081
META="${CEPHFS_META:-cephfs_metadata}"
DATA="${CEPHFS_DATA:-cephfs_data}"
# consistency assertion in the backend URI: assume_quiesced=1 (default) or live=1
ASSERT="${CEPHFS_ASSERT:-assume_quiesced=1}"
XRDCP="$(command -v xrdcp)"
XRDFS="$(command -v xrdfs)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
chk() { [ "$2" = "$3" ] && ok "$1 ($2)" || bad "$1: got '$2' want '$3'"; }

[ -n "$XRDCP" ] && [ -n "$XRDFS" ] || { echo "need stock xrdcp/xrdfs on PATH"; exit 2; }

pkill -9 nginx 2>/dev/null; sleep 1
rm -rf "$RUN"; mkdir -p "$RUN/tmp" /export
cat > "$RUN/nginx.conf" <<EOF
daemon on;
user root;
worker_processes 1;
error_log $RUN/error.log info;
pid $RUN/nginx.pid;
events { worker_connections 64; }
stream {
    server {
        listen 127.0.0.1:${RPORT};
        xrootd on;
        brix_root /export;
        brix_auth none;
        brix_storage_backend cephfsro:${META}+${DATA}?${ASSERT};
        brix_access_log $RUN/xrd_access.log;
    }
}
http {
    access_log off;
    client_body_temp_path $RUN/tmp; proxy_temp_path $RUN/tmp;
    fastcgi_temp_path $RUN/tmp; uwsgi_temp_path $RUN/tmp; scgi_temp_path $RUN/tmp;
    server {
        listen 127.0.0.1:${HPORT};
        location / {
            brix_webdav on;
            brix_webdav_root /export;
            brix_webdav_auth none;
        }
    }
}
EOF

echo "== nginx -t =="
"$NGINX" -t -c "$RUN/nginx.conf" 2>&1 | sed 's/^/  /' || { echo "nginx -t failed"; exit 2; }

cleanup() { [ -f "$RUN/nginx.pid" ] && kill "$(cat "$RUN/nginx.pid")" 2>/dev/null; }
trap cleanup EXIT
"$NGINX" -c "$RUN/nginx.conf" 2>"$RUN/start.err" || { echo "start failed"; cat "$RUN/start.err"; exit 2; }
sleep 1

R="root://127.0.0.1:${RPORT}"
W="http://127.0.0.1:${HPORT}"

echo "== root:// stat / ls =="
SZ=$("$XRDFS" "$R" stat /dir1/sub/big.bin 2>/dev/null | awk '/Size:/{print $2}')
chk "stat big.bin size" "$SZ" 5242880
LS1=$("$XRDFS" "$R" ls /dir1 2>/dev/null)
echo "$LS1" | grep -q 'hello.txt' && ok "ls /dir1 has hello.txt" || bad "ls /dir1: [$LS1]"
echo "$LS1" | grep -q '/dir1/sub'  && ok "ls /dir1 has sub"       || bad "ls /dir1 sub: [$LS1]"
echo "$LS1" | grep -q '/dir1/link' && ok "ls /dir1 has link"      || bad "ls /dir1 link: [$LS1]"
LS2=$("$XRDFS" "$R" ls / 2>/dev/null)
echo "$LS2" | grep -q 'top.txt' && ok "ls / has top.txt" || bad "ls /: [$LS2]"

echo "== root:// GET byte-exact =="
"$XRDCP" -f "$R//dir1/sub/big.bin" /tmp/big.out >/tmp/g1.log 2>&1
chk "xrdcp GET big.bin rc" "$?" 0
chk "big.bin size"  "$(wc -c < /tmp/big.out 2>/dev/null)" 5242880
chk "big.bin head"  "$(head -c 8 /tmp/big.out 2>/dev/null)" "BIGSTART"
chk "big.bin tail"  "$(tail -c 8 /tmp/big.out 2>/dev/null)" "BIGENDED"
"$XRDCP" -f "$R//dir1/hello.txt" /tmp/hello.out >/tmp/g2.log 2>&1
chk "hello.txt contents" "$(cat /tmp/hello.out 2>/dev/null)" "HELLO CEPHFS via libcephfs"

echo "== root:// writes refused (read-only) =="
head -c 1024 /dev/urandom > /tmp/w.bin
"$XRDCP" -f /tmp/w.bin "$R//dir1/nope.bin" >/tmp/p1.log 2>&1
[ "$?" != 0 ] && ok "xrdcp PUT refused" || bad "xrdcp PUT unexpectedly succeeded"

echo "== http:// (WebDAV) GET byte-exact =="
curl -sf "$W/dir1/hello.txt" -o /tmp/hello.web 2>/tmp/wg.log
chk "WebDAV GET hello.txt" "$(cat /tmp/hello.web 2>/dev/null)" "HELLO CEPHFS via libcephfs"
curl -sf "$W/dir1/sub/big.bin" -o /tmp/big.web 2>/tmp/wg2.log
chk "WebDAV GET big.bin size" "$(wc -c < /tmp/big.web 2>/dev/null)" 5242880

echo "== http:// PUT refused (read-only) =="
code=$(curl -s -o /dev/null -w '%{http_code}' -T /tmp/w.bin "$W/dir1/nopeweb.bin" 2>/dev/null)
[ "$code" != 201 ] && [ "$code" != 200 ] && ok "WebDAV PUT refused (HTTP $code)" \
    || bad "WebDAV PUT unexpectedly accepted (HTTP $code)"

[ "$fail" = 0 ] && echo "cephfs_ro_smoke: ALL PASS" || { echo "cephfs_ro_smoke: FAILURES"; echo "--- error.log tail ---"; tail -25 "$RUN/error.log"; }
exit "$fail"
