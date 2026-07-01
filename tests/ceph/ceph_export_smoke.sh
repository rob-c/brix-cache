#!/usr/bin/env bash
#
# ceph_export_smoke.sh — runs INSIDE the xrd-ceph-work container. Stands up the
# in-container nginx with a Ceph-backed export (/export → pool xrdtest, auth
# disabled) on both faces, and verifies:
#   root://  : xrdcp PUT/GET byte-exact, xrdfs stat, xrdfs xattr set/get/list
#   http://  : xrdcp (WebDAV) PUT/GET byte-exact
#   backend  : the objects actually land in the RADOS pool (rados ls)
#
# Prereqs in the container: /opt/nginx-src/objs/nginx built (XROOTD_HAVE_CEPH),
# /work/repo source, /etc/ceph/ceph.conf for pool xrdtest.
set -u

NGINX=/opt/nginx-src/objs/nginx
REPO=/work/repo
RUN=/work/run
RPORT=1094
HPORT=8080
POOL="${CEPH_POOL:-xrdtest}"
# Stock xrootd-client (the in-tree native client can't link here: a pre-existing
# WIP break in shared/xrdproto). http:// uses curl (WebDAV).
XRDCP="$(command -v xrdcp)"
XRDFS="$(command -v xrdfs)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
chk() { [ "$2" = "$3" ] && ok "$1 ($2)" || bad "$1: got '$2' want '$3'"; }

[ -n "$XRDCP" ] && [ -n "$XRDFS" ] || { echo "need stock xrdcp/xrdfs on PATH"; exit 2; }

# Hard-kill any stale nginx (workers rename their cmdline to "nginx: worker
# process", so pkill -f objs/nginx misses them and they keep the ports).
pkill -9 nginx 2>/dev/null; sleep 1
rm -rf "$RUN"; mkdir -p "$RUN/tmp" /export
cat > "$RUN/nginx.conf" <<EOF
daemon on;
user root;            # container is root; worker must write the export svc dirs
worker_processes 1;   # deterministic single worker
error_log $RUN/error.log info;
pid $RUN/nginx.pid;
events { worker_connections 64; }
stream {
    server {
        listen 127.0.0.1:${RPORT};
        xrootd on;
        xrootd_root /export;
        xrootd_auth none;
        xrootd_allow_write on;
        xrootd_upload_resume off;
        xrootd_storage_backend ceph:${POOL};
        xrootd_access_log $RUN/xrd_access.log;
    }
}
http {
    access_log off;
    client_body_temp_path $RUN/tmp;
    proxy_temp_path $RUN/tmp;
    fastcgi_temp_path $RUN/tmp;
    uwsgi_temp_path $RUN/tmp;
    scgi_temp_path $RUN/tmp;
    client_max_body_size 1g;
    server {
        listen 127.0.0.1:${HPORT};
        location / {
            xrootd_webdav on;
            xrootd_webdav_root /export;
            xrootd_webdav_auth none;
            xrootd_webdav_allow_write on;
        }
    }
}
EOF

echo "== nginx -t =="
"$NGINX" -t -c "$RUN/nginx.conf" 2>&1 | sed 's/^/  /' || { echo "nginx -t failed"; exit 2; }

cleanup() { [ -f "$RUN/nginx.pid" ] && kill "$(cat "$RUN/nginx.pid")" 2>/dev/null; }
trap cleanup EXIT
"$NGINX" -c "$RUN/nginx.conf" 2>"$RUN/start.err" || { echo "nginx start failed"; cat "$RUN/start.err"; exit 2; }
sleep 1

R="root://127.0.0.1:${RPORT}/"
W="http://127.0.0.1:${HPORT}"
head -c 1500000 /dev/urandom > /tmp/in.bin     # ~1.5 MB

echo "== root:// data movement =="
chk "xrdcp PUT (root)"  "$("$XRDCP" -f /tmp/in.bin "${R}/c1.bin" >/tmp/put.log 2>&1 && echo 0 || echo $?)" 0
chk "xrdcp GET (root)"  "$("$XRDCP" -f "${R}/c1.bin" /tmp/out1.bin >/tmp/get.log 2>&1 && echo 0 || echo $?)" 0
cmp -s /tmp/in.bin /tmp/out1.bin && ok "root GET byte-exact" || bad "root GET differs"
SZ=$("$XRDFS" "root://127.0.0.1:${RPORT}" stat /c1.bin 2>/dev/null | awk '/Size:/{print $2}')
chk "root stat size" "$SZ" 1500000

echo "== root:// xattr set/get/list =="
"$XRDFS" "root://127.0.0.1:${RPORT}" xattr /c1.bin set user.flavor=strawberry >/tmp/xa.log 2>&1
chk "xattr set" "$?" 0
GOT=$("$XRDFS" "root://127.0.0.1:${RPORT}" xattr /c1.bin get user.flavor 2>/dev/null | tail -1)
echo "$GOT" | grep -q strawberry && ok "xattr get returns value ($GOT)" || bad "xattr get: '$GOT'"
"$XRDFS" "root://127.0.0.1:${RPORT}" xattr /c1.bin list 2>/dev/null | grep -q user.flavor \
    && ok "xattr list shows user.flavor" || bad "xattr list missing user.flavor"

echo "== http:// (WebDAV via curl) data movement =="
chk "curl PUT (http)"  "$(curl -sf -T /tmp/in.bin "${W}/w1.bin" >/tmp/wput.log 2>&1 && echo 0 || echo $?)" 0
chk "curl GET (http)"  "$(curl -sf "${W}/w1.bin" -o /tmp/out2.bin >/tmp/wget.log 2>&1 && echo 0 || echo $?)" 0
cmp -s /tmp/in.bin /tmp/out2.bin && ok "http GET byte-exact" || bad "http GET differs"

echo "== objects landed in RADOS pool '$POOL' =="
LS=$(rados -c /etc/ceph/ceph.conf -p "$POOL" ls 2>/dev/null)
echo "$LS" | grep -q 'c1.bin' && ok "rados ls shows c1.bin" || bad "rados ls missing c1.bin: [$LS]"
echo "$LS" | grep -q 'w1.bin' && ok "rados ls shows w1.bin" || bad "rados ls missing w1.bin"

[ "$fail" = 0 ] && echo "ceph_export_smoke: ALL PASS" || { echo "ceph_export_smoke: FAILURES"; echo "--- error.log tail ---"; tail -20 "$RUN/error.log"; }
exit "$fail"
