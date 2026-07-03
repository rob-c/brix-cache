#!/usr/bin/env bash
# tests/run_dashboard_vfs_browse.sh — the dashboard's VFS export browser e2e.
#
# Proves the explorer goes through the VFS (never raw POSIX): a posix export
# and a PBLOCK export (logical namespace in sqlite, bytes in packed blobs)
# both list and download identically through /xrootd/api/v1/vfs*. Plus the
# security posture: admin-auth required, traversal rejected, feature 404s
# where the directive is off.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
PFX="$(mktemp -d /tmp/dash_vfs.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           rm -rf "$PFX"; }
trap cleanup EXIT
P_DAV=12921; P_DASH=12922; P_OFF=12923; P_PB=12924

mkdir -p "$PFX/posix_root/subdir" "$PFX/pblock_root" "$PFX/tmp" "$PFX/logs"
printf 'posix payload' > "$PFX/posix_root/hello.txt"
printf 'nested' > "$PFX/posix_root/subdir/inner.txt"

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
events { worker_connections 128; }
http {
    client_body_temp_path $PFX/tmp;
    server {   # posix export (explicit backend => registers in the census)
        listen 127.0.0.1:$P_DAV;
        location / {
            xrootd_webdav on;
            xrootd_webdav_root $PFX/posix_root;
            xrootd_webdav_auth none;
            xrootd_webdav_storage_backend posix;
        }
    }
    server {   # pblock export (logical ns in sqlite, bytes in packed blobs)
        listen 127.0.0.1:$P_PB;
        location / {
            dav_methods PUT;
            xrootd_webdav on;
            xrootd_webdav_root $PFX/pblock_root;
            xrootd_webdav_auth none;
            xrootd_webdav_allow_write on;
            xrootd_webdav_storage_backend pblock;
        }
    }
    server {   # dashboard WITH the VFS browser
        listen 127.0.0.1:$P_DASH;
        location /xrootd/ {
            xrootd_dashboard on;
            xrootd_dashboard_password "vfsb";
            xrootd_dashboard_vfs_browse on;
        }
    }
    server {   # dashboard WITHOUT it (feature must 404)
        listen 127.0.0.1:$P_OFF;
        location /xrootd/ {
            xrootd_dashboard on;
            xrootd_dashboard_password "vfsb";
        }
    }
}
EOF
"$NGINX" -t -c "$PFX/nginx.conf" -p "$PFX" >/dev/null 2>&1 \
    && ok "config parses (xrootd_dashboard_vfs_browse)" || bad "nginx -t failed"
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.6

TS="$(date +%s)"; H="$(printf '%s' "$TS" | openssl dgst -sha256 -hmac "vfsb" -hex | sed 's/^.*= //')"
CK="Cookie: xrd_dashboard=${H}.${TS}"
API="http://127.0.0.1:$P_DASH/xrootd/api/v1"

# seed the pblock export THROUGH the data plane (its namespace lives in sqlite)
printf 'pblock payload bytes' > "$PFX/pb_src.bin"
PUTC="$(curl -s -o /dev/null -w '%{http_code}' -T "$PFX/pb_src.bin" \
        "http://127.0.0.1:$P_PB/stored.bin")"
[ "$PUTC" = 201 ] || [ "$PUTC" = 204 ] \
    && ok "pblock seeded via WebDAV PUT ($PUTC)" || bad "pblock PUT: $PUTC"

# 1: export census names both backends
CEN="$(curl -s -H "$CK" "$API/vfs")"
printf '%s' "$CEN" | grep -q '"backend":"posix"' \
    && printf '%s' "$CEN" | grep -q '"backend":"pblock"' \
    && ok "census lists posix + pblock exports" \
    || bad "census: $CEN"

# resolve each export's index by its root
PIDX="$(printf '%s' "$CEN" | python3 -c '
import json,sys
d=json.load(sys.stdin)
for e in d["exports"]:
    if e["backend"]=="posix": print(e["index"]); break')"
BIDX="$(printf '%s' "$CEN" | python3 -c '
import json,sys
d=json.load(sys.stdin)
for e in d["exports"]:
    if e["backend"]=="pblock": print(e["index"]); break')"

# 2: posix listing via VFS (file + dir, size correct)
L="$(curl -s -H "$CK" "$API/vfs/files?export=$PIDX&path=/")"
printf '%s' "$L" | grep -q '"name":"hello.txt"' \
    && printf '%s' "$L" | grep -q '"type":"dir"' \
    && printf '%s' "$L" | python3 -c '
import json,sys
d=json.load(sys.stdin)
e=[x for x in d["entries"] if x["name"]=="hello.txt"][0]
raise SystemExit(0 if e["size"]==13 and e["type"]=="file" else 1)' \
    && ok "posix export lists via VFS (size+kind)" || bad "posix listing: $L"

# 3: THE point — pblock's LOGICAL namespace lists (not catalog.db/blobs)
LB="$(curl -s -H "$CK" "$API/vfs/files?export=$BIDX&path=/")"
printf '%s' "$LB" | grep -q '"name":"stored.bin"' \
    && ! printf '%s' "$LB" | grep -q 'catalog.db' \
    && ok "pblock export shows the LOGICAL namespace" \
    || bad "pblock listing: $LB"

# 4: pblock download byte-exact via the VFS serve pipeline
curl -s -H "$CK" "$API/vfs/download?export=$BIDX&path=/stored.bin" \
     -o "$PFX/pb_out.bin"
cmp -s "$PFX/pb_src.bin" "$PFX/pb_out.bin" \
    && ok "pblock download byte-exact through VFS" || bad "pblock download differs"

# security-neg: no cookie → 401; traversal → 400; directive off → 404
C1="$(curl -s -o /dev/null -w '%{http_code}' "$API/vfs/files?export=$PIDX&path=/")"
C2="$(curl -s -o /dev/null -w '%{http_code}' -H "$CK" \
      "$API/vfs/files?export=$PIDX&path=/../../../etc")"
C3="$(curl -s -o /dev/null -w '%{http_code}' -H "$CK" \
      "http://127.0.0.1:$P_OFF/xrootd/api/v1/vfs")"
[ "$C1" = 401 ] && ok "unauthenticated → 401" || bad "no-auth: $C1"
[ "$C2" = 400 ] && ok "traversal path rejected (400)" || bad "traversal: $C2"
[ "$C3" = 404 ] && ok "feature off → 404" || bad "directive-off: $C3"

exit $fail
