#!/bin/sh
# tests/run_ucred_conf.sh — parse-level checks for the per-user credential directives.
# 1 accepted with valid args; 2 rejected with a bad fallback value; 3 defaults (absent) parse.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
NGINX=${NGINX:-/tmp/nginx-1.28.3/objs/nginx}
PFX=/tmp/ucred-conf-test; rm -rf "$PFX"
mkdir -p "$PFX/logs" "$PFX/export" "$PFX/creds" "$PFX/tmp" \
         "$PFX/proxy_temp" "$PFX/fastcgi_temp" "$PFX/uwsgi_temp" "$PFX/scgi_temp"
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; FAILED=1; }
FAILED=0

mkconf() { # $1 = extra directives
cat > "$PFX/nginx.conf" <<EOF
daemon off; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
events { worker_connections 16; }
http {
    access_log $PFX/logs/access.log;
    client_body_temp_path $PFX/tmp;
    proxy_temp_path $PFX/proxy_temp;
    fastcgi_temp_path $PFX/fastcgi_temp;
    uwsgi_temp_path $PFX/uwsgi_temp;
    scgi_temp_path $PFX/scgi_temp;
    server { listen 127.0.0.1:18443;
        location / { brix_webdav on; brix_webdav_auth none; brix_export $PFX/export; $1 }
    }
}
EOF
}

mkconf "brix_storage_credential_dir $PFX/creds; brix_storage_credential_fallback deny;"
"$NGINX" -t -c "$PFX/nginx.conf" >/dev/null 2>&1 && ok "valid directives accepted" \
    || bad "valid directives rejected"

mkconf "brix_storage_credential_fallback sometimes;"
"$NGINX" -t -c "$PFX/nginx.conf" >/dev/null 2>&1 && bad "bad fallback value accepted" \
    || ok "bad fallback value rejected"

mkconf ""
"$NGINX" -t -c "$PFX/nginx.conf" >/dev/null 2>&1 && ok "defaults (absent) parse" \
    || bad "defaults broke parsing"
exit $FAILED
