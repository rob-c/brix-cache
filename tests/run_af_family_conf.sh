#!/usr/bin/env bash
# Config-grammar test for xrootd_cache_origin_family: valid tokens accepted,
# bad token rejected at nginx -t.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
PFX="$(mktemp -d /tmp/af_conf.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
trap 'rm -rf "$PFX"' EXIT
mkdir -p "$PFX/root" "$PFX/cache"

mkconf() {  # $1 = family token
cat > "$PFX/nginx.conf" <<EOF
daemon off; error_log $PFX/e.log info; pid $PFX/pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:11939; xrootd on; xrootd_auth none;
    xrootd_storage_backend root://127.0.0.1:11940;
    xrootd_cache_store posix:$PFX/cache; xrootd_cache_root /;
    xrootd_cache_origin_family $1;
} }
EOF
}

for tok in auto inet inet6; do
    mkconf "$tok"
    if "$NGINX" -t -c "$PFX/nginx.conf" >/dev/null 2>&1; then
        ok "accepts xrootd_cache_origin_family $tok"
    else
        bad "rejected valid token $tok"
    fi
done

mkconf "ipv4"
if "$NGINX" -t -c "$PFX/nginx.conf" >/dev/null 2>&1; then
    bad "accepted bogus token ipv4"
else
    ok "rejects bogus token ipv4"
fi

exit $fail
