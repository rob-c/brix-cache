#!/bin/bash
set -e
export NGINX_CONF="${NGINX_CONF:-/etc/brix/nginx.conf}"
mkdir -p /data/xrootd /data/xrootd/cache /var/log/brix
# nginx workers drop to an unprivileged user; make the storage/cache trees
# writable so posix storage writes and cache fills succeed.
chmod -R a+rwX /data/xrootd

# Launch nginx (validating the mounted config first) only when that is the
# command; otherwise run whatever was passed (e.g. an ad-hoc shell or client).
if [ "${1:-}" = "nginx" ]; then
    nginx -t -c "$NGINX_CONF"
    exec nginx -c "$NGINX_CONF" -g 'daemon off;'
fi
exec "$@"
