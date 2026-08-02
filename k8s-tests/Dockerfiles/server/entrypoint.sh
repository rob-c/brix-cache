#!/bin/bash
set -e

# The topology-role chart mounts the rendered server config at /etc/brix and
# points NGINX_CONF at it; the stock compiled conf-path (/etc/nginx/nginx.conf)
# is the vanilla http server and ignores that mount. So when the container is
# launched with the default `nginx` CMD, run nginx against NGINX_CONF explicitly
# (validate first for a clear crash message). Non-nginx invocations — init
# containers overriding command/args (start-gate sleep, seeders) — fall through
# to exec "$@" unchanged.
export NGINX_CONF="${NGINX_CONF:-/etc/brix/nginx.conf}"

# Storage export + log/pid dir the rendered configs reference (error_log/pid
# live under /var/log/brix). The PKI dirs (/etc/grid-security/*) are supplied by
# read-only secret/configMap mounts — never mkdir them, that faults the RO fs.
mkdir -p /data/xrootd /data/xrootd/cache /var/log/brix
# nginx workers drop to an unprivileged user; make the storage/cache trees
# writable so posix storage writes and cache fills succeed.
chmod -R a+rwX /data/xrootd

if [ "${1:-}" = "nginx" ]; then
    nginx -t -c "$NGINX_CONF"
    exec nginx -c "$NGINX_CONF" -g 'daemon off;'
fi

exec "$@"
