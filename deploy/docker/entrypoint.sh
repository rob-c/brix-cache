#!/usr/bin/env bash
# deploy/docker/entrypoint.sh — container entry for the BriX-Cache image.
#
#   nginx            validate $BRIX_CONF with `nginx -t`, then run in the
#                    foreground. BRIX_DEMO_PKI=1 mints a throwaway CA + host +
#                    user certificate into /etc/brix/pki first when that tree
#                    is empty (compose stacks; never for production).
#   <anything else>  exec as given (a smoke client, a shell, xrdcp, ...).
set -euo pipefail

BRIX_CONF="${BRIX_CONF:-/etc/brix/nginx.conf}"
BRIX_PKI_DIR="${BRIX_PKI_DIR:-/etc/brix/pki}"

mkdir -p /data /var/cache/brix /var/lib/brix/creds /var/lib/brix/state \
         /var/log/brix /run/brix
# Workers run unprivileged; the storage and cache trees must be writable to
# them for posix writes, cache fills and staged uploads to land.
chmod a+rwX /data /var/cache/brix /var/lib/brix/state /var/log/brix /run/brix

# The delegated-credential store is the opposite case: it holds private keys
# and brix writes to it only when it is 0700 and owned by the worker identity
# (otherwise every delegation PUT is refused with 507). A mounted volume
# arrives root-owned 0755, so hand it to the `user` the config names (nginx's
# default is nobody) before the master starts.
if [ "$(id -u)" = 0 ]; then
    worker_user="$(sed -n 's/^[[:space:]]*user[[:space:]]\{1,\}\([^[:space:];]*\).*/\1/p' "$BRIX_CONF" 2>/dev/null | head -1)"
    chown "${worker_user:-nobody}" /var/lib/brix/creds
fi
chmod 0700 /var/lib/brix/creds

if [ "${BRIX_DEMO_PKI:-0}" = "1" ] && [ ! -s "$BRIX_PKI_DIR/ca/ca.pem" ]; then
    OUT="$BRIX_PKI_DIR" brix-pki-init
fi

if [ "${1:-}" = "nginx" ]; then
    shift
    nginx -t -c "$BRIX_CONF"
    exec nginx -c "$BRIX_CONF" -g 'daemon off;' "$@"
fi
exec "$@"
