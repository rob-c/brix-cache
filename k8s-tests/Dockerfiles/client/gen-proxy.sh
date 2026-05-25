#!/usr/bin/env bash
# Generate a short-lived x509 proxy certificate from the mounted user cert/key.
#
# Usage:
#   xrd-gen-proxy [--hours N]
#
# Environment (all have defaults that match the client pod spec):
#   CLIENT_CERT   Path to user EE certificate PEM (default: /etc/grid-security/usercert.pem)
#   CLIENT_KEY    Path to user private key PEM     (default: /etc/grid-security/userkey.pem)
#   PROXY_FILE    Output proxy path                (default: /tmp/x509up_u0)
set -euo pipefail

HOURS=24
while [[ $# -gt 0 ]]; do
    case "$1" in
        --hours) HOURS="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

CLIENT_CERT="${CLIENT_CERT:-/etc/grid-security/usercert.pem}"
CLIENT_KEY="${CLIENT_KEY:-/etc/grid-security/userkey.pem}"
PROXY_FILE="${PROXY_FILE:-/tmp/x509up_u0}"

if [ ! -f "$CLIENT_CERT" ]; then
    echo "ERROR: CLIENT_CERT not found at $CLIENT_CERT" >&2
    exit 1
fi
if [ ! -f "$CLIENT_KEY" ]; then
    echo "ERROR: CLIENT_KEY not found at $CLIENT_KEY" >&2
    exit 1
fi

# Ensure key is readable only by owner (voms-proxy-init requires this).
chmod 400 "$CLIENT_KEY"

grid-proxy-init \
    -valid "${HOURS}:00" \
    -cert  "$CLIENT_CERT" \
    -key   "$CLIENT_KEY" \
    -out   "$PROXY_FILE"

echo "Proxy written to $PROXY_FILE (valid ${HOURS}h)"
openssl x509 -noout -subject -enddate -in "$PROXY_FILE"

# Export for xrdcp / xrdfs.
export X509_USER_PROXY="$PROXY_FILE"
echo "export X509_USER_PROXY=$PROXY_FILE"
