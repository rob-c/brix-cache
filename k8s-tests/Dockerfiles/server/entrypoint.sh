#!/bin/bash
set -e

export NGINX_CONF="${NGINX_CONF:-/etc/nginx/nginx.conf}"

mkdir -p /etc/grid-security/certificates
mkdir -p /etc/grid-security/vomsdir

exec "$@"
