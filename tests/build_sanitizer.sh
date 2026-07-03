#!/usr/bin/env bash
# tests/build_sanitizer.sh — configure+build the nginx module AND the native
# client with ASan+UBSan for the sanitizer CI lane.  This is a slow, full
# rebuild; the default incremental `make` build does not use sanitizer flags.
#
# Usage:
#   tests/build_sanitizer.sh               # nginx source at NGINX_SRC default
#   NGINX_SRC=/opt/nginx-src tests/build_sanitizer.sh
#
# After this build, start the instrumented fleet and run the smoke lane:
#   SANITIZE=1 tests/manage_test_servers.sh restart
#   BRIX_SANITIZER_LANE=1 pytest tests/test_sanitizer_smoke.py -v
#   SANITIZE=1 tests/manage_test_servers.sh stop   # LSan fires on exit
#   ls "${SANITIZE_LOG_DIR:-/tmp/xrd-test/sanitize}/asan.*"
#
# Environment variables:
#   NGINX_SRC  — nginx source tree root (default: /tmp/nginx-1.28.3)

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
NGINX_SRC="${NGINX_SRC:-/tmp/nginx-1.28.3}"
SAN="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
# Preserve the client Makefile's default link-hardening flags and add the
# sanitizer.  The client Makefile uses LDFLAGS ?= (conditional default), so a
# command-line override replaces the default entirely; we restore hardening here.
CLIENT_LDFLAGS="-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack ${SAN}"

if [[ ! -x "${NGINX_SRC}/configure" ]]; then
    printf 'ERROR: nginx source not found at %s\n' "$NGINX_SRC" >&2
    printf '       Set NGINX_SRC= to the nginx source tree (it must have ./configure).\n' >&2
    exit 1
fi

echo "==> Configuring nginx module with ASan+UBSan (NGINX_SRC=${NGINX_SRC})"
# ./configure must run from the nginx source tree; --add-module points back to
# this repository.  --with-cc-opt / --with-ld-opt are appended to nginx's own
# compile and link flags, so the instrumented module is linked against the
# ASan runtime.
cd "$NGINX_SRC"
./configure \
    --with-stream \
    --with-stream_ssl_module \
    --with-http_ssl_module \
    --with-http_dav_module \
    --with-threads \
    "--add-module=${REPO}" \
    "--with-cc-opt=${SAN}" \
    "--with-ld-opt=${SAN}"

echo "==> Building nginx module"
make -j"$(nproc)"

echo "==> Building native client (xrdcp/xrdfs/etc.) with ASan+UBSan"
# CFLAGS passed on the command line is a make "override" variable and propagates
# automatically to the shared/xrdproto sub-make ($(MAKE) -C ...) via MAKEFLAGS,
# so libxrdproto.a is also instrumented — mixing sanitized and non-sanitized
# translation units in a single binary produces false positives.
( cd "${REPO}/client" && make -j"$(nproc)" CFLAGS="${SAN}" LDFLAGS="${CLIENT_LDFLAGS}" )

echo "==> Sanitizer build complete"
printf '    nginx:  %s/objs/nginx\n' "$NGINX_SRC"
printf '    client: %s/client/bin/xrdcp  (and xrdfs, xrd, ...)\n' "$REPO"
