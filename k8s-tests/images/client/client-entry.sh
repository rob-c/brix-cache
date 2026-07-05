#!/bin/bash
set -e
export TEST_ROOT="${TEST_ROOT:-/tmp/tr}"
export PYTHONPATH="/opt/brix/tests${PYTHONPATH:+:$PYTHONPATH}"
mkdir -p "$TEST_ROOT/data"
# Lay out client PKI + tokens if the authority material is mounted.
if [ -d /auth/pki ]; then
    PKI_SRC=/auth/pki JWKS_SRC=/auth/jwks/jwks.json bash /opt/brix/client-pki-init.sh || true
fi
exec "$@"
