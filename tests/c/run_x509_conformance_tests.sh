#!/usr/bin/env bash
# run_x509_conformance_tests.sh — build+run the C-level x509 conformance tests.
#
# These link the ngx-free trust cores (signing_policy.c + store_policy.c) against
# real forge-generated certificates and exercise the enforcement DECISION logic
# (brix_sp_table_check), CRL store flags, and PKIX chain building directly — no
# nginx.  The wire-level proof that brix_gsi_verify_chain calls this logic lives
# in the pytest e2e layer (tests/test_wlcg_conformance_*.py).
set -euo pipefail
cd "$(dirname "$0")/../.."

FIX="${BRIX_X509_FIXTURES:-/tmp/x509conf}"
PYTHONPATH=tests python3 -c "import x509forge, pathlib; x509forge.forge_all(pathlib.Path('$FIX'))"

gcc -Wall -Wextra -Werror -I src $(pkg-config --cflags openssl 2>/dev/null) \
    -o /tmp/brix_x509conf \
    tests/c/x509_conformance_test.c \
    src/auth/crypto/signing_policy.c \
    src/auth/crypto/store_policy.c \
    $(pkg-config --libs openssl 2>/dev/null || echo -lssl -lcrypto)

BRIX_X509_FIXTURES="$FIX" /tmp/brix_x509conf
