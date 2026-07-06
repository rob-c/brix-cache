#!/usr/bin/env bash
# run_x509_oracle.sh — forge the clause matrix, then replay every c-oracle/davs
# case through the C oracle (real cores + brix_store_configure) and assert each
# verdict matches the manifest's spec.  Exit 0 = full conformance.
set -euo pipefail
cd "$(dirname "$0")/../.."

FIX="${BRIX_X509_FIXTURES:-/tmp/x509oracle}"
PYTHONPATH=tests python3 -c \
  "import x509forge, clauses, pathlib; x509forge.build_all(pathlib.Path('$FIX'), clauses.ALL_CLAUSES)"

gcc -Wall -Wextra -Werror -I src $(pkg-config --cflags openssl 2>/dev/null) \
    -o /tmp/brix_x509_oracle \
    tests/c/x509_oracle.c \
    src/auth/crypto/signing_policy.c \
    src/auth/crypto/store_policy.c \
    $(pkg-config --libs openssl 2>/dev/null || echo -lssl -lcrypto)

BRIX_X509_FIXTURES="$FIX" /tmp/brix_x509_oracle "${1:-}"
