#!/usr/bin/env bash
# run_signing_policy_tests.sh — build+run the ngx-free signing_policy unit tests.
set -euo pipefail
cd "$(dirname "$0")/../.."

gcc -Wall -Wextra -Werror -I src -o /tmp/brix_sp_ut \
    tests/c/signing_policy_unittest.c \
    src/auth/crypto/signing_policy.c

/tmp/brix_sp_ut
