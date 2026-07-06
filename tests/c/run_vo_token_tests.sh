#!/usr/bin/env bash
# run_vo_token_tests.sh — build+run the ngx-free VO-name sanitization tests.
set -euo pipefail
cd "$(dirname "$0")/../.."

gcc -Wall -Wextra -Werror -I src -o /tmp/brix_vo_token_ut \
    tests/c/vo_token_unittest.c

/tmp/brix_vo_token_ut
