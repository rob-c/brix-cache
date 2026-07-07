#!/usr/bin/env bash
#
# run_sesslog_tests.sh — build+run ngx-free session lifecycle log tests.
set -euo pipefail

cd "$(dirname "$0")/../.."

BIN="$(mktemp /tmp/brix_sesslog_ut.XXXXXX)"
cc -Wall -Wextra -Werror -I src -o "${BIN}" \
    tests/c/sesslog_unittest.c src/observability/sesslog/sesslog.c

"${BIN}"
rc=$?
rm -f "${BIN}"
exit "${rc}"
