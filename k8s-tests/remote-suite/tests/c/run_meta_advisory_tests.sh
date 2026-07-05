#!/usr/bin/env bash
#
# run_meta_advisory_tests.sh — compile + run the pure advisory unix-metadata codec
# unit test (Phase 0). Pure libc (no nginx, no sd.h), so it builds standalone.
#
# Usage:  tests/c/run_meta_advisory_tests.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
BIN="$(mktemp /tmp/test_meta_advisory.XXXXXX)"
trap 'rm -f "${BIN}"' EXIT

cc -O -Wall -Wextra -Werror -o "${BIN}" \
   "${HERE}/test_meta_advisory.c" \
   "${REPO}/src/fs/backend/meta_advisory.c"
"${BIN}"
