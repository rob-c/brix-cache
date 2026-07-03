#!/usr/bin/env bash
#
# run_fs_usage_tests.sh — compile + run the pure freshness-predicate unit test
# for the TTL-cached statvfs sampler. Header-only (brix_cache_sample_fresh is a
# static inline in src/fs/cache/fs_usage.h), so no compiled object is needed.
#
# Usage:  tests/c/run_fs_usage_tests.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$(mktemp /tmp/test_fs_usage.XXXXXX)"

cc -O -Wall -Werror -o "${BIN}" "${HERE}/test_fs_usage.c"
"${BIN}"
rc=$?
rm -f "${BIN}"
exit "${rc}"
