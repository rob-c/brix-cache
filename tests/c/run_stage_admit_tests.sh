#!/usr/bin/env bash
#
# run_stage_admit_tests.sh — compile + run the pure two-tier staging-backpressure
# decision unit test. Header-only (xrootd_wt_stage_decide is a static inline in
# src/cache/stage_admit.h), so no compiled object is needed.
#
# Usage:  tests/c/run_stage_admit_tests.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$(mktemp /tmp/test_stage_admit.XXXXXX)"

cc -O -Wall -Werror -o "${BIN}" "${HERE}/test_stage_admit.c"
"${BIN}"
rc=$?
rm -f "${BIN}"
exit "${rc}"
