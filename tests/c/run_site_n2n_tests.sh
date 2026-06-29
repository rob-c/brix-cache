#!/usr/bin/env bash
#
# run_site_n2n_tests.sh — compile + run the pure site name-translation (N2N) unit
# test (RAL/Glasgow RADOS object names + CephFS POSIX paths). Pure libc.
#
# Usage:  tests/c/run_site_n2n_tests.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
BIN="$(mktemp /tmp/test_site_n2n.XXXXXX)"
trap 'rm -f "${BIN}"' EXIT

cc -O -Wall -Wextra -Werror -o "${BIN}" \
   "${HERE}/test_site_n2n.c" \
   "${REPO}/src/fs/backend/site_n2n.c"
"${BIN}"
