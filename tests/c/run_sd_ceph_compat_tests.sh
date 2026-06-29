#!/usr/bin/env bash
# run_sd_ceph_compat_tests.sh — pure libradosstriper layout helpers (cluster-free).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
BIN="$(mktemp /tmp/test_sd_ceph_compat.XXXXXX)"
trap 'rm -f "${BIN}"' EXIT
cc -O -Wall -Wextra -Werror -o "${BIN}" \
   "${HERE}/test_sd_ceph_compat.c" \
   "${REPO}/src/fs/backend/rados/sd_ceph_compat.c"
"${BIN}"
