#!/usr/bin/env bash
# run_cvmfs_core_unit.sh — build+run the shared CVMFS inner-ring core unit tests.
#
# WHAT: compiles shared/cvmfs/ (grammar + signature + config) with the standalone
#       unittest harness — no nginx — and runs it. Exit 0 = all checks pass.
set -euo pipefail
cd "$(dirname "$0")/.."

DEPS="shared/cvmfs/grammar/classify.c \
      shared/cvmfs/grammar/hash.c \
      shared/cvmfs/signature/manifest.c \
      shared/cvmfs/signature/whitelist.c \
      shared/cvmfs/signature/verify.c \
      shared/cvmfs/config/repo.c \
      shared/cvmfs/failover/failover.c"

gcc -Wall -Wextra -Werror -I shared -I src -o /tmp/cvmfs_core_ut \
    shared/cvmfs/cvmfs_core_unittest.c $DEPS -lcrypto

/tmp/cvmfs_core_ut
