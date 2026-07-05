#!/usr/bin/env bash
# run_cvmfs_conf_unit.sh — build+run the stock CVMFS_* config-parsing unit tests.
set -euo pipefail
cd "$(dirname "$0")/.."
gcc -Wall -Wextra -Werror -I shared -o /tmp/cvmfs_conf_ut \
    shared/cvmfs/config/cvmfs_conf_unittest.c \
    shared/cvmfs/config/cvmfs_conf.c \
    shared/cvmfs/config/repo.c \
    shared/cvmfs/failover/failover.c
/tmp/cvmfs_conf_ut
