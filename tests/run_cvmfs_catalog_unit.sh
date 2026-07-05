#!/usr/bin/env bash
# run_cvmfs_catalog_unit.sh — build+run the CVMFS SQLite catalog reader tests.
set -euo pipefail
cd "$(dirname "$0")/.."
gcc -Wall -Wextra -Werror -I shared -o /tmp/cvmfs_cat_ut \
    shared/cvmfs/catalog/catalog_unittest.c \
    shared/cvmfs/catalog/catalog.c \
    shared/cvmfs/grammar/hash.c \
    -lsqlite3 -lcrypto
/tmp/cvmfs_cat_ut
