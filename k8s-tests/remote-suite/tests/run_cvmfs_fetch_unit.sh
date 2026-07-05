#!/usr/bin/env bash
# run_cvmfs_fetch_unit.sh — build+run the CVMFS object-decode + fetch orchestrator
# standalone unit tests (hash-verified mirror-agnostic retry).
set -euo pipefail
cd "$(dirname "$0")/.."
gcc -Wall -Wextra -Werror -I shared -o /tmp/cvmfs_fetch_ut \
    shared/cvmfs/fetch/fetch_unittest.c \
    shared/cvmfs/fetch/fetch.c \
    shared/cvmfs/object/object.c \
    shared/cvmfs/failover/failover.c \
    shared/cvmfs/grammar/hash.c \
    shared/cache/cas_store.c \
    -lcrypto -lz
/tmp/cvmfs_fetch_ut
