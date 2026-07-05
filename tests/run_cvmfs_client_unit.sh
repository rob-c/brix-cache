#!/usr/bin/env bash
# run_cvmfs_client_unit.sh — end-to-end test of the CVMFS-brix client assembler
# (trust chain → catalog resolve → content read) over a mock transport.
set -euo pipefail
cd "$(dirname "$0")/.."
gcc -Wall -Wextra -Werror -I shared -o /tmp/cvmfs_client_ut \
    shared/cvmfs/client/client_unittest.c \
    shared/cvmfs/client/client.c \
    shared/cvmfs/fetch/fetch.c \
    shared/cvmfs/object/object.c \
    shared/cvmfs/failover/failover.c \
    shared/cvmfs/catalog/catalog.c \
    shared/cvmfs/grammar/hash.c \
    shared/cvmfs/grammar/classify.c \
    shared/cvmfs/signature/manifest.c \
    shared/cvmfs/signature/whitelist.c \
    shared/cvmfs/signature/verify.c \
    shared/cvmfs/config/repo.c \
    shared/cache/cas_store.c \
    -lsqlite3 -lcrypto -lz
/tmp/cvmfs_client_ut
