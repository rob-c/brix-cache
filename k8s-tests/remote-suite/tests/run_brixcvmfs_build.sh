#!/usr/bin/env bash
# run_brixcvmfs_build.sh — compile+link the CVMFS-brix FUSE driver against the
# shared core + fuse3 + curl + sqlite. Proves the driver builds into a real
# binary (a live mount needs FUSE + network, done in a deploy/CI env).
set -euo pipefail
cd "$(dirname "$0")/.."

if ! pkg-config --exists fuse3; then echo "SKIP: fuse3 not present"; exit 0; fi

gcc -Wall -Wextra -Werror -I shared \
    $(pkg-config --cflags fuse3) \
    -o /tmp/brixcvmfs \
    client/apps/fs/brixcvmfs.c \
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
    shared/cvmfs/config/repo.c shared/cvmfs/config/cvmfs_conf.c \
    shared/cache/cas_store.c shared/net/proxy_env.c \
    $(pkg-config --libs fuse3) -lcurl -lsqlite3 -lcrypto -lz

echo "OK: brixcvmfs built ($(du -h /tmp/brixcvmfs | cut -f1))"
/tmp/brixcvmfs 2>&1 | head -1 || true    # usage banner (argc<3 path)
