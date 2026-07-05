#!/usr/bin/env bash
# run_mount_cvmfs_live.sh — LIVE test of the mount.cvmfs helper driving brixMount:
# `mount.cvmfs <repo> <mnt>` daemon-mounts a signed mock repo over HTTP. This is
# the autofs/`mount -t cvmfs` code path.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO=test.cern.ch; PORT=18926
WEB=$(mktemp -d); MNT=$(mktemp -d); CACHE=$(mktemp -d); TMP=$(mktemp -d); PUB=$(mktemp); HP=""; fail=0
cleanup(){ fusermount3 -u "$MNT" 2>/dev/null||fusermount -u "$MNT" 2>/dev/null||true; [ -n "$HP" ]&&kill "$HP" 2>/dev/null||true; rm -rf "$WEB" "$MNT" "$CACHE" "$TMP" "$PUB"; }
trap cleanup EXIT

CORE="shared/cvmfs/client/client.c shared/cvmfs/fetch/fetch.c shared/cvmfs/object/object.c \
shared/cvmfs/failover/failover.c shared/cvmfs/catalog/catalog.c shared/cvmfs/grammar/hash.c \
shared/cvmfs/grammar/classify.c shared/cvmfs/signature/manifest.c shared/cvmfs/signature/whitelist.c \
shared/cvmfs/signature/verify.c shared/cvmfs/config/repo.c shared/cvmfs/config/cvmfs_conf.c shared/cache/cas_store.c shared/net/proxy_env.c"

gcc -Wall -I shared -o /tmp/brix_mkrepo tests/cvmfs/brix_mkrepo.c \
    shared/cvmfs/grammar/hash.c shared/cvmfs/object/object.c shared/cvmfs/catalog/catalog.c -lsqlite3 -lcrypto -lz
EXPECT=$(/tmp/brix_mkrepo "$REPO" "$WEB" "$PUB")
gcc -Wall -Wextra -Werror -I shared $(pkg-config --cflags fuse3) -DBRIXCVMFS_NO_MAIN -o /tmp/brixMount \
    client/apps/fs/brixmount.c client/apps/fs/brixcvmfs.c $CORE \
    $(pkg-config --libs fuse3) -lcurl -lsqlite3 -lcrypto -lz

( cd "$WEB" && exec python3 -m http.server "$PORT" >/dev/null 2>&1 ) & HP=$!
sleep 1

echo "== mount via mount.cvmfs helper (daemonizing) =="
BRIXMOUNT_BIN=/tmp/brixMount \
BRIXCVMFS_SERVER="http://localhost:$PORT/cvmfs/$REPO" BRIXCVMFS_PUBKEY="$PUB" \
BRIXCVMFS_CACHE="$CACHE" BRIXCVMFS_TMP="$TMP" \
    sh deploy/cvmfs/mount.cvmfs "$REPO" "$MNT" -o auto_unmount
sleep 1

LS=$(ls -1 "$MNT" 2>&1); GOT=$(cat "$MNT/hello" 2>&1)
echo "   ls:[$LS] got:[$GOT]"
[ "$LS" = "hello" ] && [ "$GOT" = "$EXPECT" ] || fail=1

echo "== auto.cvmfs program map emits an -fstype=cvmfs entry =="
MAP=$(sh deploy/cvmfs/auto.cvmfs "$REPO"); echo "   map: $MAP"
echo "$MAP" | grep -q "fstype=cvmfs" || fail=1

[ "$fail" = 0 ] && echo "MOUNT.CVMFS LIVE OK — helper + autofs map drive CVMFS-brix"
exit $fail
