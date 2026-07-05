#!/usr/bin/env bash
# run_brixcvmfs_live.sh — LIVE end-to-end: build a signed mock CVMFS repo, serve
# it over HTTP, mount it with brixcvmfs, and read a file through the real FUSE
# path. Exercises the entire brix stack over a real network + kernel mount.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO=test.cern.ch
PORT=18923
WEB=$(mktemp -d /tmp/brixweb.XXXXXX)
MNT=$(mktemp -d /tmp/brixmnt.XXXXXX)
CACHE=$(mktemp -d /tmp/brixcache.XXXXXX)
TMP=$(mktemp -d /tmp/brixtmp.XXXXXX)
PUB=$(mktemp /tmp/brixpub.XXXXXX)
HTTP_PID=""
fail=0

cleanup() {
    fusermount3 -u "$MNT" 2>/dev/null || fusermount -u "$MNT" 2>/dev/null || true
    [ -n "$HTTP_PID" ] && kill "$HTTP_PID" 2>/dev/null || true
    rm -rf "$WEB" "$MNT" "$CACHE" "$TMP" "$PUB"
}
trap cleanup EXIT

SHARED="shared/cvmfs/grammar/hash.c shared/cvmfs/object/object.c shared/cvmfs/catalog/catalog.c"

echo "== build mkrepo =="
gcc -Wall -I shared -o /tmp/brix_mkrepo tests/cvmfs/brix_mkrepo.c $SHARED -lsqlite3 -lcrypto -lz

echo "== build brixcvmfs =="
gcc -Wall -Wextra -Werror -I shared $(pkg-config --cflags fuse3) -o /tmp/brixcvmfs \
    client/apps/fs/brixcvmfs.c \
    shared/cvmfs/client/client.c shared/cvmfs/fetch/fetch.c shared/cvmfs/object/object.c \
    shared/cvmfs/failover/failover.c shared/cvmfs/catalog/catalog.c shared/cvmfs/grammar/hash.c \
    shared/cvmfs/grammar/classify.c shared/cvmfs/signature/manifest.c shared/cvmfs/signature/whitelist.c \
    shared/cvmfs/signature/verify.c shared/cvmfs/config/repo.c shared/cvmfs/config/cvmfs_conf.c \
    shared/cache/cas_store.c shared/net/proxy_env.c \
    $(pkg-config --libs fuse3) -lcurl -lsqlite3 -lcrypto -lz

echo "== generate signed repo =="
EXPECT=$(/tmp/brix_mkrepo "$REPO" "$WEB" "$PUB")
echo "   expected content: [$EXPECT]"

echo "== serve over HTTP :$PORT =="
( cd "$WEB" && exec python3 -m http.server "$PORT" >/dev/null 2>&1 ) &
HTTP_PID=$!
sleep 1

echo "== mount =="
BRIXCVMFS_SERVER="http://localhost:$PORT/cvmfs/$REPO" BRIXCVMFS_PUBKEY="$PUB" \
BRIXCVMFS_CACHE="$CACHE" BRIXCVMFS_TMP="$TMP" \
    /tmp/brixcvmfs "$REPO" "$MNT" -o auto_unmount -f &
MOUNT_PID=$!
sleep 2

echo "== readdir =="
LS=$(ls -1 "$MNT" 2>&1); echo "   ls: $LS"
[ "$LS" = "hello" ] || { echo "   FAIL: readdir"; fail=1; }

echo "== read file =="
GOT=$(cat "$MNT/hello" 2>&1); echo "   got: [$GOT]"
[ "$GOT" = "$EXPECT" ] || { echo "   FAIL: content mismatch"; fail=1; }

echo "== stat =="
SZ=$(stat -c '%s' "$MNT/hello" 2>&1); echo "   size: $SZ"

if [ "$fail" = 0 ]; then echo "LIVE MOUNT OK — read a signed CVMFS repo end-to-end through brixcvmfs"; fi
exit $fail
