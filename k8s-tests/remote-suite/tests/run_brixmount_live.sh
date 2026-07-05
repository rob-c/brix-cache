#!/usr/bin/env bash
# run_brixmount_live.sh — LIVE test of the brixMount umbrella driving CVMFS-brix:
# `brixMount cvmfs test.cern.ch <mnt>` mounts a signed mock repo over HTTP.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO=test.cern.ch
PORT=18924
WEB=$(mktemp -d /tmp/bmweb.XXXXXX); MNT=$(mktemp -d /tmp/bmmnt.XXXXXX)
CACHE=$(mktemp -d /tmp/bmcache.XXXXXX); TMP=$(mktemp -d /tmp/bmtmp.XXXXXX)
PUB=$(mktemp /tmp/bmpub.XXXXXX); HTTP_PID=""; fail=0

cleanup() {
    fusermount3 -u "$MNT" 2>/dev/null || fusermount -u "$MNT" 2>/dev/null || true
    [ -n "$HTTP_PID" ] && kill "$HTTP_PID" 2>/dev/null || true
    rm -rf "$WEB" "$MNT" "$CACHE" "$TMP" "$PUB"
}
trap cleanup EXIT

CORE="shared/cvmfs/client/client.c shared/cvmfs/fetch/fetch.c shared/cvmfs/object/object.c \
shared/cvmfs/failover/failover.c shared/cvmfs/catalog/catalog.c shared/cvmfs/grammar/hash.c \
shared/cvmfs/grammar/classify.c shared/cvmfs/signature/manifest.c shared/cvmfs/signature/whitelist.c \
shared/cvmfs/signature/verify.c shared/cvmfs/config/repo.c shared/cvmfs/config/cvmfs_conf.c shared/cache/cas_store.c shared/net/proxy_env.c"

echo "== build mkrepo + generate signed repo =="
gcc -Wall -I shared -o /tmp/brix_mkrepo tests/cvmfs/brix_mkrepo.c \
    shared/cvmfs/grammar/hash.c shared/cvmfs/object/object.c shared/cvmfs/catalog/catalog.c \
    -lsqlite3 -lcrypto -lz
EXPECT=$(/tmp/brix_mkrepo "$REPO" "$WEB" "$PUB")

echo "== build brixMount umbrella (cvmfs driver linked; xrootdfs weak-absent) =="
gcc -Wall -Wextra -Werror -I shared $(pkg-config --cflags fuse3) -DBRIXCVMFS_NO_MAIN \
    -o /tmp/brixMount \
    client/apps/fs/brixmount.c client/apps/fs/brixcvmfs.c $CORE \
    $(pkg-config --libs fuse3) -lcurl -lsqlite3 -lcrypto -lz

echo "== serve + mount via umbrella =="
( cd "$WEB" && exec python3 -m http.server "$PORT" >/dev/null 2>&1 ) & HTTP_PID=$!
sleep 1
BRIXCVMFS_SERVER="http://localhost:$PORT/cvmfs/$REPO" BRIXCVMFS_PUBKEY="$PUB" \
BRIXCVMFS_CACHE="$CACHE" BRIXCVMFS_TMP="$TMP" \
    /tmp/brixMount cvmfs "$REPO" "$MNT" -o auto_unmount -f &
sleep 2

echo "== verify =="
LS=$(ls -1 "$MNT" 2>&1); GOT=$(cat "$MNT/hello" 2>&1)
echo "   ls:[$LS] got:[$GOT]"
[ "$LS" = "hello" ] && [ "$GOT" = "$EXPECT" ] || fail=1

echo "== unknown-type rejection =="
/tmp/brixMount bogus x /tmp >/dev/null 2>&1; [ $? -eq 2 ] || fail=1

if [ "$fail" = 0 ]; then echo "BRIXMOUNT LIVE OK — umbrella mounted CVMFS-brix end-to-end"; fi
exit $fail
