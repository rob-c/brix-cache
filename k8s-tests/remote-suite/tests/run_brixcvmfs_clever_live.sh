#!/usr/bin/env bash
# run_brixcvmfs_clever_live.sh — LIVE test of the default-on "clever" overlay
# mount: cache lives in <mnt>/.brixcache (reached via a preserved dirfd), hidden
# by the FUSE overlay while mounted, populated by reads, and persists after
# unmount. Also exercises DPI hardening (-o fresh,tls with http fallback).
set -uo pipefail
cd "$(dirname "$0")/.."
REPO=test.cern.ch; PORT=18931
WEB=$(mktemp -d); MNT=$(mktemp -d); TMP=$(mktemp -d); PUB=$(mktemp); HP=""; fail=0
cleanup(){ fusermount3 -u "$MNT" 2>/dev/null||fusermount -u "$MNT" 2>/dev/null||true; [ -n "$HP" ]&&kill "$HP" 2>/dev/null||true; rm -rf "$WEB" "$MNT" "$TMP" "$PUB"; }
trap cleanup EXIT

CORE="shared/cvmfs/client/client.c shared/cvmfs/fetch/fetch.c shared/cvmfs/object/object.c \
shared/cvmfs/failover/failover.c shared/cvmfs/catalog/catalog.c shared/cvmfs/grammar/hash.c \
shared/cvmfs/grammar/classify.c shared/cvmfs/signature/manifest.c shared/cvmfs/signature/whitelist.c \
shared/cvmfs/signature/verify.c shared/cvmfs/config/repo.c shared/cvmfs/config/cvmfs_conf.c shared/cache/cas_store.c shared/net/proxy_env.c"
gcc -Wall -I shared -o /tmp/brix_mkrepo tests/cvmfs/brix_mkrepo.c \
    shared/cvmfs/grammar/hash.c shared/cvmfs/object/object.c shared/cvmfs/catalog/catalog.c -lsqlite3 -lcrypto -lz
gcc -Wall -Wextra -Werror -I shared $(pkg-config --cflags fuse3) -o /tmp/brixcvmfs \
    client/apps/fs/brixcvmfs.c $CORE $(pkg-config --libs fuse3) -lcurl -lsqlite3 -lcrypto -lz

EXPECT=$(/tmp/brix_mkrepo "$REPO" "$WEB" "$PUB")
( cd "$WEB" && exec python3 -m http.server "$PORT" >/dev/null 2>&1 ) & HP=$!
sleep 1

echo "== clever mount (default; cache → <mnt>/.brixcache), DPI hardening on =="
# NOTE: no BRIXCVMFS_CACHE (that would force non-clever). -o fresh,tls exercises
# hardening; tls falls back to http against the plain-http mock server.
BRIXCVMFS_SERVER="http://localhost:$PORT/cvmfs/$REPO" BRIXCVMFS_PUBKEY="$PUB" BRIXCVMFS_TMP="$TMP" \
    /tmp/brixcvmfs "$REPO" "$MNT" -o fresh,tls,retries=3,auto_unmount -f &
sleep 3

echo "== while mounted: overlay hides .brixcache, shows cvmfs tree =="
LS=$(ls -1a "$MNT" 2>&1); echo "   ls -a: $(echo $LS)"
echo "$LS" | grep -qx hello || { echo "   FAIL: hello not visible"; fail=1; }
echo "$LS" | grep -qx .brixcache && { echo "   FAIL: .brixcache leaked through overlay"; fail=1; }

GOT=$(cat "$MNT/hello" 2>&1)
[ "$GOT" = "$EXPECT" ] || { echo "   FAIL: content mismatch [$GOT]"; fail=1; }

echo "== unmount =="
fusermount3 -u "$MNT" 2>/dev/null || fusermount -u "$MNT" 2>/dev/null
sleep 1

echo "== after unmount: .brixcache visible + populated + persists =="
[ -d "$MNT/.brixcache" ] || { echo "   FAIL: .brixcache missing after unmount"; fail=1; }
NOBJ=$(find "$MNT/.brixcache" -type f 2>/dev/null | grep -v '/\.tmp\.' | wc -l)
echo "   cached objects: $NOBJ"
[ "$NOBJ" -ge 1 ] || { echo "   FAIL: overlay cache empty"; fail=1; }

[ "$fail" = 0 ] && echo "CLEVER OVERLAY + DPI-HARDENING LIVE OK"
exit $fail
