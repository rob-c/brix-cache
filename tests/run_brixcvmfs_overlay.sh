#!/usr/bin/env bash
# run_brixcvmfs_overlay.sh — LIVE test of the cvmfs-rw writable overlay: a
# signed mock repo is mounted with the union driver; local writes/modifies/
# deletes land in <mnt>/.brixwrites/upper (beside .brixcache), win over the
# lower repo, persist across remounts, and the plain read-only mount stays
# EROFS. Also exercises the reserved-name guard and the user.overlay xattr.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO=test.cern.ch; PORT=18933
WEB=$(mktemp -d); MNT=$(mktemp -d); TMP=$(mktemp -d); PUB=$(mktemp); HP=""; fail=0
cleanup(){ fusermount3 -u "$MNT" 2>/dev/null||fusermount -u "$MNT" 2>/dev/null||true; [ -n "$HP" ]&&kill "$HP" 2>/dev/null||true; rm -rf "$WEB" "$MNT" "$TMP" "$PUB"; }
trap cleanup EXIT

CORE="shared/cvmfs/client/client.c shared/cvmfs/fetch/fetch.c shared/cvmfs/object/object.c \
shared/cvmfs/failover/failover.c shared/cvmfs/catalog/catalog.c shared/cvmfs/grammar/hash.c \
shared/cvmfs/grammar/classify.c shared/cvmfs/signature/manifest.c shared/cvmfs/signature/whitelist.c \
shared/cvmfs/signature/verify.c shared/cvmfs/config/repo.c shared/cvmfs/config/cvmfs_conf.c shared/cache/cas_store.c shared/net/proxy_env.c"
gcc -Wall -I shared -o /tmp/brix_mkrepo tests/cvmfs/brix_mkrepo.c \
    shared/cvmfs/grammar/hash.c shared/cvmfs/object/object.c shared/cvmfs/catalog/catalog.c -lsqlite3 -lcrypto -lz
gcc -Wall -Wextra -Werror -I shared -I client/lib $(pkg-config --cflags fuse3) -o /tmp/brixcvmfs_rw \
    client/apps/fs/brixcvmfs.c client/apps/fs/brixcvmfs_rw.c client/lib/fs/overlay.c $CORE \
    $(pkg-config --libs fuse3) -lcurl -lsqlite3 -lcrypto -lz
# the real brixMount front-end (cvmfs drivers only; xrootdfs is weak-absent)
gcc -Wall -Wextra -Werror -I shared -I client/lib $(pkg-config --cflags fuse3) \
    -DBRIXCVMFS_NO_MAIN -o /tmp/brixmount_ov \
    client/apps/fs/brixmount.c client/apps/fs/brixcvmfs.c client/apps/fs/brixcvmfs_rw.c \
    client/lib/fs/overlay.c $CORE \
    $(pkg-config --libs fuse3) -lcurl -lsqlite3 -lcrypto -lz

EXPECT=$(/tmp/brix_mkrepo "$REPO" "$WEB" "$PUB")
( cd "$WEB" && exec python3 -m http.server "$PORT" >/dev/null 2>&1 ) & HP=$!
sleep 1
export BRIXCVMFS_SERVER="http://localhost:$PORT/cvmfs/$REPO" BRIXCVMFS_PUBKEY="$PUB" BRIXCVMFS_TMP="$TMP"

mount_rw(){ /tmp/brixcvmfs_rw --rw "$REPO" "$MNT" -o auto_unmount -f & sleep 3; }
umnt(){ fusermount3 -u "$MNT" 2>/dev/null || fusermount -u "$MNT" 2>/dev/null; sleep 1; }
xov(){ python3 -c "import os,sys; sys.stdout.write(os.getxattr(sys.argv[1],'user.overlay').decode())" "$1" 2>/dev/null; }

echo "== rw mount: lower reads work =="
mount_rw
GOT=$(cat "$MNT/hello" 2>&1)
[ "$GOT" = "$EXPECT" ] || { echo "   FAIL: lower read [$GOT]"; fail=1; }

echo "== create a new file =="
echo local > "$MNT/newfile" 2>/dev/null || { echo "   FAIL: create refused"; fail=1; }
[ "$(cat "$MNT/newfile" 2>&1)" = "local" ] || { echo "   FAIL: new-file readback"; fail=1; }
LS=$(ls -1a "$MNT")
echo "$LS" | grep -qx newfile     || { echo "   FAIL: newfile not listed"; fail=1; }
echo "$LS" | grep -qx .brixwrites || { echo "   FAIL: .brixwrites not visible"; fail=1; }
echo "$LS" | grep -qx .brixcache  && { echo "   FAIL: .brixcache leaked"; fail=1; }
[ "$(xov "$MNT/newfile")" = "new" ] || { echo "   FAIL: user.overlay(newfile) != new"; fail=1; }

echo "== modify a lower file (copy-up) =="
echo changed > "$MNT/hello" || { echo "   FAIL: modify refused"; fail=1; }
[ "$(cat "$MNT/hello")" = "changed" ] || { echo "   FAIL: modified readback"; fail=1; }
[ "$(xov "$MNT/hello")" = "modified" ] || { echo "   FAIL: user.overlay(hello) != modified"; fail=1; }

echo "== nested mkdir + write =="
mkdir -p "$MNT/newdir/sub" || { echo "   FAIL: mkdir -p"; fail=1; }
echo nested > "$MNT/newdir/sub/f"
[ "$(cat "$MNT/newdir/sub/f")" = "nested" ] || { echo "   FAIL: nested readback"; fail=1; }

echo "== rename a (copied-up) lower file: whiteout stays behind =="
mv "$MNT/hello" "$MNT/hello.moved" || { echo "   FAIL: mv"; fail=1; }
[ "$(cat "$MNT/hello.moved")" = "changed" ] || { echo "   FAIL: moved content"; fail=1; }
cat "$MNT/hello" 2>/dev/null && { echo "   FAIL: hello still visible after mv"; fail=1; }
ls -1a "$MNT" | grep -qx hello && { echo "   FAIL: hello still listed"; fail=1; }

echo "== reserved names refused =="
touch "$MNT/.brix.wh.x" 2>/dev/null && { echo "   FAIL: reserved name accepted"; fail=1; }

echo "== unmount: overlay tree on disk =="
umnt
[ -f "$MNT/.brixwrites/upper/newfile" ]       || { echo "   FAIL: upper/newfile missing"; fail=1; }
[ -f "$MNT/.brixwrites/upper/.brix.wh.hello" ] || { echo "   FAIL: whiteout marker missing"; fail=1; }
[ -f "$MNT/.brixwrites/upper/hello.moved" ]    || { echo "   FAIL: upper/hello.moved missing"; fail=1; }

echo "== unmounted --overlay-list works on the raw tree =="
RAWLS=$(/tmp/brixmount_ov --overlay-list "$MNT")
echo "$RAWLS" | grep -qx "upper newfile"  || { echo "   FAIL: raw list newfile"; fail=1; }
echo "$RAWLS" | grep -qx "deleted hello"  || { echo "   FAIL: raw list whiteout"; fail=1; }
echo "$RAWLS" | grep -qx "dir newdir"     || { echo "   FAIL: raw list dir"; fail=1; }
/tmp/brixmount_ov --overlay-list "$TMP" >/dev/null 2>&1 \
    && { echo "   FAIL: list accepted non-overlay dir"; fail=1; }

echo "== remount via brixMount cvmfs-rw: local changes persist =="
/tmp/brixmount_ov cvmfs-rw "$REPO" "$MNT" -o auto_unmount -f & sleep 3
[ "$(cat "$MNT/newfile" 2>&1)" = "local" ]        || { echo "   FAIL: newfile lost"; fail=1; }
[ "$(cat "$MNT/hello.moved" 2>&1)" = "changed" ]  || { echo "   FAIL: hello.moved lost"; fail=1; }
[ "$(cat "$MNT/newdir/sub/f" 2>&1)" = "nested" ]  || { echo "   FAIL: nested lost"; fail=1; }
cat "$MNT/hello" 2>/dev/null && { echo "   FAIL: deleted hello resurfaced"; fail=1; }

echo "== mounted --overlay-list classifies through the passthrough =="
MLS=$(/tmp/brixmount_ov --overlay-list "$MNT")
echo "$MLS" | grep -qx "new newfile"      || { echo "   FAIL: mounted list newfile [$MLS]"; fail=1; }
echo "$MLS" | grep -qx "deleted hello"    || { echo "   FAIL: mounted list whiteout"; fail=1; }
echo "$MLS" | grep -qx "new hello.moved"  || { echo "   FAIL: mounted list moved"; fail=1; }

echo "== mounted --overlay-reset restores pristine lower =="
/tmp/brixmount_ov --overlay-reset "$MNT" || { echo "   FAIL: reset rc"; fail=1; }
[ "$(cat "$MNT/hello" 2>&1)" = "$EXPECT" ] || { echo "   FAIL: hello not restored"; fail=1; }
cat "$MNT/newfile" 2>/dev/null && { echo "   FAIL: newfile survived reset"; fail=1; }
umnt

echo "== regression: plain ro mount stays EROFS, pristine lower =="
/tmp/brixcvmfs_rw "$REPO" "$MNT" -o auto_unmount -f & sleep 3
[ "$(cat "$MNT/hello" 2>&1)" = "$EXPECT" ] || { echo "   FAIL: ro lower content"; fail=1; }
touch "$MNT/rofail" 2>/dev/null && { echo "   FAIL: ro mount writable"; fail=1; }
ls -1a "$MNT" | grep -qx .brixwrites && { echo "   FAIL: ro mount leaks .brixwrites"; fail=1; }
umnt

[ "$fail" = 0 ] && echo "CVMFS-RW OVERLAY LIVE OK"
exit $fail
