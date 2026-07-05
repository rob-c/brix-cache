#!/usr/bin/env bash
# run_brixcvmfs_atlas_live.sh — REAL repo smoke: mount live atlas.cern.ch via a
# CVMFS Stratum-1 (Cloudflare mirror), descend a nested catalog, read a file.
# Network-gated: SKIPs cleanly if atlas/keys are unavailable.
set -uo pipefail
cd "$(dirname "$0")/.."
S1="${ATLAS_S1:-http://s1cern-cvmfs.openhtc.io/cvmfs/atlas.cern.ch}"
KEYS="${CVMFS_KEYS:-/etc/cvmfs/keys/cern.ch}"

if ! curl -fsS -o /dev/null --max-time 8 "$S1/.cvmfspublished" 2>/dev/null; then
    echo "SKIP: atlas Stratum-1 unreachable ($S1)"; exit 0; fi
[ -e "$KEYS" ] || { echo "SKIP: cern.ch key not present ($KEYS)"; exit 0; }
pkg-config --exists fuse3 || { echo "SKIP: no fuse3"; exit 0; }

CORE="shared/cvmfs/client/client.c shared/cvmfs/fetch/fetch.c shared/cvmfs/object/object.c \
shared/cvmfs/failover/failover.c shared/cvmfs/catalog/catalog.c shared/cvmfs/grammar/hash.c \
shared/cvmfs/grammar/classify.c shared/cvmfs/signature/manifest.c shared/cvmfs/signature/whitelist.c \
shared/cvmfs/signature/verify.c shared/cvmfs/config/repo.c shared/cvmfs/config/cvmfs_conf.c \
shared/cache/cas_store.c shared/net/proxy_env.c"
gcc -Wall -Wextra -Werror -I shared $(pkg-config --cflags fuse3) -o /tmp/brixcvmfs \
    client/apps/fs/brixcvmfs.c $CORE $(pkg-config --libs fuse3) -lcurl -lsqlite3 -lcrypto -lz

MNT=$(mktemp -d); CACHE=$(mktemp -d); TMP=$(mktemp -d); fail=0
cleanup(){ fusermount3 -u "$MNT" 2>/dev/null||fusermount -u "$MNT" 2>/dev/null||true; rm -rf "$MNT" "$CACHE" "$TMP"; }
trap cleanup EXIT

BRIXCVMFS_SERVER="$S1" BRIXCVMFS_PUBKEY="$KEYS" BRIXCVMFS_CACHE="$CACHE" BRIXCVMFS_TMP="$TMP" \
    /tmp/brixcvmfs atlas.cern.ch "$MNT" -o noclever -f >/tmp/atlas_smoke.log 2>&1 &
sleep 8

echo "== top-level (root catalog) =="; TOP=$(ls "$MNT" 2>&1); echo "$TOP"
echo "$TOP" | grep -q repo || { echo "FAIL: no /repo"; fail=1; }
echo "== nested catalog descent + real file read =="
F=$(timeout 40 find "$MNT/repo" -maxdepth 4 -type f -size -20k 2>/dev/null | head -1)
if [ -n "$F" ] && timeout 20 head -c 1 "$F" >/dev/null 2>&1; then
    echo "   read ${F#$MNT} ($(stat -c%s "$F" 2>/dev/null) bytes) OK"
else echo "FAIL: could not read a real atlas file"; fail=1; fi

[ "$fail" = 0 ] && echo "ATLAS LIVE OK — cvmfs-brix reads real atlas.cern.ch"
exit $fail
