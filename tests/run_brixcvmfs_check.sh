#!/usr/bin/env bash
# run_brixcvmfs_check.sh — LIVE test of `brixcvmfs --check` (the cvmfs_config
# chksetup analog): verify a repo's trust chain + root catalog WITHOUT mounting,
# and confirm a wrong master key is rejected.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO=test.cern.ch; PORT=18930
WEB=$(mktemp -d); PUB=$(mktemp); CACHE=$(mktemp -d); TMP=$(mktemp -d); HP=""; fail=0
cleanup(){ [ -n "$HP" ] && kill "$HP" 2>/dev/null || true; rm -rf "$WEB" "$PUB" "$PUB.bad" "$CACHE" "$TMP"; }
trap cleanup EXIT

gcc -Wall -I shared -o /tmp/brix_mkrepo tests/cvmfs/brix_mkrepo.c \
    shared/cvmfs/grammar/hash.c shared/cvmfs/object/object.c shared/cvmfs/catalog/catalog.c -lsqlite3 -lcrypto -lz
CORE="shared/cvmfs/client/client.c shared/cvmfs/fetch/fetch.c shared/cvmfs/object/object.c \
shared/cvmfs/failover/failover.c shared/cvmfs/catalog/catalog.c shared/cvmfs/grammar/hash.c \
shared/cvmfs/grammar/classify.c shared/cvmfs/signature/manifest.c shared/cvmfs/signature/whitelist.c \
shared/cvmfs/signature/verify.c shared/cvmfs/config/repo.c shared/cvmfs/config/cvmfs_conf.c shared/cache/cas_store.c shared/net/proxy_env.c"
gcc -Wall -Wextra -Werror -I shared $(pkg-config --cflags fuse3) -o /tmp/brixcvmfs \
    client/apps/fs/brixcvmfs.c $CORE $(pkg-config --libs fuse3) -lcurl -lsqlite3 -lcrypto -lz

/tmp/brix_mkrepo "$REPO" "$WEB" "$PUB" >/dev/null
( cd "$WEB" && exec python3 -m http.server "$PORT" >/dev/null 2>&1 ) & HP=$!
sleep 1
export BRIXCVMFS_SERVER="http://localhost:$PORT/cvmfs/$REPO" BRIXCVMFS_CACHE="$CACHE" BRIXCVMFS_TMP="$TMP"

echo "== healthy check =="
if BRIXCVMFS_PUBKEY="$PUB" /tmp/brixcvmfs --check "$REPO" | grep -q "^HEALTHY"; then
    echo "   HEALTHY ok"; else echo "   FAIL healthy"; fail=1; fi

echo "== wrong-key check must fail =="
openssl genrsa 2>/dev/null | openssl rsa -pubout -out "$PUB.bad" 2>/dev/null
if BRIXCVMFS_PUBKEY="$PUB.bad" /tmp/brixcvmfs --check "$REPO" >/dev/null 2>&1; then
    echo "   FAIL: bad key accepted"; fail=1; else echo "   bad key rejected ok"; fi

[ "$fail" = 0 ] && echo "BRIXCVMFS --check OK"
exit $fail
