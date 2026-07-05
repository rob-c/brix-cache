#!/usr/bin/env bash
# run_proxy_env_live.sh — LIVE test that the clients pick up an env proxy:
#   (A) the CONNECT tunnel handshake (sock.c path, via proxy_connect) works;
#   (B) brixcvmfs (libcurl) routes through http_proxy, reports it, and mounts;
#   (C) no_proxy forces a direct connection.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO=test.cern.ch; HPORT=18940; PPORT=18941
WEB=$(mktemp -d); MNT=$(mktemp -d); CACHE=$(mktemp -d); TMP=$(mktemp -d); PUB=$(mktemp)
PLOG=$(mktemp); HP=""; PP=""; fail=0
cleanup(){ fusermount3 -u "$MNT" 2>/dev/null||fusermount -u "$MNT" 2>/dev/null||true
  [ -n "$HP" ]&&kill "$HP" 2>/dev/null||true; [ -n "$PP" ]&&kill "$PP" 2>/dev/null||true
  rm -rf "$WEB" "$MNT" "$CACHE" "$TMP" "$PUB" "$PLOG"; }
trap cleanup EXIT

CORE="shared/cvmfs/client/client.c shared/cvmfs/fetch/fetch.c shared/cvmfs/object/object.c \
shared/cvmfs/failover/failover.c shared/cvmfs/catalog/catalog.c shared/cvmfs/grammar/hash.c \
shared/cvmfs/grammar/classify.c shared/cvmfs/signature/manifest.c shared/cvmfs/signature/whitelist.c \
shared/cvmfs/signature/verify.c shared/cvmfs/config/repo.c shared/cvmfs/config/cvmfs_conf.c \
shared/cache/cas_store.c shared/net/proxy_env.c"

echo "== build =="
gcc -Wall -I shared -o /tmp/brix_mkrepo tests/cvmfs/brix_mkrepo.c \
    shared/cvmfs/grammar/hash.c shared/cvmfs/object/object.c shared/cvmfs/catalog/catalog.c -lsqlite3 -lcrypto -lz
gcc -Wall -Wextra -Werror -I shared -o /tmp/proxy_harness \
    tests/cvmfs/proxy_tunnel_harness.c shared/net/proxy_connect.c
gcc -Wall -Wextra -Werror -I shared $(pkg-config --cflags fuse3) -o /tmp/brixcvmfs \
    client/apps/fs/brixcvmfs.c $CORE $(pkg-config --libs fuse3) -lcurl -lsqlite3 -lcrypto -lz

/tmp/brix_mkrepo "$REPO" "$WEB" "$PUB" >/dev/null
EXPECT="Hello from a LIVE CVMFS-brix mount!"
( cd "$WEB" && exec python3 -m http.server "$HPORT" >/dev/null 2>&1 ) & HP=$!
python3 tests/cvmfs/tiny_proxy.py "$PPORT" "$PLOG" >/dev/null 2>&1 & PP=$!
sleep 1.5

echo "== (A) CONNECT tunnel handshake =="
if /tmp/proxy_harness 127.0.0.1 "$PPORT" localhost "$HPORT" "/cvmfs/$REPO/.cvmfspublished"; then
    grep -q "CONNECT localhost:$HPORT" "$PLOG" && echo "   tunnel used + 200 ok" || { echo "   FAIL: proxy log missing CONNECT"; fail=1; }
else echo "   FAIL: tunnel handshake"; fail=1; fi

echo "== (A2) real brix_tcp_connect: direct path unchanged + proxy path tunnels =="
if [ -f client/libbrix.a ]; then
    LDLIBS="-lssl -lcrypto -lz -lkrb5 -lk5crypto -lcom_err -lzstd -llzma -lbrotlienc -lbrotlidec -lbz2 -l:liblz4.so.1 -luring -lpthread"
    if gcc -Wall -Iclient/lib -Isrc -Ishared -DXRDPROTO_NO_NGX -o /tmp/brix_conn tests/cvmfs/brix_connect_harness.c \
           client/libbrix.a shared/xrdproto/libxrdproto.a $LDLIBS 2>/tmp/bc_build.err; then
        : > "$PLOG"
        env -u http_proxy -u https_proxy -u all_proxy /tmp/brix_conn localhost "$HPORT" >/dev/null 2>&1 \
            && [ ! -s "$PLOG" ] && echo "   direct connect ok (no proxy, path unchanged)" \
            || { echo "   FAIL: direct brix_tcp_connect"; fail=1; }
        : > "$PLOG"
        env http_proxy="http://127.0.0.1:$PPORT" /tmp/brix_conn localhost "$HPORT" >/dev/null 2>&1 \
            && grep -q "CONNECT localhost:$HPORT" "$PLOG" && echo "   proxied connect tunnels ok" \
            || { echo "   FAIL: proxied brix_tcp_connect"; fail=1; }
    else echo "   SKIP: libbrix harness link failed ($(tail -1 /tmp/bc_build.err))"; fi
else echo "   SKIP: client/libbrix.a not built (run make -C client lib)"; fi

echo "== (B) brixcvmfs via http_proxy (report + mount) =="
: > "$PLOG"
ERR=$(mktemp)
env -u no_proxy -u NO_PROXY http_proxy="http://127.0.0.1:$PPORT" \
    BRIXCVMFS_SERVER="http://localhost:$HPORT/cvmfs/$REPO" BRIXCVMFS_PUBKEY="$PUB" \
    BRIXCVMFS_CACHE="$CACHE" BRIXCVMFS_TMP="$TMP" \
    /tmp/brixcvmfs "$REPO" "$MNT" -o fresh,auto_unmount -f 2>"$ERR" &
sleep 3
GOT=$(cat "$MNT/hello" 2>&1)
[ "$GOT" = "$EXPECT" ] || { echo "   FAIL: content via proxy [$GOT]"; fail=1; }
grep -q "using HTTP proxy 127.0.0.1:$PPORT" "$ERR" && echo "   reported proxy use ok" || { echo "   FAIL: no proxy report"; fail=1; }
grep -q "GET-forward localhost:$HPORT" "$PLOG" && echo "   proxy actually forwarded ok" || { echo "   FAIL: proxy not used"; fail=1; }
fusermount3 -u "$MNT" 2>/dev/null || fusermount -u "$MNT" 2>/dev/null; sleep 1
rm -f "$ERR"

echo "== (C) no_proxy forces direct =="
: > "$PLOG"; CACHE2=$(mktemp -d); ERR2=$(mktemp)
env http_proxy="http://127.0.0.1:$PPORT" no_proxy="localhost,127.0.0.1" \
    BRIXCVMFS_SERVER="http://localhost:$HPORT/cvmfs/$REPO" BRIXCVMFS_PUBKEY="$PUB" \
    BRIXCVMFS_CACHE="$CACHE2" BRIXCVMFS_TMP="$TMP" \
    /tmp/brixcvmfs "$REPO" "$MNT" -o auto_unmount -f 2>"$ERR2" &
sleep 3
G2=$(cat "$MNT/hello" 2>&1)
[ "$G2" = "$EXPECT" ] || { echo "   FAIL: direct mount [$G2]"; fail=1; }
[ -s "$PLOG" ] && { echo "   FAIL: no_proxy ignored (proxy was used)"; fail=1; } || echo "   no_proxy honored (direct) ok"
fusermount3 -u "$MNT" 2>/dev/null || fusermount -u "$MNT" 2>/dev/null; sleep 1
rm -rf "$CACHE2" "$ERR2"

[ "$fail" = 0 ] && echo "PROXY-FROM-ENV LIVE OK (tunnel + brixcvmfs report/use + no_proxy)"
exit $fail
