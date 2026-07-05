#!/usr/bin/env bash
# run_cvmfs_bench.sh — cvmfs-brix vs stock cvmfs2 through a failproxy, pulling N
# real atlas.cern.ch files across a fault-rate sweep. Measures success rate + time.
#
#   NFILES (default 25)   MODE (loss|reorder|stall, default loss)
#   RATES  (default "0 15 30")   as integer percents
set -uo pipefail
cd "$(dirname "$0")/.."
REPO="${REPO:-cms.cern.ch}"
S1="${ATLAS_S1:-http://s1cern-cvmfs.openhtc.io/cvmfs/$REPO}"
KEYS=/etc/cvmfs/keys/cern.ch
NFILES=${NFILES:-25}; MODE=${MODE:-loss}; RATES=${RATES:-"0 15 30"}; PPORT=18950
BRIX=/tmp/brixcvmfs

curl -fsS -o /dev/null --max-time 8 "$S1/.cvmfspublished" || { echo "SKIP: atlas unreachable"; exit 0; }
command -v cvmfs2 >/dev/null || { echo "SKIP: no stock cvmfs2"; exit 0; }

CORE="shared/cvmfs/client/client.c shared/cvmfs/fetch/fetch.c shared/cvmfs/object/object.c \
shared/cvmfs/failover/failover.c shared/cvmfs/catalog/catalog.c shared/cvmfs/grammar/hash.c \
shared/cvmfs/grammar/classify.c shared/cvmfs/signature/manifest.c shared/cvmfs/signature/whitelist.c \
shared/cvmfs/signature/verify.c shared/cvmfs/config/repo.c shared/cvmfs/config/cvmfs_conf.c \
shared/cache/cas_store.c shared/net/proxy_env.c"
[ -x "$BRIX" ] || gcc -Wall -Wextra -Werror -I shared $(pkg-config --cflags fuse3) -o "$BRIX" \
    client/apps/fs/brixcvmfs.c $CORE $(pkg-config --libs fuse3) -lcurl -lsqlite3 -lcrypto -lz

FILELIST=$(mktemp)
brix_mount(){ # <cache> <tmp> <mnt> [extra_env]; backgrounds brix, sets $BPID.
  # NB: must background in the CURRENT shell (not via $(...)) — a subshell exit
  # kills the backgrounded FUSE process.
  # Use `env` so an env assignment passed via $4 (e.g. http_proxy=...) is applied:
  # a NAME=value from a variable expansion is NOT recognised as a shell assignment.
  env BRIXCVMFS_SERVER="$S1" BRIXCVMFS_PUBKEY="$KEYS" BRIXCVMFS_CACHE="$1" BRIXCVMFS_TMP="$2" ${4:-} \
    "$BRIX" "$REPO" "$3" -o noclever,fresh,retries=5,auto_unmount -f >/dev/null 2>&1 &
  BPID=$!; }
umount_wait(){ fusermount3 -u "$1" 2>/dev/null || fusermount -u "$1" 2>/dev/null; sleep 1; }
# Poll until the repo root is visible (mount finished) or timeout. A timeout under
# heavy loss is itself a valid result (the client could not mount).
wait_ready(){ local mnt=$1 n=0; while [ $n -lt 80 ]; do
  [ -n "$(ls -A "$mnt" 2>/dev/null)" ] && return 0; sleep 0.5; n=$((n+1)); done; return 1; }

echo "== enumerate $NFILES $REPO files (clean brix mount) =="
E_MNT=$(mktemp -d); E_C=$(mktemp -d); E_T=$(mktemp -d)
brix_mount "$E_C" "$E_T" "$E_MNT"; EP=$BPID; wait_ready "$E_MNT" || echo "   (enumerate mount slow)"
find "$E_MNT" -maxdepth 6 -type f -size -64k 2>/dev/null | head -"$NFILES" | sed "s#$E_MNT/##" > "$FILELIST"
NGOT=$(wc -l < "$FILELIST"); echo "   enumerated $NGOT files"
umount_wait "$E_MNT"; kill "$EP" 2>/dev/null; rm -rf "$E_C" "$E_T" "$E_MNT"
[ "$NGOT" -ge 1 ] || { echo "FAIL: no files enumerated"; exit 1; }

read_files(){ # <mnt> → prints "ok total secs"
  local mnt=$1 ok=0 tot=0 t0 t1
  t0=$(date +%s.%N)
  while IFS= read -r f; do tot=$((tot+1)); timeout 25 cat "$mnt/$f" >/dev/null 2>&1 && ok=$((ok+1)); done < "$FILELIST"
  t1=$(date +%s.%N)
  echo "$ok $tot $(awk "BEGIN{printf \"%.1f\", $t1-$t0}")"
}

printf "\n%-6s | %-28s | %-28s\n" "$MODE%" "CVMFS-brix (ok/N, secs)" "stock cvmfs2 (ok/N, secs)"
printf -- "-------+------------------------------+------------------------------\n"
for R in $RATES; do
  PLOG=$(mktemp)
  python3 tests/cvmfs/failproxy.py "$PPORT" --mode "$MODE" --rate "$(awk "BEGIN{print $R/100}")" --log "$PLOG" >/dev/null 2>&1 & FP=$!
  sleep 1

  # --- cvmfs-brix through failproxy (cold cache) ---
  BC=$(mktemp -d); BT=$(mktemp -d); BM=$(mktemp -d)
  brix_mount "$BC" "$BT" "$BM" "http_proxy=http://127.0.0.1:$PPORT"; BP=$BPID
  if wait_ready "$BM"; then BRES=$(read_files "$BM"); else BRES="0 $NGOT mount-fail"; fi
  umount_wait "$BM"; kill "$BP" 2>/dev/null; rm -rf "$BC" "$BT" "$BM"

  # --- stock cvmfs2 through failproxy (cold cache) ---
  SC=$(mktemp -d); SM=$(mktemp -d)
  cat > /tmp/bench_stock.conf <<EOF
CVMFS_SERVER_URL=$S1
CVMFS_HTTP_PROXY=http://127.0.0.1:$PPORT
CVMFS_KEYS_DIR=$KEYS
CVMFS_CACHE_BASE=$SC
CVMFS_RELOAD_SOCKETS=$SC
CVMFS_SHARED_CACHE=no
CVMFS_MAX_RETRIES=5
EOF
  timeout 60 cvmfs2 -o config=/tmp/bench_stock.conf "$REPO" "$SM" >/dev/null 2>&1 & SP=$!
  if wait_ready "$SM"; then SRES=$(read_files "$SM"); else SRES="0 $NGOT mount-fail"; fi
  umount_wait "$SM"; kill "$SP" 2>/dev/null; rm -rf "$SC" "$SM"

  kill "$FP" 2>/dev/null
  REQ=$(awk '/STATS/{r=$2} END{sub("req=","",r); print r+0}' "$PLOG" 2>/dev/null)
  FAULTS=$(awk '/STATS/{f=$3} END{sub("fault=","",f); print f+0}' "$PLOG" 2>/dev/null); rm -f "$PLOG"
  printf "%-6s | %-28s | %-28s | proxyreq=%s faults=%s\n" "$R" \
         "$(echo $BRES|awk '{printf "%s/%s  %ss",$1,$2,$3}')" \
         "$(echo $SRES|awk '{printf "%s/%s  %ss",$1,$2,$3}')" "${REQ:-?}" "${FAULTS:-?}"
done
rm -f "$FILELIST"
echo; echo "(mode=$MODE, N=$NGOT files, $REPO via $S1; both clients COLD cache [fresh dir/cell,"
echo " brix -o noclever, stock CVMFS_SHARED_CACHE=no]; proxyreq>0 proves reads hit the proxy)"
