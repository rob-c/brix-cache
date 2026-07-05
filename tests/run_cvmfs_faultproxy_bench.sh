#!/usr/bin/env bash
# run_cvmfs_faultproxy_bench.sh — cvmfs-brix vs stock cvmfs2 through the REAL
# in-repo TCP fault injector (client/bin/fault_proxy, tests/c/fault_proxy.c).
#
# The proxy is a transparent TCP relay to a real CVMFS Stratum-1; faults are pulled
# over its control port. `lossy <pct>` severs the connection per chunk (faithful
# application-visible packet-loss-as-resets); `reorder <pct> <ms>` delivers a % of
# chunks late (out-of-order latency). Both clients point their SERVER URL at the
# proxy (no byte corruption — TCP integrity preserved), so this measures
# reconnect/resume resilience.
#
#   REPO (default atlas.cern.ch)  MODE (lossy|reorder, default lossy)
#   RATES ("0 1 5 15" pct, fractional ok)  NFILES (default 15)  S1HOST
set -uo pipefail
cd "$(dirname "$0")/.."
REPO="${REPO:-atlas.cern.ch}"
S1HOST="${S1HOST:-cernvmfs.gridpp.rl.ac.uk}"
KEYS=/etc/cvmfs/keys/cern.ch
MODE=${MODE:-lossy}; RATES=${RATES:-"0 1 5 15"}; NFILES=${NFILES:-15}
FP=client/bin/fault_proxy; BRIX=/tmp/brixcvmfs

[ -x "$FP" ] || { echo "SKIP: fault_proxy not built ($FP)"; exit 0; }
command -v cvmfs2 >/dev/null || { echo "SKIP: no stock cvmfs2"; exit 0; }
curl -fsS -o /dev/null --max-time 8 -H "Host: 127.0.0.1" "http://$S1HOST/cvmfs/$REPO/.cvmfspublished" \
  || { echo "SKIP: $S1HOST does not serve $REPO by path"; exit 0; }
[ -x "$BRIX" ] || { echo "SKIP: build /tmp/brixcvmfs first"; exit 0; }

LPORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
CPORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
"$FP" "$LPORT" "$S1HOST" 80 "$CPORT" >/dev/null 2>&1 & FPP=$!
sleep 1
SURL="http://127.0.0.1:$LPORT/cvmfs/$REPO"
ctl(){ exec 3<>"/dev/tcp/127.0.0.1/$CPORT"; printf '%s\n' "$1" >&3; timeout 2 head -c 120 <&3 >/dev/null 2>&1 || true; exec 3>&- 3<&-; }
cleanup(){ ctl clear 2>/dev/null || true; kill "$FPP" 2>/dev/null || true; }
trap cleanup EXIT

wait_ready(){ local m=$1 n=0; while [ $n -lt 100 ]; do [ -n "$(ls -A "$m" 2>/dev/null)" ] && return 0; sleep 0.5; n=$((n+1)); done; return 1; }
umnt(){ fusermount3 -u "$1" 2>/dev/null||fusermount -u "$1" 2>/dev/null; sleep 1; }
read_files(){ local m=$1 ok=0 t=0 a b; a=$(date +%s.%N)
  while IFS= read -r f; do t=$((t+1)); timeout 30 cat "$m/$f" >/dev/null 2>&1 && ok=$((ok+1)); done < "$FILELIST"
  b=$(date +%s.%N); echo "$ok $t $(awk "BEGIN{printf \"%.1f\",$b-$a}")"; }

FILELIST=$(mktemp)
echo "== enumerate $NFILES $REPO files (fault-free) =="
ctl clear
E_M=$(mktemp -d); E_C=$(mktemp -d); E_T=$(mktemp -d)
env BRIXCVMFS_SERVER="$SURL" BRIXCVMFS_PUBKEY="$KEYS" BRIXCVMFS_CACHE="$E_C" BRIXCVMFS_TMP="$E_T" \
  "$BRIX" "$REPO" "$E_M" -o noclever,fresh,retries=6,auto_unmount -f >/dev/null 2>&1 & EP=$!
wait_ready "$E_M" || echo "  (enumerate slow)"
find "$E_M" -maxdepth 6 -type f -size -64k 2>/dev/null | head -"$NFILES" | sed "s#$E_M/##" > "$FILELIST"
NGOT=$(wc -l < "$FILELIST"); echo "  enumerated $NGOT files"
umnt "$E_M"; kill "$EP" 2>/dev/null; rm -rf "$E_C" "$E_T" "$E_M"
[ "$NGOT" -ge 1 ] || { echo "FAIL: no files"; exit 1; }

printf "\n%-7s | %-26s | %-26s\n" "$MODE%" "CVMFS-brix (ok/N, secs)" "stock cvmfs2 (ok/N, secs)"
printf -- "--------+----------------------------+----------------------------\n"
for R in $RATES; do
  if [ "$R" = "0" ]; then ctl clear; else [ "$MODE" = reorder ] && ctl "reorder $R 60" || ctl "lossy $R"; fi

  BC=$(mktemp -d); BT=$(mktemp -d); BM=$(mktemp -d)
  env BRIXCVMFS_SERVER="$SURL" BRIXCVMFS_PUBKEY="$KEYS" BRIXCVMFS_CACHE="$BC" BRIXCVMFS_TMP="$BT" \
    "$BRIX" "$REPO" "$BM" -o noclever,fresh,retries=6,auto_unmount -f >/dev/null 2>&1 & BP=$!
  if wait_ready "$BM"; then BRES=$(read_files "$BM"); else BRES="0 $NGOT mount-fail"; fi
  umnt "$BM"; kill "$BP" 2>/dev/null; rm -rf "$BC" "$BT" "$BM"

  SC=$(mktemp -d); SM=$(mktemp -d)
  cat > /tmp/fpbench_stock.conf <<EOF
CVMFS_SERVER_URL=$SURL
CVMFS_HTTP_PROXY=DIRECT
CVMFS_KEYS_DIR=$KEYS
CVMFS_CACHE_BASE=$SC
CVMFS_RELOAD_SOCKETS=$SC
CVMFS_SHARED_CACHE=no
CVMFS_MAX_RETRIES=6
EOF
  timeout 90 cvmfs2 -o config=/tmp/fpbench_stock.conf "$REPO" "$SM" >/dev/null 2>&1 & SP=$!
  if wait_ready "$SM"; then SRES=$(read_files "$SM"); else SRES="0 $NGOT mount-fail"; fi
  umnt "$SM"; kill "$SP" 2>/dev/null; rm -rf "$SC" "$SM"

  printf "%-7s | %-26s | %-26s\n" "$R" \
    "$(echo $BRES|awk '{printf "%s/%s  %ss",$1,$2,$3}')" \
    "$(echo $SRES|awk '{printf "%s/%s  %ss",$1,$2,$3}')"
done
rm -f "$FILELIST"
echo; echo "(REAL fault_proxy $MODE via $S1HOST → $REPO; $NGOT files; both COLD cache, direct to proxy;"
echo " lossy=per-chunk connection sever, reorder=per-chunk late delivery — TCP integrity preserved)"
