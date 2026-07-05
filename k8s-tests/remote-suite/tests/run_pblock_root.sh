#!/usr/bin/env bash
#
# run_pblock_root.sh — end-to-end root:// (XRootD wire) on the pblock storage
# driver: data movement (xrdcp PUT/GET single + multi-block, byte-exact),
# metadata (xrdfs stat size), and namespace (xrdfs mkdir / ls / rm). Stands up
# its own stream-only nginx on a pblock-backed export and asserts each op lands
# entirely in the block catalog + data dir.
#
# Usage: tests/run_pblock_root.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDCP="$HERE/client/bin/xrdcp"
XRDFS="$HERE/client/bin/xrdfs"
PORT=11494
PFX="$(mktemp -d /tmp/pblock_root.XXXXXX)"
H="root://127.0.0.1:${PORT}/"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
chk() { [ "$2" = "$3" ] && ok "$1 ($2)" || bad "$1: got '$2' want '$3'"; }

mkdir -p "$PFX/root" "$PFX/logs"
cat > "$PFX/nginx.conf" <<EOF
daemon on;
error_log $PFX/logs/error.log info;
pid $PFX/nginx.pid;
events { worker_connections 64; }
stream {
    server {
        listen 127.0.0.1:${PORT};
        xrootd on;
        brix_root $PFX/root;
        brix_auth none;
        brix_allow_write on;
        brix_upload_resume off;
        brix_storage_backend  pblock;
        brix_pblock_block_size 1m;
        brix_access_log $PFX/logs/access.log;
    }
}
EOF

cleanup() { [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; rm -rf "$PFX" /tmp/pbr_*.bin; }
trap cleanup EXIT

"$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/logs/start.err" || { echo "nginx failed to start"; cat "$PFX/logs/start.err"; exit 2; }
sleep 1

cp_up()   { "$XRDCP" -f "$1" "${H}$2" >/dev/null 2>&1 && echo 0 || echo $?; }
cp_down() { "$XRDCP" -f "${H}$1" "$2" >/dev/null 2>&1 && echo 0 || echo $?; }

echo "== data movement =="
head -c 700000  /dev/urandom > /tmp/pbr_small.bin     # < 1 block
head -c 2621440 /dev/urandom > /tmp/pbr_multi.bin     # 2.5 blocks
chk "PUT small (1 block)"  "$(cp_up /tmp/pbr_small.bin s.bin)" 0
chk "PUT multi (3 blocks)" "$(cp_up /tmp/pbr_multi.bin m.bin)" 0
chk "GET small"            "$(cp_down s.bin /tmp/pbr_s.got)" 0
chk "GET multi"            "$(cp_down m.bin /tmp/pbr_m.got)" 0
cmp -s /tmp/pbr_small.bin /tmp/pbr_s.got && ok "GET small byte-exact" || bad "GET small differs"
cmp -s /tmp/pbr_multi.bin /tmp/pbr_m.got && ok "GET multi byte-exact" || bad "GET multi differs"

echo "== metadata =="
STAT_SZ=$("$XRDFS" "root://127.0.0.1:${PORT}" stat /m.bin 2>/dev/null | awk '/Size:/{print $2}')
chk "stat size (multi)" "$STAT_SZ" 2621440

echo "== checksum-at-rest (Layer 4, whole multi-block object) =="
REF_A=$("$HERE/client/bin/xrdadler32" /tmp/pbr_multi.bin 2>/dev/null | awk '{print $1}')
SRV_A=$("$XRDFS" "root://127.0.0.1:${PORT}" query checksum /m.bin 2>/dev/null | grep adler32 | awk '{print $2}')
chk "adler32 whole-file" "$SRV_A" "$REF_A"
REF_C=$("$HERE/client/bin/xrdcrc32c" /tmp/pbr_multi.bin 2>/dev/null | awk '{print $1}')
SRV_C=$("$XRDFS" "root://127.0.0.1:${PORT}" query checksum "/m.bin?cks.type=crc32c" 2>/dev/null | grep crc32c | awk '{print $2}')
chk "crc32c whole-file"  "$SRV_C" "$REF_C"

echo "== namespace mutation =="
chk "mkdir /d"        "$("$XRDFS" "root://127.0.0.1:${PORT}" mkdir /d >/dev/null 2>&1 && echo 0 || echo $?)" 0
chk "PUT /d/x.bin"    "$(cp_up /tmp/pbr_small.bin d/x.bin)" 0
LS_OUT=$("$XRDFS" "root://127.0.0.1:${PORT}" ls / 2>/dev/null)
echo "$LS_OUT" | grep -q 's.bin' && ok "ls shows s.bin" || bad "ls missing s.bin"
echo "$LS_OUT" | grep -q '/d'    && ok "ls shows /d"    || bad "ls missing /d"
chk "rm /s.bin"       "$("$XRDFS" "root://127.0.0.1:${PORT}" rm /s.bin >/dev/null 2>&1 && echo 0 || echo $?)" 0
chk "stat removed"    "$("$XRDFS" "root://127.0.0.1:${PORT}" stat /s.bin >/dev/null 2>&1 && echo present || echo gone)" gone

echo "== on-disk =="
[ -f "$PFX/root/catalog.db" ] && ok "catalog.db present"     || bad "no catalog.db"
[ -d "$PFX/root/data" ]       && ok "data/ block dir present" || bad "no data/"

[ "$fail" = 0 ] && echo "run_pblock_root: ALL PASS" || echo "run_pblock_root: FAILURES"
exit "$fail"
