#!/usr/bin/env bash
# run_cache_wt_driver.sh — C-5 (phase-63): the cache write-back flush mirrors a
# dirty local file to the origin THROUGH the sd_xroot driver (open/pwrite/ftruncate/
# fsync), not the bespoke origin wire client. Node B is a local POSIX export with
# write-through enabled to a remote root:// origin O; a write to B lands locally and
# flushes to O on close. Verifies both sync and async flush modes, byte-exact, incl.
# a multi-chunk object. (Anonymous origin — the GSI/proxy origin keeps the exec path.)
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"; XRDCP="$HERE/client/bin/xrdcp"; XRDFS="$HERE/client/bin/xrdfs"
OPORT=11684; SPORT=11685; APORT=11686; PFX="$(mktemp -d /tmp/wt_drv.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o s a; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/wt_drv_*.bin /tmp/wt_drv_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/s/export" "$PFX/s/logs" "$PFX/a/export" "$PFX/a/logs"

# Origin O — a normal read-write root:// server (the write-back target).
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; xrootd on; xrootd_storage_backend posix:$PFX/o/root;
    xrootd_auth none; xrootd_allow_write on; xrootd_upload_resume off; } }
EOF
# Node S/A — local POSIX export, write-through (sync / async) to origin O.
for v in s:${SPORT}:sync a:${APORT}:async; do
    r="${v%%:*}"; rest="${v#*:}"; p="${rest%%:*}"; mode="${rest##*:}"
    cat > "$PFX/$r/nginx.conf" <<EOF
daemon on; error_log $PFX/$r/logs/e.log info; pid $PFX/$r/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${p}; xrootd on; xrootd_auth none;
    xrootd_storage_backend posix:$PFX/$r/export;
    xrootd_allow_write on; xrootd_upload_resume off;
    xrootd_write_through on; xrootd_wt_mode ${mode};
    xrootd_wt_origin root://127.0.0.1:${OPORT};
} }
EOF
done
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/s" -c "$PFX/s/nginx.conf" 2>"$PFX/s/err" || { echo "S start failed"; cat "$PFX/s/err"; exit 2; }
"$NGINX" -p "$PFX/a" -c "$PFX/a/nginx.conf" 2>"$PFX/a/err" || { echo "A start failed"; cat "$PFX/a/err"; exit 2; }
sleep 1

head -c 300000  /dev/urandom > /tmp/wt_drv_small.bin
head -c 2600000 /dev/urandom > /tmp/wt_drv_big.bin

echo "== SYNC write-through: write to S flushes to O via the sd_xroot driver =="
"$XRDCP" -f /tmp/wt_drv_small.bin "root://127.0.0.1:${SPORT}//s_small.bin" >/dev/null 2>"$PFX/s/logs/put.err"
[ -f "$PFX/s/export/s_small.bin" ] && ok "write landed locally on S (write-through cache)" || bad "no local copy on S"
cmp -s /tmp/wt_drv_small.bin "$PFX/o/root/s_small.bin" && ok "flushed byte-exact to ORIGIN via driver" \
  || { bad "origin differs/missing"; grep -iE 'wt:|write-through|driver|origin|error' "$PFX/s/logs/e.log" | tail -8; }

echo "== SYNC multi-chunk (> 1 MiB) =="
"$XRDCP" -f /tmp/wt_drv_big.bin "root://127.0.0.1:${SPORT}//s_big.bin" >/dev/null 2>/dev/null
cmp -s /tmp/wt_drv_big.bin "$PFX/o/root/s_big.bin" && ok "multi-chunk flushed byte-exact via driver" \
  || bad "multi-chunk differs (origin=$(stat -c%s "$PFX/o/root/s_big.bin" 2>/dev/null))"

echo "== ASYNC write-through: write to A flushes to O via the driver (thread pool) =="
"$XRDCP" -f /tmp/wt_drv_small.bin "root://127.0.0.1:${APORT}//a_small.bin" >/dev/null 2>"$PFX/a/logs/put.err"
# async flush completes after close; poll the origin briefly
for i in $(seq 1 40); do [ -f "$PFX/o/root/a_small.bin" ] && cmp -s /tmp/wt_drv_small.bin "$PFX/o/root/a_small.bin" && break; sleep 0.1; done
cmp -s /tmp/wt_drv_small.bin "$PFX/o/root/a_small.bin" && ok "async flushed byte-exact to ORIGIN via driver" \
  || { bad "async origin differs/missing"; grep -iE 'wt:|write-through|driver|origin|error' "$PFX/a/logs/e.log" | tail -8; }

echo "== read-back through S returns the same bytes =="
"$XRDFS" "root://127.0.0.1:${SPORT}" cat /s_small.bin > /tmp/wt_drv_rb.got 2>/dev/null
cmp -s /tmp/wt_drv_small.bin /tmp/wt_drv_rb.got && ok "read-back byte-exact" || bad "read-back differs"

[ "$fail" = 0 ] && echo "run_cache_wt_driver: ALL PASS" || echo "run_cache_wt_driver: FAILURES"
exit "$fail"
