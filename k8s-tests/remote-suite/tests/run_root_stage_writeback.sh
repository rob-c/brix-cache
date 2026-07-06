#!/usr/bin/env bash
# run_root_stage_writeback.sh — Option A: root:// kXR_write (random-access direct pwrite)
# routed through the sd_stage decorator's WRITE-BACK object. The cache node B has the
# origin O as its backend and a LOCAL stage store; a root:// upload buffers on the stage
# store (sd_stage_wb_pwrite) and flushes to O on close (sd_stage_wb_close → the one
# staging engine FLUSH). Byte-exact data on O proves root:// now uses the SAME stage
# mechanism as the staged (HTTP PUT) path — the prerequisite for retiring run_flush.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"; XRDCP="$HERE/client/bin/xrdcp"; XRDFS="$HERE/client/bin/xrdfs"
OPORT=11772; BPORT=11773; PFX="$(mktemp -d /tmp/root_wb.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o b; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/root_wb_*.bin; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/b/export" "$PFX/b/stage" "$PFX/b/logs"

# Origin O — plain root:// backend (the flush target).
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${OPORT}; brix_root on; brix_export $PFX/o/root;
    brix_auth none; brix_allow_write on;
} }
EOF
# Cache node B — backend = O, LOCAL stage store, sync flush. root:// write → sd_stage write-back.
cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${BPORT}; brix_root on; brix_export $PFX/b/export;
    brix_auth none; brix_allow_write on; brix_upload_resume off;
    brix_storage_backend root://127.0.0.1:${OPORT};
    brix_stage on;
    brix_stage_store posix:$PFX/b/stage;
    brix_stage_flush sync;
} }
EOF

head -c 2621440 /dev/urandom > /tmp/root_wb_src.bin      # 2.5 MiB, multi-write
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B start failed"; cat "$PFX/b/err"; exit 2; }
sleep 1

echo "== root:// upload to B: pwrite buffers on the stage store, close flushes to O =="
"$XRDCP" -f /tmp/root_wb_src.bin "root://127.0.0.1:${BPORT}//m.bin" >/dev/null 2>"$PFX/b/logs/cp.err" \
  && ok "upload accepted" || { bad "upload failed"; grep -iE 'stage|flush|origin|error|write' "$PFX/b/logs/e.log" | tail -10; }

echo "== byte-exact on the backend O (root:// -> B stage -> O flush chain) =="
cmp -s /tmp/root_wb_src.bin "$PFX/o/root/m.bin" \
  && ok "flushed object byte-exact on the backend O" \
  || bad "origin bytes differ (got=$(stat -c%s "$PFX/o/root/m.bin" 2>/dev/null))"

echo "== read-back through B (served from the backend) byte-exact =="
"$XRDFS" root://127.0.0.1:${BPORT} cat /m.bin > /tmp/root_wb_got.bin 2>/dev/null
cmp -s /tmp/root_wb_src.bin /tmp/root_wb_got.bin && ok "read-back byte-exact" || bad "read-back differs"

[ "$fail" = 0 ] && echo "run_root_stage_writeback: ALL PASS" || echo "run_root_stage_writeback: FAILURES"
exit "$fail"
