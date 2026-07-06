#!/usr/bin/env bash
#
# run_remote_backend_write.sh — Mode A (transparent write-through) for a writable
# remote root:// backend. Node B's PRIMARY storage IS a remote root:// server
# (node O), selected with `brix_storage_backend root://O`. A write to B streams
# straight through the sd_xroot driver to O (no local copy); a read back through B
# returns the same bytes. Byte-exact, incl. a multi-chunk object.
#
# Usage: tests/run_remote_backend_write.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDCP="$HERE/client/bin/xrdcp"
XRDFS="$HERE/client/bin/xrdfs"
OPORT=11650
BPORT=11651
PFX="$(mktemp -d /tmp/remote_bw.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() {
    for r in o b; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done
    rm -rf "$PFX" /tmp/remote_bw_*.bin /tmp/remote_bw_*.got
}
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/b/export" "$PFX/b/logs"

# Origin O — a normal read-write root:// server.
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; brix_root on; brix_export $PFX/o/root;
    brix_auth none; brix_allow_write on; brix_upload_resume off; } }
EOF

# Node B — its export storage IS the remote origin O (sd_xroot backend).
cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${BPORT}; brix_root on; brix_export $PFX/b/export; brix_auth none;
    brix_allow_write on; brix_upload_resume off;
    brix_storage_backend root://127.0.0.1:${OPORT};
} }
EOF

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "origin start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "node start failed"; cat "$PFX/b/err"; exit 2; }
sleep 1

head -c 300000  /dev/urandom > /tmp/remote_bw_small.bin     # < 1 MiB
head -c 2600000 /dev/urandom > /tmp/remote_bw_big.bin       # multi-chunk

echo "== write-through: a write to B streams to origin O, no local copy =="
"$XRDCP" -f /tmp/remote_bw_small.bin "root://127.0.0.1:${BPORT}//small.bin" >/dev/null 2>"$PFX/b/logs/put.err"
if cmp -s /tmp/remote_bw_small.bin "$PFX/o/root/small.bin"; then
    ok "write landed byte-exact on the ORIGIN (via sd_xroot)"
else
    bad "origin file differs / missing"; grep -iE 'xroot|origin|write|error' "$PFX/b/logs/e.log" | tail -6
fi
[ ! -e "$PFX/b/export/small.bin" ] && ok "no local copy on node B (transparent passthrough)" \
    || bad "unexpected local copy on B"

echo "== read-back through B returns the same bytes =="
"$XRDFS" "root://127.0.0.1:${BPORT}" cat /small.bin > /tmp/remote_bw_s.got 2>/dev/null
cmp -s /tmp/remote_bw_small.bin /tmp/remote_bw_s.got && ok "read-back byte-exact" || bad "read-back differs"

echo "== stat through B reflects the origin object =="
sz=$("$XRDFS" "root://127.0.0.1:${BPORT}" stat /small.bin 2>/dev/null | grep -oiE 'size[: ]+[0-9]+' | grep -oE '[0-9]+' | head -1)
[ "$sz" = "300000" ] && ok "stat size correct ($sz)" || bad "stat size wrong (got '$sz')"

echo "== multi-chunk write-through (> 1 MiB) =="
"$XRDCP" -f /tmp/remote_bw_big.bin "root://127.0.0.1:${BPORT}//big.bin" >/dev/null 2>/dev/null
cmp -s /tmp/remote_bw_big.bin "$PFX/o/root/big.bin" && ok "multi-chunk write byte-exact on origin" \
    || bad "multi-chunk differs (origin=$(stat -c%s "$PFX/o/root/big.bin" 2>/dev/null))"

[ "$fail" = 0 ] && echo "run_remote_backend_write: ALL PASS" || echo "run_remote_backend_write: FAILURES"
exit "$fail"
