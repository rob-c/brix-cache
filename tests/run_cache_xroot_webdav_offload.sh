#!/usr/bin/env bash
#
# run_cache_xroot_webdav_offload.sh — phase-64 SP2: the HTTP read plane fills a
# cache MISS from a REMOTE root:// source on a WORKER THREAD, not inline on the
# event loop. The sd_xroot wire client cannot do blocking socket I/O on the
# un-pumped loop (it fails EIO), so an inline fill is impossible here; a byte-exact
# cold GET therefore PROVES the fill ran off-loop (corroborated by the "offloaded
# cache fill" log line). XCache topology: a WebDAV cache node B fronts a root://
# origin O with a LOCAL posix cache store. A cold GET is filled off-loop, stored
# locally, and served via sendfile; a warm GET is a local cache hit.
#
# Usage: tests/run_cache_xroot_webdav_offload.sh [nginx-binary]
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
OPORT=11672
BPORT=8495
PFX="$(mktemp -d /tmp/cache_xrdav.XXXXXX)"
U="http://127.0.0.1:${BPORT}"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() {
    for r in o b; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done
    rm -rf "$PFX" /tmp/cxw_*.got
}
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/b/export" "$PFX/b/cache" "$PFX/b/tmp" "$PFX/b/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; xrootd on; xrootd_root $PFX/o/root; xrootd_auth none; } }
EOF

cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    client_body_temp_path $PFX/b/tmp;
    server {
        listen 127.0.0.1:${BPORT};
        location / {
            xrootd_webdav on;
            xrootd_webdav_root $PFX/b/export;
            xrootd_webdav_auth none;
            xrootd_webdav_storage_backend root://127.0.0.1:${OPORT};
            xrootd_webdav_cache_store posix:$PFX/b/cache;
        }
    }
}
EOF

# seed two files DIRECTLY on the origin O's namespace
head -c 500000  /dev/urandom > "$PFX/o/root/small.bin"
head -c 2600000 /dev/urandom > "$PFX/o/root/big.bin"

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B start failed"; cat "$PFX/b/err"; exit 2; }
sleep 1

echo "== cold WebDAV GET: cache MISS fills from the remote root:// source off-loop =="
code=$(curl -s -o /tmp/cxw_s.got -w '%{http_code}' "$U/small.bin")
[ "$code" = 200 ] && ok "cold GET 200" || bad "cold GET status=$code"
cmp -s "$PFX/o/root/small.bin" /tmp/cxw_s.got \
  && ok "byte-exact (filled from remote xroot, served from local cache)" \
  || { bad "cold GET differs"; grep -iE 'cache|xroot|offload|fill|error|stall' "$PFX/b/logs/e.log" | tail -8; }
grep -q "offloaded cache fill" "$PFX/b/logs/e.log" \
  && ok "fill ran OFF the event loop (thread pool)" \
  || bad "no off-loop offload logged (fill may have run inline)"
[ -f "$PFX/b/cache/small.bin" ] && ok "object landed in the LOCAL posix cache store" || bad "no local cache entry"

echo "== warm WebDAV GET: served from the local cache (sendfile, no offload) =="
code=$(curl -s -o /tmp/cxw_s2.got -w '%{http_code}' "$U/small.bin")
{ [ "$code" = 200 ] && cmp -s "$PFX/o/root/small.bin" /tmp/cxw_s2.got; } \
  && ok "warm hit byte-exact" || bad "warm hit failed (status=$code)"

echo "== multi-chunk cold GET (> 1 MiB fill chunk), off-loop =="
code=$(curl -s -o /tmp/cxw_b.got -w '%{http_code}' "$U/big.bin")
{ [ "$code" = 200 ] && cmp -s "$PFX/o/root/big.bin" /tmp/cxw_b.got; } \
  && ok "multi-chunk byte-exact" \
  || bad "multi-chunk failed (status=$code got=$(stat -c%s /tmp/cxw_b.got 2>/dev/null))"

[ "$fail" = 0 ] && echo "run_cache_xroot_webdav_offload: ALL PASS" || echo "run_cache_xroot_webdav_offload: FAILURES"
exit "$fail"
