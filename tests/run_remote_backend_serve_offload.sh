#!/usr/bin/env bash
# run_remote_backend_serve_offload.sh — phase-64 SP3: serve a REMOTE root:// primary
# backend over WebDAV. sd_xroot eagerly connects on open AND reads over a socket, so
# the whole serve must run off the event loop (the read-only complement to the
# off-loop fill). A byte-exact GET proves open+read ran on the thread pool (inline
# they FAIL on the un-pumped loop), corroborated by the "serve offload" log line.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
OPORT=11722; BPORT=8531; PFX="$(mktemp -d /tmp/rbserve.XXXXXX)"; U="http://127.0.0.1:${BPORT}"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o b; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/rbs_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/b/export" "$PFX/b/tmp" "$PFX/b/logs"
cat > "$PFX/o/nginx.conf" <<E2
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; xrootd on; xrootd_root $PFX/o/root; xrootd_auth none; } }
E2
cat > "$PFX/b/nginx.conf" <<E2
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http { client_body_temp_path $PFX/b/tmp; server { listen 127.0.0.1:${BPORT};
  location / { xrootd_webdav on; xrootd_webdav_root $PFX/b/export; xrootd_webdav_auth none;
    xrootd_webdav_storage_backend root://127.0.0.1:${OPORT}; } } }
E2
head -c 500000  /dev/urandom > "$PFX/o/root/small.bin"
head -c 2600000 /dev/urandom > "$PFX/o/root/big.bin"
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O fail"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B fail"; cat "$PFX/b/err"; exit 2; }
sleep 1
echo "== GET a REMOTE root:// backend object over WebDAV (open+read off-loop) =="
code=$(curl -s -o /tmp/rbs_s.got -w '%{http_code}' "$U/small.bin")
{ [ "$code" = 200 ] && cmp -s "$PFX/o/root/small.bin" /tmp/rbs_s.got; } \
  && ok "GET 200 byte-exact (remote xroot backend served via off-loop materialise)" \
  || { bad "GET failed (status=$code)"; grep -iE "serve offload|xroot|error|stall" "$PFX/b/logs/e.log" | tail -6; }
grep -q "serve offload: materialising remote" "$PFX/b/logs/e.log" && ok "serve ran OFF the event loop (thread pool)" || bad "no serve-offload logged"
echo "== Range GET (206 from the materialised temp) =="
RB=$(curl -s -r 1000-1010 "$U/big.bin" | cmp -s - <(dd if="$PFX/o/root/big.bin" bs=1 skip=1000 count=11 2>/dev/null) && echo ok || echo no)
[ "$RB" = ok ] && ok "Range GET byte-exact" || bad "Range GET differs"
echo "== multi-chunk (>1 MiB) =="
code=$(curl -s -o /tmp/rbs_b.got -w '%{http_code}' "$U/big.bin")
{ [ "$code" = 200 ] && cmp -s "$PFX/o/root/big.bin" /tmp/rbs_b.got; } && ok "multi-chunk byte-exact" || bad "multi-chunk failed ($code)"
echo "== errors on B? =="; grep -cE "\[(error|crit|alert)\]" "$PFX/b/logs/e.log" | sed 's/^/  error-lines=/'
[ "$fail" = 0 ] && echo "run_remote_backend_serve_offload: ALL PASS" || echo "run_remote_backend_serve_offload: FAILURES"
exit "$fail"
