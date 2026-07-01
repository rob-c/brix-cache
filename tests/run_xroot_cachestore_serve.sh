#!/usr/bin/env bash
# run_xroot_cachestore_serve.sh — phase-64 SP3: a REMOTE xroot cache_store, served
# over WebDAV. The cache STORE is a root:// server S; serving a hit reads the cached
# object (and its cinfo, via kXR_fattr) back from S over a socket — which, like the
# open, cannot run on the event loop. The whole cache open (cinfo load + miss fill +
# serve) runs off-loop via the serve-readback offload. Cold GET fills S + serves
# byte-exact; warm GET serves from S with the posix source hidden.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
SPORT=11732; BPORT=8533; PFX="$(mktemp -d /tmp/xrcs.XXXXXX)"; U="http://127.0.0.1:${BPORT}"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in s b; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/xrcs_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/s/root" "$PFX/s/logs" "$PFX/b/backend" "$PFX/b/tmp" "$PFX/b/logs"
cat > "$PFX/s/nginx.conf" <<E2
daemon on; error_log $PFX/s/logs/e.log info; pid $PFX/s/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${SPORT}; xrootd on; xrootd_root $PFX/s/root; xrootd_auth none; xrootd_allow_write on; } }
E2
cat > "$PFX/b/nginx.conf" <<E2
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http { client_body_temp_path $PFX/b/tmp; server { listen 127.0.0.1:${BPORT};
  location / { xrootd_webdav on; xrootd_webdav_root $PFX/b/backend; xrootd_webdav_auth none;
    xrootd_webdav_cache_store root://127.0.0.1:${SPORT}; } } }
E2
head -c 600000 /dev/urandom > "$PFX/b/backend/f.bin"; SHA=$(sha256sum "$PFX/b/backend/f.bin"|cut -d' ' -f1)
"$NGINX" -p "$PFX/s" -c "$PFX/s/nginx.conf" 2>"$PFX/s/err" || { echo "S fail"; cat "$PFX/s/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B fail"; cat "$PFX/b/err"; exit 2; }
sleep 1
echo "== cold GET: fill posix source -> xroot cache_store S, served off-loop =="
code=$(curl -s -o /tmp/xrcs_c.got -w '%{http_code}' "$U/f.bin")
{ [ "$code" = 200 ] && [ "$(sha256sum /tmp/xrcs_c.got|cut -d' ' -f1)" = "$SHA" ]; } \
  && ok "cold GET 200 byte-exact" || { bad "cold GET $code"; grep -iE "serve offload|cache|xroot|error" "$PFX/b/logs/e.log"|tail -8; }
grep -q "serve offload: materialising remote" "$PFX/b/logs/e.log" && ok "served OFF the event loop (thread pool)" || bad "no serve-offload logged"
[ -f "$PFX/s/root/f.bin" ] && ok "cached object landed on the xroot store S" || bad "no object on S"
echo "== warm GET: served from the xroot cache (posix source hidden) =="
mv "$PFX/b/backend/f.bin" "$PFX/b/backend/.f.hidden"
code=$(curl -s -o /tmp/xrcs_w.got -w '%{http_code}' "$U/f.bin")
{ [ "$code" = 200 ] && [ "$(sha256sum /tmp/xrcs_w.got|cut -d' ' -f1)" = "$SHA" ]; } \
  && ok "WARM hit byte-exact from xroot cache (source hidden)" || bad "warm $code"
echo "== errors on B? =="; grep -cE "\[(error|crit|alert)\]" "$PFX/b/logs/e.log" | sed 's/^/  error-lines=/'
[ "$fail" = 0 ] && echo "run_xroot_cachestore_serve: ALL PASS" || echo "run_xroot_cachestore_serve: FAILURES"
exit "$fail"
