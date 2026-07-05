#!/usr/bin/env bash
# run_http_store_writable.sh — phase-64 SP3: a WRITABLE http store. sd_http gained a
# buffered staged PUT + DELETE, so an HTTP/WebDAV origin can be a stage_store. A
# WebDAV server A (the module's own) is the stage buffer; a WebDAV node B (posix
# backend) stages PUTs onto A over HTTP, sync-flushes to the backend, serves exact.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
APORT=8552; BPORT=8553; PFX="$(mktemp -d /tmp/htwr.XXXXXX)"; U="http://127.0.0.1:${BPORT}"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in a b; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/htwr_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/a/root" "$PFX/a/tmp" "$PFX/a/logs" "$PFX/b/backend" "$PFX/b/tmp" "$PFX/b/logs"
cat > "$PFX/a/nginx.conf" <<E2
daemon on; error_log $PFX/a/logs/e.log info; pid $PFX/a/nginx.pid;
events { worker_connections 64; }
http { client_body_temp_path $PFX/a/tmp; server { listen 127.0.0.1:${APORT};
  location / { dav_methods PUT DELETE; brix_webdav on; brix_webdav_root $PFX/a/root; brix_webdav_auth none; brix_webdav_allow_write on; } } }
E2
cat > "$PFX/b/nginx.conf" <<E2
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http { client_body_temp_path $PFX/b/tmp; server { listen 127.0.0.1:${BPORT};
  location / { dav_methods PUT DELETE;
    brix_webdav on; brix_webdav_root $PFX/b/backend; brix_webdav_auth none; brix_webdav_allow_write on;
    brix_webdav_stage on; brix_webdav_stage_store http://127.0.0.1:${APORT}; brix_webdav_stage_flush sync; } } }
E2
head -c 350000 /dev/urandom > "$PFX/src.bin"; SHA=$(sha256sum "$PFX/src.bin"|cut -d' ' -f1)
"$NGINX" -p "$PFX/a" -c "$PFX/a/nginx.conf" 2>"$PFX/a/err" || { echo "A fail"; cat "$PFX/a/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B fail"; cat "$PFX/b/err"; exit 2; }
sleep 1
echo "== WebDAV PUT -> staged on HTTP origin (A) -> sync-flushed to posix backend (B) =="
code=$(curl -s -o /dev/null -w '%{http_code}' -T "$PFX/src.bin" "$U/h.bin")
echo "  PUT status=$code (want 201)"
[ -f "$PFX/b/backend/h.bin" ] && [ "$(sha256sum "$PFX/b/backend/h.bin"|cut -d' ' -f1)" = "$SHA" ] \
  && ok "object reached the posix backend byte-exact (flushed FROM the http stage)" \
  || { bad "no/bad backend object"; grep -iE "stage move|staged commit|http|error" "$PFX/b/logs/e.log"|grep -v access_json|tail -6; }
echo "== GET serves it (from backend) =="
curl -s -o /tmp/htwr_g.got "$U/h.bin"; [ "$(sha256sum /tmp/htwr_g.got|cut -d' ' -f1)" = "$SHA" ] && ok "GET byte-exact" || bad "GET differs"
echo "  post-flush: stage copy dropped from the http origin? $([ -f "$PFX/a/root/h.bin" ] && echo 'still present' || echo 'dropped (DELETE ok)')"
echo "== errors on B? =="; grep -cE "\[(error|crit|alert)\]" "$PFX/b/logs/e.log" | sed 's/^/  error-lines=/'
[ "$fail" = 0 ] && echo "run_http_store_writable: ALL PASS" || echo "run_http_store_writable: FAILURES"
exit "$fail"
