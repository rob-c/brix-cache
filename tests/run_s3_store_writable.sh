#!/usr/bin/env bash
# run_s3_store_writable.sh — phase-64 SP3: a WRITABLE s3 store. sd_remote gained
# staged_* (single-PUT / multipart upload via sd_s3) + unlink (DELETE), so an S3
# endpoint can be a stage_store. Topology: an S3 server A (the module's own S3) is
# the stage buffer; a WebDAV node B (posix backend) stages PUTs onto A, sync-flushes
# to the backend, and serves byte-exact. Proves the s3 'w' + stage_store cells.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
APORT=9002; BPORT=8541; PFX="$(mktemp -d /tmp/s3wr.XXXXXX)"; U="http://127.0.0.1:${BPORT}"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in a b; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/s3wr_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/a/s3root" "$PFX/a/logs" "$PFX/b/backend" "$PFX/b/tmp" "$PFX/b/logs"
cat > "$PFX/a/nginx.conf" <<E2
daemon on; error_log $PFX/a/logs/e.log info; pid $PFX/a/nginx.pid;
events { worker_connections 64; }
http { server { listen 127.0.0.1:${APORT};
  location / { brix_s3 on; brix_s3_root $PFX/a/s3root; brix_s3_bucket xrdstage; brix_s3_allow_write on; } } }
E2
cat > "$PFX/b/nginx.conf" <<E2
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http { client_body_temp_path $PFX/b/tmp; server { listen 127.0.0.1:${BPORT};
  location / { dav_methods PUT DELETE;
    brix_webdav on; brix_webdav_root $PFX/b/backend; brix_webdav_auth none; brix_webdav_allow_write on;
    brix_webdav_stage on; brix_webdav_stage_store s3://127.0.0.1:${APORT}/xrdstage; brix_webdav_stage_flush sync; } } }
E2
head -c 400000 /dev/urandom > "$PFX/src.bin"; SHA=$(sha256sum "$PFX/src.bin"|cut -d' ' -f1)
"$NGINX" -p "$PFX/a" -c "$PFX/a/nginx.conf" 2>"$PFX/a/err" || { echo "A fail"; cat "$PFX/a/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B fail"; cat "$PFX/b/err"; exit 2; }
sleep 1
echo "== sanity: A is a live S3 server (anonymous PUT works) =="
echo hello | curl -s -o /dev/null -w '%{http_code}\n' -T - "http://127.0.0.1:${APORT}/xrdstage/ping.txt" | sed 's/^/  direct PUT to A: /'
echo "== WebDAV PUT -> staged on S3 (A) -> sync-flushed to posix backend (B) =="
code=$(curl -s -o /dev/null -w '%{http_code}' -T "$PFX/src.bin" "$U/o.bin")
echo "  PUT status=$code (want 201)"
[ -f "$PFX/b/backend/o.bin" ] && [ "$(sha256sum "$PFX/b/backend/o.bin"|cut -d' ' -f1)" = "$SHA" ] \
  && ok "object reached the posix backend byte-exact (flushed FROM the s3 stage)" \
  || { bad "no/bad backend object"; grep -iE "stage move|staged commit|s3|error" "$PFX/b/logs/e.log"|tail -6; }
echo "== GET serves it (from backend) =="
curl -s -o /tmp/s3wr_g.got "$U/o.bin"
[ "$(sha256sum /tmp/s3wr_g.got|cut -d' ' -f1)" = "$SHA" ] && ok "GET byte-exact" || bad "GET differs"
echo "  post-flush: stage copy dropped from S3? $([ -f "$PFX/a/s3root/o.bin" ] && echo 'still present' || echo 'dropped (unlink ok)')"
echo "== errors on B? =="; grep -cE "\[(error|crit|alert)\]" "$PFX/b/logs/e.log" | sed 's/^/  error-lines=/'
[ "$fail" = 0 ] && echo "run_s3_store_writable: ALL PASS" || echo "run_s3_store_writable: FAILURES"
exit "$fail"
