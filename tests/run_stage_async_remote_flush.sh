#!/usr/bin/env bash
# run_stage_async_remote_flush.sh — phase-64 SP4: the async stage-flush MOVER runs on
# the thread pool, so a flush to a REMOTE backend works. Topology: a WebDAV node B
# stages PUTs on a LOCAL posix store and ASYNC-flushes to a REMOTE root:// origin O.
# The scheduler offloads the mover to a worker thread; inline on the event loop the
# sd_xroot socket write would FAIL (un-pumped loop), so O receiving the bytes proves
# the offload. The stage copy is dropped on completion.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
OPORT=11742; BPORT=8585; PFX="$(mktemp -d /tmp/saf.XXXXXX)"; U="http://127.0.0.1:${BPORT}"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o b; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/b/export" "$PFX/b/stage" "$PFX/b/tmp" "$PFX/b/logs"
cat > "$PFX/o/nginx.conf" <<E2
daemon on; error_log $PFX/o/logs/e.log error; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; brix_root on; brix_export $PFX/o/root; brix_auth none; brix_allow_write on; } }
E2
cat > "$PFX/b/nginx.conf" <<E2
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http { client_body_temp_path $PFX/b/tmp; server { listen 127.0.0.1:${BPORT};
  location / { dav_methods PUT DELETE;
    brix_webdav on; brix_export $PFX/b/export; brix_webdav_auth none; brix_allow_write on;
    brix_storage_backend root://127.0.0.1:${OPORT};
    brix_stage on; brix_stage_store posix:$PFX/b/stage; brix_stage_flush async; } } }
E2
head -c 420000 /dev/urandom > "$PFX/src.bin"; SHA=$(sha256sum "$PFX/src.bin"|cut -d' ' -f1)
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O fail"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B fail"; cat "$PFX/b/err"; exit 2; }
sleep 1
echo "== WebDAV PUT (async stage) → local stage, then OFF-LOOP flush to the REMOTE xroot backend =="
code=$(curl -s -o /dev/null -w '%{http_code}' -T "$PFX/src.bin" "$U/o.bin")
[ "$code" = 201 ] && ok "PUT 201 (staged locally, flush deferred)" || bad "PUT $code"
[ -f "$PFX/b/stage/o.bin" ] && ok "object staged on the local posix store" || true
echo "== poll the REMOTE origin O until the off-loop flush lands the object =="
got=""; for i in $(seq 1 12); do sleep 1; [ -f "$PFX/o/root/o.bin" ] && { got=$i; break; }; done
{ [ -n "$got" ] && [ "$(sha256sum "$PFX/o/root/o.bin" 2>/dev/null|cut -d' ' -f1)" = "$SHA" ]; } \
  && ok "async flush reached the REMOTE backend after ~${got}s, byte-exact (mover ran off-loop)" \
  || { bad "remote backend never got the object"; grep -iE "stage|flush|move|xroot|error" "$PFX/b/logs/e.log"|grep -v access_json|tail -8; }
[ ! -f "$PFX/b/stage/o.bin" ] && ok "stage copy dropped after the flush completed" || bad "stage copy not dropped"
[ "$fail" = 0 ] && echo "run_stage_async_remote_flush: ALL PASS" || echo "run_stage_async_remote_flush: FAILURES"
exit "$fail"
