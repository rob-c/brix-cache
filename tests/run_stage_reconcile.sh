#!/usr/bin/env bash
# run_stage_reconcile.sh — phase-64 SP4: STAGED writes are recoverable across a crash.
# A WebDAV PUT with an ASYNC stage flush commits the object durably onto the stage
# store and journals a FLUSH record, returning 201 at once. If the server is killed
# (-9) before the scheduler flushes stage→backend, the backend has nothing — but on
# restart, worker-0 RECONCILE replays the journaled FLUSH (rebuild both tiers, re-read
# the staged object, write the backend, drop the stage copy). The write is not lost.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
BPORT=8581; PFX="$(mktemp -d /tmp/strec.XXXXXX)"; U="http://127.0.0.1:${BPORT}"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
killall_inst(){ [ -f "$PFX/nginx.pid" ] && kill -9 -"$(cat "$PFX/nginx.pid")" 2>/dev/null; pkill -9 -f "$PFX/nginx.conf" 2>/dev/null; }
cleanup(){ killall_inst; rm -rf "$PFX" /tmp/strec_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/backend" "$PFX/stage" "$PFX/journal" "$PFX/tmp" "$PFX/logs"
cat > "$PFX/nginx.conf" <<E2
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
env XROOTD_STAGE_JOURNAL_DIR=$PFX/journal;
worker_processes 1;
thread_pool default threads=2;
events { worker_connections 64; }
http { client_body_temp_path $PFX/tmp; server { listen 127.0.0.1:${BPORT};
  location / { dav_methods PUT DELETE;
    xrootd_webdav on; xrootd_webdav_root $PFX/backend; xrootd_webdav_auth none; xrootd_webdav_allow_write on;
    xrootd_webdav_stage on; xrootd_webdav_stage_store posix:$PFX/stage; xrootd_webdav_stage_flush async; } } }
E2
head -c 350000 /dev/urandom > "$PFX/src.bin"; SHA=$(sha256sum "$PFX/src.bin"|cut -d' ' -f1)
setsid "$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/start.err" || { echo "START FAIL"; cat "$PFX/start.err"; exit 2; }
# wait ready fast (well under the 1s flush tick), PUT, then crash immediately
for i in $(seq 1 20); do curl -s -o /dev/null --max-time 1 "$U/" && break; sleep 0.05; done
code=$(curl -s -o /dev/null -w '%{http_code}' -T "$PFX/src.bin" "$U/o.bin")
killall_inst    # CRASH (-9) right after the 201, before the async flush tick
echo "== PUT (async stage) then CRASH before flush: status=$code =="
[ "$code" = 201 ] && ok "PUT 201 (object staged durably, flush deferred)" || bad "PUT $code"
sleep 0.3
if [ -f "$PFX/backend/o.bin" ]; then
  echo "  note: the async flush raced the crash (write already on the backend) — reconcile not exercised this run"
else
  ls "$PFX"/journal/*.req >/dev/null 2>&1 && ok "journal FLUSH record survived the crash" || bad "no journal record"
  [ -f "$PFX/stage/o.bin" ] && ok "staged object durable on the stage store" || bad "no staged object"
  echo "== RESTART: worker-0 reconcile must replay the FLUSH → backend =="
  setsid "$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/start2.err" || { bad "restart failed"; cat "$PFX/start2.err"; }
  sleep 1.5
  { [ -f "$PFX/backend/o.bin" ] && [ "$(sha256sum "$PFX/backend/o.bin"|cut -d' ' -f1)" = "$SHA" ]; } \
    && ok "RECONCILE re-flushed the staged write to the backend, byte-exact (not lost)" \
    || { bad "backend object missing/wrong after reconcile"; grep -iE "reconcile|stage|flush" "$PFX/logs/e.log"|grep -v access_json|tail -6; }
  ls "$PFX"/journal/*.req >/dev/null 2>&1 && bad "journal record not cleared after replay" || ok "journal record cleared after successful replay"
  grep -q "restart reconcile" "$PFX/logs/e.log" && ok "reconcile logged the replay" || true
  code=$(curl -s -o /tmp/strec_g.got -w '%{http_code}' "$U/o.bin")
  { [ "$code" = 200 ] && [ "$(sha256sum /tmp/strec_g.got|cut -d' ' -f1)" = "$SHA" ]; } && ok "GET 200 byte-exact (served from the recovered backend)" || bad "GET $code"
fi
[ "$fail" = 0 ] && echo "run_stage_reconcile: ALL PASS" || echo "run_stage_reconcile: FAILURES"
exit "$fail"
