#!/usr/bin/env bash
# run_tape_recall_async.sh — phase-64 SP5: async nearline (tape) recall. A GET of an
# OFFLINE object on a tape:// backend cannot block the worker for the MSS latency, so
# the recall is started and the open "parks": the HTTP plane answers 202 "staging" +
# Retry-After. The client polls; once the recall (here a delayed stub, simulating MSS
# latency) brings the object online, the cache tier fills from tape and serves 200.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
BPORT=8571; PFX="$(mktemp -d /tmp/tprec.XXXXXX)"; U="http://127.0.0.1:${BPORT}"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; rm -rf "$PFX" /tmp/tprec_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/tape" "$PFX/cache" "$PFX/export" "$PFX/tmp" "$PFX/logs"
cat > "$PFX/nginx.conf" <<E2
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
env XROOTD_FRM_STUB_RECALL_DELAY_MS=2500;
thread_pool default threads=2;
events { worker_connections 64; }
http { client_body_temp_path $PFX/tmp; server { listen 127.0.0.1:${BPORT};
  location / { xrootd_webdav on; xrootd_webdav_root $PFX/export; xrootd_webdav_auth none;
    xrootd_webdav_storage_backend tape://stub${PFX}/tape;
    xrootd_webdav_cache_store posix:${PFX}/cache; } } }
E2
# Seed an OFFLINE object: on "tape" (<base>/<key>) with NO online buffer.
head -c 500000 /dev/urandom > "$PFX/tape/f.bin"; SHA=$(sha256sum "$PFX/tape/f.bin"|cut -d' ' -f1)
"$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/start.err" || { echo "START FAIL"; cat "$PFX/start.err"; cat "$PFX/logs/e.log"; exit 2; }
sleep 1
echo "== GET an OFFLINE tape object: recall starts, open parks → 202 staging =="
code=$(curl -s -o /dev/null -w '%{http_code}' "$U/f.bin")
[ "$code" = 202 ] && ok "202 Accepted (staging) — worker NOT blocked for the recall" \
  || { bad "expected 202, got $code"; grep -iE "recall|frm|nearline|cache|error" "$PFX/logs/e.log"|grep -v access_json|tail -6; }
[ -d "$PFX/tape/.recalling" ] && ok "recall marker in flight (async MSS simulated)" || bad "no recall marker"
echo "== poll (Retry-After) until the recall completes and the object serves 200 =="
got=""; for i in $(seq 1 15); do
  sleep 1
  code=$(curl -s -o /tmp/tprec_p.got -w '%{http_code}' "$U/f.bin")
  if [ "$code" = 200 ]; then got=$i; break; fi
done
{ [ -n "$got" ] && [ "$(sha256sum /tmp/tprec_p.got|cut -d' ' -f1)" = "$SHA" ]; } \
  && ok "recall completed after ~${got}s → 200 byte-exact (filled tape→cache, served)" \
  || { bad "never served 200 (last=$code)"; grep -iE "recall|frm|cache|error" "$PFX/logs/e.log"|grep -v access_json|tail -8; }
echo "== warm GET: now a cache hit (online) =="
code=$(curl -s -o /tmp/tprec_w.got -w '%{http_code}' "$U/f.bin")
{ [ "$code" = 200 ] && [ "$(sha256sum /tmp/tprec_w.got|cut -d' ' -f1)" = "$SHA" ]; } && ok "warm cache hit byte-exact" || bad "warm $code"
[ "$fail" = 0 ] && echo "run_tape_recall_async: ALL PASS" || echo "run_tape_recall_async: FAILURES"
exit "$fail"
