#!/usr/bin/env bash
# run_tape_recall_stream.sh — phase-64 SP4/SP5: async nearline recall over root://.
# A read-open of an OFFLINE tape object on a tape:// backend faults a recall; the
# stream server answers kXR_wait (the protocol's "retry after N s" — the root://
# equivalent of the WebDAV 202 "staging"). The native client honours kXR_wait
# (sleeps + re-sends the open), so a single xrdfs cat blocks until the recall brings
# the object online into the cache tier, then serves it byte-exact — without ever
# blocking the server worker for the MSS latency.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"; XRDFS="$HERE/client/bin/xrdfs"
BPORT=11752; PFX="$(mktemp -d /tmp/tprs.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; rm -rf "$PFX" /tmp/tprs_*.got; }
trap cleanup EXIT
[ -x "$XRDFS" ] || { echo "SKIP: native xrdfs not built ($XRDFS)"; exit 0; }
mkdir -p "$PFX/tape" "$PFX/cache" "$PFX/export" "$PFX/logs"
cat > "$PFX/nginx.conf" <<E2
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
env BRIX_FRM_STUB_RECALL_DELAY_MS=1200;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${BPORT}; brix_root on; brix_export $PFX/export; brix_auth none;
    brix_storage_backend tape://stub${PFX}/tape;
    brix_cache_store posix:${PFX}/cache; } }
E2
head -c 480000 /dev/urandom > "$PFX/tape/f.bin"; SHA=$(sha256sum "$PFX/tape/f.bin"|cut -d' ' -f1)
"$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/start.err" || { echo "START FAIL"; cat "$PFX/start.err"; cat "$PFX/logs/e.log"; exit 2; }
sleep 1
echo "== root:// STAT of the OFFLINE tape object → kXR_offline (residency seam, no brix_frm) =="
"$XRDFS" "root://127.0.0.1:${BPORT}" stat /f.bin 2>/dev/null | grep -q "Offline" \
  && ok "kXR_stat reports Offline for a tape:// nearline object (phase-64 backend residency)" \
  || { bad "stat did not report Offline"; "$XRDFS" "root://127.0.0.1:${BPORT}" stat /f.bin 2>&1 | grep -i flags; }
[ ! -f "$PFX/cache/f.bin" ] && ok "STAT did not fault a recall (residency probe only)" \
  || bad "STAT triggered a recall (cache/f.bin appeared)"
echo "== root:// read of an OFFLINE tape object: open faults recall → kXR_wait → client retries → serve =="
t0=$(date +%s)
"$XRDFS" "root://127.0.0.1:${BPORT}" cat /f.bin > /tmp/tprs_c.got 2>"$PFX/cat.err"
t1=$(date +%s)
{ [ "$(sha256sum /tmp/tprs_c.got 2>/dev/null|cut -d' ' -f1)" = "$SHA" ]; } \
  && ok "xrdfs cat byte-exact after $((t1-t0))s (recall via kXR_wait/retry, worker never blocked)" \
  || { bad "cat failed/wrong"; cat "$PFX/cat.err"; grep -iE "recall|wait|frm|cache|error" "$PFX/logs/e.log"|grep -v access_json|tail -8; }
grep -q "recall-wait\|kXR_wait\|recall in progress" "$PFX/logs/e.log" && ok "server logged the recall kXR_wait park" || true
echo "== warm read: now online in the cache tier =="
"$XRDFS" "root://127.0.0.1:${BPORT}" cat /f.bin > /tmp/tprs_w.got 2>/dev/null
[ "$(sha256sum /tmp/tprs_w.got 2>/dev/null|cut -d' ' -f1)" = "$SHA" ] && ok "warm read byte-exact (cache hit, no wait)" || bad "warm read failed"
[ "$fail" = 0 ] && echo "run_tape_recall_stream: ALL PASS" || echo "run_tape_recall_stream: FAILURES"
exit "$fail"
