#!/usr/bin/env bash
# run_nonstaged_reap.sh — phase-64 SP4: a NON-staged direct write interrupted by a
# crash leaves an orphan "<final>.xrd-tmp.<pid>.<rand>" temp in the export tree.
# Unlike a staged write (recoverable), a broken direct write is discarded — so on
# startup worker-0 REAPS the orphans, identifying them by a DEAD owner pid. A temp
# whose owner is still alive (a draining worker during a reload) is KEPT — safe.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
BPORT=8583; PFX="$(mktemp -d /tmp/nsreap.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/export/sub" "$PFX/tmp" "$PFX/logs"
cat > "$PFX/nginx.conf" <<E2
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
worker_processes 1;
events { worker_connections 64; }
http { client_body_temp_path $PFX/tmp; server { listen 127.0.0.1:${BPORT};
  location / { dav_methods PUT DELETE;
    xrootd_webdav on; xrootd_webdav_storage_backend posix:$PFX/export; xrootd_webdav_auth none; xrootd_webdav_allow_write on; } } }
E2
# Plant orphan temps as if from a previous crashed run:
DEAD=999999                          # a pid with no live process
echo dead1 > "$PFX/export/a.bin.xrd-tmp.${DEAD}.111"          # → reap (dead owner)
echo dead2 > "$PFX/export/sub/c.bin.xrd-tmp.${DEAD}.222"      # → reap (dead, nested)
echo live  > "$PFX/export/b.bin.xrd-tmp.$$.333"              # → KEEP (this shell is alive)
echo real  > "$PFX/export/keep.bin"                          # → KEEP (a normal file)
"$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/start.err" || { echo "START FAIL"; cat "$PFX/start.err"; exit 2; }
sleep 1   # worker-0 init runs the reaper
echo "== after startup: dead-owner orphan temps reaped, live + normal kept =="
[ ! -f "$PFX/export/a.bin.xrd-tmp.${DEAD}.111" ]     && ok "dead-owner temp reaped" || bad "dead-owner temp NOT reaped"
[ ! -f "$PFX/export/sub/c.bin.xrd-tmp.${DEAD}.222" ] && ok "nested dead-owner temp reaped (recursive walk)" || bad "nested temp NOT reaped"
[ -f "$PFX/export/b.bin.xrd-tmp.$$.333" ]            && ok "LIVE-owner temp kept (reload-safe: in-flight write preserved)" || bad "live-owner temp wrongly reaped"
[ -f "$PFX/export/keep.bin" ]                        && ok "normal file untouched" || bad "normal file removed"
grep -q "reaped .* orphaned upload temp" "$PFX/logs/e.log" && ok "reaper logged the cleanup" || bad "no reaper log"
echo "== a real PUT still works (no regression) =="
head -c 200000 /dev/urandom > "$PFX/src.bin"
code=$(curl -s -o /dev/null -w '%{http_code}' -T "$PFX/src.bin" "http://127.0.0.1:${BPORT}/real.bin")
{ [ "$code" = 201 ] && cmp -s "$PFX/src.bin" "$PFX/export/real.bin"; } && ok "PUT 201 byte-exact" || bad "PUT $code"
[ "$fail" = 0 ] && echo "run_nonstaged_reap: ALL PASS" || echo "run_nonstaged_reap: FAILURES"
exit "$fail"
