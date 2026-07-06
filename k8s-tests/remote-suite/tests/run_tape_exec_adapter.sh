#!/usr/bin/env bash
# run_tape_exec_adapter.sh — phase-64 SP5: the "exec" MSS adapter (real HSM model).
# sd_frm shells out to $BRIX_FRM_STAGECMD <verb> <key> <online> for residency
# (exists), recall (async-submit), and migrate. Here the stagecmd is a test script
# backed by a local "tape" dir; recall backgrounds the copy (returns at once), so the
# open parks → 202 → poll → 200. Proves a real operator stagecmd drives the tier.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
BPORT=8575; PFX="$(mktemp -d /tmp/tpexec.XXXXXX)"; U="http://127.0.0.1:${BPORT}"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; rm -rf "$PFX" /tmp/tpexec_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/realtape" "$PFX/online" "$PFX/cache" "$PFX/export" "$PFX/tmp" "$PFX/logs"
# the operator stagecmd: a real-MSS stand-in backed by $PFX/realtape
cat > "$PFX/stagecmd.sh" <<SC
#!/bin/bash
verb="\$1"; key="\$2"; online="\$3"; TAPE="$PFX/realtape"
case "\$verb" in
  exists)  [ -f "\$TAPE/\$key" ] && exit 0 || exit 1 ;;
  recall)  ( sleep 2; mkdir -p "\$(dirname "\$online")"; cp "\$TAPE/\$key" "\$online" ) & exit 0 ;;  # async submit
  migrate) mkdir -p "\$(dirname "\$TAPE/\$key")"; cp "\$online" "\$TAPE/\$key" ; exit \$? ;;
  *) exit 2 ;;
esac
SC
chmod +x "$PFX/stagecmd.sh"
cat > "$PFX/nginx.conf" <<E2
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
env BRIX_FRM_STAGECMD=$PFX/stagecmd.sh;
thread_pool default threads=2;
events { worker_connections 64; }
http { client_body_temp_path $PFX/tmp; server { listen 127.0.0.1:${BPORT};
  location / { brix_webdav on; brix_export $PFX/export; brix_webdav_auth none;
    brix_storage_backend tape://exec${PFX}/online;
    brix_cache_store posix:${PFX}/cache; } } }
E2
# Seed an offline object on the REAL tape (the stagecmd's domain), keyed "f.bin"
head -c 480000 /dev/urandom > "$PFX/realtape/f.bin"; SHA=$(sha256sum "$PFX/realtape/f.bin"|cut -d' ' -f1)
"$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/start.err" || { echo "START FAIL"; cat "$PFX/start.err"; cat "$PFX/logs/e.log"; exit 2; }
sleep 1
echo "== PROPFIND xrd:locality of the offline object → NEARLINE (residency seam, no recall) =="
loc=$(curl -s -X PROPFIND -H 'Depth: 0' \
  --data '<D:propfind xmlns:D="DAV:" xmlns:xrd="http://brix.org/2010/ns/dav"><D:prop><xrd:locality/></D:prop></D:propfind>' \
  "$U/f.bin")
echo "$loc" | grep -q "<xrd:locality>NEARLINE</xrd:locality>" \
  && ok "PROPFIND locality NEARLINE (from the tape backend via the VFS seam, no FRM xattr)" \
  || { bad "locality not NEARLINE"; echo "$loc" | grep -oE "<xrd:locality>[^<]*</xrd:locality>" | head -1; }
[ ! -f "$PFX/online/f.bin" ] && ok "PROPFIND did not trigger a recall (residency probe only)" \
  || bad "PROPFIND faulted a recall (online/f.bin appeared)"
echo "== GET offline object via the EXEC adapter: recall submitted, open parks → 202 =="
code=$(curl -s -o /dev/null -w '%{http_code}' "$U/f.bin")
[ "$code" = 202 ] && ok "202 staging (exec stagecmd submitted the recall, non-blocking)" \
  || { bad "expected 202, got $code"; grep -iE "frm|exec|recall|cache|error" "$PFX/logs/e.log"|grep -v access_json|tail -8; }
echo "== poll until the stagecmd's recall completes → 200 =="
got=""; for i in $(seq 1 15); do sleep 1; code=$(curl -s -o /tmp/tpexec_p.got -w '%{http_code}' "$U/f.bin"); [ "$code" = 200 ] && { got=$i; break; }; done
{ [ -n "$got" ] && [ "$(sha256sum /tmp/tpexec_p.got|cut -d' ' -f1)" = "$SHA" ]; } \
  && ok "recalled via exec stagecmd after ~${got}s → 200 byte-exact" \
  || { bad "never served (last=$code)"; grep -iE "frm|exec|recall|cache|error" "$PFX/logs/e.log"|grep -v access_json|tail -8; }
[ "$fail" = 0 ] && echo "run_tape_exec_adapter: ALL PASS" || echo "run_tape_exec_adapter: FAILURES"
exit "$fail"
