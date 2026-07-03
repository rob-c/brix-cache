#!/usr/bin/env bash
# run_s3_tape_residency.sh — phase-64 P6 step 1: the VFS residency SEAM
# (brix_vfs_residency) replacing the FRM residency-xattr probe. An S3 export over a
# tape:// (frm/exec) backend must advertise tape state from the BACKEND's residency
# model — not an xattr: HEAD of a nearline object → x-amz-storage-class: GLACIER, GET
# → 403 InvalidObjectState (S3/Glacier: an explicit restore is required, checked
# BEFORE any open so a plain GET never faults a recall). An ONLINE object is served
# normally. Proves s3/object.c is decoupled from src/frm onto the seam.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
PORT=9007; PPORT=9009; PFX="$(mktemp -d /tmp/s3tres.XXXXXX)"; U="http://127.0.0.1:${PORT}"; P="http://127.0.0.1:${PPORT}"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for p in nginx.pid plain.pid; do [ -f "$PFX/$p" ] && kill "$(cat "$PFX/$p")" 2>/dev/null; done; rm -rf "$PFX" /tmp/s3tres_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/realtape" "$PFX/online" "$PFX/s3root" "$PFX/cache" "$PFX/plain" "$PFX/logs"
# the operator stagecmd (exec MSS adapter): residency via `exists` against realtape.
cat > "$PFX/stagecmd.sh" <<SC
#!/bin/bash
verb="\$1"; key="\$2"; online="\$3"; TAPE="$PFX/realtape"
case "\$verb" in
  exists)  [ -f "\$TAPE/\$key" ] && exit 0 || exit 1 ;;
  recall)  ( sleep 1; mkdir -p "\$(dirname "\$online")"; cp "\$TAPE/\$key" "\$online" ) & exit 0 ;;
  migrate) mkdir -p "\$(dirname "\$TAPE/\$key")"; cp "\$online" "\$TAPE/\$key" ; exit \$? ;;
  *) exit 2 ;;
esac
SC
chmod +x "$PFX/stagecmd.sh"
cat > "$PFX/nginx.conf" <<E2
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
env BRIX_FRM_STAGECMD=$PFX/stagecmd.sh;
events { worker_connections 64; }
http { server { listen 127.0.0.1:${PORT};
  location / { brix_s3 on; brix_s3_root $PFX/s3root; brix_s3_bucket xrdtape;
    brix_s3_storage_backend tape://exec${PFX}/online;
    brix_s3_cache_store posix:${PFX}/cache; } } }
E2
# A plain POSIX s3 export — the non-regression control: an export with NO nearline
# tier must classify ONLINE (the seam's default) and serve normally, NOT false-trip
# InvalidObjectState. This is the #1 thing the FRM→seam migration must not break.
cat > "$PFX/plain.conf" <<E2
daemon on; error_log $PFX/logs/p.log info; pid $PFX/plain.pid;
events { worker_connections 64; }
http { server { listen 127.0.0.1:${PPORT};
  location / { brix_s3 on; brix_s3_root $PFX/plain; brix_s3_bucket xrdplain; } } }
E2
# f.bin: offline (on tape only, the stagecmd's domain).
head -c 320000 /dev/urandom > "$PFX/realtape/f.bin"
# h.bin: a normal object on the plain posix export.
head -c 256000 /dev/urandom > "$PFX/plain/h.bin"; HSHA=$(sha256sum "$PFX/plain/h.bin"|cut -d' ' -f1)
"$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/start.err" || { echo "START FAIL"; cat "$PFX/start.err"; cat "$PFX/logs/e.log"; exit 2; }
"$NGINX" -p "$PFX" -c "$PFX/plain.conf" 2>"$PFX/pstart.err" || { echo "PLAIN START FAIL"; cat "$PFX/pstart.err"; exit 2; }
sleep 1

echo "== HEAD of a NEARLINE object: residency seam → x-amz-storage-class: GLACIER =="
hdr=$(curl -s -I "$U/xrdtape/f.bin"); code=$(printf '%s' "$hdr"|awk 'NR==1{print $2}')
echo "$hdr" | grep -qi "x-amz-storage-class:.*GLACIER" \
  && ok "HEAD ${code} advertised GLACIER (residency from the tape backend, no xattr)" \
  || { bad "no GLACIER header (HEAD=$code)"; printf '%s\n' "$hdr"|head -8; grep -iE "frm|exec|residency|error" "$PFX/logs/e.log"|grep -v access_json|tail -6; }

echo "== GET of a NEARLINE object: 403 InvalidObjectState, BEFORE any recall =="
code=$(curl -s -o "$PFX/get.body" -w '%{http_code}' "$U/xrdtape/f.bin")
{ [ "$code" = 403 ] && grep -q "InvalidObjectState" "$PFX/get.body"; } \
  && ok "GET 403 InvalidObjectState (no stage faulted — S3/Glacier semantics)" \
  || { bad "expected 403 InvalidObjectState, got $code"; head -c 240 "$PFX/get.body"; echo; }
# the recall must NOT have been triggered by the GET (online buffer still has no f.bin)
[ ! -f "$PFX/online/f.bin" ] && ok "GET did not trigger a recall (online buffer untouched)" \
  || bad "GET faulted a recall (online/f.bin appeared) — should be restore-on-demand only"

echo "== non-regression: a plain POSIX s3 export (no nearline tier) → ONLINE, served =="
code=$(curl -s -o /tmp/s3tres_h.got -w '%{http_code}' "$P/xrdplain/h.bin")
{ [ "$code" = 200 ] && [ "$(sha256sum /tmp/s3tres_h.got|cut -d' ' -f1)" = "$HSHA" ]; } \
  && ok "GET 200 byte-exact (a non-tape export is unaffected — no false InvalidObjectState)" \
  || { bad "plain GET failed (code=$code)"; grep -iE "error|InvalidObjectState" "$PFX/logs/p.log"|grep -v access_json|tail -6; }
hp=$(curl -s -I "$P/xrdplain/h.bin"); echo "$hp" | grep -qi "x-amz-storage-class:.*GLACIER" \
  && bad "plain HEAD wrongly advertised GLACIER (seam false-positive on a posix export)" \
  || ok "plain HEAD did NOT advertise GLACIER (no nearline tier ⇒ ONLINE)"

echo "== errors? =="; grep -cE "\[(error|crit|alert)\]" "$PFX/logs/e.log" "$PFX/logs/p.log" | sed 's/^/  /'
[ "$fail" = 0 ] && echo "run_s3_tape_residency: ALL PASS" || echo "run_s3_tape_residency: FAILURES"
exit "$fail"
