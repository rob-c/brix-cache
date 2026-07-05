#!/usr/bin/env bash
# run_cachestore_sidecar.sh — phase-64 SP3 (last cell): http/s3 as a CACHE_STORE via
# SIDECAR cinfo. These drivers expose no xattr surface, so cstore persists each
# object's hit-state as a co-located "<key>.xrdcinfo" OBJECT through the store's own
# staged PUT. A cold GET fills the store + writes the sidecar; after a node restart
# (fresh per-worker cinfo L1) with the SOURCE hidden, a GET must load the sidecar and
# serve from the store — proving the cinfo round-trips on the store itself (G3).
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
PFX="$(mktemp -d /tmp/cssc.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for f in "$PFX"/*/*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done; rm -rf "$PFX" /tmp/cssc_*.got; }
trap cleanup EXIT

# test_cachestore <label> <store_kind:s3|http> <store_port> <bport>
test_cachestore() {
    local label="$1" kind="$2" sport="$3" bport="$4"
    local d="$PFX/$label"
    mkdir -p "$d/sa/store" "$d/sa/logs" "$d/sa/tmp" "$d/b/backend" "$d/b/logs" "$d/b/tmp"
    echo "== cache_store: $label (SIDECAR cinfo) =="

    if [ "$kind" = s3 ]; then
        cat > "$d/sa.conf" <<E2
daemon on; error_log $d/sa/logs/e.log info; pid $d/sa/nginx.pid;
events { worker_connections 64; }
http { server { listen 127.0.0.1:${sport};
  location / { brix_s3 on; brix_s3_root $d/sa/store; brix_s3_bucket xrdcache; brix_s3_allow_write on; } } }
E2
        local url="s3://127.0.0.1:${sport}/xrdcache"
    else
        cat > "$d/sa.conf" <<E2
daemon on; error_log $d/sa/logs/e.log info; pid $d/sa/nginx.pid;
events { worker_connections 64; }
http { client_body_temp_path $d/sa/tmp; server { listen 127.0.0.1:${sport};
  location / { dav_methods PUT DELETE; brix_webdav on; brix_webdav_root $d/sa/store; brix_webdav_auth none; brix_webdav_allow_write on; } } }
E2
        local url="http://127.0.0.1:${sport}"
    fi
    cat > "$d/b.conf" <<E2
daemon on; error_log $d/b/logs/e.log info; pid $d/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http { client_body_temp_path $d/b/tmp; server { listen 127.0.0.1:${bport};
  location / { brix_webdav on; brix_webdav_root $d/b/backend; brix_webdav_auth none;
    brix_webdav_cache_store $url; } } }
E2
    head -c 450000 /dev/urandom > "$d/b/backend/f.bin"; local sha=$(sha256sum "$d/b/backend/f.bin"|cut -d' ' -f1)
    "$NGINX" -p "$d/sa" -c "$d/sa.conf" 2>"$d/saerr" || { bad "$label store server failed"; cat "$d/saerr"; return; }
    "$NGINX" -p "$d/b"  -c "$d/b.conf"  2>"$d/berr"  || { bad "$label node failed"; cat "$d/berr"; return; }
    sleep 1
    local code=$(curl -s -o /tmp/cssc_c.got -w '%{http_code}' "http://127.0.0.1:${bport}/f.bin")
    { [ "$code" = 200 ] && [ "$(sha256sum /tmp/cssc_c.got|cut -d' ' -f1)" = "$sha" ]; } \
      && ok "$label cold GET byte-exact (filled store + sidecar)" \
      || { bad "$label cold GET $code"; grep -iE "cinfo|sidecar|cache|stage move|error" "$d/b/logs/e.log"|grep -v access_json|tail -6; }
    # xmeta: the record rides as "<key>.cinfo" (a stock-readable cinfo v4)
    [ -f "$d/sa/store/f.bin.cinfo" ] && ok "$label <key>.cinfo xmeta sidecar landed on the store" \
      || bad "$label no sidecar object on the store"
    [ "$(head -c4 "$d/sa/store/f.bin.cinfo" 2>/dev/null | od -An -td4 | tr -d ' ')" = 4 ] \
      && ok "$label sidecar is a stock-prefixed record" \
      || bad "$label sidecar prefix is not cinfo v4"
    mv "$d/b/backend/f.bin" "$d/b/backend/.hidden"     # hide the SOURCE
    kill "$(cat "$d/b/nginx.pid")" 2>/dev/null; sleep 0.6
    "$NGINX" -p "$d/b" -c "$d/b.conf" 2>"$d/berr2" || { bad "$label B restart failed"; return; }
    sleep 1
    code=$(curl -s -o /tmp/cssc_w.got -w '%{http_code}' "http://127.0.0.1:${bport}/f.bin")
    { [ "$code" = 200 ] && [ "$(sha256sum /tmp/cssc_w.got|cut -d' ' -f1)" = "$sha" ]; } \
      && ok "$label post-restart hit byte-exact (cinfo LOADED from sidecar, served from store; source hidden)" \
      || { bad "$label post-restart hit $code"; grep -iE "cinfo|sidecar|cache|error" "$d/b/logs/e.log"|grep -v access_json|tail -6; }
    kill "$(cat "$d/b/nginx.pid")" 2>/dev/null
    kill "$(cat "$d/sa/nginx.pid")" 2>/dev/null
}

test_cachestore s3   s3   9011 8561
test_cachestore http http 9012 8562
[ "$fail" = 0 ] && echo "run_cachestore_sidecar: ALL PASS" || echo "run_cachestore_sidecar: FAILURES"
exit "$fail"
