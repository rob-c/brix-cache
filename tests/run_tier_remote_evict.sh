#!/usr/bin/env bash
#
# run_tier_remote_evict.sh — phase-64 SP2 remote cache-store EVICTION: when a
# cached object is removed (a namespace DELETE, or overwritten), the cache must
# reclaim BOTH the object bytes AND its cinfo record from the REMOTE store — over
# the wire this is a kXR_rm (object) + kXR_fattr-del (the user.xrd.cinfo xattr).
# Without the sd_xroot unlink slot the object would leak on the remote store and a
# stale cinfo would survive; this proves both are gone.
#
# Topology:
#   O (origin, root://, writable) — the source (a DELETE removes it here too)
#   S (store,  root://, writable) — the remote cache store (object + cinfo xattr)
#   B (WebDAV cache)              — storage_backend=root://O, cache_store=root://S
#
# Usage: tests/run_tier_remote_evict.sh [nginx-binary]
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
OPORT=11732
SPORT=11733
BPORT=8525
PFX="$(mktemp -d /tmp/tier_revict.XXXXXX)"
U="http://127.0.0.1:${BPORT}"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() {
    for r in o s b; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done
    rm -rf "$PFX" /tmp/rev_*.got
}
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/s/root" "$PFX/s/logs" \
         "$PFX/b/export" "$PFX/b/tmp" "$PFX/b/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log error; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; xrootd on; brix_root $PFX/o/root; brix_auth none; brix_allow_write on; } }
EOF

cat > "$PFX/s/nginx.conf" <<EOF
daemon on; error_log $PFX/s/logs/e.log error; pid $PFX/s/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${SPORT}; xrootd on; brix_root $PFX/s/root; brix_auth none; brix_allow_write on; } }
EOF

cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    client_body_temp_path $PFX/b/tmp;
    server {
        listen 127.0.0.1:${BPORT};
        location / {
            dav_methods PUT DELETE;
            brix_webdav on;
            brix_webdav_root $PFX/b/export;
            brix_webdav_auth none;
            brix_webdav_allow_write on;
            brix_webdav_storage_backend root://127.0.0.1:${OPORT};
            brix_webdav_cache_store root://127.0.0.1:${SPORT};
        }
    }
}
EOF

head -c 300000 /dev/urandom > "$PFX/o/root/e.bin"

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/s" -c "$PFX/s/nginx.conf" 2>"$PFX/s/err" || { echo "S start failed"; cat "$PFX/s/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B start failed"; cat "$PFX/b/err"; exit 2; }
sleep 1

has_cinfo_xattr() { getfattr -d -m '.' "$1" 2>/dev/null | grep -qi 'cinfo'; }

echo "== cache the object into the remote store S =="
code=$(curl -s -o /tmp/rev_a.got -w '%{http_code}' "$U/e.bin")
{ [ "$code" = 200 ] && cmp -s "$PFX/o/root/e.bin" /tmp/rev_a.got; } && ok "cold GET byte-exact" || bad "cold GET failed ($code)"
[ -f "$PFX/s/root/e.bin" ] && ok "object bytes on the remote store S" || bad "object not on S"
if command -v getfattr >/dev/null 2>&1; then
    has_cinfo_xattr "$PFX/s/root/e.bin" && ok "cinfo xattr present on S" || bad "cinfo xattr missing on S"
fi

echo "== WebDAV DELETE evicts the object + cinfo from the REMOTE store (kXR_rm + fattr-del) =="
code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$U/e.bin")
{ [ "$code" = 204 ] || [ "$code" = 200 ]; } && ok "DELETE accepted ($code)" || { bad "DELETE status=$code"; grep -iE 'delete|unlink|evict|error' "$PFX/b/logs/e.log" | tail -8; }
sleep 0.3
[ ! -f "$PFX/s/root/e.bin" ] \
  && ok "object REMOVED from the remote store S (kXR_rm reached the store)" \
  || bad "object LEFT on the remote store S (remote eviction did not unlink)"
if command -v getfattr >/dev/null 2>&1; then
    # If the object file is gone the xattr is gone with it; only meaningful if a
    # stray object remained. Assert no cinfo-bearing object survives on S.
    if ls "$PFX"/s/root/e.bin >/dev/null 2>&1 && has_cinfo_xattr "$PFX/s/root/e.bin"; then
        bad "stale cinfo xattr survived on S after eviction"
    else
        ok "no stale cinfo xattr on S after eviction"
    fi
fi
[ ! -f "$PFX/o/root/e.bin" ] && ok "object also removed from the origin O (source delete)" || bad "object left on origin O"

echo "== a fresh GET after eviction is a clean MISS (re-fills), proving no stale state =="
head -c 300000 /dev/urandom > "$PFX/o/root/e.bin"     # re-create at origin
code=$(curl -s -o /tmp/rev_b.got -w '%{http_code}' "$U/e.bin")
{ [ "$code" = 200 ] && cmp -s "$PFX/o/root/e.bin" /tmp/rev_b.got; } \
  && ok "post-eviction GET re-fills byte-exact (no stale cached object served)" \
  || bad "post-eviction GET wrong ($code) — stale state after evict"

echo "== write-overwrite invalidates the cached copy (a different evict trigger) =="
# GET again to (re)cache, then PUT new content: the write-open must evict the
# cached copy on the remote store so the next GET serves the NEW bytes, not stale.
curl -s -o /dev/null "$U/e.bin"                       # ensure it is cached on S
[ -f "$PFX/s/root/e.bin" ] && ok "object re-cached on S before overwrite" || bad "re-cache failed"
head -c 250000 /dev/urandom > /tmp/rev_new
NEWSHA=$(sha256sum /tmp/rev_new | cut -d' ' -f1)
code=$(curl -s -o /dev/null -w '%{http_code}' -T /tmp/rev_new "$U/e.bin")
{ [ "$code" = 201 ] || [ "$code" = 200 ] || [ "$code" = 204 ]; } && ok "overwrite PUT accepted ($code)" || bad "overwrite PUT status=$code"
sleep 0.3
code=$(curl -s -o /tmp/rev_c.got -w '%{http_code}' "$U/e.bin")
{ [ "$code" = 200 ] && [ "$(sha256sum /tmp/rev_c.got | cut -d' ' -f1)" = "$NEWSHA" ]; } \
  && ok "post-overwrite GET serves the NEW bytes (cached copy was invalidated)" \
  || bad "post-overwrite GET served stale/wrong bytes ($code) — write did not evict the cache"

[ "$fail" = 0 ] && echo "run_tier_remote_evict: ALL PASS" || echo "run_tier_remote_evict: FAILURES"
exit "$fail"
