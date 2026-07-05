#!/usr/bin/env bash
#
# run_tier_sidecar_meta.sh — phase-64 SP2 SIDECAR cinfo mode: on a store with no
# usable xattr surface the cinfo record is kept as a co-located "<key>.xrdcinfo"
# OBJECT on the store (a staged PUT), not a user.xrd.cinfo xattr. Forced here via
# `brix_webdav_cache_meta sidecar` over a REMOTE root:// store. The proof is the
# same G3 property as XATTR mode: a warm hit survives a cache-node restart with the
# origin DOWN, because the object bytes AND its cinfo sidecar object both live on
# the remote store.
#
# Topology:
#   O (origin, root://)          — the source data (read-only)
#   S (store,  root://, writable) — object bytes + the "<key>.xrdcinfo" cinfo object
#   B (WebDAV cache)             — storage_backend=root://O, cache_store=root://S,
#                                  cache_meta=sidecar
#
# Usage: tests/run_tier_sidecar_meta.sh [nginx-binary]
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
OPORT=11742
SPORT=11743
BPORT=8527
PFX="$(mktemp -d /tmp/tier_sidecar.XXXXXX)"
U="http://127.0.0.1:${BPORT}"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
start_node() { "$NGINX" -p "$PFX/$1" -c "$PFX/$1/nginx.conf" 2>"$PFX/$1/err"; }
stop_node()  { [ -f "$PFX/$1/nginx.pid" ] && kill "$(cat "$PFX/$1/nginx.pid")" 2>/dev/null; }
cleanup() { for r in o s b; do stop_node "$r"; done; rm -rf "$PFX" /tmp/sc_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/s/root" "$PFX/s/logs" \
         "$PFX/b/export" "$PFX/b/tmp" "$PFX/b/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log error; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; xrootd on; brix_root $PFX/o/root; brix_auth none; } }
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
            brix_webdav on;
            brix_webdav_root $PFX/b/export;
            brix_webdav_auth none;
            brix_webdav_storage_backend root://127.0.0.1:${OPORT};
            brix_webdav_cache_store root://127.0.0.1:${SPORT};
            brix_webdav_cache_meta sidecar;
        }
    }
}
EOF

head -c 400000 /dev/urandom > "$PFX/o/root/s.bin"

start_node o || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
start_node s || { echo "S start failed"; cat "$PFX/s/err"; exit 2; }
start_node b || { echo "B start failed"; cat "$PFX/b/err"; exit 2; }
sleep 1

echo "== cold GET: fills object + a SIDECAR cinfo object onto the remote store S =="
code=$(curl -s -o /tmp/sc_a.got -w '%{http_code}' "$U/s.bin")
{ [ "$code" = 200 ] && cmp -s "$PFX/o/root/s.bin" /tmp/sc_a.got; } \
  && ok "cold GET byte-exact" || { bad "cold GET failed ($code)"; grep -iE 'sidecar|cinfo|cache|store|error' "$PFX/b/logs/e.log" | tail -10; }
[ -f "$PFX/s/root/s.bin" ] && ok "object bytes on the remote store S" || bad "object not on S"

echo "== cinfo is a co-located <key>.xrdcinfo OBJECT on S (not an xattr) =="
[ -f "$PFX/s/root/s.bin.xrdcinfo" ] \
  && ok "cinfo sidecar object s.bin.xrdcinfo present on the store" \
  || bad "no <key>.xrdcinfo object on S (SIDECAR cinfo not persisted)"
if command -v getfattr >/dev/null 2>&1; then
    getfattr -d -m '.' "$PFX/s/root/s.bin" 2>/dev/null | grep -qi 'cinfo' \
      && bad "cinfo also written as an xattr (should be a sidecar object in this mode)" \
      || ok "no user.*cinfo xattr on the object (sidecar mode, not xattr)"
fi
if ls "$PFX"/b/export/*.cinfo "$PFX"/b/**/*.cinfo >/dev/null 2>&1; then
    bad "a LOCAL .cinfo sidecar exists on B (state must live on S)"
else
    ok "no local cinfo state on the cache node B"
fi

echo "== warm GET served from the store =="
code=$(curl -s -o /tmp/sc_w.got -w '%{http_code}' "$U/s.bin")
{ [ "$code" = 200 ] && cmp -s "$PFX/o/root/s.bin" /tmp/sc_w.got; } \
  && ok "warm hit byte-exact" || bad "warm hit failed ($code)"

echo "== G3 PROOF: origin down + cache-node restart → warm hit survives (state on S) =="
stop_node o
sleep 0.3
stop_node b
sleep 0.3
start_node b || { echo "B restart failed"; cat "$PFX/b/err"; exit 2; }
sleep 1
code=$(curl -s -o /tmp/sc_r.got -w '%{http_code}' "$U/s.bin")
{ [ "$code" = 200 ] && cmp -s "$PFX/o/root/s.bin" /tmp/sc_r.got; } \
  && ok "warm hit SURVIVES restart with origin DOWN (sidecar cinfo on S rehydrated the hit)" \
  || { bad "post-restart hit failed ($code) — sidecar cinfo did not survive on the store"; \
       grep -iE 'sidecar|cinfo|store|miss|error' "$PFX/b/logs/e.log" | tail -12; }

[ "$fail" = 0 ] && echo "run_tier_sidecar_meta: ALL PASS" || echo "run_tier_sidecar_meta: FAILURES"
exit "$fail"
