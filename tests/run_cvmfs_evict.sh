#!/usr/bin/env bash
#
# run_cvmfs_evict.sh — eviction on the unified cache-store surface.
#
# Two honest forms are shipped here, because occupancy/watermark eviction is NOT
# reachable through a cvmfs (HTTP) location in the current architecture:
#
#   * the watermark LRU reaper (src/fs/cache/reap_watermark.c) is armed only in
#     the STREAM init_process (ngx_stream_brix_init_process); no HTTP module arms
#     it, and `brix_cache_evict_at`/`brix_cache_evict_to` feed the tier-store
#     policy struct but have no HTTP-plane occupancy consumer;
#   * cvmfs is READ-ONLY (writes → 405), so its own requests can never drive a
#     DELETE/overwrite eviction either.
#
# So we assert:
#   A (plumbing)  the unified eviction directives brix_cache_evict_at /
#                 brix_cache_evict_to parse+merge on a real cvmfs location and a
#                 malformed value is rejected — proving they reach the cvmfs
#                 config surface;
#   B (behaviour) the SAME cache-store eviction engine a cvmfs node uses actually
#                 evicts a cached object + its cinfo — exercised via the write
#                 plane (WebDAV DELETE / overwrite), the form sanctioned in the
#                 task brief (modelled on run_tier_remote_evict.sh). The cache
#                 location carries brix_cache_evict_at/evict_to for config-parse
#                 validation; those thresholds have no occupancy consumer yet
#                 (parsed and validated here, occupancy-based eviction not wired).
#
# Occupancy-timer eviction itself is covered by tests/run_cache_watermark.sh
# (stream plane, df-relative thresholds).
#
# Usage: tests/run_cvmfs_evict.sh [nginx-binary]
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
OPORT=11752; SPORT=11753; BPORT=8527; TPORT=12881
PFX="$(mktemp -d /tmp/cvmfs_evict.XXXXXX)"
U="http://127.0.0.1:${BPORT}"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() {
    for r in o s b; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done
    rm -rf "$PFX" /tmp/cev_*.got
}
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/s/root" "$PFX/s/logs" \
         "$PFX/b/export" "$PFX/b/tmp" "$PFX/b/logs" "$PFX/t"

# ---------------------------------------------------------------------------
# A. PLUMBING — the unified eviction directives are valid on a cvmfs location.
# ---------------------------------------------------------------------------
tcfg() {  # $1 = body, writes a cvmfs location carrying $1
    cat > "$PFX/t/nginx.conf" <<EOF
daemon off; pid $PFX/t/nginx.pid; error_log $PFX/t/logs.err warn;
thread_pool default threads=2;
events { worker_connections 64; }
http { server { listen 127.0.0.1:${TPORT};
  location /cvmfs/ {
    brix_cvmfs on;
    brix_export $PFX/t;
    brix_storage_backend http://127.0.0.1:1;
    brix_cache_store posix:$PFX/t;
    $1
  } } }
EOF
}
mkdir -p "$PFX/t/logs" 2>/dev/null
tcfg "brix_cache_evict_at 50; brix_cache_evict_to 20;"
"$NGINX" -t -c "$PFX/t/nginx.conf" -p "$PFX/t" 2>/dev/null \
    && ok "evict_at/evict_to parse+merge under cvmfs" \
    || bad "cvmfs rejected valid brix_cache_evict_at/evict_to"
tcfg "brix_cache_evict_at lots;"
"$NGINX" -t -c "$PFX/t/nginx.conf" -p "$PFX/t" 2>/dev/null \
    && bad "cvmfs accepted a non-numeric brix_cache_evict_at" \
    || ok "malformed brix_cache_evict_at rejected under cvmfs"

# ---------------------------------------------------------------------------
# B. BEHAVIOUR — real eviction of a cached object on the shared cache store.
#    Topology (as run_tier_remote_evict.sh): O origin, S remote store, B cache.
#    The B cache location carries the unified brix_cache_evict_at/evict_to.
# ---------------------------------------------------------------------------
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log error; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; brix_root on; brix_export $PFX/o/root; brix_auth none; brix_allow_write on; } }
EOF
cat > "$PFX/s/nginx.conf" <<EOF
daemon on; error_log $PFX/s/logs/e.log error; pid $PFX/s/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${SPORT}; brix_root on; brix_export $PFX/s/root; brix_auth none; brix_allow_write on; } }
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
            brix_export $PFX/b/export;
            brix_webdav_auth none;
            brix_allow_write on;
            brix_storage_backend root://127.0.0.1:${OPORT};
            brix_cache_store root://127.0.0.1:${SPORT};
            brix_cache_evict_at 50;
            brix_cache_evict_to 20;
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

# cold GET caches the object into the remote store S
code=$(curl -s -o /tmp/cev_a.got -w '%{http_code}' "$U/e.bin")
{ [ "$code" = 200 ] && cmp -s "$PFX/o/root/e.bin" /tmp/cev_a.got; } \
    && ok "cold GET byte-exact (fills the cache store)" || bad "cold GET failed ($code)"
[ -f "$PFX/s/root/e.bin" ] && ok "object cached on the store S" || bad "object not cached on S"
if command -v getfattr >/dev/null 2>&1; then
    has_cinfo_xattr "$PFX/s/root/e.bin" && ok "cinfo present on cached object" || bad "cinfo missing on cached object"
fi

# cache a manifest-analogue alongside e.bin — it must survive eviction of e.bin
printf 'D 0001\nN atlas.cern.ch\nC abc123\n' > "$PFX/o/root/.cvmfspublished"
code=$(curl -s -o /tmp/cev_man.got -w '%{http_code}' "$U/.cvmfspublished")
[ "$code" = 200 ] && ok "manifest cold GET (fills cache store)" || bad "manifest cold GET failed ($code)"
[ -f "$PFX/s/root/.cvmfspublished" ] && ok "manifest cached on store S" || bad "manifest not cached on S"

# DELETE evicts the object + cinfo from the cache store (real eviction)
code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$U/e.bin")
{ [ "$code" = 204 ] || [ "$code" = 200 ]; } && ok "DELETE accepted ($code)" || bad "DELETE status=$code"
sleep 0.3
[ ! -f "$PFX/s/root/e.bin" ] \
    && ok "object EVICTED from the cache store (bytes + cinfo gone)" \
    || bad "object left on the cache store after eviction"

# manifest-survival: evicting e.bin must not disturb .cvmfspublished in the store
# (probe-count machinery not available here; asserting store-file presence only)
[ -f "$PFX/s/root/.cvmfspublished" ] \
    && ok "manifest survives eviction of unrelated object (store-file-presence)" \
    || bad "manifest evicted alongside e.bin — store-level protection broken"

# a fresh GET after eviction is a clean MISS that re-fills — no stale state
head -c 300000 /dev/urandom > "$PFX/o/root/e.bin"
code=$(curl -s -o /tmp/cev_b.got -w '%{http_code}' "$U/e.bin")
{ [ "$code" = 200 ] && cmp -s "$PFX/o/root/e.bin" /tmp/cev_b.got; } \
    && ok "post-eviction GET re-fills byte-exact (no stale object served)" \
    || bad "post-eviction GET wrong ($code)"

# overwrite is a second eviction trigger: the write invalidates the cached copy
curl -s -o /dev/null "$U/e.bin"                       # re-cache on S
[ -f "$PFX/s/root/e.bin" ] && ok "object re-cached on S before overwrite" || bad "re-cache failed"
head -c 250000 /dev/urandom > "$PFX/t/new"
NEWSHA=$(sha256sum "$PFX/t/new" | cut -d' ' -f1)
code=$(curl -s -o /dev/null -w '%{http_code}' -T "$PFX/t/new" "$U/e.bin")
{ [ "$code" = 201 ] || [ "$code" = 200 ] || [ "$code" = 204 ]; } && ok "overwrite PUT accepted ($code)" || bad "overwrite PUT status=$code"
sleep 0.3
code=$(curl -s -o /tmp/cev_c.got -w '%{http_code}' "$U/e.bin")
{ [ "$code" = 200 ] && [ "$(sha256sum /tmp/cev_c.got | cut -d' ' -f1)" = "$NEWSHA" ]; } \
    && ok "post-overwrite GET serves NEW bytes (cached copy invalidated)" \
    || bad "post-overwrite GET served stale bytes ($code) — write did not evict"

[ "$fail" = 0 ] && echo "run_cvmfs_evict: ALL PASS" || echo "run_cvmfs_evict: FAILURES"
exit "$fail"
