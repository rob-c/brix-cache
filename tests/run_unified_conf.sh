#!/usr/bin/env bash
# Unified brix config grammar: bare storage directives valid on the HTTP
# plane, inherited server->location, coexisting with (for now) old names.
#
# The three cases below are the binding intent:
#   1. unified names (brix_export, brix_cache_store, ...) parse in an HTTP
#      location;
#   2. server-level unified directives inherit into locations of different
#      protocols (webdav + s3);
#   3. a malformed unified value is still rejected by `nginx -t`.
set -u
NGINX_BIN=${NGINX_BIN:-/tmp/nginx-1.28.3/objs/nginx}
PFX=$(mktemp -d /tmp/unified-conf.XXXXXX); mkdir -p "$PFX"/{logs,data,cache}
pass=0; fail=0
ok()  { echo "ok  - $1"; pass=$((pass+1)); }
bad() { echo "FAIL- $1"; fail=$((fail+1)); }

t() { # t <name> <expect:0|1> <config-body>
    local name=$1 expect=$2 body=$3
    cat > "$PFX/nginx.conf" <<EOF
daemon off; pid $PFX/nginx.pid; error_log $PFX/logs/err.log warn;
thread_pool default threads=2;
events { worker_connections 64; }
http { $body }
EOF
    "$NGINX_BIN" -t -c "$PFX/nginx.conf" -p "$PFX" >/dev/null 2>&1
    local rc=$?
    if [ "$expect" = 0 ] && [ $rc -eq 0 ]; then ok "$name";
    elif [ "$expect" = 1 ] && [ $rc -ne 0 ]; then ok "$name";
    else bad "$name (rc=$rc, expected exit $expect)"; fi
}

# success: unified names at location level under webdav
t "unified names parse in webdav location" 0 "
server { listen 127.0.0.1:18499;
  location /dav/ {
    brix_webdav on;
    brix_webdav_auth none;
    brix_export $PFX/data;
    brix_cache_store posix:$PFX/cache;
    brix_cache_evict_at 85; brix_cache_evict_to 70;
  } }"

# success: server-level unified directives inherit into locations.
# The two protocols sit on separate ports (Task 2 forbids mixing brix
# protocols under one listen port); each server still proves that its
# server-level brix_cache_store/brix_export inherit into the location.
t "server-level brix_cache_store inherits" 0 "
server { listen 127.0.0.1:18499;
  brix_cache_store posix:$PFX/cache;
  brix_export $PFX/data;
  location /dav/ { brix_webdav on; brix_webdav_auth none; } }
server { listen 127.0.0.1:18498;
  brix_cache_store posix:$PFX/cache;
  brix_export $PFX/data;
  location /v/   { brix_s3 on; brix_s3_bucket b; } }"

# error: malformed unified directive still rejected
t "brix_cache_evict_at rejects non-numeric" 1 "
server { listen 127.0.0.1:18499;
  location /dav/ { brix_webdav on; brix_webdav_auth none; brix_export $PFX/data;
    brix_cache_evict_at lots; } }"

# error: two protocols in one location
t "two protocols in one location rejected" 1 "
server { listen 127.0.0.1:18499;
  location / { brix_webdav on; brix_webdav_auth none; brix_export $PFX/data;
               brix_s3 on; brix_s3_bucket b; } }"

# error: two protocols under one listen port (different locations)
t "two protocols on one port rejected" 1 "
server { listen 127.0.0.1:18499;
  location /dav/ { brix_webdav on; brix_webdav_auth none; brix_export $PFX/data; }
  location /v/   { brix_s3 on; brix_s3_bucket b; brix_export $PFX/data; } }"

# success: same two protocols on different ports
t "protocols on separate ports accepted" 0 "
server { listen 127.0.0.1:18499;
  location /dav/ { brix_webdav on; brix_webdav_auth none; brix_export $PFX/data; } }
server { listen 127.0.0.1:18498;
  location /v/   { brix_s3 on; brix_s3_bucket b; brix_export $PFX/data; } }"

# cvmfs-specific rejection tests (Task 3)
# CV is a minimal valid cvmfs location base: brix_cvmfs on + explicit export
# root (required: the pure-cache-node "/" auto-default requires a running VFS
# registry) + an http backend + a cache store.
CV="brix_cvmfs on; brix_export $PFX/data;
    brix_cvmfs_storage_backend http://127.0.0.1:1;
    brix_cvmfs_cache_store posix:$PFX/cache;"

# brix_stage on alone is caught by the existing tier check ("requires
# brix_stage_store"); use both together to specifically test the cvmfs
# read-only rejection that fires before the tier-level check.
t "brix_stage under cvmfs rejected" 1 "
server { listen 127.0.0.1:18499; location / { $CV
  brix_stage on; brix_stage_store posix:$PFX/data; } }"

t "brix_stage_store alone under cvmfs rejected" 1 "
server { listen 127.0.0.1:18499; location / { $CV
  brix_stage_store posix:$PFX/data; } }"

t "brix_cache_slice_size under cvmfs rejected" 1 "
server { listen 127.0.0.1:18499; location / { $CV brix_cache_slice_size 1m; } }"

t "brix_allow_write under cvmfs rejected" 1 "
server { listen 127.0.0.1:18499; location / { $CV brix_allow_write on; } }"

# geo-without-here is already caught by the existing cvmfs_geo_rank_config
# check; this test is regression coverage to ensure it stays rejected.
t "origin_select geo without brix_cvmfs_here rejected" 1 "
server { listen 127.0.0.1:18499; location / { $CV
  brix_cvmfs_origin_select geo; } }"

echo "unified_conf: $pass passed, $fail failed"; rm -rf "$PFX"
[ $fail -eq 0 ]
