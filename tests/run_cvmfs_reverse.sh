#!/usr/bin/env bash
# tests/run_cvmfs_reverse.sh — module CVMFS personality e2e (built up over
# Tasks 8/9). Task-8 scope: the directives parse and merge.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PFX="$(mktemp -d /tmp/cvmfs_rev.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           [ -n "${MOCK:-}" ] && kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
MPORT=12831; CPORT=12832
mkdir -p "$PFX/cache" "$PFX/logs"

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http {
    access_log off;
    server {
        listen 127.0.0.1:$CPORT;
        location /cvmfs/ {
            xrootd_cvmfs_storage_backend http://127.0.0.1:$MPORT;
            xrootd_cvmfs_cache_store posix:$PFX/cache;
            xrootd_cvmfs on;
            xrootd_cvmfs_manifest_ttl 61;
        }
    }
}
EOF
"$NGINX" -t -c "$PFX/nginx.conf" -p "$PFX" 2>/dev/null \
    && ok "cvmfs directives parse" || bad "nginx -t rejected cvmfs config"
exit $fail
