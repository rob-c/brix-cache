#!/usr/bin/env bash
# tests/run_cvmfs_manifest.sh — manifest caching semantics:
#   1 within TTL: second GET served from cache (0 extra origin hits)
#   2 after TTL + bump: refetch returns the NEW manifest
#   3 error-neg: after TTL with origin DOWN: bounded stale-serve (200, old body)
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MPORT=12861; CPORT=12862; TTL=4
PFX="$(mktemp -d /tmp/cvmfs_man.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           [ -n "${MOCK:-}" ] && kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"
python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 2 --seed 1 &
MOCK=$!; sleep 0.5

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location /cvmfs/ {
        brix_storage_backend http://127.0.0.1:$MPORT;
        brix_cache_store posix:$PFX/cache;
        brix_cvmfs on;
        brix_cvmfs_manifest_ttl $TTL;
    }
} }
EOF
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5
M="/cvmfs/test.cern.ch/.cvmfspublished"

# 1: within TTL → cached
curl -s "http://127.0.0.1:$CPORT$M" -o "$PFX/m1"
N1="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -oF cvmfspublished | wc -l)"
curl -s "http://127.0.0.1:$CPORT$M" -o "$PFX/m2"
N2="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -oF cvmfspublished | wc -l)"
[ "$N1" = "$N2" ] && cmp -s "$PFX/m1" "$PFX/m2" && ok "fresh manifest from cache" \
    || bad "manifest not cached within TTL (origin $N1→$N2)"

# 2: after TTL + bump → refetched, new content
curl -s "http://127.0.0.1:$MPORT/ctl/manifest/bump" >/dev/null
sleep $((TTL + 1))
curl -s "http://127.0.0.1:$CPORT$M" -o "$PFX/m3"
cmp -s "$PFX/m1" "$PFX/m3" && bad "manifest stale after TTL" \
    || ok "expired manifest revalidated"

# 3: after TTL with origin down → bounded stale-serve of m3
kill "$MOCK"; MOCK=""; sleep $((TTL + 1))
C="$(curl -s -o "$PFX/m4" -w '%{http_code}' "http://127.0.0.1:$CPORT$M")"
[ "$C" = 200 ] && cmp -s "$PFX/m3" "$PFX/m4" && ok "stale-if-error serve" \
    || bad "stale-if-error: code=$C"
exit $fail
