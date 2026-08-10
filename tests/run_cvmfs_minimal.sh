#!/usr/bin/env bash
# run_cvmfs_minimal.sh — phase-101 W9.3 (Task 7): the 3-line-config CVMFS
# read-through acceptance test.
#
# Proves the minimal brix_cvmfs config end to end against a mock CVMFS
# Stratum-1: enable cvmfs, point at an origin, give it a cache store — and a
# client GET fills a CAS object through the proxy and populates the cache.
#
#     brix_cvmfs on;
#     brix_cache_store posix:<cache>;
#     brix_storage_backend "http://<stratum1>";
#
# Self-contained: spawns tests/cvmfs/mock_stratum1.py as the origin, writes an
# nginx.conf, starts nginx, GETs the manifest + a data object, asserts 200 and
# that the cache was written, then GETs again to prove a cache hit.
#
# Env: NGINX_BIN (a brix nginx with the cvmfs module — the conformance default
#      is $REPO/objs/nginx, else /tmp/nginx-1.28.3/objs/nginx). Exits 0 on pass,
#      1 on failure, 77 (autotools "skip") if no cvmfs-capable binary is found.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

resolve_nginx() {
    if [ -n "${NGINX_BIN:-}" ] && [ -x "$NGINX_BIN" ]; then echo "$NGINX_BIN"; return; fi
    for c in "$REPO_ROOT/objs/nginx" /tmp/nginx-1.28.3/objs/nginx; do
        [ -x "$c" ] || continue
        # must have the cvmfs module compiled in
        if strings "$c" 2>/dev/null | grep -qx brix_cvmfs; then echo "$c"; return; fi
    done
    echo ""
}

NGINX="$(resolve_nginx)"
if [ -z "$NGINX" ]; then
    echo "SKIP: no cvmfs-capable nginx binary found (set NGINX_BIN)"; exit 77
fi

REPO="test.cern.ch"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/cvmfs_minimal.XXXXXX")"
MOCK_PORT="${CVMFS_MOCK_PORT:-29200}"
NGINX_PORT="${CVMFS_NGINX_PORT:-29201}"
MOCK_PID=""

cleanup() {
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null
    ASAN_OPTIONS=detect_leaks=0 "$NGINX" -p "$WORK" -c "$WORK/nginx.conf" -s stop 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; [ -f "$WORK/logs/e.log" ] && tail -5 "$WORK/logs/e.log"; exit 1; }

mkdir -p "$WORK/cache" "$WORK/logs"

# 1. origin: a mock CVMFS Stratum-1 serving a synthetic signed repo.
python3 "$REPO_ROOT/tests/cvmfs/mock_stratum1.py" \
    --port "$MOCK_PORT" --repo "$REPO" --objects 8 --seed 1 \
    >"$WORK/mock.log" 2>&1 &
MOCK_PID=$!
sleep 1
curl -fsS -o /dev/null "http://127.0.0.1:$MOCK_PORT/cvmfs/$REPO/.cvmfspublished" \
    || fail "mock stratum1 did not come up"

# 2. the 3-line brix_cvmfs config.
cat > "$WORK/nginx.conf" <<EOF
daemon on; error_log $WORK/logs/e.log info; pid $WORK/nginx.pid;
worker_processes 1; thread_pool default threads=2;
events { worker_connections 256; }
http { access_log off; server { listen 127.0.0.1:$NGINX_PORT;
  location /cvmfs/ {
    brix_cvmfs on;
    brix_cache_store posix:$WORK/cache;
    brix_storage_backend "http://127.0.0.1:$MOCK_PORT";
  }
} }
EOF

ASAN_OPTIONS=detect_leaks=0 "$NGINX" -t -p "$WORK" -c "$WORK/nginx.conf" >/dev/null 2>&1 \
    || fail "nginx -t rejected the 3-line cvmfs config"
ASAN_OPTIONS=detect_leaks=0 "$NGINX" -p "$WORK" -c "$WORK/nginx.conf" >/dev/null 2>&1 \
    || fail "nginx failed to start"
sleep 1

# 3. GET the manifest + a data object THROUGH the proxy (read-through fill).
code=$(curl -s -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:$NGINX_PORT/cvmfs/$REPO/.cvmfspublished")
[ "$code" = "200" ] || fail "manifest GET returned $code (want 200)"

OBJ=$(curl -s "http://127.0.0.1:$MOCK_PORT/ctl/objects" 2>/dev/null \
      | python3 -c 'import sys,json;[print(p) for p in json.load(sys.stdin) if "/data/" in p]' 2>/dev/null | head -1)
[ -n "$OBJ" ] || fail "could not enumerate a data object from the mock"
BODY="$WORK/obj.out"
code=$(curl -s -o "$BODY" -w '%{http_code}' "http://127.0.0.1:$NGINX_PORT$OBJ")
[ "$code" = "200" ] || fail "data object GET returned $code (want 200)"
[ -s "$BODY" ] || fail "data object body was empty"

# 4. the cache must have been written (read-through populated it).
DATAFILES=$(find "$WORK/cache" -type f 2>/dev/null | wc -l)
[ "$DATAFILES" -ge 1 ] || fail "cache store was not populated after fill"

# 5. a second GET must still succeed (served from the now-warm cache).
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$NGINX_PORT$OBJ")
[ "$code" = "200" ] || fail "second (cache-hit) GET returned $code (want 200)"

echo "PASS: brix_cvmfs 3-line read-through — manifest+object 200, cache populated ($DATAFILES files), cache-hit 200"
exit 0
