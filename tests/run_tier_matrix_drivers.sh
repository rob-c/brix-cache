#!/usr/bin/env bash
#
# run_tier_matrix_drivers.sh — phase-64 SP3 (§24): parametrise the §3 driver×role
# matrix. This harness exercises the STAGE_STORE role (the write-stage buffer) for
# each driver: a WebDAV node with a posix backend + a stage_store of the given
# driver, sync write-back. A PUT lands on the stage store, the engine flushes it to
# the backend, and a GET serves it byte-exact — flipping that (driver, stage_store)
# matrix cell READY. The flush mover (src/fs/xfer/stage_engine.c) is driver-generic,
# so each cell is the same assertion against a different store URL.
#
# Host drivers (posix/pblock/xroot) run anywhere; the rados cell runs only when
# XROOTD_TEST_RADOS_POOL is set (inside the ceph build container, where librados +
# a reachable pool exist):
#   tests/run_tier_matrix_drivers.sh                                  # posix/pblock/xroot
#   XROOTD_TEST_RADOS_POOL=xrdtest \
#     tests/run_tier_matrix_drivers.sh /opt/nginx-src/objs/nginx      # + rados (container)
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
RADOS_POOL="${XROOTD_TEST_RADOS_POOL:-}"
PFX="$(mktemp -d /tmp/tiermx.XXXXXX)"
PORT=8520
fail=0
declare -A RESULT
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
# Match the working ceph-test convention: when run as root (the container), pin the
# worker to root so it can write the test's root-owned backend dir.
USERLINE=""; [ "$(id -u)" = 0 ] && USERLINE="user root; worker_processes 1;"
cleanup() {
    for f in "$PFX"/*/*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done
    rm -rf "$PFX"
}
trap cleanup EXIT

# test_stage_store <driver> <store_url> <needs_remote_store_server>
#   needs_remote_store_server=1 spins a writable root:// server first (the xroot
#   stage buffer); the store_url then points at it.
test_stage_store() {
    local drv="$1" url="$2" needsrv="${3:-0}"
    local d="$PFX/$drv"
    local pb=$((PORT++)) ps=$((PORT++))
    mkdir -p "$d/backend" "$d/store" "$d/tmp" "$d/logs"
    echo "== stage_store: $drv =="

    if [ "$needsrv" = 1 ]; then
        mkdir -p "$d/sroot" "$d/slogs"
        url="root://127.0.0.1:${ps}"
        cat > "$d/s.conf" <<EOF
daemon on; $USERLINE error_log $d/slogs/e.log error; pid $d/s.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${ps}; xrootd on; xrootd_root $d/sroot;
    xrootd_auth none; xrootd_allow_write on; } }
EOF
        "$NGINX" -p "$d" -c "$d/s.conf" 2>"$d/serr" \
            || { bad "$drv: remote store server failed to start"; RESULT[$drv]=FAIL; return; }
    fi

    cat > "$d/b.conf" <<EOF
daemon on; $USERLINE error_log $d/logs/e.log info; pid $d/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
http { client_body_temp_path $d/tmp; server { listen 127.0.0.1:${pb};
  location / { dav_methods PUT DELETE;
    xrootd_webdav on; xrootd_webdav_root $d/backend; xrootd_webdav_auth none;
    xrootd_webdav_allow_write on;
    xrootd_webdav_stage on; xrootd_webdav_stage_store $url;
    xrootd_webdav_stage_flush sync; } } }
EOF
    "$NGINX" -p "$d" -c "$d/b.conf" 2>"$d/berr" \
        || { bad "$drv: node failed to start"; cat "$d/berr"; RESULT[$drv]=FAIL; return; }
    sleep 1

    head -c 900000 /dev/urandom > "$d/src.bin"
    local sha; sha="$(sha256sum "$d/src.bin" | cut -d' ' -f1)"
    local code; code="$(curl -s --max-time 25 -o /dev/null -w '%{http_code}' \
                        -T "$d/src.bin" "http://127.0.0.1:${pb}/m.bin")"
    curl -s --max-time 25 -o "$d/got.bin" "http://127.0.0.1:${pb}/m.bin"

    if [ "$code" = 201 ] && [ -f "$d/backend/m.bin" ] \
       && [ "$(sha256sum "$d/got.bin" 2>/dev/null | cut -d' ' -f1)" = "$sha" ]; then
        ok "$drv stage_store: PUT 201 → flushed to backend → GET byte-exact"
        RESULT[$drv]=PASS
    else
        bad "$drv stage_store (PUT=$code, backend=$([ -f "$d/backend/m.bin" ] && echo yes || echo no))"
        grep -iE "stage move|staged commit" "$d/logs/e.log" 2>/dev/null | tail -3
        RESULT[$drv]=FAIL
    fi

    [ -f "$d/nginx.pid" ] && kill "$(cat "$d/nginx.pid")" 2>/dev/null
    [ -f "$d/s.pid" ]     && kill "$(cat "$d/s.pid")" 2>/dev/null
    sleep 0.3
}

echo "############ phase-64 SP3 §24 — tier driver matrix (stage_store role) ############"
test_stage_store posix  "posix:$PFX/posix/store"   0
test_stage_store pblock "pblock:$PFX/pblock/store" 0
test_stage_store xroot  ""                         1   # url filled from the started server
if [ -n "$RADOS_POOL" ]; then
    rados -p "$RADOS_POOL" rm /m.bin >/dev/null 2>&1 || true
    test_stage_store rados "rados://$RADOS_POOL"    0
    rados -p "$RADOS_POOL" rm /m.bin >/dev/null 2>&1 || true
else
    echo "== stage_store: rados — SKIP (set XROOTD_TEST_RADOS_POOL in the ceph container) =="
    RESULT[rados]=SKIP
fi

echo
echo "== §3 matrix summary — stage_store column =="
for drv in posix pblock xroot rados; do
    printf '  %-8s %s\n' "$drv" "${RESULT[$drv]:-?}"
done
[ "$fail" = 0 ] && echo "run_tier_matrix_drivers: ALL PASS" || echo "run_tier_matrix_drivers: FAILURES"
exit "$fail"
