#!/usr/bin/env bash
#
# run_io_uring_backend.sh — exercises the io_uring disk-I/O backend end to end.
#
# The whole io_uring path is INVISIBLE to a stub build (no liburing): the normal
# test binary compiles it out, so these three real, data-corrupting / crashing
# bugs shipped undetected until a host actually ran the backend:
#
#   1. driver-backed corruption — a write to a REMOTE (sd_xroot) backend with a
#      thread pool configured was routed onto a raw IORING_OP_WRITE against the
#      handle's placeholder fd, landing 0 bytes on the origin.  io_uring must
#      only touch plain POSIX fds; driver-backed handles fall to the pool.
#   2. queue-depth stall — a streaming write wedged after exactly queue_depth
#      in-flight ops (256 x 32 KiB = 8 MiB) on a kernel whose registered eventfd
#      never signalled; the startup self-test now proves eventfd delivery and
#      falls back to the pool when it does not work.
#   3. teardown UAF — a client vanishing mid-write left a late CQE that posted a
#      completion event living in the freed connection pool, crashing the worker
#      in ngx_event_process_posted.  In-flight slots are now orphaned at
#      disconnect and their CQEs dropped.
#
# SKIPS cleanly when the binary has no io_uring (stub build or a kernel that
# fails the self-test): run it against a liburing build to get coverage.
#
# Usage: tests/run_io_uring_backend.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
PORT_O=11778
PORT_B=11779
PORT_L=11780
PFX="$(mktemp -d /tmp/uring_be.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() {
    for r in o b l; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done
    rm -rf "$PFX"
}
trap cleanup EXIT
mkdir -p "$PFX"/{o/root,o/logs,b/export,b/logs,l/export,l/logs}

XRDCP="$(command -v xrdcp || echo "$(cd "$(dirname "$0")/.." && pwd)/client/bin/xrdcp")"
[ -x "$XRDCP" ] || { echo "SKIP: no xrdcp client available"; exit 0; }

# --- probe: can this binary actually enable io_uring here? -------------------
# `brix_io_uring on` fails startup fast when the backend is unavailable (stub
# build, no kernel support, or the eventfd-delivery self-test fails).  Use that
# as the capability gate so the suite skips instead of misreporting.
cat > "$PFX/l/nginx.conf" <<EOF
daemon on; error_log $PFX/l/logs/e.log info; pid $PFX/l/nginx.pid;
thread_pool default threads=4;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${PORT_L}; brix_root on; brix_export $PFX/l/export;
    brix_auth none; brix_allow_write on; brix_io_uring on; } }
EOF
if ! "$NGINX" -p "$PFX/l" -c "$PFX/l/nginx.conf" 2>"$PFX/l/start.err"; then
    echo "SKIP: io_uring unavailable for this binary/kernel — $(grep -oiE 'io_uring[^"]*' "$PFX/l/start.err" | head -1)"
    exit 0
fi
sleep 1
grep -q "io_uring disk-I/O backend active" "$PFX/l/logs/e.log" \
    || { echo "SKIP: io_uring did not activate (self-test fell back to pool)"; exit 0; }
ok "io_uring backend active (batch eventfd-delivery self-test passed)"

# The self-test is `on` (fail-fast) above, so reaching here means BOTH the
# single-NOP and the under-load burst drained via the eventfd on this kernel —
# i.e. a kernel that drops completions once the ring saturates (the xrd1 8 MiB
# stall) would have refused to start here and the suite would have SKIPped.
# That is the fallback contract; the functional checks below then confirm the
# enabled backend actually moves bytes without stalling or crashing.

# --- 1. local write PAST the queue-depth wall (256 x 32 KiB = 8 MiB) --------
head -c 33554432 /dev/urandom > "$PFX/big.bin"       # 32 MiB, 4x the wall
"$XRDCP" -f "$PFX/big.bin" "root://127.0.0.1:${PORT_L}//big.bin" >/dev/null 2>&1
if cmp -s "$PFX/big.bin" "$PFX/l/export/big.bin"; then
    ok "32 MiB local write completed (no queue-depth stall)"
else
    bad "local write stalled/short (got=$(stat -c%s "$PFX/l/export/big.bin" 2>/dev/null))"
fi

# --- 2. driver-backed remote write-through must NOT ride io_uring -----------
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${PORT_O}; brix_root on; brix_export $PFX/o/root;
    brix_auth none; brix_allow_write on; brix_upload_resume off; } }
EOF
cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/logs/e.log info; pid $PFX/b/nginx.pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${PORT_B}; brix_root on; brix_export $PFX/b/export;
    brix_auth none; brix_allow_write on; brix_upload_resume off; brix_io_uring on;
    brix_storage_backend root://127.0.0.1:${PORT_O}; } }
EOF
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "O start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/err" || { echo "B start failed"; cat "$PFX/b/err"; exit 2; }
sleep 1
head -c 2600000 /dev/urandom > "$PFX/remote.bin"     # multi-chunk (> 8 MiB not needed; > 1 MiB)
"$XRDCP" -f "$PFX/remote.bin" "root://127.0.0.1:${PORT_B}//remote.bin" >/dev/null 2>&1
if cmp -s "$PFX/remote.bin" "$PFX/o/root/remote.bin"; then
    ok "remote write-through byte-exact on origin (driver-backed op used the pool, not io_uring)"
else
    bad "remote write landed 0/partial on origin (got=$(stat -c%s "$PFX/o/root/remote.bin" 2>/dev/null)) — io_uring wrongly claimed a driver-backed write"
fi

# --- 3. teardown UAF: kill the client mid-write, io_uring in flight ---------
"$XRDCP" -f --xrate 8m "$PFX/big.bin" "root://127.0.0.1:${PORT_L}//killed.bin" >/dev/null 2>&1 &
cp_pid=$!
sleep 2
kill -9 "$cp_pid" 2>/dev/null
sleep 3
if grep -qE "exited on signal" "$PFX/l/logs/e.log"; then
    bad "worker crashed on mid-write disconnect (io_uring teardown UAF)"
    grep -E "exited on signal" "$PFX/l/logs/e.log" | head -2
else
    ok "no worker death after mid-write client kill (in-flight slots orphaned)"
fi
head -c 500000 /dev/urandom > "$PFX/probe.bin"
"$XRDCP" -f "$PFX/probe.bin" "root://127.0.0.1:${PORT_L}//probe.bin" >/dev/null 2>&1
cmp -s "$PFX/probe.bin" "$PFX/l/export/probe.bin" \
    && ok "server still serving after the abrupt disconnect" \
    || bad "server not serving after disconnect"

[ $fail -eq 0 ] && echo "run_io_uring_backend: ALL PASS" \
    || { echo "run_io_uring_backend: FAILURES"; exit 1; }
