#!/usr/bin/env bash
# profile_load.sh — CPU flame graph of the nginx-xrootd module under load
#
# WHAT: Drives the perf load fleet via run_load_test.sh and samples the nginx
#       WORKER processes with `perf` for the duration of the hot window, then
#       renders a flame graph SVG with Brendan Gregg's FlameGraph scripts.
#
#       In `both` mode it captures a READ pass and a WRITE pass SEPARATELY and
#       merges them into ONE SVG under synthetic `read`/`write` root frames, so
#       the two workloads appear as two distinct towers you can compare side by
#       side (NOT interleaved like run_load_test's own `--mode both`).
#
# WHY:  run_load_test.sh owns the whole fleet lifecycle (PKI -> start -> load ->
#       stop). We can't profile the workers unless we attach DURING the load
#       window, so this wrapper launches that sweep in the background, waits for
#       the nginx workers to start burning CPU (skipping the idle PKI/setup
#       lead-in so idle epoll_wait samples don't bury the real work), records,
#       and collapses the result.
#
# HOW:  ./tests/profile_load.sh read   [concurrency] [load_args...]
#       ./tests/profile_load.sh write  [concurrency] [load_args...]
#       ./tests/profile_load.sh both   [concurrency] [load_args...]   # read+write, one SVG
#
#   Examples:
#       ./tests/profile_load.sh both 128 --suite root-gsi --read-sink devnull
#       PERF_FREQ=2999 ./tests/profile_load.sh both 200 --suite root-gsi --read-sink devnull
#
#   Output: /tmp/xrd-perf-test/flame/<mode>-<ts>.svg  (+ per-pass .perf.data/.folded)
#
# Env knobs:
#   PERF_EVENT=task-clock   software timer sampler — DEFAULT. Always works, even
#                           on WSL2 kernels with no hardware PMU. This IS an
#                           on-CPU flame graph. Set PERF_EVENT=cycles to use the
#                           hardware PMU if this kernel exposes it.
#   CALLGRAPH=dwarf         DWARF unwinding — DEFAULT. Works with the current
#                           `-g -O3` build (no frame pointers). Set CALLGRAPH=fp
#                           if you rebuilt with -fno-omit-frame-pointer (cheaper,
#                           lower overhead, shorter capture).
#   PERF_FREQ=997           samples/sec per task. Raise for a denser/finer graph
#                           (e.g. 2999); a read workload is mostly off-CPU so it
#                           always samples sparser than write.
#   PERF_MMAP=512M          per-CPU perf ring buffer. Raise if you see
#                           "lost N chunks / lost X%" at high PERF_FREQ.
#   DWARF_STACK=8192        bytes of user stack copied per DWARF sample. Lower
#                           (e.g. 4096) to cut data volume / sample loss.
#   FLAMEGRAPH_DIR=~/FlameGraph   location of the FlameGraph scripts.
#   MAX_RECORD_SECS=180     hard cap on a single pass's record window.

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NGINX_PERF_DIR="/tmp/xrd-perf-test"
PIDFILE="$NGINX_PERF_DIR/logs/nginx.pid"
OUTDIR="$NGINX_PERF_DIR/flame"

PERF_EVENT="${PERF_EVENT:-task-clock}"
CALLGRAPH="${CALLGRAPH:-dwarf}"
PERF_FREQ="${PERF_FREQ:-997}"
PERF_MMAP="${PERF_MMAP:-}"          # per-CPU ring buffer (-m). EMPTY = perf default (safe vs perf_event_mlock_kb, which the worker fleet divides down to a few MB). Set e.g. 8M only if you also raise perf_event_mlock_kb.
DWARF_STACK="${DWARF_STACK:-8192}"  # bytes of user stack copied per DWARF sample
MAX_RECORD_SECS="${MAX_RECORD_SECS:-180}"
FLAMEGRAPH_DIR="${FLAMEGRAPH_DIR:-$HOME/FlameGraph}"

log() { echo "  [profile_load] $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# ---------------------------------------------------------------------------
# Pre-flight: tools must exist
# ---------------------------------------------------------------------------
command -v perf >/dev/null 2>&1 || die "perf not found — run: sudo dnf install -y perf"
[[ -x "$FLAMEGRAPH_DIR/stackcollapse-perf.pl" && -x "$FLAMEGRAPH_DIR/flamegraph.pl" ]] \
    || die "FlameGraph scripts not found in $FLAMEGRAPH_DIR (git clone https://github.com/brendangregg/FlameGraph)"

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
MODE="${1:-read}"
case "$MODE" in read|write|both) ;; *) die "mode must be read|write|both (got '$MODE')"; esac
shift || true
CONCURRENCY="32"
if [[ "${1:-}" =~ ^[0-9,]+$ ]]; then CONCURRENCY="$1"; shift; fi
LOAD_ARGS=("$@")

mkdir -p "$OUTDIR"
TS="$(date +%Y%m%d-%H%M%S)"

# ---------------------------------------------------------------------------
# Worker discovery — children of the perf nginx MASTER only, so we never
# profile the functional-suite fleet that may also be running.
# ---------------------------------------------------------------------------
worker_pids() {
    local master
    [[ -f "$PIDFILE" ]] || return 1
    master="$(cat "$PIDFILE" 2>/dev/null)" || return 1
    [[ -n "$master" ]] && kill -0 "$master" 2>/dev/null || return 1
    pgrep -P "$master" 2>/dev/null | paste -sd, -
}

# Sum of utime+stime jiffies across the worker set (load-start detector).
worker_cpu_jiffies() {
    local pids="$1" total=0 p st u s
    IFS=',' read -ra arr <<< "$pids"
    for p in "${arr[@]}"; do
        [[ -r "/proc/$p/stat" ]] || continue
        st="$(cut -d' ' -f14-15 "/proc/$p/stat" 2>/dev/null)" || continue
        read -r u s <<< "$st"
        total=$(( total + u + s ))
    done
    echo "$total"
}

# ---------------------------------------------------------------------------
# Token JWKS — the perf nginx config requires /tmp/xrd-load/tokens/jwks.json,
# but run_load_test.sh's setup_test_data only mkdir's the dir; the JWKS itself
# is normally generated by the pytest fleet (manage_test_servers.sh). Generate
# it here so the profiler is self-contained and doesn't depend on a prior
# pytest run. A pre-existing signing key is reused (idempotent).
# ---------------------------------------------------------------------------
TOKEN_DIR="/tmp/xrd-load/tokens"
if [[ ! -f "$TOKEN_DIR/jwks.json" ]]; then
    log "generating token JWKS ($TOKEN_DIR/jwks.json)..."
    mkdir -p "$TOKEN_DIR"
    python3 "$SCRIPT_DIR/../utils/make_token.py" init "$TOKEN_DIR" >/dev/null \
        || die "make_token.py init failed — cannot create $TOKEN_DIR/jwks.json"
fi

# ---------------------------------------------------------------------------
# capture_one <mode:read|write> <base-path>
#
# Runs ONE profiled load pass: launch the sweep, attach perf to the workers
# during the hot window, and collapse to "<base>.folded". Self-contained — each
# call starts and stops its own fleet, so read and write passes never overlap.
# ---------------------------------------------------------------------------
CUR_LOAD_PID=""
cleanup() { [[ -n "$CUR_LOAD_PID" ]] && kill -- -"$CUR_LOAD_PID" 2>/dev/null || true; }
trap cleanup EXIT

capture_one() {
    local pass_mode="$1" base="$2"

    # Launch the sweep in its own session so run_load_test's process-group
    # reaping of nginx never reaches our perf process.
    log "[$pass_mode] launching load sweep: concurrency=$CONCURRENCY args='${LOAD_ARGS[*]}'"
    setsid bash "$SCRIPT_DIR/run_load_test.sh" nginx \
        --mode "$pass_mode" --concurrency "$CONCURRENCY" "${LOAD_ARGS[@]}" \
        >"$base.loadlog" 2>&1 &
    CUR_LOAD_PID=$!

    # Wait for workers, then for CPU to actually climb (load started).
    log "[$pass_mode] waiting for perf nginx workers..."
    local pids="" i
    for i in $(seq 1 120); do
        kill -0 "$CUR_LOAD_PID" 2>/dev/null || die "[$pass_mode] sweep exited before workers — see $base.loadlog"
        pids="$(worker_pids || true)"
        [[ -n "$pids" ]] && break
        sleep 1
    done
    [[ -n "$pids" ]] || die "[$pass_mode] no nginx workers after 120s — see $base.loadlog"
    log "[$pass_mode] workers: $pids"

    log "[$pass_mode] waiting for load to start (worker CPU climbing)..."
    local before now started=0
    before="$(worker_cpu_jiffies "$pids")"
    for i in $(seq 1 180); do
        kill -0 "$CUR_LOAD_PID" 2>/dev/null || break
        sleep 1
        now="$(worker_cpu_jiffies "$pids")"
        if (( now - before > 25 )); then started=1; break; fi   # >0.25 CPU = real work
        before="$now"
    done
    [[ "$started" == "1" ]] && log "[$pass_mode] load active — recording" \
                            || log "[$pass_mode] CPU never climbed; recording anyway"

    # Re-read PIDs (reuseport workers may have re-forked during warmup).
    pids="$(worker_pids || echo "$pids")"

    # Record. perf stops on its own when the sweep finishes (watcher SIGINTs it),
    # bounded by MAX_RECORD_SECS.
    # DWARF copies DWARF_STACK bytes of user stack per sample, so at high -F the
    # ring buffer overruns ("lost N chunks"). A large per-CPU mmap (-m) absorbs
    # the bursts; shrink DWARF_STACK if you still see >10% loss (most module
    # stacks are shallow). fp call-graph (rebuild w/ -fno-omit-frame-pointer)
    # avoids the stack copy entirely.
    local cg="--call-graph $CALLGRAPH"
    [[ "$CALLGRAPH" == "dwarf" ]] && cg="--call-graph dwarf,${DWARF_STACK:-8192}"
    local mmap_opt=""
    [[ -n "$PERF_MMAP" ]] && mmap_opt="-m $PERF_MMAP"
    log "[$pass_mode] perf record -F $PERF_FREQ -e $PERF_EVENT $cg $mmap_opt -p <workers>  (<= ${MAX_RECORD_SECS}s)"
    perf record -F "$PERF_FREQ" -e "$PERF_EVENT" $cg $mmap_opt \
        -p "$pids" -o "$base.perf.data" -- sleep "$MAX_RECORD_SECS" &
    local perf_pid=$!

    ( while kill -0 "$CUR_LOAD_PID" 2>/dev/null && kill -0 "$perf_pid" 2>/dev/null; do sleep 1; done
      kill -INT "$perf_pid" 2>/dev/null || true ) &
    local watch_pid=$!

    wait "$perf_pid" 2>/dev/null || true
    kill "$watch_pid" 2>/dev/null || true
    log "[$pass_mode] recording done; waiting for sweep to finish..."
    wait "$CUR_LOAD_PID" 2>/dev/null || true
    CUR_LOAD_PID=""

    [[ -s "$base.perf.data" ]] || die "[$pass_mode] no samples — check $base.loadlog and PERF_EVENT/perf_event_paranoid"
    perf script -i "$base.perf.data" 2>/dev/null \
        | "$FLAMEGRAPH_DIR/stackcollapse-perf.pl" > "$base.folded"
    local n; n="$(wc -l < "$base.folded")"
    log "[$pass_mode] folded $n unique stacks"
}

# ---------------------------------------------------------------------------
# Drive the pass(es) and render the SVG.
# ---------------------------------------------------------------------------
SUBTITLE="c=$CONCURRENCY, $PERF_EVENT/$CALLGRAPH @ ${PERF_FREQ}Hz"

if [[ "$MODE" == "both" ]]; then
    READ_BASE="$OUTDIR/read-$TS"
    WRITE_BASE="$OUTDIR/write-$TS"
    capture_one read  "$READ_BASE"
    capture_one write "$WRITE_BASE"

    # Merge under synthetic root frames so read and write are two towers in one
    # graph (prefix every folded stack with "read;" / "write;").
    COMBINED="$OUTDIR/readwrite-$TS"
    sed 's/^/read;/'  "$READ_BASE.folded"  >  "$COMBINED.folded"
    sed 's/^/write;/' "$WRITE_BASE.folded" >> "$COMBINED.folded"

    "$FLAMEGRAPH_DIR/flamegraph.pl" \
        --title "nginx-xrootd read | write  ($SUBTITLE)" \
        --width 1800 "$COMBINED.folded" > "$COMBINED.svg"

    trap - EXIT
    log "DONE"
    log "  flame graph (read|write) : $COMBINED.svg"
    log "  read  folded/raw         : $READ_BASE.folded / $READ_BASE.perf.data"
    log "  write folded/raw         : $WRITE_BASE.folded / $WRITE_BASE.perf.data"
    echo "$COMBINED.svg"
else
    BASE="$OUTDIR/${MODE}-$TS"
    capture_one "$MODE" "$BASE"
    "$FLAMEGRAPH_DIR/flamegraph.pl" \
        --title "nginx-xrootd $MODE  ($SUBTITLE)" \
        --width 1600 "$BASE.folded" > "$BASE.svg"

    trap - EXIT
    log "DONE"
    log "  flame graph : $BASE.svg"
    log "  raw samples : $BASE.perf.data"
    log "  folded      : $BASE.folded"
    log "  load log    : $BASE.loadlog"
    echo "$BASE.svg"
fi
