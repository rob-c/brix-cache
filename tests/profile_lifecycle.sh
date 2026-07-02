#!/usr/bin/env bash
#
# profile_lifecycle.sh — throwaway lifecycle profiler for the nginx-xrootd module.
#
# WHAT: self-provisions a minimal nginx-xrootd instance (anonymous + GSI stream
# blocks, multiple workers) in a scratch prefix, then measures the four lifecycle
# events and prints a one-screen costs report:
#
#     cold start ......... boot -> first accepted connection (the real SLO)
#     reload ............. SIGHUP -> a fresh worker is serving again
#     worker respawn ..... SIGKILL a worker -> master respawns it
#     full shutdown ...... SIGQUIT -> master process gone
#
# It also surfaces the module's own permanent per-phase summary lines
# ("xrootd postconfig: ..." / "xrootd init_process[wN]: ...") and an optional
# strace -c syscall summary of a cold start.
#
# WHY: there was no repeatable way to measure startup/shutdown cost or to compare
# before/after a fix. This is a measurement tool only — nothing here ships in the
# module; the permanent instrumentation lives in src/core/compat/lifecycle_timing.c.
# It self-provisions because the shared /tmp/xrd-test fixtures are transient.
#
# HOW: generates a self-signed cert (to exercise the GSI ephemeral-DH keypool warm
# path, the dominant per-worker cost), starts the freshly-built objs/nginx as a
# daemon, and times each event with a monotonic-ish `date +%s.%N` plus a TCP
# connect probe via bash /dev/tcp. Phase deltas come from the error.log NOTICE
# lines the module already emits. Idempotent: tears down and recreates its prefix
# on every run.
#
# USAGE:
#   tests/profile_lifecycle.sh                 # full run, default ports
#   NGINX=/path/to/objs/nginx tests/profile_lifecycle.sh
#   WORKERS=4 PORT_ANON=21094 PORT_GSI=21095 tests/profile_lifecycle.sh
#   STRACE=1 tests/profile_lifecycle.sh        # also capture a syscall summary
#
set -u

NGINX="${NGINX:-/tmp/nginx-1.28.3/objs/nginx}"
PREFIX="${PREFIX:-/tmp/xrd-lifecycle-prof}"
PORT_ANON="${PORT_ANON:-21094}"
PORT_GSI="${PORT_GSI:-21095}"
WORKERS="${WORKERS:-2}"
STRACE="${STRACE:-0}"
TIMEOUT_S="${TIMEOUT_S:-15}"

CONF="$PREFIX/conf/nginx.conf"
ELOG="$PREFIX/logs/error.log"
PIDFILE="$PREFIX/logs/nginx.pid"

# ---- helpers ---------------------------------------------------------------

now() { date +%s.%N; }

# elapsed milliseconds between two `now` snapshots, integer.
ms_between() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%d", (b - a) * 1000 }'; }

# Succeeds when a TCP connection to 127.0.0.1:$1 is accepted.
can_connect() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

# Poll until the port accepts, or TIMEOUT_S elapses. Echoes nothing; returns 0/1.
wait_accept() {
    local port="$1" deadline
    deadline=$(awk -v t="$TIMEOUT_S" 'BEGIN { print systime() + t }')
    while :; do
        can_connect "$port" && return 0
        [ "$(date +%s)" -ge "$deadline" ] && return 1
        sleep 0.01
    done
}

master_pid() { [ -f "$PIDFILE" ] && cat "$PIDFILE" 2>/dev/null; }
worker_pids() { local m; m="$(master_pid)"; [ -n "$m" ] && pgrep -P "$m" 2>/dev/null; }

# Block until exactly $WORKERS workers exist AND the init_process line count has
# stopped climbing, so a prior reload's still-arriving worker lines can't satisfy
# the next measurement's counter (otherwise respawn reads a false ~0 ms).
settle() {
    local deadline prev; deadline=$(awk -v t="$TIMEOUT_S" 'BEGIN { print systime() + t }')
    while :; do
        prev="$(init_count)"
        if [ "$(worker_pids | grep -c .)" -eq "$WORKERS" ]; then
            sleep 0.15
            [ "$(init_count)" -eq "$prev" ] && return 0
        fi
        [ "$(date +%s)" -ge "$deadline" ] && return 0
        sleep 0.05
    done
}

# Number of "init_process[" lines currently in the error log (a new one per worker
# bring-up — the signal that a worker has finished its per-worker startup).
# grep -c prints "0" (and exits 1) when there are no matches; callers read the
# count from stdout, so emit exactly one number whether or not the log exists.
init_count() {
    if [ -f "$ELOG" ]; then
        grep -c "init_process\[" "$ELOG" 2>/dev/null
    else
        echo 0
    fi
}

# Wait until the init_process line count exceeds $1, then return.
wait_new_worker() {
    local base="$1" deadline
    deadline=$(awk -v t="$TIMEOUT_S" 'BEGIN { print systime() + t }')
    while :; do
        [ "$(init_count)" -gt "$base" ] && return 0
        [ "$(date +%s)" -ge "$deadline" ] && return 1
        sleep 0.01
    done
}

# ---- provisioning ----------------------------------------------------------

provision() {
    rm -rf "$PREFIX"
    mkdir -p "$PREFIX/conf" "$PREFIX/logs" "$PREFIX/data" "$PREFIX/tmp"

    # Self-signed cert+key so the GSI block (and its keypool warm-up) is exercised.
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -keyout "$PREFIX/conf/host.key" -out "$PREFIX/conf/host.crt" \
        -subj "/CN=lifecycle-prof" >/dev/null 2>&1

    cat >"$CONF" <<EOF
worker_processes $WORKERS;
daemon on;
master_process on;
pid $PIDFILE;
error_log $ELOG notice;
# A thread pool must exist for the GSI keypool to fill off-thread (otherwise the
# warm-up falls back to synchronous, as it does on a server with no async I/O).
thread_pool default threads=4 max_queue=512;
events { worker_connections 1024; }

stream {
    server {
        listen $PORT_ANON;
        xrootd on;
        xrootd_storage_backend posix:$PREFIX/data;
        xrootd_auth none;
    }
    server {
        listen $PORT_GSI;
        xrootd on;
        xrootd_storage_backend posix:$PREFIX/data;
        xrootd_auth gsi;
        xrootd_certificate     $PREFIX/conf/host.crt;
        xrootd_certificate_key $PREFIX/conf/host.key;
        xrootd_trusted_ca      $PREFIX/conf/host.crt;
    }
}
EOF
}

# ---- measurements ----------------------------------------------------------

# Returns 0 and sets COLD_MS; leaves the server running.
measure_cold_start() {
    : > "$ELOG"
    local t0 t1
    t0="$(now)"
    "$NGINX" -p "$PREFIX" -c "$CONF" 2>/dev/null
    if ! wait_accept "$PORT_ANON"; then
        echo "FATAL: server never accepted on $PORT_ANON (see $ELOG)" >&2
        tail -5 "$ELOG" >&2
        return 1
    fi
    t1="$(now)"
    COLD_MS="$(ms_between "$t0" "$t1")"
}

# Requires a running server. Sets RELOAD_MS.
measure_reload() {
    local base t0 t1
    base="$(init_count)"
    t0="$(now)"
    "$NGINX" -p "$PREFIX" -c "$CONF" -s reload 2>/dev/null
    wait_new_worker "$base" || { echo "WARN: no new worker after reload" >&2; }
    wait_accept "$PORT_ANON"
    t1="$(now)"
    RELOAD_MS="$(ms_between "$t0" "$t1")"
}

# Requires a running server. Sets RESPAWN_MS.
measure_respawn() {
    local victim base t0 t1
    victim="$(worker_pids | head -1)"
    if [ -z "$victim" ]; then echo "WARN: no worker to kill" >&2; RESPAWN_MS=-1; return; fi
    base="$(init_count)"
    t0="$(now)"
    kill -KILL "$victim" 2>/dev/null
    wait_new_worker "$base" || echo "WARN: worker not respawned in ${TIMEOUT_S}s" >&2
    t1="$(now)"
    RESPAWN_MS="$(ms_between "$t0" "$t1")"
}

# Requires a running server. Sets SHUT_MS. Leaves the server stopped.
measure_shutdown() {
    local m t0 t1
    m="$(master_pid)"
    t0="$(now)"
    "$NGINX" -p "$PREFIX" -c "$CONF" -s quit 2>/dev/null
    local deadline; deadline=$(awk -v t="$TIMEOUT_S" 'BEGIN { print systime() + t }')
    while kill -0 "$m" 2>/dev/null; do
        [ "$(date +%s)" -ge "$deadline" ] && break
        sleep 0.01
    done
    t1="$(now)"
    SHUT_MS="$(ms_between "$t0" "$t1")"
}

# Optional: syscall summary of a cold start (best-effort; needs strace).
measure_strace() {
    command -v strace >/dev/null 2>&1 || { echo "(strace not installed)"; return; }
    local out="$PREFIX/logs/strace.txt"
    strace -f -c -o "$out" "$NGINX" -p "$PREFIX" -c "$CONF" -g "daemon off;" \
        >/dev/null 2>&1 &
    local sp=$!
    wait_accept "$PORT_ANON"
    "$NGINX" -p "$PREFIX" -c "$CONF" -s quit 2>/dev/null
    wait "$sp" 2>/dev/null
    echo "Top syscalls by time (strace -c, cold start):"
    grep -vE "^%|^-|calls" "$out" 2>/dev/null | sort -k2 -rn | head -8 | sed 's/^/    /'
}

# ---- report ----------------------------------------------------------------

main() {
    [ -x "$NGINX" ] || { echo "FATAL: nginx binary not found/executable: $NGINX" >&2; exit 1; }
    provision

    measure_cold_start || exit 1
    settle
    measure_reload
    settle
    measure_respawn
    settle
    measure_shutdown

    echo "============================================================"
    echo " nginx-xrootd lifecycle profile  (workers=$WORKERS)"
    echo "============================================================"
    printf "  cold start (boot -> first accept) : %6s ms\n" "$COLD_MS"
    printf "  reload     (HUP  -> serving again): %6s ms\n" "$RELOAD_MS"
    printf "  respawn    (kill -> worker back)  : %6s ms\n" "$RESPAWN_MS"
    printf "  shutdown   (quit -> master gone)  : %6s ms\n" "$SHUT_MS"
    echo "------------------------------------------------------------"
    echo " module phase breakdown (from error.log):"
    grep -hE "postconfig:|init_process\[" "$ELOG" 2>/dev/null | sed -E 's/^.*: xrootd /    xrootd /' | sort -u
    echo "------------------------------------------------------------"

    if [ "$STRACE" = "1" ]; then
        # Re-provision so the strace run starts from a clean tree.
        provision
        measure_strace
        echo "------------------------------------------------------------"
    fi

    # Leave the tree stopped and clean.
    [ -n "$(master_pid)" ] && "$NGINX" -p "$PREFIX" -c "$CONF" -s stop 2>/dev/null
    echo " (scratch prefix: $PREFIX)"
}

main "$@"
