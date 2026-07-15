# tests/lib/util.sh - Phase-38 extraction of manage_test_servers.sh.
# Sourced (not executed) by manage_test_servers.sh; uses its global
# config vars.  Do not run directly.

# render_cfg <template> <dest> KEY=VAL [KEY=VAL ...]
#
# Fill {KEY} placeholders in a committed template (tests/configs/) and write the
# result to <dest>.  The xrootd/XrdHttp counterpart to substitute_config(): every
# test-server config is an explicit, reviewable, committed file — NEVER generated
# inline in shell.  Values are escaped for the |-delimited sed s/// command.
render_cfg() {
    local tpl="$1" dest="$2"; shift 2
    if [[ ! -f "$tpl" ]]; then
        echo "render_cfg: template not found: $tpl" >&2
        return 1
    fi
    local sed_args=() kv k v
    for kv in "$@"; do
        k="${kv%%=*}"; v="${kv#*=}"
        v="${v//\\/\\\\}"; v="${v//|/\\|}"; v="${v//&/\\&}"
        sed_args+=(-e "s|{${k}}|${v}|g")
    done
    sed "${sed_args[@]}" "$tpl" > "$dest"
}

usage() {
    cat <<'EOF'
Usage:
    tests/manage_test_servers.sh <start-all|stop-all|start|stop|force-stop|restart|status> [all|nginx|ref|xrdhttp]

Examples:
  tests/manage_test_servers.sh start-all
  tests/manage_test_servers.sh stop-all
  tests/manage_test_servers.sh force-stop ref
  tests/manage_test_servers.sh restart nginx
  tests/manage_test_servers.sh status xrdhttp
EOF
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

find_xrd_sec_lib() {
    local candidate
    for candidate in \
        /usr/lib64/libXrdSec-5.so \
        /usr/lib/libXrdSec-5.so \
        /usr/lib64/libXrdSec.so \
        /usr/lib/libXrdSec.so; do
        if [[ -f "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

pids_on_port() {
    local port="$1"

    if have_cmd ss; then
        ss -ltnp "( sport = :${port} )" 2>/dev/null \
            | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' \
            | sort -u
        return 0
    fi

    if have_cmd lsof; then
        lsof -t -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null | sort -u
        return 0
    fi

    return 0
}

kill_pid_list() {
    local pids="$1"
    local pid

    if [[ -z "$pids" ]]; then
        return 0
    fi

    while IFS= read -r pid; do
        [[ -z "$pid" ]] && continue
        kill "$pid" >/dev/null 2>&1 || true
    done <<<"$pids"

    sleep 0.3

    while IFS= read -r pid; do
        [[ -z "$pid" ]] && continue
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill -9 "$pid" >/dev/null 2>&1 || true
        fi
    done <<<"$pids"
}

# Wait until the xrootd endpoint at $url (root://host:port[/...]) is serving.
#
# Two phases, fast-first:
#   1. TCP accept poll — a /dev/tcp connect is ~0 ms whether the port is up OR
#      refused, so we can poll on a tight 50 ms cadence until the listening
#      socket appears (or the budget expires) without ever blocking.
#   2. one xrdfs verification — port-open != serving, so confirm with a real
#      `xrdfs ls /` (~20 ms once ready); a few quick retries cover the brief
#      listen->serve gap.
#
# WHY: the old single-phase loop ran `timeout 2s xrdfs ...` on EVERY poll. Each
# poll of a not-yet-ready endpoint ate the full 2 s XrdCl reconnect timeout
# (plus the inter-try sleep) before retrying, so a single still-booting xrootd
# cost multiple seconds and start-all serialised ~16 of them — ~27 s of the
# ~35 s start-all wall time was spent here. A TCP connect tells us "not up yet"
# instantly, so we only spend the XrdCl cost once, on a port we already know
# accepts.
#
# Budget = $tries * $sleep_s seconds, preserving each caller's original deadline
# (e.g. the `1 0.1` fast pre-check stays a ~100 ms "is it already up?" probe; the
# default `30 0.5` stays a 15 s post-launch wait).
wait_ready_xrdfs() {
    local url="$1"
    local tries="${2:-30}"
    local sleep_s="${3:-0.5}"

    local hostport="${url#root://}"
    hostport="${hostport%%/*}"
    local host="${hostport%%:*}"
    local port="${hostport##*:}"

    local budget_ms
    budget_ms=$(awk -v t="$tries" -v s="$sleep_s" 'BEGIN { printf "%d", t * s * 1000 }')

    # Phase 1: wait for the listening socket via a cheap TCP connect.
    if [[ -n "$host" && -n "$port" ]]; then
        local waited_ms=0
        local listening=0
        while (( waited_ms < budget_ms )); do
            if (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null; then
                listening=1
                break
            fi
            sleep 0.05
            waited_ms=$(( waited_ms + 50 ))
        done
        (( listening == 0 )) && return 1
    fi

    # Phase 2: confirm xrootd actually serves (listening != serving).
    if ! have_cmd xrdfs; then
        return 0
    fi
    local i
    for ((i = 0; i < 10; i++)); do
        if have_cmd timeout; then
            if timeout 2s xrdfs "$url" ls / >/dev/null 2>&1; then
                return 0
            fi
        elif xrdfs "$url" ls / >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

find_xrd_library() {
    local candidate
    for candidate in "$@"; do
        if [[ -f "/usr/lib64/$candidate" ]]; then
            echo "/usr/lib64/$candidate"
            return 0
        fi
        if [[ -f "/usr/lib/$candidate" ]]; then
            echo "/usr/lib/$candidate"
            return 0
        fi
    done
    return 1
}
