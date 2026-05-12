#!/usr/bin/env bash
#
# Helper launcher for the local nginx+xrootd test environment.
#
# Manages:
#   - Multiple nginx instances (ports 11094-11123, 8443, 9100, 18444-18456)
#   - Reference xrootd instances (ports 11098-11113)
#   - PKI regeneration (CA, certs, proxies, VOMS)
#
# Usage:
#   tests/manage_test_servers.sh start
#   tests/manage_test_servers.sh stop
#   tests/manage_test_servers.sh force-stop
#   tests/manage_test_servers.sh restart
#   tests/manage_test_servers.sh status
#
# Optional subcommands:
#   tests/manage_test_servers.sh start nginx
#   tests/manage_test_servers.sh start ref
#
# Environment variables:
#   TEST_ROOT - Base directory for test files (default: /tmp/xrd-test)
#   NGINX_BIN - Path to nginx binary (default: /tmp/nginx-1.28.3/objs/nginx)
#   REF_BIN   - Path to xrootd binary (default: xrootd)

set -euo pipefail

TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"
NGINX_PREFIX="${NGINX_PREFIX:-$TEST_ROOT}"
NGINX_CONF_REL="${NGINX_CONF_REL:-conf/nginx.conf}"
NGINX_PORT="${NGINX_PORT:-11094}"

REF_BIN="${REF_BIN:-xrootd}"
REF_DIR="${REF_DIR:-$TEST_ROOT/ref}"
REF_CFG="${REF_CFG:-${REF_DIR}/conformance.cfg}"
REF_LOG="${REF_LOG:-${REF_DIR}/conformance.log}"
REF_PID_FILE="${REF_PID_FILE:-${REF_DIR}/run-conf/xrootd.pid}"
REF_PORT="${REF_PORT:-11098}"

DATA_DIR="${DATA_DIR:-$TEST_ROOT/data}"
PKI_DIR="${PKI_DIR:-$TEST_ROOT/pki}"
LOG_DIR="${LOG_DIR:-$TEST_ROOT/logs}"
TMP_DIR="${TMP_DIR:-$TEST_ROOT/tmp}"

NGINX_BIN="${NGINX_BIN:-/tmp/nginx-1.28.3/objs/nginx}"

# Config templates directory
CONFIGS_DIR="$(cd "$(dirname "$0")" && pwd)/configs"

usage() {
    cat <<'EOF'
Usage:
    tests/manage_test_servers.sh <start|stop|force-stop|restart|status> [all|nginx|ref]

Examples:
  tests/manage_test_servers.sh start
  tests/manage_test_servers.sh force-stop ref
  tests/manage_test_servers.sh restart nginx
  tests/manage_test_servers.sh status ref
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

wait_ready_xrdfs() {
    local url="$1"
    local tries="${2:-30}"
    local sleep_s="${3:-0.5}"
    local i

    if ! have_cmd xrdfs; then
        return 0
    fi

    for ((i = 0; i < tries; i++)); do
        if have_cmd timeout; then
            if timeout 2s xrdfs "$url" ls / >/dev/null 2>&1; then
                return 0
            fi
        elif xrdfs "$url" ls / >/dev/null 2>&1; then
            return 0
        fi
        sleep "$sleep_s"
    done
    return 1
}

regenerate_pki() {
    local pki_dir="${1:-$PKI_DIR}"

    if [[ ! -d "$pki_dir" ]]; then
        echo "PKI directory does not exist, creating: $pki_dir"
        mkdir -p "$pki_dir"/{ca,server,user,voms,vomsdir}
    fi

    cd /home/rcurrie/HEP-x/nginx-xrootd || return 1

    python3 -c "
import os
import sys
sys.path.insert(0, 'tests')

os.environ['PKI_DIR'] = '$pki_dir'
from pki_helpers import blitz_test_pki
blitz_test_pki()
" 2>&1 || echo "WARNING: PKI regeneration failed, continuing anyway"

    python3 utils/make_proxy.py "$pki_dir" 2>&1 || true

    echo "PKI generated in $pki_dir"
}

# Substitute template variables in config files
substitute_config() {
    local src="$1"
    local dest="$2"
    
    # Provide sensible defaults which can be overridden by the environment
    : "${NGINX_ANON_PORT:=11094}"
    : "${NGINX_GSI_PORT:=11095}"
    : "${NGINX_GSI_TLS_PORT:=11096}"
    : "${NGINX_TOKEN_PORT:=11097}"
    : "${NGINX_METRICS_PORT:=9100}"
    : "${NGINX_WEBDAV_PORT:=8443}"
    : "${NGINX_HTTP_WEBDAV_PORT:=8080}"
    : "${NGINX_S3_PORT:=9001}"
    : "${TOKEN_DIR:=${TEST_ROOT}/tokens}"
    : "${CRL_RELOAD_INTERVAL:=5}"
    : "${HTTP_STUB_PORT:=11123}"
    : "${WEBDAV_AUTH_CACHE_NGINX_PORT:=18445}"
    : "${WEBDAV_TPC_SOURCE_REQUIRED_PORT:=18450}"
    : "${WEBDAV_TPC_SOURCE_OPEN_PORT:=18451}"
    : "${WEBDAV_TPC_DEST_CAFILE_PORT:=18452}"
    : "${WEBDAV_TPC_DEST_CADIR_PORT:=18453}"
    : "${WEBDAV_TPC_DEST_NO_SERVICE_CERT_PORT:=18454}"
    : "${WEBDAV_TPC_DEST_DISABLED_PORT:=18455}"
    : "${WEBDAV_TPC_DEST_READONLY_PORT:=18456}"
    : "${MAP_A_HOST:=127.0.0.1}"
    : "${MAP_A_PORT:=${REF_PORT:-11098}}"
    : "${MAP_B_HOST:=127.0.0.1}"
    : "${MAP_B_PORT:=$(( ${REF_PORT:-11098} + 1 ))}"
    : "${AUTHDB_PATH:=${REF_DIR:-${TEST_ROOT}/ref}/authdb}"
    : "${SOURCE_REQUIRED_ROOT:=${DATA_DIR}/source_required}"
    : "${SOURCE_OPEN_ROOT:=${DATA_DIR}/source_open}"
    : "${DEST_CAFILE_ROOT:=${DATA_DIR}/dest_cafile}"
    : "${DEST_CADIR_ROOT:=${DATA_DIR}/dest_cadir}"
    : "${DEST_NO_SERVICE_CERT_ROOT:=${DATA_DIR}/dest_no_service_cert}"
    : "${DEST_DISABLED_ROOT:=${DATA_DIR}/dest_disabled}"
    : "${DEST_READONLY_ROOT:=${DATA_DIR}/dest_readonly}"

    sed -e "s|{PORT}|$NGINX_PORT|g" \
        -e "s|{ANON_PORT}|${NGINX_ANON_PORT}|g" \
        -e "s|{GSI_PORT}|${NGINX_GSI_PORT}|g" \
        -e "s|{GSI_TLS_PORT}|${NGINX_GSI_TLS_PORT}|g" \
        -e "s|{TOKEN_PORT}|${NGINX_TOKEN_PORT}|g" \
        -e "s|{METRICS_PORT}|${NGINX_METRICS_PORT}|g" \
        -e "s|{WEBDAV_PORT}|${NGINX_WEBDAV_PORT}|g" \
        -e "s|{HTTP_WEBDAV_PORT}|${NGINX_HTTP_WEBDAV_PORT}|g" \
        -e "s|{S3_PORT}|${NGINX_S3_PORT}|g" \
        -e "s|{TOKEN_DIR}|${TOKEN_DIR}|g" \
        -e "s|{LOG_DIR}|$LOG_DIR|g" \
        -e "s|{DATA_DIR}|$DATA_DIR|g" \
        -e "s|{TMP_DIR}|$TMP_DIR|g" \
        -e "s|{CA_CERT}|$PKI_DIR/ca/ca.pem|g" \
        -e "s|{CA_DIR}|$PKI_DIR/ca|g" \
        -e "s|{SERVER_CERT}|$PKI_DIR/server/hostcert.pem|g" \
        -e "s|{SERVER_KEY}|$PKI_DIR/server/hostkey.pem|g" \
        -e "s|{CA_PEM}|$PKI_DIR/ca/ca.pem|g" \
        -e "s|{CLIENT_CERT}|$PKI_DIR/user/usercert.pem|g" \
        -e "s|{CLIENT_KEY}|$PKI_DIR/user/userkey.pem|g" \
        -e "s|{CRL_PATH}|$PKI_DIR/ca/crl.pem|g" \
        -e "s|{VOMSDIR}|$PKI_DIR/vomsdir|g" \
        -e "s|{CRL_RELOAD_INTERVAL}|${CRL_RELOAD_INTERVAL}|g" \
        -e "s|{HTTP_STUB_PORT}|${HTTP_STUB_PORT}|g" \
        -e "s|{AUTH_PORT}|${WEBDAV_AUTH_CACHE_NGINX_PORT}|g" \
        -e "s|{SOURCE_REQUIRED_PORT}|${WEBDAV_TPC_SOURCE_REQUIRED_PORT}|g" \
        -e "s|{SOURCE_OPEN_PORT}|${WEBDAV_TPC_SOURCE_OPEN_PORT}|g" \
        -e "s|{DEST_CAFILE_PORT}|${WEBDAV_TPC_DEST_CAFILE_PORT}|g" \
        -e "s|{DEST_CADIR_PORT}|${WEBDAV_TPC_DEST_CADIR_PORT}|g" \
        -e "s|{DEST_NO_SERVICE_CERT_PORT}|${WEBDAV_TPC_DEST_NO_SERVICE_CERT_PORT}|g" \
        -e "s|{DEST_DISABLED_PORT}|${WEBDAV_TPC_DEST_DISABLED_PORT}|g" \
        -e "s|{DEST_READONLY_PORT}|${WEBDAV_TPC_DEST_READONLY_PORT}|g" \
        -e "s|{SOURCE_REQUIRED_ROOT}|${SOURCE_REQUIRED_ROOT}|g" \
        -e "s|{SOURCE_OPEN_ROOT}|${SOURCE_OPEN_ROOT}|g" \
        -e "s|{DEST_CAFILE_ROOT}|${DEST_CAFILE_ROOT}|g" \
        -e "s|{DEST_CADIR_ROOT}|${DEST_CADIR_ROOT}|g" \
        -e "s|{DEST_NO_SERVICE_CERT_ROOT}|${DEST_NO_SERVICE_CERT_ROOT}|g" \
        -e "s|{DEST_DISABLED_ROOT}|${DEST_DISABLED_ROOT}|g" \
        -e "s|{DEST_READONLY_ROOT}|${DEST_READONLY_ROOT}|g" \
        -e "s|{MAP_A_HOST}|${MAP_A_HOST}|g" \
        -e "s|{MAP_A_PORT}|${MAP_A_PORT}|g" \
        -e "s|{MAP_B_HOST}|${MAP_B_HOST}|g" \
        -e "s|{MAP_B_PORT}|${MAP_B_PORT}|g" \
        -e "s|{AUTHDB_PATH}|${AUTHDB_PATH}|g" \
        "$src" > "$dest"
}

start_nginx() {
    if [[ ! -x "$NGINX_BIN" ]]; then
        echo "ERROR: nginx binary not found/executable: $NGINX_BIN" >&2
        return 1
    fi

    mkdir -p "${LOG_DIR}" "${TMP_DIR}" "${DATA_DIR}" "${NGINX_PREFIX}/conf"

    # Generate the main nginx config from the nginx_shared.conf template.
    # This is the canonical shared instance: all standard ports live here.
    # If NGINX_CONF_PREGENERATED=1 the caller already wrote the config — skip.
    local shared_template="${CONFIGS_DIR}/nginx_shared.conf"
    local main_conf="${NGINX_PREFIX}/${NGINX_CONF_REL}"
    if [[ "${NGINX_CONF_PREGENERATED:-0}" == "1" ]]; then
        if [[ ! -f "$main_conf" ]]; then
            echo "ERROR: NGINX_CONF_PREGENERATED=1 but ${main_conf} not found" >&2
            return 1
        fi
    elif [[ -f "$shared_template" ]]; then
        substitute_config "$shared_template" "$main_conf"
    elif [[ ! -f "$main_conf" ]]; then
        echo "ERROR: nginx_shared.conf template not found and no pre-existing ${main_conf}" >&2
        return 1
    fi

    if [[ -f "${LOG_DIR}/nginx.pid" ]]; then
        local pid
        pid="$(cat "${LOG_DIR}/nginx.pid" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
            echo "nginx already running (pid=$pid)"
            return 0
        fi
    fi

    "$NGINX_BIN" -p "$NGINX_PREFIX" -c "$NGINX_CONF_REL"

    if [[ -n "${SKIP_XRDFS_CHECK:-}" ]]; then
        echo "nginx started (skipping xrdfs readiness because SKIP_XRDFS_CHECK set)"
    else
        if wait_ready_xrdfs "root://localhost:${NGINX_PORT}"; then
            echo "nginx started and ready on ${NGINX_PORT}"
        else
            echo "WARNING: nginx started but readiness probe failed on ${NGINX_PORT}" >&2
        fi
    fi
}

stop_nginx() {
    if [[ ! -x "$NGINX_BIN" ]]; then
        echo "nginx binary not found: $NGINX_BIN"
        return 0
    fi

    # Stop main nginx instance
    "$NGINX_BIN" -p "$NGINX_PREFIX" -c "$NGINX_CONF_REL" -s stop >/dev/null 2>&1 || true

    local pid_file="${LOG_DIR}/nginx.pid"
    if [[ -f "$pid_file" ]]; then
        sleep 0.2
    fi

    # Stop additional nginx instances
    for pid_file in "${LOG_DIR}"/*.pid; do
        [[ -f "$pid_file" ]] || continue
        
        local basename
        basename="$(basename "$pid_file" .pid)"
        
        if [[ "$basename" == "nginx" ]]; then
            continue  # Already stopped above
        fi
        
        local pid
        pid="$(cat "$pid_file" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
            kill "$pid" >/dev/null 2>&1 || true
            sleep 0.2
        fi
    done

    echo "nginx stopped"
}

force_stop_nginx() {
    stop_nginx

    local pid_file="${LOG_DIR}/nginx.pid"
    local pids=""
    if [[ -f "$pid_file" ]]; then
        pids="$(cat "$pid_file" 2>/dev/null || true)"
        kill_pid_list "$pids"
    fi

    # Kill all nginx instance PIDs
    for pid_file in "${LOG_DIR}"/*.pid; do
        [[ -f "$pid_file" ]] || continue
        
        local pids_instance
        pids_instance="$(cat "$pid_file" 2>/dev/null || true)"
        kill_pid_list "$pids_instance"
    done

    # Extra safety net: kill listeners on known fixed nginx test ports.
    pids="$(
        {
            pids_on_port 11094
            pids_on_port 11095
            pids_on_port 11096
            pids_on_port 11097
            pids_on_port 11099
            pids_on_port 11100
            pids_on_port 11101
            pids_on_port 11102
            pids_on_port 11103
            pids_on_port 11104
            pids_on_port 11105
            pids_on_port 11106
            pids_on_port 11107
            pids_on_port 11108
            pids_on_port 11109
            pids_on_port 11110
            pids_on_port 11120
            pids_on_port 11121
            pids_on_port 11122
            pids_on_port 11123
            pids_on_port 8080
            pids_on_port 8443
            pids_on_port 9001
            pids_on_port 9100
            pids_on_port 18444
            pids_on_port 18445
            pids_on_port 18450
            pids_on_port 18451
            pids_on_port 18452
            pids_on_port 18453
            pids_on_port 18454
            pids_on_port 18455
            pids_on_port 18456
        } | sort -u
    )"
    kill_pid_list "$pids"

    rm -f "${LOG_DIR}"/*.pid
    echo "nginx force-stopped"
}

write_ref_cfg() {
    mkdir -p "${REF_DIR}/admin-conf" "${REF_DIR}/run-conf"

    cat >"$REF_CFG" <<EOF
xrd.port ${REF_PORT}
oss.localroot ${DATA_DIR}
all.export /
all.adminpath ${REF_DIR}/admin-conf
all.pidpath   ${REF_DIR}/run-conf
xrd.trace off
EOF
}

write_gsi_ref_cfg() {
    local cfg="$1"
    local port="$2"
    local data_dir="$3"
    local admin_dir="$4"
    local run_dir="$5"
    local sec_lib

    if ! sec_lib="$(find_xrd_sec_lib)"; then
        return 1
    fi

    if [[ ! -f "$PKI_DIR/ca/ca.pem" ||
          ! -f "$PKI_DIR/server/hostcert.pem" ||
          ! -f "$PKI_DIR/server/hostkey.pem" ]]; then
        return 1
    fi

    cat >"$cfg" <<EOF
xrd.port ${port}
xrd.network nodnr
xrd.allow host *
oss.localroot ${data_dir}
all.export /
all.adminpath ${admin_dir}
all.pidpath   ${run_dir}
xrd.trace off
xrootd.seclib ${sec_lib}
sec.protocol gsi -certdir:${PKI_DIR}/ca -cert:${PKI_DIR}/server/hostcert.pem -key:${PKI_DIR}/server/hostkey.pem -gridmap:none -gmapopt:10
sec.protbind * gsi
EOF
}

write_anon_ref_cfg() {
    local cfg="$1"
    local port="$2"
    local data_dir="$3"
    local admin_dir="$4"
    local run_dir="$5"

    cat >"$cfg" <<EOF
xrd.port ${port}
oss.localroot ${data_dir}
all.export /
all.adminpath ${admin_dir}
all.pidpath   ${run_dir}
xrd.trace off
EOF
}

start_extra_ref_gsi() {
    local label="$1"
    local port="$2"
    local data_dir="$3"
    local admin_dir="${REF_DIR}/${label}-admin-conf"
    local run_dir="${REF_DIR}/${label}-run-conf"
    local cfg="${REF_DIR}/${label}-conformance.cfg"
    local log="${REF_DIR}/${label}-conformance.log"

    if [[ -n "${SKIP_XRDFS_CHECK:-}" ]]; then
        if pids_on_port "$port" | grep -q .; then
            echo "reference xrootd ${label} appears to be listening on $port (SKIP_XRDFS_CHECK set)"
            return 0
        fi
    elif wait_ready_xrdfs "root://localhost:$port" 1 0.1; then
        echo "reference xrootd ${label} already running on $port"
        return 0
    fi

    mkdir -p "$admin_dir" "$run_dir" "$data_dir"
    if ! write_gsi_ref_cfg "$cfg" "$port" "$data_dir" "$admin_dir" "$run_dir"; then
        echo "WARNING: reference xrootd ${label} GSI config unavailable; falling back to anonymous config" >&2
        write_anon_ref_cfg "$cfg" "$port" "$data_dir" "$admin_dir" "$run_dir"
    fi

    "$REF_BIN" -c "$cfg" -l "$log" -b >/dev/null 2>&1 || true

    if [[ -n "${SKIP_XRDFS_CHECK:-}" ]]; then
        echo "reference xrootd ${label} started on $port"
    elif wait_ready_xrdfs "root://localhost:$port"; then
        echo "reference xrootd ${label} started and ready on $port"
    else
        echo "WARNING: reference xrootd ${label} started but readiness probe failed on $port" >&2
    fi
}

start_ref() {
    if ! have_cmd "$REF_BIN"; then
        echo "ERROR: xrootd binary not found on PATH" >&2
        return 1
    fi

    if [[ -n "${SKIP_XRDFS_CHECK:-}" ]]; then
        if pids_on_port "${REF_PORT}" | grep -q .; then
            echo "reference xrootd appears to be listening on ${REF_PORT} (SKIP_XRDFS_CHECK set)"
            return 0
        fi
    else
        if wait_ready_xrdfs "root://localhost:${REF_PORT}" 1 0.1; then
            echo "reference xrootd already running on ${REF_PORT}"
            return 0
        fi
    fi

    if [[ "${REF_CFG_PREGENERATED:-0}" != "1" ]]; then
        write_ref_cfg
    fi
    rm -f "$REF_PID_FILE"

    "$REF_BIN" -c "$REF_CFG" -l "$REF_LOG" -b >/dev/null 2>&1

    for _ in {1..20}; do
        if [[ -f "$REF_PID_FILE" ]]; then
            break
        fi
        sleep 0.1
    done

    if [[ -n "${SKIP_XRDFS_CHECK:-}" ]]; then
        echo "reference xrootd started (skipping xrdfs readiness because SKIP_XRDFS_CHECK set)"
    else
        if wait_ready_xrdfs "root://localhost:${REF_PORT}"; then
            echo "reference xrootd started and ready on ${REF_PORT}"
        else
            echo "WARNING: reference xrootd started but readiness probe failed on ${REF_PORT}" >&2
        fi
    fi

    # Start additional reference xrootd instances for GSI and shared ports
    local ref_gsi_port="${REF_XROOTD_GSI_PORT:-11099}"
    local ref_shared_port="${REF_XROOTD_GSI_SHARED_PORT:-11100}"
    local ref_gsi_data_dir="${REF_XROOTD_GSI_DATA_DIR:-${TEST_ROOT}/data-gsi-bridge}"

    start_extra_ref_gsi "gsi" "$ref_gsi_port" "$ref_gsi_data_dir"
    start_extra_ref_gsi "shared" "$ref_shared_port" "$DATA_DIR"
}

stop_ref() {
    local pid=""
    if [[ -f "$REF_PID_FILE" ]]; then
        pid="$(cat "$REF_PID_FILE" 2>/dev/null || true)"
    fi

    if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
        kill "$pid" >/dev/null 2>&1 || true
        for _ in {1..20}; do
            if ! kill -0 "$pid" >/dev/null 2>&1; then
                break
            fi
            sleep 0.1
        done
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill -9 "$pid" >/dev/null 2>&1 || true
        fi
        rm -f "$REF_PID_FILE"
        echo "reference xrootd stopped"
        return 0
    fi

    if wait_ready_xrdfs "root://localhost:${REF_PORT}" 1 0.1; then
        echo "WARNING: reference xrootd appears to be running on ${REF_PORT} but is unmanaged by this script" >&2
        return 0
    fi

    rm -f "$REF_PID_FILE"
    echo "reference xrootd not running"
}

force_stop_ref() {
    stop_ref

    local pids=""

    # Kill any process listening on known fixed xrootd reference test ports.
    pids="$(
        {
            pids_on_port "$REF_PORT"
            pids_on_port 11098
            pids_on_port 11099
            pids_on_port 11100
            pids_on_port 11111
            pids_on_port 11112
            pids_on_port 11113
        } | sort -u
    )"
    kill_pid_list "$pids"

    # Also kill xrootd daemons started with this specific config path.
    if have_cmd pgrep; then
        pids="$(pgrep -f "xrootd.*${REF_CFG}" 2>/dev/null || true)"
        kill_pid_list "$pids"
    fi

    rm -f "$REF_PID_FILE"
    echo "reference xrootd force-stopped"
}

status_nginx() {
    local pid_file="${LOG_DIR}/nginx.pid"
    if [[ -f "$pid_file" ]]; then
        local pid
        pid="$(cat "$pid_file" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
            echo "nginx: running (pid=$pid, port=${NGINX_PORT})"
            return 0
        fi
    fi
    echo "nginx: stopped"
}

status_ref() {
    if [[ -f "$REF_PID_FILE" ]]; then
        local pid
        pid="$(cat "$REF_PID_FILE" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
            echo "ref xrootd: running (pid=$pid, port=${REF_PORT})"
            return 0
        fi
    fi

    if [[ -n "${SKIP_XRDFS_CHECK:-}" ]]; then
        if pids_on_port "${REF_PORT}" | grep -q .; then
            echo "ref xrootd: running (port=${REF_PORT}, unmanaged)"
            return 0
        fi
    else
        if wait_ready_xrdfs "root://localhost:${REF_PORT}" 1 0.1; then
            echo "ref xrootd: running (port=${REF_PORT}, unmanaged)"
            return 0
        fi
    fi

    echo "ref xrootd: stopped"
}

ACTION="${1:-}"
TARGET="${2:-all}"

if [[ -z "$ACTION" ]]; then
    usage
    exit 1
fi

case "$ACTION" in
    start)
        case "$TARGET" in
            all) force_stop_ref; force_stop_nginx; regenerate_pki; start_nginx; start_ref ;;
            nginx)
                if [[ "${SKIP_NGINX_FORCE_STOP_ON_START:-0}" == "1" ]]; then
                    start_nginx
                else
                    force_stop_nginx
                    start_nginx
                fi
                ;;
            ref) force_stop_ref; start_ref ;;
            *) usage; exit 1 ;;
        esac
        ;;
    stop)
        case "$TARGET" in
            all) stop_ref; stop_nginx ;;
            nginx) stop_nginx ;;
            ref) stop_ref ;;
            *) usage; exit 1 ;;
        esac
        ;;
    force-stop)
        case "$TARGET" in
            all) force_stop_ref; force_stop_nginx ;;
            nginx) force_stop_nginx ;;
            ref) force_stop_ref ;;
            *) usage; exit 1 ;;
        esac
        ;;
    restart)
        case "$TARGET" in
            all) stop_ref; stop_nginx; regenerate_pki; start_nginx; start_ref ;;
            nginx) stop_nginx; start_nginx ;;
            ref) stop_ref; start_ref ;;
            *) usage; exit 1 ;;
        esac
        ;;
    status)
        case "$TARGET" in
            all) status_nginx; status_ref ;;
            nginx) status_nginx ;;
            ref) status_ref ;;
            *) usage; exit 1 ;;
        esac
        ;;
    *)
        usage
        exit 1
        ;;
esac
