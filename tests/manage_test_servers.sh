#!/usr/bin/env bash
#
# Helper launcher for the local nginx+xrootd test environment.
#
# Manages:
#   - Multiple nginx instances (ports 11094-11123, 8443, 8444, 9100, 18444-18456)
#   - Reference xrootd instances (ports 11098-11113)
#   - PKI regeneration (CA, certs, proxies, VOMS)
#
# Usage:
#   tests/manage_test_servers.sh start-all
#   tests/manage_test_servers.sh stop-all
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
    : "${NGINX_WEBDAV_GSI_TLS_PORT:=8444}"
    : "${NGINX_HTTP_WEBDAV_PORT:=8080}"
    : "${NGINX_S3_PORT:=9001}"
    : "${TOKEN_DIR:=${TEST_ROOT}/tokens}"
    : "${CRL_PATH:=${PKI_DIR}/ca/test-user.crl.pem}"
    : "${CRL_RELOAD_INTERVAL:=5}"
    : "${HTTP_STUB_PORT:=11123}"
    : "${UPSTREAM_PORT:=12120}"
    : "${TOKEN_FILE:=${TEST_ROOT}/tokens/upstream.jwt}"
    : "${JWKS_FILE:=${TEST_ROOT}/tokens/jwks.json}"
    : "${REFRESH_INTERVAL_MS:=100}"
    : "${TOKEN_ISSUER:=https://test.example.com}"
    : "${TOKEN_AUDIENCE:=nginx-xrootd}"
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
    : "${BIND_HOST:=127.0.0.1}"
    : "${CMS_PORT:=11161}"
    : "${CMS_PATHS:=/}"
    : "${CACHE_DIR:=${DATA_DIR}/cache}"
    : "${METRICS_PORT:=9100}"
    : "${META_CMS_PORT:=11186}"
    : "${SELF_REGISTER_PORT:=11189}"

    sed -e "s|{PORT}|$NGINX_PORT|g" \
        -e "s|{ANON_PORT}|${NGINX_ANON_PORT}|g" \
        -e "s|{GSI_PORT}|${NGINX_GSI_PORT}|g" \
        -e "s|{GSI_TLS_PORT}|${NGINX_GSI_TLS_PORT}|g" \
        -e "s|{TOKEN_PORT}|${NGINX_TOKEN_PORT}|g" \
        -e "s|{METRICS_PORT}|${NGINX_METRICS_PORT}|g" \
-e "s|{WEBDAV_PORT}|${NGINX_WEBDAV_PORT}|g" \
        -e "s|{WEBDAV_GSI_TLS_PORT}|${NGINX_WEBDAV_GSI_TLS_PORT}|g" \
        -e "s|{HTTP_WEBDAV_PORT}|${NGINX_HTTP_WEBDAV_PORT}|g" \
        -e "s|{S3_PORT}|${NGINX_S3_PORT}|g" \
        -e "s|{TOKEN_DIR}|${TOKEN_DIR}|g" \
        -e "s|{UPSTREAM_PORT}|${UPSTREAM_PORT}|g" \
        -e "s|{TOKEN_FILE}|${TOKEN_FILE}|g" \
        -e "s|{JWKS_FILE}|${JWKS_FILE}|g" \
        -e "s|{REFRESH_INTERVAL_MS}|${REFRESH_INTERVAL_MS}|g" \
        -e "s|{TOKEN_ISSUER}|${TOKEN_ISSUER}|g" \
        -e "s|{TOKEN_AUDIENCE}|${TOKEN_AUDIENCE}|g" \
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
        -e "s|{CRL_PATH}|${CRL_PATH}|g" \
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
        -e "s|{BIND_HOST}|${BIND_HOST}|g" \
        -e "s|{CMS_PORT}|${CMS_PORT}|g" \
        -e "s|{CMS_PATHS}|${CMS_PATHS}|g" \
        -e "s|{CACHE_DIR}|${CACHE_DIR}|g" \
        -e "s|{METRICS_PORT}|${METRICS_PORT}|g" \
        -e "s|{META_CMS_PORT}|${META_CMS_PORT}|g" \
        -e "s|{SELF_REGISTER_PORT}|${SELF_REGISTER_PORT}|g" \
        -e "s|{STAGE_CMD}|${STAGE_CMD:-/bin/true}|g" \
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
            pids_on_port 11112
            pids_on_port 11113
            pids_on_port 11114
            pids_on_port 11115
            pids_on_port 11120
            pids_on_port 11121
            pids_on_port 11122
            pids_on_port 11123
            pids_on_port 11124
            pids_on_port 11125
            pids_on_port 11126
            pids_on_port 11160
            pids_on_port 11161
            pids_on_port 11162
            pids_on_port 11163
            pids_on_port 11164
            pids_on_port 11165
            pids_on_port 11166
            pids_on_port 11167
            pids_on_port 11168
            pids_on_port 11180
            pids_on_port 11181
            pids_on_port 11182
            pids_on_port 11183
            pids_on_port 11184
            pids_on_port 11191
            pids_on_port 11192
            pids_on_port 8080
            pids_on_port 8443
            pids_on_port 8444
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
            pids_on_port 18457
            pids_on_port 18458
            pids_on_port 12500
            # cluster-slots data servers + CMS ports
            pids_on_port 12602
            pids_on_port 12603
            pids_on_port 12604
            pids_on_port 12605
            pids_on_port 12607
            pids_on_port 12608
            pids_on_port 19450
            pids_on_port 19451
            pids_on_port 19452
            pids_on_port 19453
            pids_on_port 19454
            pids_on_port 19455
            pids_on_port 19456
            # proxy mode
            pids_on_port 11193
            pids_on_port 11203
            # authdb dedicated
            pids_on_port 11114
            # cluster topologies
            pids_on_port 11169
            pids_on_port 11170
            pids_on_port 11172
            pids_on_port 11173
            pids_on_port 11174
            pids_on_port 11176
            pids_on_port 11185
            pids_on_port 11187
            pids_on_port 11190
            pids_on_port 11194
            pids_on_port 11195
            pids_on_port 11196
            pids_on_port 11197
            pids_on_port 11198
            pids_on_port 11199
            # cache write-through servers
            pids_on_port 11200
            pids_on_port 11201
            pids_on_port 11202
            pids_on_port 11204
            pids_on_port 11205
            # Phase 2-3 capability-flag role servers
            pids_on_port 11206
            pids_on_port 11207
            pids_on_port 11208
            pids_on_port 11209
            # Mock-only upstream nginx (test_a_upstream_redirect.py)
            pids_on_port 11130
            pids_on_port 11131
            pids_on_port 11132
            pids_on_port 11133
            pids_on_port 11134
            pids_on_port 11135
            pids_on_port 11136
            # Real-upstream-redirect nginx (test_a_upstream_redirect.py)
            pids_on_port 11137
            # Proxy interoperability matrix + credential bridge
            pids_on_port 11213
            pids_on_port 11215
            # Real CMS manager instances (replaced Python mocks)
            pids_on_port 11177
            pids_on_port 11178
            pids_on_port 12399
            pids_on_port 12400
        } | sort -u
    )"
    kill_pid_list "$pids"

    rm -f "${LOG_DIR}"/*.pid
    echo "nginx force-stopped"
}

start_dedicated_nginx() {
    local name="$1"
    local template="$2"
    local port="$3"
    local upstream_port="${4:-}"

    local instance_root="${TEST_ROOT}/dedicated/${name}"
    local conf_rel="conf/nginx.conf"
    local conf_path="${instance_root}/${conf_rel}"
    local data_root="${TEST_ROOT}/data-${name}"

    mkdir -p \
        "${instance_root}/conf" \
        "${instance_root}/logs" \
        "${instance_root}/tmp" \
        "${data_root}" \
        "${data_root}/source_required" \
        "${data_root}/source_open" \
        "${data_root}/dest_cafile" \
        "${data_root}/dest_cadir" \
        "${data_root}/dest_no_service_cert" \
        "${data_root}/dest_disabled" \
        "${data_root}/dest_readonly" \
        "${data_root}/cache"
    rm -f "${instance_root}/logs"/*.log "${instance_root}/logs"/*.pid
    if [[ ! -f "${data_root}/test.txt" ]]; then
        printf '%s\n' "hello from nginx-xrootd" > "${data_root}/test.txt"
    fi

    (
        NGINX_PREFIX="${instance_root}"
        NGINX_CONF_REL="${conf_rel}"
        NGINX_PORT="${port}"
        LOG_DIR="${instance_root}/logs"
        TMP_DIR="${instance_root}/tmp"
        DATA_DIR="${data_root}"
        CACHE_DIR="${data_root}/cache"
        SOURCE_REQUIRED_ROOT="${data_root}/source_required"
        SOURCE_OPEN_ROOT="${data_root}/source_open"
        DEST_CAFILE_ROOT="${data_root}/dest_cafile"
        DEST_CADIR_ROOT="${data_root}/dest_cadir"
        DEST_NO_SERVICE_CERT_ROOT="${data_root}/dest_no_service_cert"
        DEST_DISABLED_ROOT="${data_root}/dest_disabled"
        DEST_READONLY_ROOT="${data_root}/dest_readonly"
        UPSTREAM_PORT="${upstream_port:-${UPSTREAM_PORT:-12120}}"
        TOKEN_FILE="${TOKEN_FILE:-${TEST_ROOT}/tokens/upstream.jwt}"
        NGINX_CONF_PREGENERATED=1
        SKIP_NGINX_FORCE_STOP_ON_START=1
        SKIP_XRDFS_CHECK=1

        substitute_config "${CONFIGS_DIR}/${template}" "${conf_path}"
        start_nginx
    )
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

start_extra_ref_anon() {
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
    write_anon_ref_cfg "$cfg" "$port" "$data_dir" "$admin_dir" "$run_dir"

    "$REF_BIN" -c "$cfg" -l "$log" -b >/dev/null 2>&1 || true

    if [[ -n "${SKIP_XRDFS_CHECK:-}" ]]; then
        echo "reference xrootd ${label} started on $port"
    elif wait_ready_xrdfs "root://localhost:$port"; then
        echo "reference xrootd ${label} started and ready on $port"
    else
        echo "WARNING: reference xrootd ${label} started but readiness probe failed on $port" >&2
    fi
}

start_root_tpc_ref() {
    local label="root-tpc-ref"
    local port="${ROOT_TPC_REF_PORT:-11111}"
    local data_dir="${TEST_ROOT}/data-root-tpc-ref"
    local admin_dir="${REF_DIR}/${label}-admin-conf"
    local run_dir="${REF_DIR}/${label}-run-conf"
    local cfg="${REF_DIR}/${label}-conformance.cfg"
    local log="${REF_DIR}/${label}-conformance.log"
    local xrdcp_cmd="${XRDCP_BIN:-xrdcp}"
    local xrdcp_bin

    if ! xrdcp_bin="$(command -v "$xrdcp_cmd" 2>/dev/null)"; then
        echo "WARNING: xrdcp binary not found; skipping reference xrootd ${label}" >&2
        return 0
    fi

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
    : > "$log"
    cat >"$cfg" <<EOF
all.role server
all.export /
oss.localroot ${data_dir}
all.adminpath ${admin_dir}
all.pidpath ${run_dir}

xrd.port ${port}
xrd.trace off
ofs.tpc streams 4 pgm ${xrdcp_bin} --server
EOF

    "$REF_BIN" -c "$cfg" -l "$log" -b >/dev/null 2>&1 || true

    if [[ -n "${SKIP_XRDFS_CHECK:-}" ]]; then
        echo "reference xrootd ${label} started on $port"
    elif wait_ready_xrdfs "root://localhost:$port"; then
        echo "reference xrootd ${label} started and ready on $port"
    else
        echo "WARNING: reference xrootd ${label} started but readiness probe failed on $port" >&2
    fi
}

# start_pss_bridge_ref — xrootd PSS (Proxy Storage Service) proxy in front of nginx.
#
# Scenario 2 of test_e2e_proxy_matrix.py::TestStorageBridge:
#   xrdcp → xrootd(PSS, port) → nginx-proxy(upstream_port) → xrootd-data → PROXY_DATA_ROOT
#
# Files written through this chain land in PROXY_DATA_ROOT (not DATA_ROOT).
start_pss_bridge_ref() {
    local port="${1:-${PROXY_BRIDGE_XROOTD_PORT:-11214}}"
    local upstream_port="${2:-${PROXY_NGINX_PORT:-11193}}"
    local label="pss-bridge"
    local data_dir="${TEST_ROOT}/data-pss-bridge"
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
    : > "$log"
    cat >"$cfg" <<EOF
all.role server
all.export /
oss.localroot ${data_dir}
all.adminpath ${admin_dir}
all.pidpath ${run_dir}

xrd.port ${port}
xrd.trace off
ofs.osslib libXrdPss.so
pss.origin localhost:${upstream_port}
pss.setopt DebugLevel 0
EOF

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

start_xrdhttp() {
    if ! have_cmd "$REF_BIN"; then
        echo "ERROR: xrootd binary not found on PATH" >&2
        return 1
    fi

    # Check for required XrdHttp libraries
    local http_lib tpc_lib sec_lib
    http_lib="$(find_xrd_library libXrdHttp-5.so libXrdHttp.so)" || true
    tpc_lib="$(find_xrd_library libXrdHttpTPC-5.so libXrdHttpTPC.so)" || true

    if [[ -z "$http_lib" ]]; then
        echo "WARNING: XrdHttp library not found; skipping xrdhttp start" >&2
        return 0
    fi
    if [[ -z "$tpc_lib" ]]; then
        echo "WARNING: XrdHttpTPC library not found; skipping xrdhttp start" >&2
        return 0
    fi

    local port="${REF_XRDHTTP_HTTP_PORT:-11113}"
    local root_port="${REF_XRDHTTP_ROOT_PORT:-11112}"
    local xrdhttp_dir="${XRDHTTP_DIR:-$TEST_ROOT/xrdhttp}"
    local cfg_path="${xrdhttp_dir}/xrdhttp.cfg"
    local log_path="${xrdhttp_dir}/xrdhttp.log"
    local pid_file="${xrdhttp_dir}/xrdhttp.pid"
    local data_dir="${XRDHTTP_DATA_DIR:-$TEST_ROOT/data-xrdhttp}"

    mkdir -p "$xrdhttp_dir" "$data_dir" "${xrdhttp_dir}/admin-conf" "${xrdhttp_dir}/run-conf"

    # Check if already running on the HTTP port
    if [[ -n "${SKIP_XRDFS_CHECK:-}" ]]; then
        if pids_on_port "$port" | grep -q .; then
            echo "XrdHttp appears to be listening on $port (SKIP_XRDFS_CHECK set)"
            return 0
        fi
    else
        local tries=3
        for ((i = 0; i < tries; i++)); do
            if timeout 2s curl -skf "https://localhost:${port}/" >/dev/null 2>&1; then
                echo "XrdHttp already running on $port"
                return 0
            fi
            sleep 0.5
        done
    fi

    # Write config
    if [[ ! -f "$PKI_DIR/ca/ca.pem" || \
          ! -f "$PKI_DIR/server/hostcert.pem" || \
          ! -f "$PKI_DIR/server/hostkey.pem" ]]; then
        echo "WARNING: PKI files missing; cannot start XrdHttp with TLS" >&2
        return 1
    fi

    cat >"$cfg_path" <<EOF
all.role server
all.export /
oss.localroot ${data_dir}
all.adminpath ${xrdhttp_dir}/admin-conf
all.pidpath   ${xrdhttp_dir}/run-conf

xrd.port ${root_port}
xrootd.seclib ${sec_lib:-/usr/lib64/libXrdSec-5.so}
xrd.protocol XrdHttp:${port} ${http_lib}

http.cert ${PKI_DIR}/server/hostcert.pem
http.key  ${PKI_DIR}/server/hostkey.pem
http.cadir ${PKI_DIR}/ca
http.desthttps yes
http.selfhttps2http no
http.exthandler xrdtpc ${tpc_lib}
tpc.timeout 10
EOF

    # Start xrootd with HTTP module
    "$REF_BIN" -c "$cfg_path" -l "$log_path" -b >/dev/null 2>&1 || true

    # Wait for readiness
    local ready=false
    for _ in {1..40}; do
        if timeout 2s curl -skf "https://localhost:${port}/" >/dev/null 2>&1; then
            ready=true
            break
        fi
        sleep 0.25
    done

    if [[ "$ready" == "true" ]]; then
        echo "XrdHttp started and ready on port $port (HTTP) / $root_port (root://)"
    else
        local log_content=""
        if [[ -f "$log_path" ]]; then
            log_content="$(tail -50 "$log_path")"
        fi
        echo "WARNING: XrdHttp started but readiness probe failed on port $port" >&2
        echo "Log tail:" >&2
        echo "$log_content" >&2
    fi

    # Save PID file for later cleanup
    if [[ -f "${xrdhttp_dir}/run-conf/xrootd.pid" ]]; then
        cp "${xrdhttp_dir}/run-conf/xrootd.pid" "$pid_file" 2>/dev/null || true
    fi
}

stop_xrdhttp() {
    local xrdhttp_dir="${XRDHTTP_DIR:-$TEST_ROOT/xrdhttp}"
    local port="${REF_XRDHTTP_HTTP_PORT:-11113}"
    local root_port="${REF_XRDHTTP_ROOT_PORT:-11112}"

    # Try to stop via PID file first
    local pid_file="${xrdhttp_dir}/xrdhttp.pid"
    if [[ -f "$pid_file" ]]; then
        local pid
        pid="$(cat "$pid_file" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
            kill "$pid" >/dev/null 2>&1 || true
            sleep 0.5
            if kill -0 "$pid" >/dev/null 2>&1; then
                kill -9 "$pid" >/dev/null 2>&1 || true
            fi
        fi
    fi

    # Also try to stop via any xrootd.pid in run-conf
    local run_pid="${xrdhttp_dir}/run-conf/xrootd.pid"
    if [[ -f "$run_pid" ]]; then
        local pid
        pid="$(cat "$run_pid" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
            kill "$pid" >/dev/null 2>&1 || true
        fi
    fi

    # Safety net: kill any process on the XrdHttp ports
    local pids=""
    pids="$(
        {
            pids_on_port "$port"
            pids_on_port "$root_port"
            pgrep -f "xrootd.*${cfg_path:-$TEST_ROOT/xrdhttp}" 2>/dev/null || true
        } | sort -u
    )"
    kill_pid_list "$pids"

    rm -f "$pid_file" "${xrdhttp_dir}/run-conf/xrootd.pid"
    echo "XrdHttp stopped (ports $port, $root_port)"
}

force_stop_xrdhttp() {
    stop_xrdhttp

    local port="${REF_XRDHTTP_HTTP_PORT:-11113}"
    local root_port="${REF_XRDHTTP_ROOT_PORT:-11112}"

    # Aggressive kill on XrdHttp ports
    local pids=""
    pids="$(pids_on_port "$port"; pids_on_port "$root_port")"
    if have_cmd pgrep; then
        pids="$pids $(pgrep -f 'xrootd.*http' 2>/dev/null || true)"
    fi
    kill_pid_list "$pids"

    echo "XrdHttp force-stopped (ports $port, $root_port)"
}

status_xrdhttp() {
    local port="${REF_XRDHTTP_HTTP_PORT:-11113}"
    local root_port="${REF_XRDHTTP_ROOT_PORT:-11112}"

    if pids_on_port "$port" | grep -q .; then
        echo "XrdHttp: running (HTTP port=$port)"
        return 0
    fi
    if pids_on_port "$root_port" | grep -q .; then
        echo "XrdHttp: running (root:// port=$root_port)"
        return 0
    fi

    # Quick HTTP probe as fallback
    if timeout 2s curl -skf "https://localhost:${port}/" >/dev/null 2>&1; then
        echo "XrdHttp: running (HTTP port=$port, unmanaged)"
        return 0
    fi

    echo "XrdHttp: stopped"
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
            pids_on_port 12120
            pids_on_port 12121
            pids_on_port 12122
            pids_on_port 12123
            pids_on_port 12124
            pids_on_port 12125
            pids_on_port 12126
            pids_on_port 11214
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

start_all_dedicated() {
    force_stop_ref
    force_stop_nginx
    regenerate_pki

    mkdir -p "${TEST_ROOT}/tokens"
    if [[ ! -f "${TEST_ROOT}/tokens/upstream.jwt" ]]; then
        printf '%s\n' "eyJhbGciOiJSUzI1NiJ9.dedicated-test.sig" > "${TEST_ROOT}/tokens/upstream.jwt"
    fi
    local jwks_refresh_dir="${TEST_ROOT}/tokens/jwks-refresh"
    mkdir -p "${jwks_refresh_dir}"
    python3 utils/make_token.py init "${jwks_refresh_dir}" >/dev/null

    local crl_dir="${TEST_ROOT}/crls"
    local crl_reload_dir="${TEST_ROOT}/crl-reload"
    mkdir -p "${crl_dir}" "${crl_reload_dir}"
    rm -f "${crl_dir}"/* "${crl_reload_dir}"/*
    if [[ -f "${PKI_DIR}/ca/test-user.crl.pem" ]]; then
        cp "${PKI_DIR}/ca/test-user.crl.pem" "${crl_dir}/ca.r0"
    fi

    start_nginx
    start_ref

    # Dedicated xrootd backends used by upstream/proxy migration work.  These
    # are real xrootd daemons; tests must not replace them with Python socket
    # listeners.
    start_extra_ref_anon "upstream-redirect" "${UPSTREAM_REDIRECT_BACKEND_PORT:-12120}" "${TEST_ROOT}/data-upstream-redirect"
    start_extra_ref_anon "upstream-wait" "${UPSTREAM_WAIT_BACKEND_PORT:-12121}" "${TEST_ROOT}/data-upstream-wait"
    start_extra_ref_anon "upstream-waitresp" "${UPSTREAM_WAITRESP_BACKEND_PORT:-12122}" "${TEST_ROOT}/data-upstream-waitresp"
    start_extra_ref_anon "upstream-error" "${UPSTREAM_ERROR_BACKEND_PORT:-12123}" "${TEST_ROOT}/data-upstream-error"
    start_extra_ref_anon "upstream-auth" "${UPSTREAM_AUTH_BACKEND_PORT:-12124}" "${TEST_ROOT}/data-upstream-auth"
    start_extra_ref_anon "upstream-auth-nofile" "${UPSTREAM_AUTH_NOFILE_BACKEND_PORT:-12125}" "${TEST_ROOT}/data-upstream-auth-nofile"
    start_extra_ref_anon "upstream-gotorls-notls" "${UPSTREAM_GOTORLS_NOTLS_BACKEND_PORT:-12126}" "${TEST_ROOT}/data-upstream-gotorls-notls"
    start_root_tpc_ref

    start_dedicated_nginx "readonly" "nginx_readonly.conf" "${READONLY_PORT:-11102}"
    start_dedicated_nginx "vo-acl" "nginx_vo_acl.conf" "${VO_PORT:-11103}"
    start_dedicated_nginx "manager" "nginx_manager.conf" "${MANAGER_PORT:-11101}"
    NGINX_WEBDAV_PORT="${WEBDAV_CRL_PORT:-11105}" \
        start_dedicated_nginx "crl" "nginx_crl.conf" "${CRL_PORT:-11104}"
    CRL_PATH="${crl_dir}" NGINX_WEBDAV_PORT="${WEBDAV_DIR_PORT:-11107}" \
        start_dedicated_nginx "crl-dir" "nginx_crl.conf" "${CRL_DIR_PORT:-11106}"
    CRL_PATH="${crl_reload_dir}" CRL_RELOAD_INTERVAL="${TEST_CRL_RELOAD_INTERVAL:-2}" \
        HTTP_STUB_PORT="${CRL_RELOAD_HTTP_PORT:-11109}" \
        start_dedicated_nginx "crl-reload" "nginx_crl_reload.conf" "${CRL_RELOAD_PORT:-11108}"
    start_dedicated_nginx "webdav-auth-cache" "nginx_webdav_auth_cache.conf" "${WEBDAV_AUTH_CACHE_MANUAL_PORT:-18444}"
    start_dedicated_nginx "webdav-tpc" "nginx_webdav_tpc.conf" "${WEBDAV_TPC_SOURCE_REQUIRED_PORT:-18450}"
    start_dedicated_nginx "root-tpc" "nginx_root_tpc.conf" "${ROOT_TPC_NGINX_PORT:-11110}"
    JWKS_FILE="${jwks_refresh_dir}/jwks.json" \
        REFRESH_INTERVAL_MS="${TEST_JWKS_REFRESH_INTERVAL_MS:-500}" \
        TOKEN_ISSUER="${TOKEN_ISSUER:-https://test.example.com}" \
        TOKEN_AUDIENCE="${TOKEN_AUDIENCE:-nginx-xrootd}" \
        start_dedicated_nginx "jwks-refresh" "nginx_jwks_refresh.conf" "${NGINX_JWKS_REFRESH_PORT:-11115}"

    start_dedicated_nginx "upstream-redirect" "nginx_upstream_redirect.conf" "${UPSTREAM_REDIRECT_NGINX_PORT:-11120}" "${UPSTREAM_REDIRECT_BACKEND_PORT:-12120}"
    start_dedicated_nginx "upstream-waitresp" "nginx_upstream_waitresp.conf" "${UPSTREAM_WAITRESP_NGINX_PORT:-11122}" "${UPSTREAM_WAITRESP_BACKEND_PORT:-12122}"
    start_dedicated_nginx "upstream-error" "nginx_upstream_error.conf" "${UPSTREAM_ERROR_NGINX_PORT:-11123}" "${UPSTREAM_ERROR_BACKEND_PORT:-12123}"
    start_dedicated_nginx "upstream-auth" "nginx_upstream_auth.conf" "${UPSTREAM_AUTH_NGINX_PORT:-11124}" "${UPSTREAM_AUTH_BACKEND_PORT:-12124}"
    start_dedicated_nginx "upstream-auth-nofile" "nginx_upstream_auth_nofile.conf" "${UPSTREAM_AUTH_NOFILE_NGINX_PORT:-11125}" "${UPSTREAM_AUTH_NOFILE_BACKEND_PORT:-12125}"
    start_dedicated_nginx "upstream-gotorls-notls" "nginx_upstream_gotorls_notls.conf" "${UPSTREAM_GOTORLS_NOTLS_NGINX_PORT:-11126}" "${UPSTREAM_GOTORLS_NOTLS_BACKEND_PORT:-12126}"

    # Mock-only upstream nginx instances (test_a_upstream_redirect.py).
    # Each instance points to a mock-only backend port (13120–13126) where NO
    # real xrootd server ever runs.  Tests bind a Python MockUpstream to the
    # backend port for the duration of each test; SO_REUSEADDR lets the next
    # test reclaim the port without a TIME_WAIT stall.
    UPSTREAM_PORT="${MOCK_REDIRECT_BACKEND_PORT:-13120}" \
        start_dedicated_nginx "mock-upstream-redirect" "nginx_upstream_redirect.conf" \
        "${MOCK_REDIRECT_NGINX_PORT:-11130}"
    UPSTREAM_PORT="${MOCK_WAIT_BACKEND_PORT:-13121}" \
        start_dedicated_nginx "mock-upstream-wait" "nginx_upstream_wait.conf" \
        "${MOCK_WAIT_NGINX_PORT:-11131}"
    UPSTREAM_PORT="${MOCK_WAITRESP_BACKEND_PORT:-13122}" \
        start_dedicated_nginx "mock-upstream-waitresp" "nginx_upstream_waitresp.conf" \
        "${MOCK_WAITRESP_NGINX_PORT:-11132}"
    UPSTREAM_PORT="${MOCK_ERROR_BACKEND_PORT:-13123}" \
        start_dedicated_nginx "mock-upstream-error" "nginx_upstream_error.conf" \
        "${MOCK_ERROR_NGINX_PORT:-11133}"
    UPSTREAM_PORT="${MOCK_AUTH_BACKEND_PORT:-13124}" \
        start_dedicated_nginx "mock-upstream-auth" "nginx_mock_upstream_auth.conf" \
        "${MOCK_AUTH_NGINX_PORT:-11134}"
    UPSTREAM_PORT="${MOCK_AUTH_NOFILE_BACKEND_PORT:-13125}" \
        start_dedicated_nginx "mock-upstream-auth-nofile" "nginx_upstream_auth_nofile.conf" \
        "${MOCK_AUTH_NOFILE_NGINX_PORT:-11135}"
    UPSTREAM_PORT="${MOCK_GOTORLS_BACKEND_PORT:-13126}" \
        start_dedicated_nginx "mock-upstream-gotorls" "nginx_upstream_gotorls_notls.conf" \
        "${MOCK_GOTORLS_NGINX_PORT:-11136}"

    # Real-upstream-redirect: nginx at REAL_REDIRECT_NGINX_PORT proxies to the
    # cluster-redir so tests can verify kXR_redirect forwarding against a real
    # XRootD redirector without a Python mock backend.
    UPSTREAM_PORT="${CLUSTER_REDIR_PORT:-11160}" \
        start_dedicated_nginx "real-upstream-redirect" "nginx_upstream_redirect.conf" \
        "${REAL_REDIRECT_NGINX_PORT:-11137}"

    start_dedicated_nginx "tpc-ssrf-default" "nginx_tpc_ssrf_default.conf" "${TPC_SSRF_DEFAULT_PORT:-11180}"
    start_dedicated_nginx "tpc-ssrf-allow-local" "nginx_tpc_ssrf_allow_local.conf" "${TPC_SSRF_ALLOW_LOCAL_PORT:-11181}"
    start_dedicated_nginx "tpc-ssrf-deny-private" "nginx_tpc_ssrf_deny_private.conf" "${TPC_SSRF_DENY_PRIVATE_PORT:-11182}"
    start_dedicated_nginx "s3-presigned" "nginx_s3_presigned.conf" "${S3_PRESIGNED_PORT:-11183}"
    start_dedicated_nginx "s3-presigned-sts" "nginx_s3_presigned_sts.conf" "${S3_PRESIGNED_STS_PORT:-11184}"
    start_dedicated_nginx "security-level-standard" "nginx_security_level_standard.conf" "${SECURITY_LEVEL_STANDARD_PORT:-11191}"
    start_dedicated_nginx "security-level-pedantic" "nginx_security_level_pedantic.conf" "${SECURITY_LEVEL_PEDANTIC_PORT:-11192}"

    # CMS cluster: redirector listens on CLUSTER_REDIR_PORT; its CMS manager
    # server listens on port 11161.  The data server connects to that CMS port
    # and serves files on CLUSTER_DS_PORT.
    local cluster_cms_port="${CLUSTER_REDIR_CMS_PORT:-11161}"
    CMS_PORT="${cluster_cms_port}" \
        start_dedicated_nginx "cluster-redir" "nginx_cluster_redir.conf" "${CLUSTER_REDIR_PORT:-11160}"
    CMS_PORT="${cluster_cms_port}" CMS_PATHS="/" \
        start_dedicated_nginx "cluster-ds" "nginx_cluster_ds.conf" "${CLUSTER_DS_PORT:-11162}"

    start_dedicated_nginx "http-cache" "nginx_http_cache.conf" "${NGINX_HTTP_CACHE_PORT:-18457}"
    start_dedicated_nginx "webdav-voms" "nginx_webdav_voms.conf" "${NGINX_WEBDAV_VOMS_PORT:-18458}"

    # CMS heartbeat tests: a real nginx CMS manager (cms-test-mgr) listens on
    # CMS_TEST_CMS_PORT (12400) for data server registrations.  The cms-test nginx
    # (12500) connects to it with xrootd_cms_interval 2, reconnecting every 2s.
    CMS_PORT="${CMS_TEST_CMS_PORT:-12400}" \
        start_dedicated_nginx "cms-test-mgr" "nginx_cluster_redir.conf" "${CMS_TEST_REDIR_PORT:-12399}"
    CMS_PORT="${CMS_TEST_CMS_PORT:-12400}" \
        start_dedicated_nginx "cms-test" "nginx_cms_test.conf" "${CMS_TEST_NGINX_PORT:-12500}"

    # Chaos Mesh tier stack: Tier3 storage ← Tier2 cache ← Tier1 proxy
    start_dedicated_nginx "chaos-tier3" "nginx_chaos_tier3_storage.conf" "${CHAOS_TIER3_PORT:-11163}"
    UPSTREAM_PORT="${CHAOS_TIER3_PORT:-11163}" \
        start_dedicated_nginx "chaos-tier2" "nginx_chaos_tier2_cache.conf" "${CHAOS_TIER2_PORT:-11164}"
    UPSTREAM_PORT="${CHAOS_TIER2_PORT:-11164}" \
        start_dedicated_nginx "chaos-tier1" "nginx_proxy.conf" "${CHAOS_TIER1_PORT:-11165}"

    # Chaos Mesh discovery cluster: separate redirector + DS for delayed-CMS tests
    local chaos_cms_port="${CHAOS_DISCOVERY_CMS_PORT:-11167}"
    CMS_PORT="${chaos_cms_port}" \
        start_dedicated_nginx "chaos-discovery-redir" "nginx_cluster_redir.conf" "${CHAOS_DISCOVERY_REDIR_PORT:-11166}"
    CMS_PORT="${chaos_cms_port}" CMS_PATHS="/chaos-discovery" \
        start_dedicated_nginx "chaos-discovery-ds" "nginx_cluster_ds.conf" "${CHAOS_DISCOVERY_DS_PORT:-11168}"

    # Proxy mode test pair (test_proxy_mode.py)
    start_extra_ref_anon "proxy-upstream" "${PROXY_UPSTREAM_PORT:-12501}" "${TEST_ROOT}/data-proxy-upstream"
    UPSTREAM_PORT="${PROXY_UPSTREAM_PORT:-12501}" \
        start_dedicated_nginx "proxy-nginx" "nginx_proxy_mode.conf" "${PROXY_NGINX_PORT:-11193}"
    UPSTREAM_PORT="${PROXY_DEAD_UPSTREAM_PORT:-19999}" \
        start_dedicated_nginx "proxy-dead" "nginx_proxy_dead.conf" "${PROXY_DEAD_NGINX_PORT:-11203}"

    # Proxy interoperability matrix — Scenarios 2 and 3 (test_e2e_proxy_matrix.py)
    # Scenario 2: xrootd PSS bridge → nginx proxy → xrootd data (PROXY_DATA_ROOT)
    start_pss_bridge_ref "${PROXY_BRIDGE_XROOTD_PORT:-11214}" "${PROXY_NGINX_PORT:-11193}"
    # Scenario 3: pure nginx→nginx stack; proxy chains to the existing data nginx
    UPSTREAM_PORT="${PROXY_NGINX_PORT:-11193}" \
        start_dedicated_nginx "pure-nginx-proxy" "nginx_pure_nginx_proxy.conf" \
        "${PROXY_PURE_NGINX_PROXY_PORT:-11213}"
    # Credential Translation Bridge — Section 4C (test_credential_translation.py)
    # Accepts GSI proxy cert; injects Bearer token for the token-only backend.
    UPSTREAM_PORT="${NGINX_TOKEN_PORT:-11097}" \
        start_dedicated_nginx "credential-bridge" "nginx_credential_bridge.conf" \
        "${CREDENTIAL_BRIDGE_PORT:-11215}"

    # Authdb: pre-create the data dir so nginx can start; authdb_setup writes real rules.
    mkdir -p "${TEST_ROOT}/data-authdb"
    [[ -f "${TEST_ROOT}/data-authdb/authdb" ]] || \
        printf '# placeholder written by start-all; authdb_setup fixture overwrites\n' \
        > "${TEST_ROOT}/data-authdb/authdb"
    start_dedicated_nginx "authdb" "nginx_authdb.conf" "${AUTHDB_PORT:-11114}"

    # Multi-path cluster (TestClusterMultiPath)
    local mp_cms="${CLUSTER_MP_CMS_PORT:-11171}"
    CMS_PORT="${mp_cms}" \
        start_dedicated_nginx "cluster-mp-redir" "nginx_cluster_redir.conf" "${CLUSTER_MP_REDIR_PORT:-11169}"
    CMS_PORT="${mp_cms}" \
        start_dedicated_nginx "cluster-mp-ds" "nginx_cluster_ds_multipath.conf" "${CLUSTER_MP_DS_PORT:-11170}"

    # Multi-server cluster (TestClusterMultiServer)
    local ms_cms="${CLUSTER_MS_CMS_PORT:-11175}"
    CMS_PORT="${ms_cms}" \
        start_dedicated_nginx "cluster-ms-redir" "nginx_cluster_redir.conf" "${CLUSTER_MS_REDIR_PORT:-11172}"
    CMS_PORT="${ms_cms}" CMS_PATHS="/" \
        start_dedicated_nginx "cluster-ms-ds1" "nginx_cluster_ds.conf" "${CLUSTER_MS_DS1_PORT:-11173}"
    CMS_PORT="${ms_cms}" CMS_PATHS="/" \
        start_dedicated_nginx "cluster-ms-ds2" "nginx_cluster_ds.conf" "${CLUSTER_MS_DS2_PORT:-11174}"

    # Multi-worker cluster: a real nginx CMS manager (cluster-mw-mgr) accepts
    # connections from both workers in cluster-mw on CLUSTER_MW_CMS_PORT (11177).
    CMS_PORT="${CLUSTER_MW_CMS_PORT:-11177}" \
        start_dedicated_nginx "cluster-mw-mgr" "nginx_cluster_redir.conf" "${CLUSTER_MW_REDIR_PORT:-11178}"
    CMS_PORT="${CLUSTER_MW_CMS_PORT:-11177}" \
        start_dedicated_nginx "cluster-mw" "nginx_cluster_multi_worker.conf" "${CLUSTER_MW_PORT:-11176}"

    # Three-tier topology (TestThreeTierTopology)
    local t3_meta_cms="${CLUSTER_3T_META_CMS_PORT:-11186}"
    local t3_sub_cms="${CLUSTER_3T_SUB_CMS_PORT:-11188}"
    CMS_PORT="${t3_meta_cms}" \
        start_dedicated_nginx "cluster-3t-meta" "nginx_cluster_redir.conf" "${CLUSTER_3T_META_PORT:-11185}"
    CMS_PORT="${t3_sub_cms}" META_CMS_PORT="${t3_meta_cms}" \
        SELF_REGISTER_PORT="${CLUSTER_3T_SELF_PORT:-11189}" \
        start_dedicated_nginx "cluster-3t-sub" "nginx_cluster_sub_manager.conf" "${CLUSTER_3T_SUB_PORT:-11187}"
    CMS_PORT="${t3_sub_cms}" CMS_PATHS="/" \
        start_dedicated_nginx "cluster-3t-leaf" "nginx_cluster_ds.conf" "${CLUSTER_3T_LEAF_PORT:-11190}"

    # Mock-CMS-select cluster: nginx queries Python mock parent CMS on CLUSTER_SELECT_CMS_PORT.
    CMS_PORT="${CLUSTER_SELECT_CMS_PORT:-12601}" CMS_PATHS="/" \
        start_dedicated_nginx "cluster-select" "nginx_cluster_parent_lookup.conf" \
        "${CLUSTER_SELECT_PORT:-11194}"

    # Full-registry (slots) cluster: 3-slot redirector + 4 data servers → overflow test.
    local slots_cms="${CLUSTER_SLOTS_CMS_PORT:-12608}"
    CMS_PORT="${slots_cms}" \
        METRICS_PORT="${CLUSTER_SLOTS_METRICS_PORT:-11196}" \
        NGINX_METRICS_PORT="${CLUSTER_SLOTS_METRICS_PORT:-11196}" \
        start_dedicated_nginx "cluster-slots-redir" "nginx_cluster_slots_redir.conf" \
        "${CLUSTER_SLOTS_REDIR_PORT:-11195}"
    CMS_PORT="${slots_cms}" CMS_PATHS="/" \
        start_dedicated_nginx "cluster-slots-ds1" "nginx_cluster_ds.conf" "${CLUSTER_SLOTS_DS1_PORT:-12602}"
    CMS_PORT="${slots_cms}" CMS_PATHS="/" \
        start_dedicated_nginx "cluster-slots-ds2" "nginx_cluster_ds.conf" "${CLUSTER_SLOTS_DS2_PORT:-12603}"
    CMS_PORT="${slots_cms}" CMS_PATHS="/" \
        start_dedicated_nginx "cluster-slots-ds3" "nginx_cluster_ds.conf" "${CLUSTER_SLOTS_DS3_PORT:-12604}"
    CMS_PORT="${slots_cms}" CMS_PATHS="/" \
        start_dedicated_nginx "cluster-slots-ds4" "nginx_cluster_ds.conf" "${CLUSTER_SLOTS_DS4_PORT:-12605}"

    # Mock-CMS-try cluster: nginx queries Python mock parent CMS on CLUSTER_TRY_CMS_PORT.
    CMS_PORT="${CLUSTER_TRY_CMS_PORT:-12606}" CMS_PATHS="/" \
        start_dedicated_nginx "cluster-try" "nginx_cluster_parent_lookup.conf" \
        "${CLUSTER_TRY_PORT:-11197}"

    # Escalation cluster: sub→Python mock parent; leaf is a standalone DS.
    CMS_PORT="${CLUSTER_ESC_CMS_PORT:-12607}" CMS_PATHS="/" \
        start_dedicated_nginx "cluster-esc-sub" "nginx_cluster_parent_lookup.conf" \
        "${CLUSTER_ESC_SUB_PORT:-11198}"
    start_dedicated_nginx "cluster-esc-leaf" "nginx_cluster_leaf.conf" \
        "${CLUSTER_ESC_LEAF_PORT:-11199}"

    # Cache and write-through servers.
    # cache-only: read-through cache backed by the anonymous nginx origin (11094).
    # wt-sync / wt-async: write-through servers forwarding dirty writes to origin (11094).
    start_dedicated_nginx "cache-only" "nginx_cache_only.conf" \
        "${CACHE_ONLY_PORT:-11200}"
    start_dedicated_nginx "wt-sync" "nginx_wt_sync.conf" \
        "${WT_SYNC_PORT:-11201}"
    start_dedicated_nginx "wt-async" "nginx_wt_async.conf" \
        "${WT_ASYNC_PORT:-11202}"

    # kXR_prepare staging-command test pair.
    # prepare-command: xrootd_prepare_command configured to a fixed hook script
    #   that appends staged paths to a log file tests can read.
    # prepare-nocmd:   same stream server without xrootd_prepare_command.
    local prep_hook="${TEST_ROOT}/dedicated/prepare-command/stage_hook.sh"
    local prep_log="${TEST_ROOT}/data-prepare-command/staged.log"
    mkdir -p "${TEST_ROOT}/dedicated/prepare-command"
    cat > "$prep_hook" <<EOF
#!/bin/sh
printf '%s\n' "\$@" >> ${prep_log}
EOF
    chmod +x "$prep_hook"
    STAGE_CMD="${prep_hook}" \
        start_dedicated_nginx "prepare-command" "nginx_prepare_command.conf" \
        "${PREPARE_CMD_PORT:-11204}"
    start_dedicated_nginx "prepare-nocmd" "nginx_prepare_staging.conf" \
        "${PREPARE_NOCMD_PORT:-11205}"

    # Phase 2 capability-flag role servers (test_protocol_flags.py).
    start_dedicated_nginx "meta-only" "nginx_meta_only.conf" \
        "${META_ONLY_PORT:-11206}"
    start_dedicated_nginx "supervisor" "nginx_supervisor.conf" \
        "${SUPERVISOR_PORT:-11207}"
    # virtual-redir: static manager_map pointing at the anon data server; no CMS.
    start_dedicated_nginx "virtual-redir" "nginx_virtual_redir.conf" \
        "${VIRTUAL_REDIR_PORT:-11208}" "${NGINX_ANON_PORT:-11094}"
    # Phase 3: collapse-redir cache (xrootd_collapse_redir on).
    start_dedicated_nginx "collapse-redir" "nginx_collapse_redir.conf" \
        "${COLLAPSE_REDIR_PORT:-11209}" "${NGINX_ANON_PORT:-11094}"

    start_xrdhttp
}

stop_all_dedicated() {
    stop_xrdhttp
    force_stop_ref
    force_stop_nginx
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
    start-all)
        start_all_dedicated
        ;;
    stop-all)
        stop_all_dedicated
        ;;
    start-dedicated)
        # Restart a single named dedicated nginx instance without a full start-all.
        case "$TARGET" in
            cluster-ds)
                CMS_PORT="${CLUSTER_REDIR_CMS_PORT:-11161}" CMS_PATHS="/" \
                    start_dedicated_nginx "cluster-ds" "nginx_cluster_ds.conf" \
                    "${CLUSTER_DS_PORT:-11162}"
                ;;
            cluster-3t-meta)
                CMS_PORT="${CLUSTER_3T_META_CMS_PORT:-11186}" \
                    start_dedicated_nginx "cluster-3t-meta" "nginx_cluster_redir.conf" \
                    "${CLUSTER_3T_META_PORT:-11185}"
                ;;
            cluster-3t-sub)
                CMS_PORT="${CLUSTER_3T_SUB_CMS_PORT:-11188}" \
                META_CMS_PORT="${CLUSTER_3T_META_CMS_PORT:-11186}" \
                SELF_REGISTER_PORT="${CLUSTER_3T_SELF_PORT:-11189}" \
                    start_dedicated_nginx "cluster-3t-sub" "nginx_cluster_sub_manager.conf" \
                    "${CLUSTER_3T_SUB_PORT:-11187}"
                ;;
            cluster-3t-leaf)
                CMS_PORT="${CLUSTER_3T_SUB_CMS_PORT:-11188}" CMS_PATHS="/" \
                    start_dedicated_nginx "cluster-3t-leaf" "nginx_cluster_ds.conf" \
                    "${CLUSTER_3T_LEAF_PORT:-11190}"
                ;;
            *) echo "start-dedicated: unknown target '${TARGET}'" >&2; exit 1 ;;
        esac
        ;;
    start)
        case "$TARGET" in
            all) start_all_dedicated ;;
            nginx)
                if [[ "${SKIP_NGINX_FORCE_STOP_ON_START:-0}" == "1" ]]; then
                    start_nginx
                else
                    force_stop_nginx
                    start_nginx
                fi
                ;;
            ref) force_stop_ref; start_ref ;;
            xrdhttp) stop_xrdhttp; start_xrdhttp ;;
            *) usage; exit 1 ;;
        esac
        ;;
    stop)
        case "$TARGET" in
            all) stop_all_dedicated ;;
            nginx) stop_nginx ;;
            ref) stop_ref ;;
            xrdhttp) stop_xrdhttp ;;
            *) usage; exit 1 ;;
        esac
        ;;
    force-stop)
        case "$TARGET" in
            all) force_stop_ref; force_stop_nginx ;;
            nginx) force_stop_nginx ;;
            ref) force_stop_ref ;;
            xrdhttp) force_stop_xrdhttp ;;
            *) usage; exit 1 ;;
        esac
        ;;
    restart)
        case "$TARGET" in
            all) stop_all_dedicated; start_all_dedicated ;;
            nginx) stop_nginx; start_nginx ;;
            ref) stop_ref; start_ref ;;
            xrdhttp) stop_xrdhttp; start_xrdhttp ;;
            *) usage; exit 1 ;;
        esac
        ;;
    status)
        case "$TARGET" in
            all) status_nginx; status_ref ;;
            nginx) status_nginx ;;
            ref) status_ref ;;
            xrdhttp) status_xrdhttp ;;
            *) usage; exit 1 ;;
        esac
        ;;
    *)
        usage
        exit 1
        ;;
esac
