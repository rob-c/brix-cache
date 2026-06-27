# tests/lib/refxrootd.sh - Phase-38 extraction of manage_test_servers.sh.
# Sourced (not executed) by manage_test_servers.sh; uses its global
# config vars.  Do not run directly.

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
            pids_on_port 12501
            pids_on_port 11214
            # Protocol stub backends (upstream_protocol_stubs.py)
            pids_on_port 13120
            pids_on_port 13121
            pids_on_port 13122
            pids_on_port 13123
            pids_on_port 13124
            pids_on_port 13125
            pids_on_port 13126
            # CMS parent stub backends (cms_parent_stubs.py)
            pids_on_port 12601
            pids_on_port 12606
            pids_on_port 12607
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
