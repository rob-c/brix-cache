# tests/lib/refxrootd.sh - Phase-38 extraction of manage_test_servers.sh.
# Sourced (not executed) by manage_test_servers.sh; uses its global
# config vars.  Do not run directly.

# --- run-as-nobody shim (root harness only) ---------------------------------
# xrootd refuses to run as the superuser ("Security reasons prohibit running as
# superuser; program is terminating"). When this harness is executed as root
# (e.g. an EL9 test box with the repo under /root), drop each reference xrootd to
# an unprivileged user via -R, and open the paths that user must then touch: its
# admin/pid dirs (chown to the user), the exported data root (a+rwX, shared with
# the root-owned nginx fleet), and the test PKI it reads for GSI (a+rX + readable
# key/cert). Non-root runs are unchanged (empty user -> original launch).
# DROP this shim once the harness always runs unprivileged (see TESTING.md §0).
# NOTE: must always return 0 — callers assign `u="$(_ref_runas_user)"` under
# `set -e`, so a bare `[ root ] && echo` (exit 1 when unprivileged) would abort
# the whole start-all on any non-root box.
_ref_runas_user() { if [ "$(id -u)" = "0" ]; then echo "${REF_RUNAS_USER:-nobody}"; fi; }

_ref_launch() {  # _ref_launch <cfg> <log>
    local cfg="$1" log="$2" u; u="$(_ref_runas_user)"
    if [ -z "$u" ]; then
        "$REF_BIN" -c "$cfg" -l "$log" -b >/dev/null 2>&1
        return $?
    fi
    local adm run root
    adm="$(sed -nE 's/^all\.adminpath[[:space:]]+([^[:space:]]+).*/\1/p' "$cfg" | head -1)"
    run="$(sed -nE 's/^all\.pidpath[[:space:]]+([^[:space:]]+).*/\1/p' "$cfg" | head -1)"
    root="$(sed -nE 's/^oss\.localroot[[:space:]]+([^[:space:]]+).*/\1/p' "$cfg" | head -1)"
    [ -n "$adm" ]  && { mkdir -p "$adm";  chown -R "$u" "$adm"  2>/dev/null; }
    [ -n "$run" ]  && { mkdir -p "$run";  chown -R "$u" "$run"  2>/dev/null; }
    [ -n "$root" ] && chmod -R a+rwX "$root" 2>/dev/null
    # xrootd (as $u) must write its own log AND a sibling ".lock" file in the log
    # directory (root-owned by default) — so open the log dir, not just the file.
    local logdir; logdir="$(dirname "$log")"
    mkdir -p "$logdir" 2>/dev/null
    chmod a+rwx "$logdir" 2>/dev/null
    : > "$log" 2>/dev/null; chown "$u" "$log" 2>/dev/null
    if [ -d "${PKI_DIR:-/nonexistent}" ]; then
        chmod a+rX "$PKI_DIR" "$PKI_DIR"/ca "$PKI_DIR"/server 2>/dev/null
        # The public cert + CA chain may be world-readable.
        chmod a+r  "$PKI_DIR"/server/hostcert.pem 2>/dev/null
        chmod a+r  "$PKI_DIR"/ca/*.pem 2>/dev/null
        # The PRIVATE hostkey must NOT be group/world-readable: XrdHttp refuses a
        # key with "excessive access rights" and fails HTTPS init. Give the -R
        # user exclusive read (own + 0400) so xrootd-as-$u can read it while the
        # root-owned nginx fleet still can (root ignores mode bits).
        chown "$u" "$PKI_DIR"/server/hostkey.pem 2>/dev/null
        chmod 0400 "$PKI_DIR"/server/hostkey.pem 2>/dev/null
    fi
    "$REF_BIN" -c "$cfg" -l "$log" -R "$u" -b >/dev/null 2>&1
}

write_ref_cfg() {
    mkdir -p "${REF_DIR}/admin-conf" "${REF_DIR}/run-conf"
    render_cfg "${CONFIGS_DIR}/xrootd_ref.conf" "$REF_CFG" \
        PORT="${REF_PORT}" \
        DATA_DIR="${DATA_DIR}" \
        ADMIN_DIR="${REF_DIR}/admin-conf" \
        RUN_DIR="${REF_DIR}/run-conf"
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

    render_cfg "${CONFIGS_DIR}/xrootd_ref_gsi.conf" "$cfg" \
        PORT="${port}" \
        DATA_DIR="${data_dir}" \
        ADMIN_DIR="${admin_dir}" \
        RUN_DIR="${run_dir}" \
        SECLIB="${sec_lib}" \
        CA_DIR="${PKI_DIR}/ca" \
        SERVER_CERT="${PKI_DIR}/server/hostcert.pem" \
        SERVER_KEY="${PKI_DIR}/server/hostkey.pem"
}

write_anon_ref_cfg() {
    local cfg="$1"
    local port="$2"
    local data_dir="$3"
    local admin_dir="$4"
    local run_dir="$5"

    render_cfg "${CONFIGS_DIR}/xrootd_ref.conf" "$cfg" \
        PORT="${port}" \
        DATA_DIR="${data_dir}" \
        ADMIN_DIR="${admin_dir}" \
        RUN_DIR="${run_dir}"
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

    _ref_launch "$cfg" "$log" || true

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

    _ref_launch "$cfg" "$log" || true

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
    render_cfg "${CONFIGS_DIR}/xrootd_root_tpc.conf" "$cfg" \
        DATA_DIR="${data_dir}" \
        ADMIN_DIR="${admin_dir}" \
        RUN_DIR="${run_dir}" \
        PORT="${port}" \
        XRDCP_BIN="${xrdcp_bin}"

    _ref_launch "$cfg" "$log" || true

    if [[ -n "${SKIP_XRDFS_CHECK:-}" ]]; then
        echo "reference xrootd ${label} started on $port"
    elif wait_ready_xrdfs "root://localhost:$port"; then
        echo "reference xrootd ${label} started and ready on $port"
    else
        echo "WARNING: reference xrootd ${label} started but readiness probe failed on $port" >&2
    fi
}

start_pss_bridge_ref() {
    local port="${1:-${PROXY_BRIDGE_BRIX_PORT:-11214}}"
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
    render_cfg "${CONFIGS_DIR}/xrootd_pss_bridge.conf" "$cfg" \
        DATA_DIR="${data_dir}" \
        ADMIN_DIR="${admin_dir}" \
        RUN_DIR="${run_dir}" \
        PORT="${port}" \
        ORIGIN="localhost:${upstream_port}"

    # pss (XrdPss) forwards via XrdCl, whose client pool spawns many
    # threads under load independent of xrd.sched. Cap it: 1 event loop +
    # 1 worker thread. Combined with xrd.sched maxt 4 above, this keeps the
    # proxy bridge to a small fixed thread count (code-path testing, not perf).
    XRD_PARALLELEVTLOOP=1 XRD_WORKERTHREADS=1 \
    _ref_launch "$cfg" "$log" || true

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

    _ref_launch "$REF_CFG" "$REF_LOG"

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
    local ref_gsi_port="${REF_BRIX_GSI_PORT:-11099}"
    local ref_shared_port="${REF_BRIX_GSI_SHARED_PORT:-11100}"
    local ref_gsi_data_dir="${REF_BRIX_GSI_DATA_DIR:-${TEST_ROOT}/data-gsi-bridge}"

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
