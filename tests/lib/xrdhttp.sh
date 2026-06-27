# tests/lib/xrdhttp.sh - Phase-38 extraction of manage_test_servers.sh.
# Sourced (not executed) by manage_test_servers.sh; uses its global
# config vars.  Do not run directly.

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
# The whole test fleet runs on loopback (127.0.0.1 / localhost), so XrdHttpTPC's
# default SSRF guard ("connection to local/private addresses is forbidden")
# rejects every interop pull with HTTP 403.  The guard has two independent flags
# (allow_local for loopback/127.0.0.1, allow_private for RFC1918) and a 127.0.0.1
# source trips the LOCAL check — so permit BOTH for this local reference instance
# so the nginx<->XrdHttp TPC interop tests work.
tpc.allow local
tpc.allow private
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
