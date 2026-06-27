# tests/lib/nginx.sh - Phase-38 extraction of manage_test_servers.sh.
# Sourced (not executed) by manage_test_servers.sh; uses its global
# config vars.  Do not run directly.

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

    if [[ "${VALGRIND:-0}" == "1" ]]; then
        # Run under Memcheck, detached and in the foreground-of-its-own-session so
        # valgrind stays attached to the master+worker (forced `daemon off`).  The
        # script continues to the readiness probe below; `stop` later triggers the
        # graceful shutdown that makes each worker flush its report.
        local supp_arg=""
        [[ -f "$VALGRIND_SUPP" ]] && supp_arg="--suppressions=$VALGRIND_SUPP"
        setsid valgrind $VALGRIND_OPTS $supp_arg \
            --log-file="$VALGRIND_LOG_DIR/vg.%p.log" \
            "$NGINX_BIN" -p "$NGINX_PREFIX" -c "$NGINX_CONF_REL" -g 'daemon off;' \
            </dev/null >>"$VALGRIND_LOG_DIR/nginx.stdout" 2>&1 &
        disown
        # Memcheck boots ~20x slower; give the worker time to bind before probing.
        sleep 8
    else
        "$NGINX_BIN" -p "$NGINX_PREFIX" -c "$NGINX_CONF_REL"
    fi

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

    # Kill all dedicated-instance nginx PIDs.  start_dedicated_nginx writes each
    # instance's pid under ${TEST_ROOT}/dedicated/<name>/logs/nginx.pid, which the
    # ${LOG_DIR}/*.pid loop below does NOT cover.  Without this, migrated
    # dedicated instances (open-flags-lifecycle, webdav-dellock, s3-mpu,
    # readonly-http, ...) survive stop-all and block the next start-all with
    # EADDRINUSE.  Generic glob => covers every present and future migration.
    for pid_file in "${TEST_ROOT}"/dedicated/*/logs/nginx.pid; do
        [[ -f "$pid_file" ]] || continue
        kill_pid_list "$(cat "$pid_file" 2>/dev/null || true)"
    done

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
            pids_on_port 11116
            pids_on_port 11117
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
            # Migrated dedicated fixtures
            pids_on_port 11216
            pids_on_port 11217
            pids_on_port 12980
            pids_on_port 13210
            pids_on_port 22014
            pids_on_port 22017
            # IPv6 dedicated fixtures
            pids_on_port 11240
            pids_on_port 11241
            pids_on_port 11243
            pids_on_port 11244
            pids_on_port 11245
            pids_on_port 11246
            # HA nginx instances
            pids_on_port 11211
            pids_on_port 11212
            # Stub-backed upstream nginx (test_a_upstream_redirect.py)
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
            # CMS cluster manager instances
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

start_ha_nginx() {
    local name="$1"
    local port="$2"
    # Capture the global DATA_DIR (main shared data root) before entering the
    # subshell so both HA instances serve files written to DATA_ROOT by tests.
    local shared_data="${DATA_DIR}"

    local instance_root="${TEST_ROOT}/dedicated/${name}"
    local conf_rel="conf/nginx.conf"
    local conf_path="${instance_root}/${conf_rel}"

    mkdir -p "${instance_root}/conf" "${instance_root}/logs" "${instance_root}/tmp"
    rm -f "${instance_root}/logs"/*.log "${instance_root}/logs"/*.pid

    (
        NGINX_PREFIX="${instance_root}"
        NGINX_CONF_REL="${conf_rel}"
        NGINX_PORT="${port}"
        LOG_DIR="${instance_root}/logs"
        TMP_DIR="${instance_root}/tmp"
        DATA_DIR="${shared_data}"
        NGINX_CONF_PREGENERATED=1
        SKIP_XRDFS_CHECK=1

        substitute_config "${CONFIGS_DIR}/nginx_ha_instance.conf" "${conf_path}"
        start_nginx
    )
}

stop_haproxy() {
    local pidfile="${TEST_ROOT}/haproxy.pid"
    if [[ -f "${pidfile}" ]]; then
        local pid
        pid="$(cat "${pidfile}" 2>/dev/null || true)"
        if [[ -n "${pid}" ]]; then
            kill "${pid}" 2>/dev/null || true
            rm -f "${pidfile}"
        fi
    fi
    kill_pid_list "$(pids_on_port "${HA_HAPROXY_PORT:-11210}")"
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
