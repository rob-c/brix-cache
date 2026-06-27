# tests/lib/dedicated.sh - Phase-38 extraction of manage_test_servers.sh.
# Sourced (not executed) by manage_test_servers.sh; uses its global
# config vars.  Do not run directly.

start_krb5_tier() {
    # (1) binary check first — cheapest, and avoids spinning a KDC for nothing.
    if ! ldd "$NGINX_BIN" 2>/dev/null | grep -q 'libkrb5\.so'; then
        echo "  krb5 tier: skipped (nginx not built with Kerberos;" \
             "rebuild with krb5-devel present)"
        return 0
    fi
    # (2) provision the realm + keytab + krb5.conf and start the KDC.  Exit 3 =
    # KDC tooling absent (kdc_helpers already explained); any other non-zero is a
    # real provisioning failure — in every case we skip the tier, never abort.
    local kdc_helper="${CONFIGS_DIR%/configs}/kdc_helpers.py"
    python3 "$kdc_helper" up
    local rc=$?
    if [[ $rc -eq 3 ]]; then
        return 0
    fi
    if [[ $rc -ne 0 ]]; then
        echo "  krb5 tier: skipped (KDC provisioning failed, rc=$rc)" >&2
        return 0
    fi
    # The nginx krb5 acceptor needs KRB5_CONFIG (realm + auth_to_local) in its
    # process environment; principal + keytab feed substitute_config.
    KRB5_CONFIG="${TEST_ROOT}/krb5/krb5.conf" \
    KRB5_PRINCIPAL="xrootd/localhost@NGINX.TEST" \
    KRB5_KEYTAB="${TEST_ROOT}/krb5/xrootd.keytab" \
        start_dedicated_nginx "krb5" "nginx_krb5.conf" "${NGINX_KRB5_PORT:-11116}"
}

start_all_dedicated() {
    force_stop_ref
    force_stop_nginx
    regenerate_pki

    mkdir -p "${TEST_ROOT}/tokens"
    local jwks_refresh_dir="${TEST_ROOT}/tokens/jwks-refresh"
    mkdir -p "${jwks_refresh_dir}"
    python3 utils/make_token.py init "${jwks_refresh_dir}" >/dev/null
    # Generate a real signed JWT for upstream token auth (credential bridge, etc.)
    # Must be signed by the MAIN tokens key (jwks.json), not the jwks-refresh key.
    local main_tokens_dir="${TEST_ROOT}/tokens"
    # Ensure the MAIN signing key + jwks.json exist before signing tokens against
    # them.  On a fully clean tree (e.g. after brutal_teardown removes tokens/)
    # the key is absent and the `gen` calls below would crash with
    # "FileNotFoundError: .../tokens/signing_key.pem", failing start-all (exit 1)
    # and aborting the whole pytest session (INTERNALERROR).  init creates both;
    # a pre-existing key is reused so multi-session behaviour is unchanged.
    if [[ ! -f "${main_tokens_dir}/signing_key.pem" ]]; then
        python3 utils/make_token.py init "${main_tokens_dir}" >/dev/null
    fi
    python3 utils/make_token.py gen "${main_tokens_dir}" \
        --sub "nginx-bridge" \
        --scope "storage.read:/ storage.modify:/" \
        --lifetime 86400 \
        --output "${main_tokens_dir}/upstream.jwt" >/dev/null
    # WLCG token for identity-shifting tests (Chaos Mesh Step 1).
    # Placed in PKI_DIR so tests can locate it alongside certificates.
    python3 utils/make_token.py gen "${main_tokens_dir}" \
        --sub "chaos-test-user" \
        --scope "storage.read:/ storage.modify:/" \
        --lifetime 86400 \
        --output "${PKI_DIR}/wlcg_token.txt" >/dev/null

    local crl_dir="${TEST_ROOT}/crls"
    local crl_reload_dir="${TEST_ROOT}/crl-reload"
    mkdir -p "${crl_dir}" "${crl_reload_dir}"
    rm -f "${crl_dir}"/* "${crl_reload_dir}"/*
    if [[ -f "${PKI_DIR}/ca/test-user.crl.pem" ]]; then
        cp "${PKI_DIR}/ca/test-user.crl.pem" "${crl_dir}/ca.r0"
    fi

    # Kick the CMS mesh off in the BACKGROUND now and barrier on it at the very
    # end of start-all.  The mesh is a self-contained set of cmsd/xrootd/nginx
    # topologies (no dependency on the rest of the fleet) whose readiness gate is
    # ~20 s of CMS cluster convergence — the single largest serial cost in
    # start-all.  Running it concurrently with the ~17 s of fleet startup overlaps
    # the two, so total wall time is max(mesh, fleet) instead of their sum.  It
    # only needs the PKI + tokens generated above, so this is the earliest safe
    # launch point.
    start_cms_mesh &
    local cms_mesh_pid=$!

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

    # --- Migrated dedicated instances (formerly self-provisioned by the test) ---
    # Each replaces a test fixture that used to spawn+teardown its own nginx; the
    # consuming test now just connects + skips if unreachable. Data root is
    # ${TEST_ROOT}/data-<name> (served by start_dedicated_nginx).
    start_dedicated_nginx "open-flags-lifecycle" "nginx_open_flags_lifecycle.conf" "${OPEN_FLAGS_LIFECYCLE_NGINX_PORT:-12980}"
    start_dedicated_nginx "webdav-dellock" "nginx_webdav-dellock.conf" "${WEBDAV_DELLOCK_PORT:-13210}"
    start_dedicated_nginx "webdav-unlock-ownership" "nginx_webdav-unlock-ownership.conf" "${WEBDAV_UNLOCK_OWNERSHIP_PORT:-22014}"
    start_dedicated_nginx "s3-mpu" "nginx_s3-mpu.conf" "${S3_MPU_PORT:-22017}"
    NGINX_S3_PORT="${READONLY_HTTP_S3_PORT:-11217}" start_dedicated_nginx "readonly-http" "nginx_readonly-http.conf" "${READONLY_HTTP_DAV_PORT:-11216}"
    start_dedicated_nginx "xrdhttp-digest" "nginx_xrdhttp_digest.conf" "${XRDHTTP_DIGEST_PORT:-12988}"

    # --- Phase 36: IPv6 dedicated instances (all listen on [::1]) ---
    # Consumed by tests/test_ipv6_*.py; each gates on requires_ipv6_loopback and
    # skips if its instance is down. Secondary ports (CMS/HTTP/upstream) are
    # hardcoded in each config since they are fixed per dedicated instance.
    start_dedicated_nginx "ipv6-stream" "nginx_ipv6_stream.conf" "${IPV6_STREAM_PORT:-11240}"
    start_dedicated_nginx "ipv6-mgr" "nginx_ipv6_mgr.conf" "${IPV6_MGR_PORT:-11241}"
    start_dedicated_nginx "ipv6-webdav" "nginx_ipv6_webdav.conf" "${IPV6_WEBDAV_PORT:-11243}"
    start_dedicated_nginx "ipv6-s3" "nginx_ipv6_s3.conf" "${IPV6_S3_PORT:-11244}"
    start_dedicated_nginx "ipv6-upstream" "nginx_ipv6_upstream.conf" "${IPV6_UPSTREAM_PORT:-11245}"
    start_dedicated_nginx "ipv6-proxy" "nginx_ipv6_proxy.conf" "${IPV6_PROXY_PORT:-11246}"
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

    # Pre-start protocol stub backends for test_a_upstream_redirect.py.
    # upstream_protocol_stubs.py binds 13121/13122/13124/13125/13126 and
    # handles XRootD protocol sequences (wait→redirect, waitresp→redirect,
    # authmore challenge, authmore+close, gotoTLS) that real xrootd never emits.
    python3 "${TESTS_DIR}/upstream_protocol_stubs.py" \
        >> "${LOG_DIR}/upstream-stubs.log" 2>&1 &
    echo $! > "${LOG_DIR}/upstream-stubs.pid"
    sleep 0.3

    # Stub-backed upstream nginx instances (test_a_upstream_redirect.py).
    # Each proxies to one port of upstream_protocol_stubs.py, which emits
    # sequences (kXR_wait, kXR_waitresp, kXR_authmore, kXR_gotoTLS) that
    # real xrootd never produces, enabling deterministic protocol edge tests.
    UPSTREAM_PORT="${STUB_REDIRECT_BACKEND_PORT:-13120}" \
        start_dedicated_nginx "stub-upstream-redirect" "nginx_upstream_redirect.conf" \
        "${STUB_REDIRECT_NGINX_PORT:-11130}"
    UPSTREAM_PORT="${STUB_WAIT_BACKEND_PORT:-13121}" \
        start_dedicated_nginx "stub-upstream-wait" "nginx_upstream_wait.conf" \
        "${STUB_WAIT_NGINX_PORT:-11131}"
    UPSTREAM_PORT="${STUB_WAITRESP_BACKEND_PORT:-13122}" \
        start_dedicated_nginx "stub-upstream-waitresp" "nginx_upstream_waitresp.conf" \
        "${STUB_WAITRESP_NGINX_PORT:-11132}"
    UPSTREAM_PORT="${STUB_ERROR_BACKEND_PORT:-13123}" \
        start_dedicated_nginx "stub-upstream-error" "nginx_upstream_error.conf" \
        "${STUB_ERROR_NGINX_PORT:-11133}"
    UPSTREAM_PORT="${STUB_AUTH_BACKEND_PORT:-13124}" \
        start_dedicated_nginx "stub-upstream-auth" "nginx_stub_upstream_auth.conf" \
        "${STUB_AUTH_NGINX_PORT:-11134}"
    UPSTREAM_PORT="${STUB_AUTH_NOFILE_BACKEND_PORT:-13125}" \
        start_dedicated_nginx "stub-upstream-auth-nofile" "nginx_upstream_auth_nofile.conf" \
        "${STUB_AUTH_NOFILE_NGINX_PORT:-11135}"
    UPSTREAM_PORT="${STUB_GOTORLS_BACKEND_PORT:-13126}" \
        start_dedicated_nginx "stub-upstream-gotorls" "nginx_upstream_gotorls_notls.conf" \
        "${STUB_GOTORLS_NGINX_PORT:-11136}"

    # Real-upstream-redirect: nginx at REAL_REDIRECT_NGINX_PORT proxies to the
    # cluster-redir to verify kXR_redirect forwarding against a real XRootD
    # redirector, complementing the stub-backed instances above.
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

    # Chaos Mesh discovery cluster: separate redirector + DS for delayed-CMS tests.
    # Start the DATA SERVER first, while its CMS manager (the redirector) is still
    # DOWN, so the DS logs a failed CMS login and then registers successfully once
    # the redirector comes up.  That is the exact delayed-start sequence asserted by
    # test_chaos_mesh::test_delayed_cms_start_registers_data_server; starting the
    # redirector first let the DS connect immediately, so the "failed then
    # successful" evidence never appeared.
    local chaos_cms_port="${CHAOS_DISCOVERY_CMS_PORT:-11167}"
    CMS_PORT="${chaos_cms_port}" CMS_PATHS="/chaos-discovery" \
        start_dedicated_nginx "chaos-discovery-ds" "nginx_cluster_ds.conf" "${CHAOS_DISCOVERY_DS_PORT:-11168}"
    # Give the DS time to fire (and FAIL) at least one CMS login while its manager
    # is still down — this is the failure window the delayed-start test looks for.
    # With the CMS fast-settle path the DS fires its first connect within ~tens of
    # ms of startup (loopback refusal is instant), so 1 s is ample margin to land
    # the "connect refused" evidence before the redirector comes up.
    sleep 1
    CMS_PORT="${chaos_cms_port}" \
        start_dedicated_nginx "chaos-discovery-redir" "nginx_cluster_redir.conf" "${CHAOS_DISCOVERY_REDIR_PORT:-11166}"

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
    start_krb5_tier

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

    # Pre-start CMS parent stub backends for cluster-select/try/esc tests.
    # cms_parent_stubs.py binds 12601/12606/12607 and serves kYR_select and
    # kYR_try responses so the nginx CMS clients find a live parent at startup.
    python3 "${TESTS_DIR}/cms_parent_stubs.py" \
        >> "${LOG_DIR}/cms-parent-stubs.log" 2>&1 &
    echo $! > "${LOG_DIR}/cms-parent-stubs.pid"
    sleep 0.3

    # CMS-select cluster: nginx queries the pre-started CMS parent stub.
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

    # CMS-try cluster: nginx queries the pre-started CMS parent stub.
    CMS_PORT="${CLUSTER_TRY_CMS_PORT:-12606}" CMS_PATHS="/" \
        start_dedicated_nginx "cluster-try" "nginx_cluster_parent_lookup.conf" \
        "${CLUSTER_TRY_PORT:-11197}"

    # Escalation cluster: sub connects to the pre-started CMS parent stub.
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
# Log XROOTD_PREPARE_COLOC env var if set (for test verification).
if [ -n "\$XROOTD_PREPARE_COLOC" ]; then
    printf 'COLOC=%s\n' "\$XROOTD_PREPARE_COLOC" >> ${prep_log}
fi
printf '%s\n' "\$@" >> ${prep_log}
EOF
    chmod +x "$prep_hook"
    STAGE_CMD="${prep_hook}" \
        start_dedicated_nginx "prepare-command" "nginx_prepare_command.conf" \
        "${PREPARE_CMD_PORT:-11204}"
    start_dedicated_nginx "prepare-nocmd" "nginx_prepare_staging.conf" \
        "${PREPARE_NOCMD_PORT:-11205}"

    # HA Cluster: two nginx instances and haproxy.
    # Note: Requires haproxy binary on PATH.
    if have_cmd haproxy; then
        start_ha_nginx "ha-nginx1" "${HA_NGINX1_PORT:-11211}"
        start_ha_nginx "ha-nginx2" "${HA_NGINX2_PORT:-11212}"
        # Process haproxy config template and start haproxy in the background.
        sed \
            -e "s|{PORT}|${HA_HAPROXY_PORT:-11210}|g" \
            -e "s|{BIND_HOST}|127.0.0.1|g" \
            -e "s|{MAP_A_HOST}|127.0.0.1|g" \
            -e "s|{MAP_A_PORT}|${HA_NGINX1_PORT:-11211}|g" \
            -e "s|{MAP_B_HOST}|127.0.0.1|g" \
            -e "s|{MAP_B_PORT}|${HA_NGINX2_PORT:-11212}|g" \
            "${CONFIGS_DIR}/haproxy.cfg" > "${TEST_ROOT}/haproxy.cfg"
        haproxy -f "${TEST_ROOT}/haproxy.cfg" -D -p "${TEST_ROOT}/haproxy.pid"
    fi
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

    # Barrier: do not report start-all complete until the backgrounded CMS mesh
    # (launched right after PKI/token setup) has finished converging — tests
    # depend on it being ready.
    wait "$cms_mesh_pid" 2>/dev/null || true

    start_xrdhttp
}

start_cms_mesh() {
    TEST_NGINX_BIN="${NGINX_BIN}" CMS_MESH_DIR="${TEST_ROOT}/cms-mesh" \
        python3 "${TESTS_DIR}/cms_mesh_servers.py" start \
        >> "${LOG_DIR}/cms-mesh.log" 2>&1 || true
}

stop_cms_mesh() {
    TEST_NGINX_BIN="${NGINX_BIN}" CMS_MESH_DIR="${TEST_ROOT}/cms-mesh" \
        python3 "${TESTS_DIR}/cms_mesh_servers.py" stop \
        >> "${LOG_DIR}/cms-mesh.log" 2>&1 || true
}

stop_krb5_tier() {
    # Stop the test KDC (best-effort) before the session-wide TEST_ROOT wipe so
    # the krb5kdc daemon is never orphaned.  No-op if the tier was never started.
    local kdc_helper="${CONFIGS_DIR%/configs}/kdc_helpers.py"
    if [[ -f "$kdc_helper" ]]; then
        python3 "$kdc_helper" down >/dev/null 2>&1 || true
    fi
}

stop_all_dedicated() {
    stop_cms_mesh
    stop_haproxy
    stop_xrdhttp
    stop_krb5_tier
    force_stop_ref
    force_stop_nginx
}
