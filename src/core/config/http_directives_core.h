/*
 * http_directives_core.h — core runtime, backend-credential/delegation and access-policy
 * directive entries for the unified HTTP plane.  #included into the
 * brix_http_common_commands[] array in http_common.c so the family is
 * reviewable as one focused file instead of buried in a 770-line table
 * (same idiom as src/protocols/root/stream/directives_*.h).  Not a
 * standalone TU: textual array-member fragments that rely on the setters
 * and enum tables visible in http_common.c.
 */
#pragma once
    { ngx_string("brix_export"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.root),
      NULL },

    { ngx_string("brix_storage_backend"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_backend),
      NULL },

    /* Per-worker seccomp-BPF syscall filter for HTTP (WebDAV/S3/cvmfs) servers —
     * off|audit|enforce.  Process-global: the strictest value across ALL brix
     * servers (stream + http) is installed once per worker, so HTTP-only workers
     * are filtered too (not just stream/root:// workers). */
    { ngx_string("brix_seccomp"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      brix_conf_set_seccomp,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.seccomp),
      &brix_seccomp_modes },

    /* Opt out of the enforce execve/execveat KILL (default off) for WebDAV
     * HTTP-TPC OIDC delegation and similar fork+exec helpers.  ptrace/process_vm_*
     * stay killed.  Process-global (strictest across stream+http; ratchets on). */
    { ngx_string("brix_seccomp_allow_exec"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      brix_conf_set_seccomp_allow_exec,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* Confined account a root-capable worker is force-dropped to at init (default
     * "nobody" + a warning). Process-global; covers HTTP-only (WebDAV/S3) workers
     * too. See brix_imp_worker_deescalate. */
    { ngx_string("brix_worker_user"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      brix_conf_set_worker_user,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_storage_credential"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_credential),
      NULL },

    { ngx_string("brix_storage_credential_dir"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_credential_dir),
      NULL },

    { ngx_string("brix_storage_credential_fallback"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_credential_fallback),
      &brix_http_ucred_fallback_enum },

    { ngx_string("brix_storage_credential_mint_ca"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE2,
      brix_conf_set_mint_ca,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_storage_credential_mint_ttl"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_credential_mint_ttl),
      NULL },

    { ngx_string("brix_backend_delegation"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_delegation),
      &brix_backend_delegation_enum },

    { ngx_string("brix_backend_token_audience_ok"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_1MORE,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_token_aud),
      NULL },

    { ngx_string("brix_backend_token_exchange_endpoint"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      brix_conf_set_backend_tx_endpoint,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_tx_endpoint),
      NULL },

    { ngx_string("brix_backend_token_exchange_client_id"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_tx_client_id),
      NULL },

    { ngx_string("brix_backend_token_exchange_client_secret"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_tx_client_secret),
      NULL },

    { ngx_string("brix_backend_s3_sts_endpoint"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      brix_conf_set_backend_sts_endpoint,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_endpoint),
      NULL },

    { ngx_string("brix_backend_s3_sts_role"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_role),
      NULL },

    { ngx_string("brix_backend_s3_sts_access_key"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_access_key),
      NULL },

    { ngx_string("brix_backend_s3_sts_secret_key"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_secret_key),
      NULL },

    { ngx_string("brix_backend_s3_sts_region"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_region),
      NULL },

    { ngx_string("brix_backend_s3_sts_ttl"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_ttl),
      NULL },

    { ngx_string("brix_backend_s3_sts_flavor"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_flavor),
      &brix_sts_flavor_enum },

    { ngx_string("brix_backend_krb5_forwardable"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_krb5_forwardable),
      NULL },

    { ngx_string("brix_backend_passthrough_persist"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_passthrough_persist),
      NULL },

    /* Phase-70 §5.6 / P90-70.3: SSS identity-injection keytab — the delegation
     * gate re-issues an SSS credential asserting the CALLER's principal to the
     * origin, signed with this keytab (never the keytab's own principal).
     * Load-validated at config time by the setter. */
    { ngx_string("brix_backend_sss_keytab"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      brix_conf_set_backend_sss_keytab,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sss_keytab),
      NULL },

    { ngx_string("brix_allow_write"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.allow_write),
      NULL },

    /* Read-back CRC verify for whole-object PUT (WebDAV/S3) routed through
     * brix_vfs_writer; off by default. Never applies to ranged/partial PUT. */
    { ngx_string("brix_verify_write"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.verify_write),
      NULL },

    { ngx_string("brix_read_only"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.read_only),
      NULL },

    { ngx_string("brix_compress"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.compress),
      NULL },

    /* E-1: refuse valid-but-dangerous configs at nginx -t rather than only
     * warning (anonymous S3, unauthenticated WebDAV writes, anonymous
     * dashboard). Off by default; see brix_shared_security_gate. */
    { ngx_string("brix_strict_security"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.strict_security),
      NULL },

    /* Per-capability TLS gating (stock xrootd.tls parity): ops exercising a
     * listed capability are refused with 403 on cleartext transports. */
    { ngx_string("brix_tls_require"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_1MORE,
      brix_conf_set_tls_require,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.tls_require),
      NULL },

    { ngx_string("brix_access_log"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.access_log),
      NULL },

    { ngx_string("brix_session_log"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.session_log),
      NULL },

    { ngx_string("brix_thread_pool"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.thread_pool_name),
      NULL },

    { ngx_string("brix_cache_peers"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_1MORE,
      brix_conf_set_peers,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_cache_verify"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.cache_verify_mode),
      &brix_http_cache_verify_enum },

    /* kTLS + trusted cache-store endpoint (phase-101 W2): both were hand-rolled
     * dual-conf-poking setters registered on webdav that wrote BOTH the webdav
     * and s3 loc-confs (and silently excluded cvmfs).  Registered once here for
     * the whole HTTP plane on the standard flag slot instead — the fields already
     * live in the shared preamble, and brix_shared_adopt_unified() below carries
     * them into every protocol conf (cvmfs now included). */
    { ngx_string("brix_ktls"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.ktls), NULL },
    { ngx_string("brix_cache_store_endpoint"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.cache_store_endpoint), NULL },
    /* Legacy read-through cache root (phase-101 W8): was the byte-parallel twins
     * brix_webdav_cache_root / brix_s3_cache_root; one bare name now covers both
     * HTTP protocols. Each protocol canonicalizes common.cache_root into
     * common.cache_root_canon at merge (after adopt). */
    { ngx_string("brix_cache_root"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.cache_root), NULL },
