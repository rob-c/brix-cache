/*
 * directives_security.inc — wire security + codec directives (signing level, in-protocol TLS, kernel-TLS, root:// read/write compression, ZIP member access)
 * #included into ngx_stream_brix_commands[] in module.c (compiler concatenates;
 * setters/enum tables from module_enums.h stay visible). Not a standalone TU.
 */
    /* Minimum signing level: none, compatible, standard, intense, pedantic. */
    { ngx_string("brix_security_level"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, security_level),
      brix_security_levels },

    /* D-1: session-posture floor (protocol-downgrade protection) — none|compat|
     * intense (default none). Distinct axis from brix_security_level (signing):
     * compat refuses a cleartext session post-handshake, intense also refuses an
     * anonymous (auth=none) identity. Enforced in brix_min_sec_enforce. */
    { ngx_string("brix_min_sec_level"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, min_sec_level),
      brix_min_sec_levels },

    /* D-2: opt-in opaque (CGI) schema enforcement — off (default) leaves only
     * the always-on byte-hygiene gate; on additionally type-checks oss.asize as
     * an unsigned integer and rejects any opaque key outside the recognized
     * namespace vocabulary, before any handler parses it. Stock accepts both
     * unchecked, so this is a deliberate posture opt-in (never a parity change).
     * Enforced in brix_open_precheck (read/open_request.c). */
    { ngx_string("brix_opaque_strict"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, opaque_strict),
      NULL },

    /* D-3: per-worker seccomp-BPF syscall filter — off|audit|enforce (default
     * off). Process-global: the strictest value across enabled server blocks is
     * installed once per worker at init_process. audit converges the allowlist
     * risk-free; enforce kills execve/ptrace/process_vm_* and EPERMs the rest. */
    { ngx_string("brix_seccomp"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_seccomp,          /* also bumps the process-global strictest */
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, seccomp),
      &brix_seccomp_modes },

    /* Opt out of the enforce execve/execveat KILL (default off) for sites that
     * legitimately fork+exec helpers (OIDC token fetch, native-TPC token-exchange,
     * kXR_prepare). ptrace/process_vm_* stay killed. Process-global (ratchets on). */
    { ngx_string("brix_seccomp_allow_exec"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_seccomp_allow_exec,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Confined account a root-capable worker is force-dropped to at init (default
     * "nobody" + a warning) so pre-auth credential parsing never runs as a
     * root-capable identity. Process-global; applies to every brix server. */
    { ngx_string("brix_worker_user"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_worker_user,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* E-4: negative-path backoff — throttle a per-principal stat/locate-harvest
     * loop. "off" (default) or "<threshold> <window_seconds> <wait_seconds>":
     * once one principal (token subject / GSI DN / client IP) produces more than
     * <threshold> kXR_NotFound outcomes within <window_seconds>, further misses
     * are answered with kXR_wait(<wait_seconds>) instead of NotFound. */
    { ngx_string("brix_negcache_backoff"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1 | NGX_CONF_TAKE3,
      brix_negcache_set,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, negcache),
      NULL },

    /* Enable kXR_ableTLS in-protocol TLS upgrade using brix_certificate/key. */
    { ngx_string("brix_tls"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tls),
      NULL },

    /* Enable kernel-TLS (SSL_OP_ENABLE_KTLS) so TLS reads can use sendfile.
     * Default ON (unified across root://, WebDAV, S3); transparent no-op when the
     * negotiated cipher/kernel cannot offload. Software kTLS can be slower than
     * userspace OpenSSL on AES-NI CPUs without a HW-offload NIC — set off there. */
    { ngx_string("brix_ktls"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, tls_ktls),
      NULL },

    /* Enable root:// inline read compression (phase-42 W4). Opt-in, off by
     * default and invisible to stock peers: advertises codecs via Qconfig
     * "cmpread" and compresses kXR_read responses for clients that open with
     * "?xrootd.compress=<codec>".  pgread/readv remain plaintext. */
    { ngx_string("brix_read_compress"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, read_compress),
      NULL },

    /* Enable root:// inline write decompression (phase-42 W5). Opt-in, off by
     * default and invisible to stock peers: advertises codecs via Qconfig
     * "cmpwrite" and decompresses kXR_write payloads for clients that open for
     * write with "?xrootd.compress=<codec>".  pgwrite remains plaintext. */
    { ngx_string("brix_write_compress"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, write_compress),
      NULL },

    /* Enable ZIP member access (phase-57 W2). Opt-in, off by default: a read
     * open with "?xrdcl.unzip=<member>" serves that member of the archive as a
     * standalone read-only file. */
    { ngx_string("brix_zip_access"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, zip_access),
      NULL },

    /* Cap the ZIP central-directory read (bomb guard); default 16 MiB. */
    { ngx_string("brix_zip_cd_max_bytes"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, zip_cd_max_bytes),
      NULL },

    /* Materialize-to-scratch for ZIP member access (a no-kernel-fd backend, or a
     * test): copy the archive into this local POSIX scratch dir and read there. */
    { ngx_string("brix_zip_stage_dir"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, zip_stage_dir),
      NULL },

    /* Force the archive through scratch even on a POSIX export (tests / policy). */
    { ngx_string("brix_zip_force_scratch"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, zip_force_scratch),
      NULL },

    /* Decline staging archives larger than this (default 512 MiB). */
    { ngx_string("brix_zip_stage_max_bytes"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, zip_stage_max_bytes),
      NULL },
