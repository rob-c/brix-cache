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
