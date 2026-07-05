/*
 * directives_storage.inc — WebDAV storage/tier directives (backend, credential, composable tier grammar mirrors, cache, pblock)
 * #included into ngx_http_brix_webdav_commands[] in webdav/module.c (compiler
 * concatenates; setters/enum tables stay visible). Not a standalone TU.
 */
    { ngx_string("brix_webdav_root"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.root),
      NULL },

    /* Storage backend for this export: "posix" (default) or "pblock"
     * (block-based, rooted at brix_webdav_root; needs the sqlite build). */
    { ngx_string("brix_webdav_storage_backend"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.storage_backend),
      NULL },

    /* Names the brix_credential block (§14) the source backend authenticates with;
     * "" = anonymous. Threads a bearer into the sd_http / sd_xroot source. Shares the
     * process-wide credential registry with the stream-scope block. */
    { ngx_string("brix_webdav_storage_credential"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.storage_credential),
      NULL },

    /* ---- phase-64 composable tier grammar mirrors (§4.4) ----
     * Shared X-macro (core/config/tier_directives.h) — identical grammar to
     * root:// and S3 by construction. */
    BRIX_TIER_DIRECTIVES("brix_webdav_", ngx_http_brix_webdav_loc_conf_t,
                         NGX_HTTP_LOC_CONF, NGX_HTTP_LOC_CONF_OFFSET),

    /* The reusable `brix_credential <name> { … }` identity block (§14) at http
     * scope — declared once inside http{} and referenced by the directive above. */
    { ngx_string("brix_credential"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1,
      brix_conf_credential_block,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    /* Write-back staging for a remote (root://) backend: stage uploads to the
     * local export and promote them on commit (vs Mode A passthrough). */
    { ngx_string("brix_webdav_storage_staging"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.storage_staging),
      NULL },

    /* pblock stripe size for newly-written files (e.g. 64m); 0/unset = 64 MiB. */
    { ngx_string("brix_webdav_pblock_block_size"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.pblock_block_size),
      NULL },

    { ngx_string("brix_webdav_cache_root"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, cache_root),
      NULL },
