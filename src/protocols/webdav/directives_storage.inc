/*
 * directives_storage.inc — WebDAV storage/tier directives (backend, credential, composable tier grammar mirrors, cache, pblock)
 * #included into ngx_http_brix_webdav_commands[] in webdav/module.c (compiler
 * concatenates; setters/enum tables stay visible). Not a standalone TU.
 */
    /* Export root, storage backend/credential and the composable tier grammar
     * (brix_export, brix_storage_backend, brix_storage_credential, brix_cache_*,
     * brix_stage*) are owned by the shared ngx_http_brix_common_module — this
     * protocol adopts them via brix_http_common_adopt(). */

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
