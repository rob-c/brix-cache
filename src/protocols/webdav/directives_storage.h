/*
 * directives_storage.h — WebDAV storage/tier directives (backend, credential, composable tier grammar mirrors, cache, pblock)
 * #included into ngx_http_brix_webdav_commands[] in webdav/module.c (compiler
 * concatenates; setters/enum tables stay visible). Not a standalone TU.
 */
#pragma once
    /* Export root, storage backend/credential and the composable tier grammar
     * (brix_export, brix_storage_backend, brix_storage_credential, brix_cache_*,
     * brix_stage*) are owned by the shared ngx_http_brix_common_module — this
     * protocol adopts them via brix_http_common_adopt(). */

    /* The `brix_credential` block -> http_common (phase-105 W2): declared
     * once beside brix_storage_credential, its referent; the setter
     * (brix_conf_credential_block, a global-registry fill) moved unchanged. */

    /* Write-back staging for a remote (root://) backend: stage uploads to the
     * local export and promote them on commit (vs Mode A passthrough). */
    { ngx_string("brix_webdav_storage_staging"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.storage_staging),
      NULL },

    /* brix_pblock_block_size moved to http_common.c (phase-101 W4) — the field
     * was already in the shared preamble; only the registration moves. */

    /* brix_webdav_cache_root -> bare brix_cache_root on the common module
     * (phase-101 W8); the field now lives in common.cache_root. */
