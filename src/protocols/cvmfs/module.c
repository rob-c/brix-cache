/*
 * module.c — nginx directive table, config lifecycle, and HTTP module context
 * for the dedicated cvmfs:// protocol plane.
 *
 * WHAT: Three responsibilities, mirroring src/protocols/s3/module.c:
 *   1. Config lifecycle (create_loc_conf / merge_loc_conf): allocates
 *      ngx_http_xrootd_cvmfs_loc_conf_t (shared preamble + cvmfs knobs),
 *      merges main→srv→loc, and when enable=1 anchors the export root,
 *      registers the composable storage backend + cache/stage tiers.
 *   2. Handler install (ngx_http_xrootd_cvmfs_set): the "xrootd_cvmfs"
 *      directive parses its flag and installs ngx_http_xrootd_cvmfs_handler
 *      as the location's content handler — the location IS the protocol
 *      endpoint; no WebDAV dispatch is involved.
 *   3. Directive table: the xrootd_cvmfs_* family, including the two
 *      per-protocol tier directives over the shared preamble.
 *
 * WHY: cvmfs:// is a first-class protocol. A CVMFS site cache is read-only
 *      by construction (allow_write is forced off) and typically a PURE cache
 *      node: no local export tree. When no root is configured the root
 *      anchors at "/" (the same pure-cache-node semantics the stream plane
 *      uses): the location serves the "/" namespace, filling from the http
 *      origin backend into the cache store.
 *
 * HOW: create/merge follow the s3 module's manual common.* init/merge idiom
 *      (established phase-64 gotcha: no shared_init). Postconfiguration
 *      resolves the thread pool per server exactly as s3 does — the cache
 *      fill/offload helpers need it.
 */

#include "cvmfs.h"
#include "core/config/root_prepare.h"
#include "core/config/http_rootfd.h"
#include "core/compat/alloc_guard.h"
#include "fs/vfs/vfs_backend_registry.h"

static ngx_int_t ngx_http_xrootd_cvmfs_postconfiguration(ngx_conf_t *cf);

/*
 * Config lifecycle
 */

static void *
ngx_http_xrootd_cvmfs_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_xrootd_cvmfs_loc_conf_t *c;

    XROOTD_PCALLOC_OR_RETURN(c, cf->pool, sizeof(*c), NULL);

    c->common.enable      = NGX_CONF_UNSET;
    c->common.allow_write = NGX_CONF_UNSET;
    c->common.read_only   = NGX_CONF_UNSET;
    c->common.compress    = NGX_CONF_UNSET;
    xrootd_pmark_conf_init(&c->common.pmark);
    /* phase-64 tier grammar scalars (str/array fields stay zeroed by pcalloc) */
    c->common.stage_enable      = NGX_CONF_UNSET;
    c->common.stage_flush_async = NGX_CONF_UNSET_UINT;
    c->common.cache_max_object  = NGX_CONF_UNSET;
    c->common.cache_evict_at    = NGX_CONF_UNSET_UINT;
    c->common.cache_evict_to    = NGX_CONF_UNSET_UINT;
    c->common.cache_meta_mode   = NGX_CONF_UNSET_UINT;
    c->common.cache_batch_cinfo = NGX_CONF_UNSET_UINT;
    c->common.cache_index_cache = NGX_CONF_UNSET_SIZE;
    c->common.cache_slice_size  = NGX_CONF_UNSET_SIZE;
    c->common.pblock_block_size = NGX_CONF_UNSET_SIZE;
    c->common.rootfd            = -1;

    c->cvmfs.enable         = NGX_CONF_UNSET;
    c->cvmfs.manifest_ttl   = NGX_CONF_UNSET;
    c->cvmfs.negative_ttl   = NGX_CONF_UNSET;
    c->cvmfs.upstream_allow = NGX_CONF_UNSET_PTR;
    c->cvmfs.upstream_max   = NGX_CONF_UNSET_UINT;

    return c;
}

static char *
ngx_http_xrootd_cvmfs_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_xrootd_cvmfs_loc_conf_t *prev = parent;
    ngx_http_xrootd_cvmfs_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->common.enable,      prev->common.enable,      0);
    ngx_conf_merge_value(conf->common.allow_write, prev->common.allow_write, 0);
    ngx_conf_merge_value(conf->common.read_only,   prev->common.read_only,   0);
    ngx_conf_merge_value(conf->common.compress,    prev->common.compress,    0);
    ngx_conf_merge_str_value(conf->common.root,    prev->common.root,        "");
    ngx_conf_merge_str_value(conf->common.thread_pool_name,
                             prev->common.thread_pool_name, "");
    ngx_conf_merge_str_value(conf->common.storage_backend,
                             prev->common.storage_backend, "");
    ngx_conf_merge_str_value(conf->common.storage_credential,
                             prev->common.storage_credential, "");
    ngx_conf_merge_size_value(conf->common.pblock_block_size,
                              prev->common.pblock_block_size, 0);
    /* phase-64 tier grammar */
    ngx_conf_merge_str_value(conf->common.cache_store, prev->common.cache_store,
                             "");
    if (conf->common.cache_store_args == NULL) {
        conf->common.cache_store_args = prev->common.cache_store_args;
    }
    ngx_conf_merge_value(conf->common.stage_enable, prev->common.stage_enable, 0);
    ngx_conf_merge_str_value(conf->common.stage_store, prev->common.stage_store,
                             "");
    if (conf->common.stage_store_args == NULL) {
        conf->common.stage_store_args = prev->common.stage_store_args;
    }
    ngx_conf_merge_uint_value(conf->common.stage_flush_async,
                              prev->common.stage_flush_async, 0);
    ngx_conf_merge_off_value(conf->common.cache_max_object,
                             prev->common.cache_max_object, 0);
    ngx_conf_merge_uint_value(conf->common.cache_evict_at,
                              prev->common.cache_evict_at, 90);
    ngx_conf_merge_uint_value(conf->common.cache_evict_to,
                              prev->common.cache_evict_to, 80);
    ngx_conf_merge_uint_value(conf->common.cache_meta_mode,
                              prev->common.cache_meta_mode, 0);
    ngx_conf_merge_uint_value(conf->common.cache_batch_cinfo,
                              prev->common.cache_batch_cinfo, 2);
    ngx_conf_merge_size_value(conf->common.cache_index_cache,
                              prev->common.cache_index_cache, 0);
    ngx_conf_merge_size_value(conf->common.cache_slice_size,
                              prev->common.cache_slice_size, 0);
    if (xrootd_pmark_conf_merge(cf, &prev->common.pmark, &conf->common.pmark)
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->cvmfs.enable, prev->cvmfs.enable, 0);
    ngx_conf_merge_sec_value(conf->cvmfs.manifest_ttl, prev->cvmfs.manifest_ttl,
                             61);
    ngx_conf_merge_sec_value(conf->cvmfs.negative_ttl, prev->cvmfs.negative_ttl,
                             10);
    ngx_conf_merge_str_value(conf->cvmfs.quarantine_dir,
                             prev->cvmfs.quarantine_dir, "");
    ngx_conf_merge_ptr_value(conf->cvmfs.upstream_allow,
                             prev->cvmfs.upstream_allow, NULL);
    ngx_conf_merge_uint_value(conf->cvmfs.upstream_max, prev->cvmfs.upstream_max,
                              8);

    if (conf->cvmfs.enable) {
        xrootd_export_root_opts_t root_opts;

        /* CVMFS is a read-only protocol: no directive can enable writes. */
        conf->common.allow_write = 0;

        /* "posix:<path>" backend names the local export tree (composable
         * xrootd_root replacement) — same rewrite every protocol applies. */
        xrootd_storage_backend_posix_root(&conf->common);

        /* Pure cache node (the normal CVMFS shape): no local export tree —
         * anchor the namespace at "/" exactly like the stream plane's pure
         * cache node; the location serves the "/" namespace, filling from
         * the http backend into the cache store. */
        if (conf->common.root.len == 0) {
            ngx_str_set(&conf->common.root, "/");
        }

        root_opts.directive_name = "xrootd_cvmfs";
        root_opts.allow_write    = 0;
        root_opts.required       = 1;
        root_opts.canon_size     = sizeof(conf->common.root_canon);
        if (xrootd_prepare_export_root(cf, &conf->common.root, &root_opts,
                                       conf->common.root_canon) != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }

        /* Persistent confinement rootfd (openat2 RESOLVE_BENEATH anchor). */
        if (xrootd_http_open_rootfd(cf, &conf->common) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }

        /* Register the composable storage backend (phase-63): the http(s)
         * Stratum-1 origin URL routes every VFS op to sd_http. */
        if (xrootd_vfs_backend_config_str(cf, conf->common.root_canon,
                &conf->common.storage_backend, conf->common.pblock_block_size,
                XROOTD_AF_AUTO)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        /* Phase-64: compose the cache/stage tiers over the backend. */
        if (xrootd_tier_register_stores(cf, &conf->common) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

/*
 * Post-config: resolve the async-I/O thread pool per server (fill/offload
 * helpers need it) — identical mechanics to the s3 module.
 */
static ngx_int_t
ngx_http_xrootd_cvmfs_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t         *cmcf;
    ngx_http_core_srv_conf_t         **cscfp;
    ngx_http_xrootd_cvmfs_loc_conf_t  *lcf;
    static ngx_str_t                   default_pool_name = ngx_string("default");
    ngx_str_t                         *pool_name;
    ngx_uint_t                         s;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_conf_ctx_t *ctx = cscfp[s]->ctx;

        lcf = ctx->loc_conf[ngx_http_xrootd_cvmfs_module.ctx_index];
        if (lcf == NULL || !lcf->cvmfs.enable) {
            continue;
        }

        pool_name = (lcf->common.thread_pool_name.len > 0)
                    ? &lcf->common.thread_pool_name
                    : &default_pool_name;

        lcf->common.thread_pool = ngx_thread_pool_get(cf->cycle, pool_name);
        if (lcf->common.thread_pool == NULL) {
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "xrootd_cvmfs: thread pool \"%V\" not found - "
                "async cache fills disabled (add a thread_pool directive)",
                pool_name);
        }
    }

    return NGX_OK;
}

static ngx_http_module_t ngx_http_xrootd_cvmfs_module_ctx = {
    NULL,                                    /* preconfiguration     */
    ngx_http_xrootd_cvmfs_postconfiguration, /* postconfiguration    */
    NULL,                                    /* create main conf     */
    NULL,                                    /* init main conf       */
    NULL,                                    /* create server conf   */
    NULL,                                    /* merge server conf    */
    ngx_http_xrootd_cvmfs_create_loc_conf,   /* create location conf */
    ngx_http_xrootd_cvmfs_merge_loc_conf,    /* merge location conf  */
};

/* "xrootd_cvmfs on" — parse the flag AND make this location a dedicated
 * CVMFS protocol endpoint (same install point the s3 module uses). */
static char *
ngx_http_xrootd_cvmfs_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    char                     *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_xrootd_cvmfs_handler;

    return NGX_CONF_OK;
}

/*
 * Directives
 */

static ngx_command_t ngx_http_xrootd_cvmfs_commands[] = {

    { ngx_string("xrootd_cvmfs"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_xrootd_cvmfs_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.enable),
      NULL },

    { ngx_string("xrootd_cvmfs_manifest_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.manifest_ttl),
      NULL },

    { ngx_string("xrootd_cvmfs_negative_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.negative_ttl),
      NULL },

    { ngx_string("xrootd_cvmfs_quarantine_dir"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.quarantine_dir),
      NULL },

    { ngx_string("xrootd_cvmfs_upstream_allow"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.upstream_allow),
      NULL },

    { ngx_string("xrootd_cvmfs_upstream_max"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.upstream_max),
      NULL },

    /* ---- per-protocol tier directives over the shared preamble ---- */

    { ngx_string("xrootd_cvmfs_storage_backend"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, common.storage_backend),
      NULL },

    { ngx_string("xrootd_cvmfs_cache_store"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234,
      xrootd_conf_set_store_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, common.cache_store),
      (void *) offsetof(ngx_http_xrootd_cvmfs_loc_conf_t,
                        common.cache_store_args) },

    { ngx_string("xrootd_cvmfs_thread_pool"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, common.thread_pool_name),
      NULL },

    ngx_null_command
};

/* Task-8 stub — Task 9 moves the symbol into handler.c and deletes this. */
ngx_int_t
ngx_http_xrootd_cvmfs_handler(ngx_http_request_t *r)
{
    (void) r;
    return NGX_HTTP_NOT_IMPLEMENTED;
}

ngx_module_t ngx_http_xrootd_cvmfs_module = {
    NGX_MODULE_V1,
    &ngx_http_xrootd_cvmfs_module_ctx,  /* module context     */
    ngx_http_xrootd_cvmfs_commands,     /* module directives  */
    NGX_HTTP_MODULE,                    /* module type        */
    NULL,                               /* init master        */
    NULL,                               /* init module        */
    NULL,                               /* init process       */
    NULL,                               /* init thread        */
    NULL,                               /* exit thread        */
    NULL,                               /* exit process       */
    NULL,                               /* exit master        */
    NGX_MODULE_V1_PADDING
};
