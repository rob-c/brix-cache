/*
 * module.c — nginx directive table, config lifecycle, and HTTP module context for the S3 endpoint.
 *
 * WHAT: Three responsibilities in one file:
 *   1. Config lifecycle (ngx_http_s3_create_loc_conf / ngx_http_s3_merge_loc_conf):
 *      Allocates ngx_http_s3_loc_conf_t with NGX_CONF_UNSET defaults, merges main→srv→loc
 *      config using ngx_conf_merge_value/ngx_conf_merge_str_value macros, and when enable=1
 *      calls xrootd_prepare_export_root() to canonicalize the root path into conf->common.root_canon.
 *   2. Post-config handler install (ngx_http_s3_set):
 *      The content of the "xrootd_s3" directive — parses a flag, then installs
 *      ngx_http_s3_handler as the location's request handler via clcf->handler.
 *   3. Directive table (ngx_http_s3_commands[] + ngx_module_t):
 *      Declares all S3 config directives with their type, parsing function, conf offset,
 *      and nginx module registration struct.
 *
 * WHY: The S3 endpoint shares the same nginx location-config model as WebDAV but has its own
 *      set of directives (xrootd_s3, xrootd_s3_root, xrootd_s3_bucket, etc.) and a distinct
 *      loc_conf structure. This file owns the full config lifecycle — allocation, merge, root
 *      canonicalization, and handler installation — so that every location block with
 *      "xrootd_s3 on" gets properly initialized before accepting traffic. The xrootd_prepare_export_root()
 *      call ensures conf->common.root_canon is valid (no path escapes) at config-time, preventing runtime failures.
 *
 * HOW:
 *   ngx_http_s3_create_loc_conf(): ngx_pcalloc(sizeof(ngx_http_s3_loc_conf_t)) — sets enable,
 *     allow_write, allow_unsigned_session_token, max_keys to NGX_CONF_UNSET (merge macros detect unset).
 *   ngx_http_s3_merge_loc_conf(): parent→child merge using ngx_conf_merge_value for flags/ints,
 *     ngx_conf_merge_str_value for strings. Defaults: enable=0, allow_write=0, allow_unsigned_session_token=0,
 *     max_keys=1000, root="", bucket="", access_key="", secret_key="", region="us-east-1". When conf->common.enable is true,
 *     calls xrootd_prepare_export_root() with directive_name="xrootd_s3_root", allow_write from config,
 *     required=0 (root not mandatory), canon_size=sizeof(conf->common.root_canon). Returns NGX_CONF_ERROR on failure.
 *   ngx_http_s3_set(): parses the "xrootd_s3" flag via ngx_conf_set_flag_slot(), then retrieves the
 *     core location conf and sets clcf->handler = ngx_http_s3_handler — this is what routes all S3 requests.
 *   Directive table: 8 directives (xrootd_s3, xrootd_s3_root, xrootd_s3_bucket, xrootd_s3_access_key,
 *     xrootd_s3_secret_key, xrootd_s3_region, xrootd_s3_allow_write, xrootd_s3_allow_unsigned_session_token,
 *     xrootd_s3_max_keys) — each with NGX_HTTP_LOC_CONF type, appropriate parsing function (flag_slot, str_slot,
 *     num_slot), and offsetof() into ngx_http_s3_loc_conf_t. Ends with ngx_null_command.
 */

#include "s3.h"
#include "../acc/acc.h"            /* XrdAcc engine directives + enum tables */
#include "../config/root_prepare.h"
#include "../config/http_rootfd.h"
#include "../compat/tmp_path.h"          /* SP4 orphan direct-write temp reaper */
#include "../config/credential_block.h"   /* §14 xrootd_credential lookup/bearer */
#include "../fs/vfs_backend_registry.h"   /* per-export backend registration */
#include "../compat/alloc_guard.h"

static ngx_int_t ngx_http_s3_postconfiguration(ngx_conf_t *cf);

/*
 * Config lifecycle
 * */

static void *
ngx_http_s3_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_s3_loc_conf_t *c;

    XROOTD_PCALLOC_OR_RETURN(c, cf->pool, sizeof(*c), NULL);

    c->common.enable      = NGX_CONF_UNSET;
    c->common.allow_write = NGX_CONF_UNSET;
    c->common.read_only   = NGX_CONF_UNSET;
    c->common.compress    = NGX_CONF_UNSET;   /* phase-42 W2 outbound GET */
    xrootd_pmark_conf_init(&c->common.pmark);  /* SciTags packet marking */
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
    c->allow_unsigned_session_token = NGX_CONF_UNSET;
    c->verify_chunk_signatures      = NGX_CONF_UNSET;
    c->list_cache                   = NGX_CONF_UNSET;
    c->list_cache_ttl               = NGX_CONF_UNSET_MSEC;
    c->max_keys    = NGX_CONF_UNSET;
    c->mpu_max_age = NGX_CONF_UNSET;
    c->zip_access  = NGX_CONF_UNSET;
    c->zip_cd_max_bytes = NGX_CONF_UNSET_SIZE;
    xrootd_acc_http_init_conf(&c->acc);   /* XrdAcc engine (off by default) */

    return c;
}

static char *
ngx_http_s3_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_s3_loc_conf_t *prev = parent;
    ngx_http_s3_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->common.enable,      prev->common.enable,      0);
    ngx_conf_merge_value(conf->common.allow_write, prev->common.allow_write, 0);
    ngx_conf_merge_value(conf->common.read_only,   prev->common.read_only,   0);
    /* Hard read-only: force allow_write off so the S3 write-method gate rejects. */
    xrootd_shared_apply_read_only(&conf->common, cf->log);
    ngx_conf_merge_value(conf->common.compress,    prev->common.compress,    0);
    ngx_conf_merge_value(conf->allow_unsigned_session_token,
                         prev->allow_unsigned_session_token, 0);
    ngx_conf_merge_value(conf->verify_chunk_signatures,
                         prev->verify_chunk_signatures, 0);
    ngx_conf_merge_value(conf->list_cache, prev->list_cache, 0);
    ngx_conf_merge_msec_value(conf->list_cache_ttl, prev->list_cache_ttl,
                              10000);   /* 10s default staleness bound */
    ngx_conf_merge_value(conf->max_keys,    prev->max_keys,    1000);
    ngx_conf_merge_value(conf->mpu_max_age, prev->mpu_max_age, 0);
    ngx_conf_merge_value(conf->zip_access,  prev->zip_access,  0);
    ngx_conf_merge_size_value(conf->zip_cd_max_bytes, prev->zip_cd_max_bytes,
                              16 * 1024 * 1024);
    xrootd_acc_http_merge_conf(&conf->acc, &prev->acc);
    ngx_conf_merge_str_value(conf->common.root,             prev->common.root,             "");
    ngx_conf_merge_str_value(conf->cache_root,       prev->cache_root,       "");
    ngx_conf_merge_str_value(conf->bucket,           prev->bucket,           "");
    ngx_conf_merge_str_value(conf->access_key,       prev->access_key,       "");
    ngx_conf_merge_str_value(conf->secret_key,       prev->secret_key,       "");
    ngx_conf_merge_str_value(conf->region,           prev->region,           "us-east-1");
    ngx_conf_merge_str_value(conf->common.thread_pool_name, prev->common.thread_pool_name, "");
    ngx_conf_merge_str_value(conf->common.storage_backend,
                             prev->common.storage_backend, "");
    ngx_conf_merge_str_value(conf->common.storage_credential,
                             prev->common.storage_credential, "");
    /* phase-64 composable tier grammar */
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

    if (conf->common.enable) {
        xrootd_export_root_opts_t root_opts;

        /* posix:<path> backend → the local export tree (composable xrootd_root). */
        xrootd_storage_backend_posix_root(&conf->common);

        root_opts.directive_name = "xrootd_s3_root";
        root_opts.allow_write    = conf->common.allow_write
                                 && !xrootd_storage_backend_is_remote(&conf->common);
        root_opts.required       = 0;
        root_opts.canon_size     = sizeof(conf->common.root_canon);
        if (xrootd_prepare_export_root(cf, &conf->common.root, &root_opts,
                                       conf->common.root_canon) != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }
        /* SP4: reap interrupted NON-staged direct-write temps under this root. */
        if (conf->common.root_canon[0] != '\0') {
            xrootd_tmp_reap_register(conf->common.root_canon);
        }

        /* Open the persistent confinement rootfd (kernel openat2
         * RESOLVE_BENEATH anchor); no-op when no xrootd_s3_root is set. */
        if (xrootd_http_open_rootfd(cf, &conf->common) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }

        /* Register the export's composable storage backend (phase-63): a
         * "root://"/"http://" URL or a driver name routes every VFS op (S3 GET
         * goes through xrootd_vfs_open) to the source backend; default POSIX is a
         * no-op. Mirrors the stream/webdav config paths. */
        if (xrootd_vfs_backend_config_str(cf, conf->common.root_canon,
                &conf->common.storage_backend, conf->common.pblock_block_size,
                XROOTD_AF_AUTO)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        /* §14: attach the named xrootd_credential's bearer to the source backend. */
        if (conf->common.storage_credential.len > 0) {
            char                       cred_z[256];
            char                       bearer[4096];
            const xrootd_credential_t *cred;

            ngx_cpystrn((u_char *) cred_z, conf->common.storage_credential.data,
                        ngx_min(conf->common.storage_credential.len + 1,
                                sizeof(cred_z)));
            cred = xrootd_credential_lookup(cred_z);
            if (cred == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_s3_storage_credential: no xrootd_credential \"%V\"",
                    &conf->common.storage_credential);
                return NGX_CONF_ERROR;
            }
            if (xrootd_credential_bearer(cred, bearer, sizeof(bearer), cf->log)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
            xrootd_vfs_backend_set_credential(conf->common.root_canon, bearer,
                (cred->x509_proxy.len > 0)
                    ? (const char *) cred->x509_proxy.data : NULL,
                (cred->ca_dir.len > 0) ? (const char *) cred->ca_dir.data : NULL);
        }

        /* Phase-64: register the composable cache/stage tiers (§4.4 mirror). */
        if (xrootd_tier_register_stores(cf, &conf->common) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        if (conf->cache_root.len > 0) {
            xrootd_export_root_opts_t cache_opts;
            cache_opts.directive_name = "xrootd_s3_cache_root";
            cache_opts.allow_write    = 0;
            cache_opts.required       = 0;
            cache_opts.canon_size     = sizeof(conf->cache_root_canon);
            if (xrootd_prepare_export_root(cf, &conf->cache_root, &cache_opts,
                                           conf->cache_root_canon) != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }
        }
    }

    return NGX_CONF_OK;
}

/*
 * Post-config: install content handler
 * */

static ngx_int_t
ngx_http_s3_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_core_srv_conf_t  **cscfp;
    ngx_http_s3_loc_conf_t     *scf;
    static ngx_str_t            default_pool_name = ngx_string("default");
    ngx_str_t                  *pool_name;
    ngx_uint_t                  s;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_conf_ctx_t *ctx = cscfp[s]->ctx;

        scf = ctx->loc_conf[ngx_http_xrootd_s3_module.ctx_index];
        if (scf == NULL || !scf->common.enable) {
            continue;
        }

        pool_name = (scf->common.thread_pool_name.len > 0)
                    ? &scf->common.thread_pool_name
                    : &default_pool_name;

        scf->common.thread_pool = ngx_thread_pool_get(cf->cycle, pool_name);
        if (scf->common.thread_pool == NULL) {
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "xrootd_s3: thread pool \"%V\" not found - "
                "async PUT I/O disabled (add a thread_pool directive)",
                pool_name);
        }
    }

    return NGX_OK;
}

static ngx_http_module_t ngx_http_s3_module_ctx = {
    NULL,                          /* preconfiguration        */
    ngx_http_s3_postconfiguration, /* postconfiguration       */
    NULL,                          /* create main conf        */
    NULL,                          /* init main conf          */
    NULL,                          /* create server conf      */
    NULL,                          /* merge server conf       */
    ngx_http_s3_create_loc_conf,   /* create location conf    */
    ngx_http_s3_merge_loc_conf,    /* merge location conf     */
};

static char *
ngx_http_s3_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;
    char                      *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_s3_handler;

    return NGX_CONF_OK;
}

/*
 * Directives
 * */

/* phase-64: xrootd_s3_stage_flush sync|async (0 = sync, 1 = async). */
static ngx_conf_enum_t  xrootd_s3_stage_flush_enum[] = {
    { ngx_string("sync"),  0 },
    { ngx_string("async"), 1 },
    { ngx_null_string,     0 }
};

/* phase-64: xrootd_s3_cache_meta map (XROOTD_CMETA_* in cache/cstore.h). */
static ngx_conf_enum_t  xrootd_s3_cache_meta_enum[] = {
    { ngx_string("auto"),    0 },
    { ngx_string("local"),   1 },
    { ngx_string("xattr"),   2 },
    { ngx_string("sidecar"), 3 },
    { ngx_null_string,       0 }
};

static ngx_command_t ngx_http_s3_commands[] = {

    { ngx_string("xrootd_s3"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_s3_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.enable),
      NULL },

    /* phase-42 W2: opt-in outbound GetObject compression (Accept-Encoding
     * negotiated, off by default).  Plain flag — no export-root side effects. */
    { ngx_string("xrootd_s3_compress"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.compress),
      NULL },

    /* The XrdAcc directives (xrootd_authdb / _format / _audit) are registered by
     * the WebDAV module with shared setters that populate the S3 loc-conf too,
     * so they are intentionally NOT redeclared here (a duplicate would conflict). */

    { ngx_string("xrootd_s3_root"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.root),
      NULL },

    /* Composable storage backend for this S3 export (phase-63): "root://host:port",
     * "http://host/base", or a driver name ("pblock"); default POSIX. */
    { ngx_string("xrootd_s3_storage_backend"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.storage_backend),
      NULL },

    /* Names the xrootd_credential block (§14) the source backend authenticates with. */
    { ngx_string("xrootd_s3_storage_credential"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.storage_credential),
      NULL },

    /* ---- phase-64 composable tier grammar mirrors (§4.4) ---- */
    { ngx_string("xrootd_s3_cache_store"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234,
      xrootd_conf_set_store_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.cache_store),
      (void *) offsetof(ngx_http_s3_loc_conf_t, common.cache_store_args) },
    { ngx_string("xrootd_s3_stage"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.stage_enable),
      NULL },
    { ngx_string("xrootd_s3_stage_store"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234,
      xrootd_conf_set_store_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.stage_store),
      (void *) offsetof(ngx_http_s3_loc_conf_t, common.stage_store_args) },
    { ngx_string("xrootd_s3_stage_flush"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.stage_flush_async),
      xrootd_s3_stage_flush_enum },
    { ngx_string("xrootd_s3_cache_max_object"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.cache_max_object),
      NULL },
    { ngx_string("xrootd_s3_cache_evict_at"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.cache_evict_at),
      NULL },
    { ngx_string("xrootd_s3_cache_evict_to"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.cache_evict_to),
      NULL },
    { ngx_string("xrootd_s3_cache_index_cache"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.cache_index_cache),
      NULL },
    { ngx_string("xrootd_s3_cache_meta"),    /* auto|local|xattr|sidecar */
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.cache_meta_mode),
      xrootd_s3_cache_meta_enum },
    { ngx_string("xrootd_s3_cache_slice_size"),  /* <size> (0 = whole-file) */
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.cache_slice_size),
      NULL },

    { ngx_string("xrootd_s3_bucket"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, bucket),
      NULL },

    { ngx_string("xrootd_s3_cache_root"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, cache_root),
      NULL },

    { ngx_string("xrootd_s3_access_key"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, access_key),
      NULL },

    { ngx_string("xrootd_s3_secret_key"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, secret_key),
      NULL },

    { ngx_string("xrootd_s3_region"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, region),
      NULL },

    { ngx_string("xrootd_s3_allow_write"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.allow_write),
      NULL },
    { ngx_string("xrootd_s3_read_only"),     /* hard read-only (overrides allow_write) */
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.read_only),
      NULL },

    { ngx_string("xrootd_s3_allow_unsigned_session_token"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, allow_unsigned_session_token),
      NULL },

    { ngx_string("xrootd_s3_verify_chunk_signatures"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, verify_chunk_signatures),
      NULL },

    { ngx_string("xrootd_s3_list_cache"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, list_cache),
      NULL },

    /* ZIP member access over S3 GetObject (phase-57 W2). Opt-in, off default. */
    { ngx_string("xrootd_s3_zip_access"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, zip_access),
      NULL },

    { ngx_string("xrootd_s3_zip_cd_max_bytes"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, zip_cd_max_bytes),
      NULL },

    { ngx_string("xrootd_s3_list_cache_ttl"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, list_cache_ttl),
      NULL },

    { ngx_string("xrootd_s3_max_keys"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, max_keys),
      NULL },

    /* Phase 39 (WS8): incomplete-multipart reaper idle age in seconds (0=off). */
    { ngx_string("xrootd_s3_mpu_max_age"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, mpu_max_age),
      NULL },

    { ngx_string("xrootd_s3_thread_pool"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.thread_pool_name),
      NULL },

    /* SciTags packet marking (src/pmark/) — see phase-34 doc */    { ngx_string("xrootd_pmark"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.enable), NULL },
    { ngx_string("xrootd_pmark_firefly"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.firefly), NULL },
    { ngx_string("xrootd_pmark_flowlabel"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.flowlabel), NULL },
    { ngx_string("xrootd_pmark_scitag_cgi"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.scitag_cgi), NULL },
    { ngx_string("xrootd_pmark_firefly_origin"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.firefly_origin), NULL },
    { ngx_string("xrootd_pmark_http_plain"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.http_plain), NULL },
    { ngx_string("xrootd_pmark_echo"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.echo), NULL },
    { ngx_string("xrootd_pmark_appname"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.appname), NULL },
    { ngx_string("xrootd_pmark_defsfile"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.pmark.defsfile), NULL },
    { ngx_string("xrootd_pmark_domain"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, xrootd_pmark_set_domain,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("xrootd_pmark_firefly_dest"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, xrootd_pmark_set_firefly_dest,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("xrootd_pmark_map_experiment"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE23, xrootd_pmark_set_map_experiment,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("xrootd_pmark_map_activity"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE3 | NGX_CONF_TAKE4,
      xrootd_pmark_set_map_activity,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },

    ngx_null_command
};

ngx_module_t ngx_http_xrootd_s3_module = {
    NGX_MODULE_V1,
    &ngx_http_s3_module_ctx,    /* module context     */
    ngx_http_s3_commands,       /* module directives  */
    NGX_HTTP_MODULE,            /* module type        */
    NULL,                       /* init master        */
    NULL,                       /* init module        */
    NULL,                       /* init process       */
    NULL,                       /* init thread        */
    NULL,                       /* exit thread        */
    NULL,                       /* exit process       */
    NULL,                       /* exit master        */
    NGX_MODULE_V1_PADDING
};
