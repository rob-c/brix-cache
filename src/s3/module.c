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
#include "../config/root_prepare.h"

static ngx_int_t ngx_http_s3_postconfiguration(ngx_conf_t *cf);

/* -------------------------------------------------------------------------
 * Config lifecycle
 * ---------------------------------------------------------------------- */

static void *
ngx_http_s3_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_s3_loc_conf_t *c;

    c = ngx_pcalloc(cf->pool, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }

    c->common.enable      = NGX_CONF_UNSET;
    c->common.allow_write = NGX_CONF_UNSET;
    c->allow_unsigned_session_token = NGX_CONF_UNSET;
    c->max_keys    = NGX_CONF_UNSET;

    return c;
}

static char *
ngx_http_s3_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_s3_loc_conf_t *prev = parent;
    ngx_http_s3_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->common.enable,      prev->common.enable,      0);
    ngx_conf_merge_value(conf->common.allow_write, prev->common.allow_write, 0);
    ngx_conf_merge_value(conf->allow_unsigned_session_token,
                         prev->allow_unsigned_session_token, 0);
    ngx_conf_merge_value(conf->max_keys,    prev->max_keys,    1000);
    ngx_conf_merge_str_value(conf->common.root,             prev->common.root,             "");
    ngx_conf_merge_str_value(conf->bucket,           prev->bucket,           "");
    ngx_conf_merge_str_value(conf->access_key,       prev->access_key,       "");
    ngx_conf_merge_str_value(conf->secret_key,       prev->secret_key,       "");
    ngx_conf_merge_str_value(conf->region,           prev->region,           "us-east-1");
    ngx_conf_merge_str_value(conf->common.thread_pool_name, prev->common.thread_pool_name, "");

    if (conf->common.enable) {
        xrootd_export_root_opts_t root_opts;
        root_opts.directive_name = "xrootd_s3_root";
        root_opts.allow_write    = conf->common.allow_write;
        root_opts.required       = 0;
        root_opts.canon_size     = sizeof(conf->common.root_canon);
        if (xrootd_prepare_export_root(cf, &conf->common.root, &root_opts,
                                       conf->common.root_canon) != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

/* -------------------------------------------------------------------------
 * Post-config: install content handler
 * ---------------------------------------------------------------------- */

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

/* -------------------------------------------------------------------------
 * Directives
 * ---------------------------------------------------------------------- */

static ngx_command_t ngx_http_s3_commands[] = {

    { ngx_string("xrootd_s3"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_s3_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.enable),
      NULL },

    { ngx_string("xrootd_s3_root"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.root),
      NULL },

    { ngx_string("xrootd_s3_bucket"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, bucket),
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

    { ngx_string("xrootd_s3_allow_unsigned_session_token"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, allow_unsigned_session_token),
      NULL },

    { ngx_string("xrootd_s3_max_keys"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, max_keys),
      NULL },

    { ngx_string("xrootd_s3_thread_pool"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, common.thread_pool_name),
      NULL },

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
