/*
 * module.c — nginx directive table and HTTP module context for the S3 module.
 */

#include "s3.h"

#include <errno.h>
#include <unistd.h>

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

    c->enable      = NGX_CONF_UNSET;
    c->allow_write = NGX_CONF_UNSET;
    c->max_keys    = NGX_CONF_UNSET;

    return c;
}

static char *
ngx_http_s3_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_s3_loc_conf_t *prev = parent;
    ngx_http_s3_loc_conf_t *conf = child;
    char                    root_buf[PATH_MAX];

    ngx_conf_merge_value(conf->enable,      prev->enable,      0);
    ngx_conf_merge_value(conf->allow_write, prev->allow_write, 0);
    ngx_conf_merge_value(conf->max_keys,    prev->max_keys,    1000);
    ngx_conf_merge_str_value(conf->root,       prev->root,       "");
    ngx_conf_merge_str_value(conf->bucket,     prev->bucket,     "");
    ngx_conf_merge_str_value(conf->access_key, prev->access_key, "");
    ngx_conf_merge_str_value(conf->secret_key, prev->secret_key, "");
    ngx_conf_merge_str_value(conf->region,     prev->region,     "us-east-1");

    if (conf->enable && conf->root.len > 0) {
        if (conf->root.len >= sizeof(root_buf)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd_s3_root is too long");
            return NGX_CONF_ERROR;
        }
        ngx_memcpy(root_buf, conf->root.data, conf->root.len);
        root_buf[conf->root.len] = '\0';

        if (realpath(root_buf, conf->root_canon) == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, errno,
                               "cannot canonicalize xrootd_s3_root \"%s\"",
                               root_buf);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

/* -------------------------------------------------------------------------
 * Post-config: install content handler
 * ---------------------------------------------------------------------- */

static ngx_http_module_t ngx_http_s3_module_ctx = {
    NULL,                          /* preconfiguration        */
    NULL,                          /* postconfiguration       */
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
      offsetof(ngx_http_s3_loc_conf_t, enable),
      NULL },

    { ngx_string("xrootd_s3_root"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, root),
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
      offsetof(ngx_http_s3_loc_conf_t, allow_write),
      NULL },

    { ngx_string("xrootd_s3_max_keys"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_s3_loc_conf_t, max_keys),
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
