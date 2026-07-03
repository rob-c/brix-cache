/*
 * module_directives.c - extracted concern
 * Phase-38 split of module.c; behavior-identical.
 */
#include "webdav_module_internal.h"

char *
webdav_conf_add_cors_origin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_webdav_loc_conf_t *wlcf = conf;
    ngx_str_t                         *value;
    ngx_str_t                         *origin;

    (void) cmd;

    if (wlcf->cors_origins == NULL) {
        wlcf->cors_origins = ngx_array_create(cf->pool, 2,
                                              sizeof(ngx_str_t));
        if (wlcf->cors_origins == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    origin = ngx_array_push(wlcf->cors_origins);
    if (origin == NULL) {
        return NGX_CONF_ERROR;
    }

    *origin = value[1];

    return NGX_CONF_OK;
}


/*
 * brix_webdav_dig_export <name> <dir> — register a named read-only diagnostic
 * export (§3). The dir is realpath'd at config time into the export's `canon` (the
 * RESOLVE_BENEATH anchor); a non-existent dir is a config error so misconfiguration
 * is caught at startup, not at request time.
 */
char *
webdav_conf_dig_export(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_webdav_loc_conf_t *wlcf = conf;
    ngx_str_t                         *value;
    brix_dig_export_t               *ex;
    char                               rp[PATH_MAX];

    (void) cmd;

    if (wlcf->dig_exports == NGX_CONF_UNSET_PTR || wlcf->dig_exports == NULL) {
        wlcf->dig_exports = ngx_array_create(cf->pool, 2,
                                             sizeof(brix_dig_export_t));
        if (wlcf->dig_exports == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;   /* value[1]=name value[2]=dir */

    if (realpath((const char *) value[2].data, rp) == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "brix_webdav_dig_export: cannot resolve \"%V\"",
                           &value[2]);
        return NGX_CONF_ERROR;
    }

    ex = ngx_array_push(wlcf->dig_exports);
    if (ex == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(ex, sizeof(*ex));
    ex->name = value[1];
    ex->dir  = value[2];
    ex->canon.len  = ngx_strlen(rp);
    ex->canon.data = ngx_pnalloc(cf->pool, ex->canon.len + 1);
    if (ex->canon.data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(ex->canon.data, rp, ex->canon.len + 1);

    return NGX_CONF_OK;
}


/*
 * brix_webdav_proxy_auth anonymous|forward|token <bearer>
 * 1 or 2 arguments: policy and optional token value.
 */
char *
webdav_conf_proxy_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr)
{
    ngx_http_brix_webdav_loc_conf_t *conf = conf_ptr;
    ngx_str_t *value = cf->args->elts;

    (void) cmd;

    if (ngx_strcmp(value[1].data, "anonymous") == 0) {
        conf->upstream_auth = WEBDAV_PROXY_AUTH_ANONYMOUS;
        return NGX_CONF_OK;
    }
    if (ngx_strcmp(value[1].data, "forward") == 0) {
        conf->upstream_auth = WEBDAV_PROXY_AUTH_FORWARD;
        return NGX_CONF_OK;
    }
    if (ngx_strcmp(value[1].data, "token") == 0) {
        if (cf->args->nelts < 3) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "brix_webdav_proxy_auth token requires a token value");
            return NGX_CONF_ERROR;
        }
        conf->upstream_auth       = WEBDAV_PROXY_AUTH_TOKEN;
        conf->upstream_auth_token = value[2];
        return NGX_CONF_OK;
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "brix_webdav_proxy_auth: unknown policy \"%V\""
                       " (expected anonymous, forward, or token <value>)",
                       &value[1]);
    return NGX_CONF_ERROR;
}


/*
 * brix_webdav_proxy_upstream <url> [<url> ...]
 * Phase 21 Step D — accepts one or more http(s):// backend URLs; each is
 * resolved at postconfiguration into one or more round-robin backends.
 */
char *
webdav_conf_proxy_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr)
{
    ngx_http_brix_webdav_loc_conf_t *conf = conf_ptr;
    ngx_str_t                         *value = cf->args->elts;
    ngx_str_t                         *slot;
    ngx_uint_t                         i;

    (void) cmd;

    if (conf->upstream_urls == NULL) {
        conf->upstream_urls = ngx_array_create(cf->pool,
                                               cf->args->nelts - 1,
                                               sizeof(ngx_str_t));
        if (conf->upstream_urls == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {
        slot = ngx_array_push(conf->upstream_urls);
        if (slot == NULL) {
            return NGX_CONF_ERROR;
        }
        *slot = value[i];
    }

    /* Keep the first URL in upstream_url for the legacy single-backend path. */
    if (conf->upstream_url.len == 0 && cf->args->nelts > 1) {
        conf->upstream_url = value[1];
    }

    return NGX_CONF_OK;
}


/*
 * Parse one "brix_webdav_open_file_cache" parameter token. Recognised tokens:
 *   max=N       -> *max     (must be > 0)
 *   inactive=T  -> *inactive (nginx time spec)
 *   off         -> *off = 1
 * Returns NGX_OK if the token was recognised and valid, NGX_ERROR for an unknown
 * token or an out-of-range value; the caller logs the offending token on error.
 */
ngx_int_t
webdav_open_file_cache_arg(ngx_str_t *arg, ngx_int_t *max, time_t *inactive,
    ngx_flag_t *off)
{
    ngx_str_t  s;

    if (ngx_strncmp(arg->data, "max=", 4) == 0) {
        *max = ngx_atoi(arg->data + 4, arg->len - 4);
        return (*max <= 0) ? NGX_ERROR : NGX_OK;
    }

    if (ngx_strncmp(arg->data, "inactive=", 9) == 0) {
        s.len  = arg->len - 9;
        s.data = arg->data + 9;
        *inactive = ngx_parse_time(&s, 1);
        return (*inactive == (time_t) NGX_ERROR) ? NGX_ERROR : NGX_OK;
    }

    if (ngx_strcmp(arg->data, "off") == 0) {
        *off = 1;
        return NGX_OK;
    }

    return NGX_ERROR;   /* unknown token */
}


char *
webdav_conf_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_webdav_loc_conf_t *wlcf = conf;

    time_t       inactive;
    ngx_str_t   *value;
    ngx_int_t    max;
    ngx_uint_t   i;
    ngx_flag_t   off;

    if (wlcf->open_file_cache != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    max = 0;
    inactive = 60;
    off = 0;

    for (i = 1; i < cf->args->nelts; i++) {
        if (webdav_open_file_cache_arg(&value[i], &max, &inactive, &off)
            != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid \"brix_webdav_open_file_cache\" "
                               "parameter \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    /* "off" disables the cache outright. */
    if (off) {
        wlcf->open_file_cache = NULL;
    }

    if (wlcf->open_file_cache == NULL) {
        return NGX_CONF_OK;
    }

    if (max == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "\"brix_webdav_open_file_cache\" must have the \"max\" parameter");
        return NGX_CONF_ERROR;
    }

    wlcf->open_file_cache = ngx_open_file_cache_init(cf->pool, max, inactive);
    if (wlcf->open_file_cache) {
        return NGX_CONF_OK;
    }

    return NGX_CONF_ERROR;
}
