/*
 * module.c - nginx directive table and HTTP module object.
 */

#include "webdav.h"
#include "../acc/acc.h"            /* XrdAcc engine directives + enum tables */
#include "../s3/s3.h"
#include "../shm/kv.h"             /* xrootd_kv_zone_directive */
#include "../shm/rate_limit.h"     /* xrootd_rate_limit_directive */
#include "../token/token_cache.h"  /* xrootd_token_cache_directive */
#include "../mirror/http_mirror.h" /* Phase 24: traffic mirror directives */
#include "../ratelimit/ratelimit.h" /* Phase 25: advanced rate-limit directives */

#include <curl/curl.h>
#include <stddef.h>

static ngx_conf_enum_t  webdav_auth_values[] = {
    { ngx_string("none"),     WEBDAV_AUTH_NONE     },
    { ngx_string("optional"), WEBDAV_AUTH_OPTIONAL },
    { ngx_string("required"), WEBDAV_AUTH_REQUIRED },
    { ngx_null_string, 0 }
};

/**
 * WHAT: Config directive handler for the xrootd_webdav_cors_origin nginx directive.
 *
 * Called by nginx when parsing "xrootd_webdav_cors_origin <origin>" directives in the
 * configuration file. Creates a dynamic array of ngx_str_t values (if not already created)
 * on first invocation, then pushes each parsed origin string onto the array for later
 * CORS origin validation via webdav_cors_origin_allowed(). The directive accepts one or
 * more occurrences to build an allowlist of permitted cross-origin request sources. Returns
 * NGX_CONF_OK on success; NGX_CONF_ERROR if pool allocation fails (rare under normal conditions).
 */
static char *
webdav_conf_add_cors_origin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_webdav_loc_conf_t *wlcf = conf;
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
 * xrootd_webdav_proxy_auth anonymous|forward|token <bearer>
 * 1 or 2 arguments: policy and optional token value.
 */
static char *
webdav_conf_proxy_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf = conf_ptr;
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
                               "xrootd_webdav_proxy_auth token requires a token value");
            return NGX_CONF_ERROR;
        }
        conf->upstream_auth       = WEBDAV_PROXY_AUTH_TOKEN;
        conf->upstream_auth_token = value[2];
        return NGX_CONF_OK;
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "xrootd_webdav_proxy_auth: unknown policy \"%V\""
                       " (expected anonymous, forward, or token <value>)",
                       &value[1]);
    return NGX_CONF_ERROR;
}

/*
 * xrootd_webdav_proxy_upstream <url> [<url> ...]
 * Phase 21 Step D — accepts one or more http(s):// backend URLs; each is
 * resolved at postconfiguration into one or more round-robin backends.
 */
char *
webdav_conf_proxy_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf = conf_ptr;
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
 * Parse one "xrootd_webdav_open_file_cache" parameter token. Recognised tokens:
 *   max=N       -> *max     (must be > 0)
 *   inactive=T  -> *inactive (nginx time spec)
 *   off         -> *off = 1
 * Returns NGX_OK if the token was recognised and valid, NGX_ERROR for an unknown
 * token or an out-of-range value; the caller logs the offending token on error.
 */
static ngx_int_t
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

static char *
webdav_conf_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_webdav_loc_conf_t *wlcf = conf;

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
                               "invalid \"xrootd_webdav_open_file_cache\" "
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
                        "\"xrootd_webdav_open_file_cache\" must have the \"max\" parameter");
        return NGX_CONF_ERROR;
    }

    wlcf->open_file_cache = ngx_open_file_cache_init(cf->pool, max, inactive);
    if (wlcf->open_file_cache) {
        return NGX_CONF_OK;
    }

    return NGX_CONF_ERROR;
}

/*
 * Directive table for the WebDAV HTTP module.  Mechanical: each entry binds a
 * config keyword to a setter and (usually) a field offset in the location conf.
 * Most use stock nginx setters (set_flag/str/num/sec/msec_slot); the handful of
 * custom handlers above (CORS origin list, proxy auth/upstream, open_file_cache)
 * and the cross-module setters (mirror, rate-limit, KV, token-cache) appear
 * where they are grouped by feature.  Defaults/merge live in config.c.
 */
/*
 * The XrdAcc directives are valid in any http location and must configure BOTH
 * the WebDAV and S3 loc-confs (an S3-only location still needs them), but nginx
 * applies just one module's setter per directive.  These shared setters fetch
 * both loc-confs and populate each, so the directive is registered only once.
 */
static char *
xrootd_acc_http_set_authdb(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_webdav_loc_conf_t *wc =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_xrootd_webdav_module);
    ngx_http_s3_loc_conf_t            *sc =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_xrootd_s3_module);
    ngx_str_t *value = cf->args->elts;
    wc->acc.authdb = value[1];
    sc->acc.authdb = value[1];
    return NGX_CONF_OK;
}

static char *
xrootd_acc_http_set_enum(ngx_conf_t *cf, ngx_conf_enum_t *e, ngx_uint_t *wp,
    ngx_uint_t *sp)
{
    ngx_str_t *value = cf->args->elts;
    ngx_uint_t i;
    for (i = 0; e[i].name.len != 0; i++) {
        if (e[i].name.len == value[1].len
            && ngx_strcmp(e[i].name.data, value[1].data) == 0)
        {
            *wp = *sp = e[i].value;
            return NGX_CONF_OK;
        }
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid value \"%V\"", &value[1]);
    return NGX_CONF_ERROR;
}

static char *
xrootd_acc_http_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_webdav_loc_conf_t *wc =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_xrootd_webdav_module);
    ngx_http_s3_loc_conf_t            *sc =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_xrootd_s3_module);
    return xrootd_acc_http_set_enum(cf, xrootd_acc_format_modes,
                                    &wc->acc.format, &sc->acc.format);
}

static char *
xrootd_acc_http_set_audit(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_webdav_loc_conf_t *wc =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_xrootd_webdav_module);
    ngx_http_s3_loc_conf_t            *sc =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_xrootd_s3_module);
    return xrootd_acc_http_set_enum(cf, xrootd_acc_audit_modes,
                                    &wc->acc.audit, &sc->acc.audit);
}

/*
 * Shared scalar setters for the XrdAcc HTTP tunables — registered once but
 * populate BOTH loc-confs (see the authdb setters above for why).  Each grabs
 * the WebDAV + S3 acc blocks and applies the value to the same field in each.
 */
static char *
xrootd_acc_http_both(ngx_conf_t *cf, xrootd_acc_http_t **wc, xrootd_acc_http_t **sc)
{
    ngx_http_xrootd_webdav_loc_conf_t *w =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_xrootd_webdav_module);
    ngx_http_s3_loc_conf_t            *s =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_xrootd_s3_module);
    *wc = &w->acc;
    *sc = &s->acc;
    return NULL;
}

static char *
xrootd_acc_http_set_refresh(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_acc_http_t *wc, *sc;
    ngx_str_t         *value = cf->args->elts;
    ngx_int_t          n;

    (void) xrootd_acc_http_both(cf, &wc, &sc);
    n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid number \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }
    wc->refresh = sc->refresh = n;
    return NGX_CONF_OK;
}

static char *
xrootd_acc_http_set_gidlifetime(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_acc_http_t *wc, *sc;
    ngx_str_t         *value = cf->args->elts;
    ngx_int_t          n;

    (void) xrootd_acc_http_both(cf, &wc, &sc);
    n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid number \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }
    wc->gidlifetime = sc->gidlifetime = n;
    return NGX_CONF_OK;
}

static char *
xrootd_acc_http_set_nisdomain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_acc_http_t *wc, *sc;
    ngx_str_t         *value = cf->args->elts;

    (void) xrootd_acc_http_both(cf, &wc, &sc);
    wc->nisdomain = sc->nisdomain = value[1];
    return NGX_CONF_OK;
}

static char *
xrootd_acc_http_set_flag(ngx_conf_t *cf, ngx_flag_t *wp, ngx_flag_t *sp,
    ngx_str_t *val)
{
    if (ngx_strcasecmp(val->data, (u_char *) "on") == 0) {
        *wp = *sp = 1;
    } else if (ngx_strcasecmp(val->data, (u_char *) "off") == 0) {
        *wp = *sp = 0;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" (expected on|off)", val);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *
xrootd_acc_http_set_pgo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_acc_http_t *wc, *sc;
    ngx_str_t         *value = cf->args->elts;

    (void) xrootd_acc_http_both(cf, &wc, &sc);
    return xrootd_acc_http_set_flag(cf, &wc->pgo, &sc->pgo, &value[1]);
}

static char *
xrootd_acc_http_set_resolve_hosts(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_acc_http_t *wc, *sc;
    ngx_str_t         *value = cf->args->elts;

    (void) xrootd_acc_http_both(cf, &wc, &sc);
    return xrootd_acc_http_set_flag(cf, &wc->resolve_hosts, &sc->resolve_hosts,
                                    &value[1]);
}

static char *
xrootd_acc_http_set_spacechar(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_acc_http_t *wc, *sc;
    ngx_str_t         *value = cf->args->elts;

    (void) xrootd_acc_http_both(cf, &wc, &sc);
    wc->spacechar = sc->spacechar = value[1];
    return NGX_CONF_OK;
}

static char *
xrootd_acc_http_set_encoding(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_acc_http_t *wc, *sc;
    ngx_str_t         *value = cf->args->elts;

    (void) xrootd_acc_http_both(cf, &wc, &sc);
    return xrootd_acc_http_set_flag(cf, &wc->encoding, &sc->encoding, &value[1]);
}

static char *
xrootd_acc_http_set_gidretran(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_acc_http_t *wc, *sc;
    ngx_str_t         *value = cf->args->elts;

    (void) xrootd_acc_http_both(cf, &wc, &sc);
    wc->gidretran = sc->gidretran = value[1];
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_xrootd_webdav_commands[] = {

    { ngx_string("xrootd_webdav"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, common.enable),
      NULL },

    /* XrdAcc engine — registered once here; the shared setters populate both
     * the WebDAV and S3 loc-confs (valid in any http location). */
    { ngx_string("xrootd_authdb"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      xrootd_acc_http_set_authdb, 0, 0, NULL },

    { ngx_string("xrootd_authdb_format"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      xrootd_acc_http_set_format, 0, 0, NULL },

    { ngx_string("xrootd_authdb_audit"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      xrootd_acc_http_set_audit, 0, 0, NULL },

    { ngx_string("xrootd_authdb_refresh"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      xrootd_acc_http_set_refresh, 0, 0, NULL },

    { ngx_string("xrootd_acc_gidlifetime"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      xrootd_acc_http_set_gidlifetime, 0, 0, NULL },

    { ngx_string("xrootd_acc_pgo"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      xrootd_acc_http_set_pgo, 0, 0, NULL },

    { ngx_string("xrootd_acc_nisdomain"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      xrootd_acc_http_set_nisdomain, 0, 0, NULL },

    { ngx_string("xrootd_acc_resolve_hosts"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      xrootd_acc_http_set_resolve_hosts, 0, 0, NULL },

    { ngx_string("xrootd_acc_spacechar"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      xrootd_acc_http_set_spacechar, 0, 0, NULL },

    { ngx_string("xrootd_acc_encoding"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      xrootd_acc_http_set_encoding, 0, 0, NULL },

    { ngx_string("xrootd_acc_gidretran"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      xrootd_acc_http_set_gidretran, 0, 0, NULL },

    { ngx_string("xrootd_webdav_root"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, common.root),
      NULL },

    { ngx_string("xrootd_webdav_cache_root"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, cache_root),
      NULL },

    { ngx_string("xrootd_webdav_vomsdir"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, vomsdir),
      NULL },

    /* Per-socket TCP congestion control (e.g. "bbr") for the HTTP data path — the
     * sender's CC governs download throughput; BBR ignores reordering's spurious
     * loss signals.  Same directive name as the stream module, different context. */
    { ngx_string("xrootd_tcp_congestion"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tcp_congestion),
      NULL },

    { ngx_string("xrootd_webdav_voms_cert_dir"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, voms_cert_dir),
      NULL },

    { ngx_string("xrootd_webdav_cadir"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, cadir),
      NULL },

    { ngx_string("xrootd_webdav_cafile"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, cafile),
      NULL },

    { ngx_string("xrootd_webdav_crl"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, crl),
      NULL },

    { ngx_string("xrootd_webdav_verify_depth"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, verify_depth),
      NULL },

    { ngx_string("xrootd_webdav_auth"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, auth),
      &webdav_auth_values },

    { ngx_string("xrootd_webdav_proxy_certs"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, proxy_certs),
      NULL },

    { ngx_string("xrootd_webdav_allow_write"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, common.allow_write),
      NULL },

    { ngx_string("xrootd_webdav_upload_resume"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, upload_resume),
      NULL },

    { ngx_string("xrootd_webdav_stage_dir"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, upload_stage_dir),
      NULL },

    /* phase-42: opt-in outbound GET response compression (Accept-Encoding). */
    { ngx_string("xrootd_webdav_compress"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, common.compress),
      NULL },

    { ngx_string("xrootd_webdav_tpc"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc),
      NULL },

    { ngx_string("xrootd_webdav_tape_rest"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tape_rest),
      NULL },

    { ngx_string("xrootd_webdav_tpc_allow_local"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_allow_local),
      NULL },

    { ngx_string("xrootd_webdav_tpc_allow_private"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_allow_private),
      NULL },

    { ngx_string("xrootd_webdav_tpc_curl"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_curl),
      NULL },

    { ngx_string("xrootd_webdav_tpc_cert"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_cert),
      NULL },

    { ngx_string("xrootd_webdav_tpc_key"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_key),
      NULL },

    { ngx_string("xrootd_webdav_tpc_cadir"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_cadir),
      NULL },

    { ngx_string("xrootd_webdav_tpc_cafile"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_cafile),
      NULL },

    { ngx_string("xrootd_webdav_tpc_timeout"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_timeout),
      NULL },

    /* Phase 39 (WS4): HTTP-TPC low-speed stall abort (both 0 = off). */
    { ngx_string("xrootd_webdav_tpc_low_speed_bytes"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_low_speed_bytes),
      NULL },

    { ngx_string("xrootd_webdav_tpc_low_speed_secs"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_low_speed_secs),
      NULL },

    { ngx_string("xrootd_webdav_tpc_marker_interval"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_marker_interval),
      NULL },

    { ngx_string("xrootd_webdav_tpc_max_streams"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_max_streams),
      NULL },

    { ngx_string("xrootd_webdav_tpc_token_endpoint"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_cred.token_endpoint),
      NULL },

    { ngx_string("xrootd_webdav_tpc_token_client_id"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_cred.token_client_id),
      NULL },

    { ngx_string("xrootd_webdav_tpc_token_client_secret"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_cred.token_client_secret),
      NULL },

    { ngx_string("xrootd_webdav_tpc_token_scope"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_cred.token_scope),
      NULL },

    { ngx_string("xrootd_webdav_token_jwks"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, token_jwks),
      NULL },

    { ngx_string("xrootd_webdav_token_issuer"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, token_issuer),
      NULL },

    { ngx_string("xrootd_webdav_token_audience"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, token_audience),
      NULL },
 
    { ngx_string("xrootd_webdav_macaroon_secret"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, token_macaroon_secret),
      NULL },

    { ngx_string("xrootd_webdav_macaroon_secret_old"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, token_macaroon_secret_old),
      NULL },

    { ngx_string("xrootd_webdav_thread_pool"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, common.thread_pool_name),
      NULL },

    { ngx_string("xrootd_webdav_cors_origin"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      webdav_conf_add_cors_origin,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_webdav_cors_credentials"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, cors_credentials),
      NULL },

    { ngx_string("xrootd_webdav_cors_max_age"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, cors_max_age),
      NULL },
    { ngx_string("xrootd_webdav_lock_timeout"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, lock_timeout),
      NULL },

    { ngx_string("xrootd_webdav_lock_startup_sweep"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, lock_startup_sweep),
      NULL },

    { ngx_string("xrootd_webdav_open_file_cache"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_ANY,
      webdav_conf_open_file_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, open_file_cache),
      NULL },

    { ngx_string("xrootd_webdav_open_file_cache_valid"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, open_file_cache_valid),
      NULL },

    { ngx_string("xrootd_webdav_open_file_cache_min_uses"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, open_file_cache_min_uses),
      NULL },

    { ngx_string("xrootd_webdav_open_file_cache_errors"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, open_file_cache_errors),
      NULL },

    { ngx_string("xrootd_webdav_open_file_cache_events"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, open_file_cache_events),
      NULL },

    /* --- upstream HTTP(S) proxy --- */

    { ngx_string("xrootd_webdav_proxy"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, upstream_proxy),
      NULL },

    /* Phase 23: enable the dynamic SHM backend pool (runtime add/drain/remove
     * via the admin REST API) instead of the static config-pool URL list. */
    { ngx_string("xrootd_webdav_proxy_dynamic"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, proxy_pool_enabled),
      NULL },

    /* One or more http(s):// backend URLs (round-robin + passive health). */
    { ngx_string("xrootd_webdav_proxy_upstream"),
      NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      webdav_conf_proxy_upstream,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_webdav_proxy_max_fails"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, upstream_max_fails),
      NULL },

    { ngx_string("xrootd_webdav_proxy_fail_timeout"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, upstream_fail_timeout),
      NULL },

    { ngx_string("xrootd_webdav_proxy_auth"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
      webdav_conf_proxy_auth,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* ---- Phase 24: traffic mirroring (off by default) ---- */
    { ngx_string("xrootd_mirror_url"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      xrootd_http_mirror_set_url,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_mirror_methods"),
      NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      xrootd_http_mirror_set_methods,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_mirror_sample"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, mirror.sample_pct),
      NULL },

    { ngx_string("xrootd_mirror_strip_auth"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, mirror.strip_auth),
      NULL },

    /* Opt-in gate for mirroring WRITE methods (PUT/DELETE/MKCOL/MOVE/COPY) to the
     * shadow.  Off by default; the shadow MUST be an isolated namespace, never the
     * primary's backing store. */
    { ngx_string("xrootd_mirror_writes"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, mirror.mirror_writes),
      NULL },

    { ngx_string("xrootd_mirror_log_diverge"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, mirror.log_diverge),
      NULL },

    { ngx_string("xrootd_mirror_timeout"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, mirror.timeout_ms),
      NULL },

    { ngx_string("xrootd_mirror_token"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, mirror.token),
      NULL },

    /* ---- Phase 25: advanced rate limiting / traffic shaping ---- */
    { ngx_string("xrootd_rate_limit_zone"),     /* http main: zone=NAME:SIZE */
      NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE,
      xrootd_rl_zone_directive,
      0,
      0,
      NULL },

    { ngx_string("xrootd_rate_limit_rule"),     /* loc: request-rate rule */
      NGX_HTTP_LOC_CONF | NGX_CONF_2MORE,
      xrootd_rl_rule_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, rl_rules),
      NULL },

    { ngx_string("xrootd_bandwidth_limit"),     /* loc: bandwidth rule */
      NGX_HTTP_LOC_CONF | NGX_CONF_2MORE,
      xrootd_rl_bw_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, rl_rules),
      NULL },

    { ngx_string("xrootd_concurrency_limit"),   /* loc: per-principal in-flight cap (W7) */
      NGX_HTTP_LOC_CONF | NGX_CONF_2MORE,
      xrootd_rl_conc_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, rl_rules),
      NULL },

    { ngx_string("xrootd_webdav_proxy_connect_timeout"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, upstream_conf.connect_timeout),
      NULL },

    { ngx_string("xrootd_webdav_proxy_send_timeout"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, upstream_conf.send_timeout),
      NULL },

    { ngx_string("xrootd_webdav_proxy_read_timeout"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, upstream_conf.read_timeout),
      NULL },

    /* ---- Phase 20: shared-memory KV zones, token cache, rate limiting ---- */

    /* xrootd_kv_zone <name> <size> key=<bytes> val=<bytes>;  (http main) */
    { ngx_string("xrootd_kv_zone"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE,
      xrootd_kv_zone_directive,
      0,
      0,
      NULL },

    /* xrootd_token_cache zone=<name>; */
    { ngx_string("xrootd_token_cache"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      xrootd_token_cache_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, token_cache_kv),
      NULL },

    /* xrootd_rate_limit zone=<name> rate=<N>r/s burst=<N> [key=dn|ip]; */
    { ngx_string("xrootd_rate_limit"),
      NGX_HTTP_LOC_CONF | NGX_CONF_2MORE,
      xrootd_rate_limit_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, rate_limit),
      NULL },

    /* ---- Phase 21 Step C: OIDC token introspection (revocation) ---- */

    /* Informational: the IdP /introspect endpoint URL (the actual request is
     * made by the operator-defined internal location). */
    { ngx_string("xrootd_webdav_token_introspect_url"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, introspect_url),
      NULL },

    /* Internal location URI that proxy_passes to the IdP; enables the check. */
    { ngx_string("xrootd_webdav_token_introspect_loc"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, introspect_loc),
      NULL },

    { ngx_string("xrootd_webdav_token_introspect_ttl"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, introspect_ttl),
      NULL },

    { ngx_string("xrootd_webdav_token_introspect_fail_open"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, introspect_fail_open),
      NULL },

    /* xrootd_webdav_revoke_cache zone=<name>; */
    { ngx_string("xrootd_webdav_revoke_cache"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      webdav_conf_revoke_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* ---- SciTags packet marking (src/pmark/) — see phase-34 doc ---- */
    { ngx_string("xrootd_pmark"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, common.pmark.enable), NULL },
    { ngx_string("xrootd_pmark_firefly"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, common.pmark.firefly), NULL },
    { ngx_string("xrootd_pmark_flowlabel"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, common.pmark.flowlabel), NULL },
    { ngx_string("xrootd_pmark_scitag_cgi"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, common.pmark.scitag_cgi), NULL },
    { ngx_string("xrootd_pmark_firefly_origin"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, common.pmark.firefly_origin), NULL },
    { ngx_string("xrootd_pmark_http_plain"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, common.pmark.http_plain), NULL },
    { ngx_string("xrootd_pmark_echo"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, common.pmark.echo), NULL },
    { ngx_string("xrootd_pmark_appname"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, common.pmark.appname), NULL },
    { ngx_string("xrootd_pmark_defsfile"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, common.pmark.defsfile), NULL },
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

/* Preconfiguration: register the $xrootd_protocol variable. */
/*
 * Resolve $xrootd_protocol for the current request: "webdav", "s3", or "http".
 * Precedence is webdav > s3 > plain http, decided by which sibling module is
 * enabled in this request's location conf (WebDAV wins if both somehow apply).
 * Used in log_format / proxy decisions to label the served protocol.
 */
static ngx_int_t
xrootd_http_protocol_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_xrootd_webdav_loc_conf_t *wdcf;
    ngx_http_s3_loc_conf_t            *scf;
    const char                        *label;
    size_t                             len;

    (void) data;

    label = "http";
    len = sizeof("http") - 1;

    wdcf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (wdcf != NULL && wdcf->common.enable) {
        label = "webdav";
        len = sizeof("webdav") - 1;
    } else {
        scf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_s3_module);
        if (scf != NULL && scf->common.enable) {
            label = "s3";
            len = sizeof("s3") - 1;
        }
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) label;

    return NGX_OK;
}

static ngx_int_t
xrootd_http_add_protocol_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var;
    ngx_str_t            name = ngx_string("xrootd_protocol");

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = xrootd_http_protocol_variable;
    var->data = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_xrootd_webdav_preconfiguration(ngx_conf_t *cf)
{
    return xrootd_http_add_protocol_variables(cf);
}

static ngx_int_t
ngx_http_xrootd_webdav_init_process(ngx_cycle_t *cycle)
{
    (void) cycle;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    return NGX_OK;
}

static void
ngx_http_xrootd_webdav_exit_process(ngx_cycle_t *cycle)
{
    (void) cycle;
    curl_global_cleanup();
}

static ngx_http_module_t ngx_http_xrootd_webdav_module_ctx = {
    ngx_http_xrootd_webdav_preconfiguration,  /* preconfiguration */
    ngx_http_xrootd_webdav_postconfiguration, /* postconfiguration */
    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */
    NULL,                                     /* create server configuration */
    NULL,                                     /* merge server configuration */
    ngx_http_xrootd_webdav_create_loc_conf,   /* create location config */
    ngx_http_xrootd_webdav_merge_loc_conf,    /* merge location config */
};

ngx_module_t ngx_http_xrootd_webdav_module = {
    NGX_MODULE_V1,
    &ngx_http_xrootd_webdav_module_ctx,
    ngx_http_xrootd_webdav_commands,
    NGX_HTTP_MODULE,
    NULL,  /* init_master */
    NULL,  /* init_module */
    ngx_http_xrootd_webdav_init_process,  /* init_process */
    NULL,  /* init_thread */
    NULL,  /* exit_thread */
    ngx_http_xrootd_webdav_exit_process,  /* exit_process */
    NULL,  /* exit_master */
    NGX_MODULE_V1_PADDING
};
