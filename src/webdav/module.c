/*
 * module.c - nginx directive table and HTTP module object.
 */

#include "webdav.h"
#include "../compat/http_protocol_vars.h"

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

static char *
webdav_conf_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_webdav_loc_conf_t *wlcf = conf;

    time_t       inactive;
    ngx_str_t   *value, s;
    ngx_int_t    max;
    ngx_uint_t   i;

    if (wlcf->open_file_cache != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    max = 0;
    inactive = 60;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "max=", 4) == 0) {

            max = ngx_atoi(value[i].data + 4, value[i].len - 4);
            if (max <= 0) {
                goto failed;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            inactive = ngx_parse_time(&s, 1);
            if (inactive == (time_t) NGX_ERROR) {
                goto failed;
            }

            continue;
        }

        if (ngx_strcmp(value[i].data, "off") == 0) {

            wlcf->open_file_cache = NULL;

            continue;
        }

    failed:

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid \"xrootd_webdav_open_file_cache\" parameter \"%V\"",
                           &value[i]);
        return NGX_CONF_ERROR;
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

static ngx_command_t ngx_http_xrootd_webdav_commands[] = {

    { ngx_string("xrootd_webdav"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, common.enable),
      NULL },

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

    { ngx_string("xrootd_webdav_tpc"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc),
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

    { ngx_string("xrootd_webdav_proxy_upstream"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, upstream_url),
      NULL },

    { ngx_string("xrootd_webdav_proxy_auth"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
      webdav_conf_proxy_auth,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
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

    ngx_null_command
};

ngx_shm_zone_t *webdav_lock_shm_zone;

/**
 * WHAT: Preconfiguration phase — allocate shared memory zone for the WebDAV lock registry.
 *
 * Called during nginx's preconfiguration lifecycle before any server or location blocks are
 * parsed. Allocates a shared memory region (ngx_shared_memory_add) named "xrootd_webdav_lock_registry"
 * sized to sizeof(webdav_lock_table_t) + one page (ngx_pagesize). This shared memory is used by the
 * lock table (webdav_lock_table_t) for inter-worker coordination — WebDAV LOCK/UNLOCK operations across
 * different nginx worker processes need access to a common lock state store. The init callback
 * (webdav_lock_init_shm) is registered so each worker can initialize its local view of the shared zone
 * when starting up. Returns NGX_ERROR if shared memory allocation fails (would cause nginx -t to reject
 * configuration).
 */
static ngx_int_t
ngx_http_xrootd_webdav_preconfiguration(ngx_conf_t *cf)
{
    ngx_str_t  name = ngx_string("xrootd_webdav_lock_registry");
    size_t     size;

    if (xrootd_http_add_protocol_variables(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    size = sizeof(webdav_lock_table_t) + ngx_pagesize;

    webdav_lock_shm_zone = ngx_shared_memory_add(cf, &name, size,
                                                  &ngx_http_xrootd_webdav_module);
    if (webdav_lock_shm_zone == NULL) {
        return NGX_ERROR;
    }

    webdav_lock_shm_zone->init = webdav_lock_init_shm;

    return NGX_OK;
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
