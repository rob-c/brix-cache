#include "dashboard_http.h"

#include <stdio.h>
#include <string.h>

/*
 * dashboard/module.c - nginx HTTP module definition for the live transfer monitor.
 *
 * WHAT: Defines the ngx_http_xrootd_dashboard_module nginx HTTP module.
 *       Provides two location-level directives:
 *         xrootd_dashboard on|off   - enable the dashboard at this location
 *         xrootd_dashboard_password "secret" - set the admin password
 *       When enabled, the content handler is installed and dispatches all
 *       requests under the location to the appropriate handler.
 *
 * ROUTING:
 *   /xrootd/                    -> page_handler (HTML dashboard, after auth)
 *   /xrootd/login               -> auth_login_handler (GET form + POST verify)
 *   /xrootd/transfers           -> compatibility JSON transfer snapshot
 *   /xrootd/api/v1/<endpoint>   -> versioned JSON API
 *
 * SECURITY NOTE:
 *   The dashboard exposes client identities, file paths, and IP addresses.
 *   Operators MUST restrict access to trusted networks via nginx allow/deny
 *   rules or firewall - the module provides no IP-level access control.
 *   The password is stored in nginx.conf in plaintext; use file permissions
 *   to protect the config file.
 */

/* Forward declarations implemented in this file */
static void *ngx_http_xrootd_dashboard_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_xrootd_dashboard_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_xrootd_dashboard_set(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_xrootd_dashboard_set_password(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_xrootd_dashboard_set_session_ttl(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_xrootd_dashboard_set_cookie_path(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_xrootd_dashboard_set_users(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static ngx_int_t
dashboard_uri_eq(ngx_str_t uri, const char *literal)
{
    size_t len = ngx_strlen(literal);

    return uri.len == len && ngx_memcmp(uri.data, literal, len) == 0;
}

static ngx_int_t
dashboard_uri_prefix(ngx_str_t uri, const char *literal)
{
    size_t len = ngx_strlen(literal);

    return uri.len > len && ngx_memcmp(uri.data, literal, len) == 0;
}

static void *
ngx_http_xrootd_dashboard_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_xrootd_dashboard_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) { return NULL; }

    conf->enable      = NGX_CONF_UNSET;
    conf->session_ttl = NGX_CONF_UNSET_UINT;
    conf->idle_threshold_ms = NGX_CONF_UNSET_MSEC;
    conf->stalled_threshold_ms = NGX_CONF_UNSET_MSEC;
    conf->cluster_stale_after_ms = NGX_CONF_UNSET_MSEC;
    return conf;
}

static char *
ngx_http_xrootd_dashboard_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_xrootd_dashboard_loc_conf_t *prev = parent;
    ngx_http_xrootd_dashboard_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_uint_value(conf->session_ttl, prev->session_ttl, 28800);
    ngx_conf_merge_msec_value(conf->idle_threshold_ms,
                              prev->idle_threshold_ms, 5000);
    ngx_conf_merge_msec_value(conf->stalled_threshold_ms,
                              prev->stalled_threshold_ms, 60000);
    ngx_conf_merge_msec_value(conf->cluster_stale_after_ms,
                              prev->cluster_stale_after_ms, 90000);
    ngx_conf_merge_str_value(conf->password, prev->password, "");
    ngx_conf_merge_str_value(conf->cookie_path, prev->cookie_path, "/xrootd");
    if (conf->users == NULL) {
        conf->users = prev->users;
    }
    if (conf->stalled_threshold_ms < conf->idle_threshold_ms) {
        return "xrootd_dashboard_stalled_threshold must be greater than or equal to xrootd_dashboard_idle_threshold";
    }
    return NGX_CONF_OK;
}

/*
 * Handler for the `xrootd_dashboard on|off` directive.
 * Parses the boolean and installs the content handler when enabled.
 */
static char *
ngx_http_xrootd_dashboard_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    char                     *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) { return rv; }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_xrootd_dashboard_main_handler;
    return NGX_CONF_OK;
}

/*
 * Handler for the `xrootd_dashboard_password "value"` directive.
 * Just a string setter - the module.c does not need to know the password content.
 */
static char *
ngx_http_xrootd_dashboard_set_password(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_dashboard_loc_conf_t *lcf = conf;
    ngx_str_t                            *value;

    if (lcf->password.data != NULL) {
        return "is duplicate";
    }
    if (lcf->users != NULL) {
        return "cannot be used with xrootd_dashboard_users";
    }

    value = cf->args->elts;
    lcf->password = value[1];
    return NGX_CONF_OK;
}

static char *
ngx_http_xrootd_dashboard_set_session_ttl(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_dashboard_loc_conf_t *lcf = conf;
    ngx_str_t                            *value;
    time_t                                seconds;

    value = cf->args->elts;
    seconds = ngx_parse_time(&value[1], 1);
    if (seconds == (time_t) NGX_ERROR || seconds <= 0) {
        return "invalid time value";
    }

    lcf->session_ttl = (ngx_uint_t) seconds;
    return NGX_CONF_OK;
}

static ngx_int_t
dashboard_cookie_path_valid(ngx_str_t *path)
{
    ngx_uint_t i;

    if (path->len == 0 || path->data == NULL || path->data[0] != '/') {
        return NGX_DECLINED;
    }

    for (i = 0; i < path->len; i++) {
        if (path->data[i] < 0x20 || path->data[i] == ';') {
            return NGX_DECLINED;
        }
    }

    return NGX_OK;
}

static char *
ngx_http_xrootd_dashboard_set_cookie_path(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_dashboard_loc_conf_t *lcf = conf;
    ngx_str_t                            *value;

    value = cf->args->elts;
    if (dashboard_cookie_path_valid(&value[1]) != NGX_OK) {
        return "must be a non-empty absolute path without control characters or semicolons";
    }

    lcf->cookie_path = value[1];
    return NGX_CONF_OK;
}

static char *
ngx_http_xrootd_dashboard_set_users(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_dashboard_loc_conf_t *lcf = conf;
    ngx_str_t                            *value;
    FILE                                 *fp;
    char                                  line[2048];

    if (lcf->password.len != 0) {
        return "cannot be used with xrootd_dashboard_password";
    }
    if (lcf->users != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;
    fp = fopen((const char *) value[1].data, "r");
    if (fp == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd_dashboard_users \"%V\" is not readable",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    lcf->users = ngx_array_create(cf->pool, 4,
        sizeof(ngx_http_xrootd_dashboard_user_t));
    if (lcf->users == NULL) {
        fclose(fp);
        return NGX_CONF_ERROR;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *colon, *end;
        ngx_http_xrootd_dashboard_user_t *user;
        size_t name_len, hash_len;

        end = line + strlen(line);
        while (end > line && (end[-1] == '\n' || end[-1] == '\r')) {
            *--end = '\0';
        }
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        colon = strchr(line, ':');
        if (colon == NULL || colon == line || colon[1] == '\0') {
            fclose(fp);
            return "contains a malformed user entry";
        }

        *colon = '\0';
        name_len = strlen(line);
        hash_len = strlen(colon + 1);

        user = ngx_array_push(lcf->users);
        if (user == NULL) {
            fclose(fp);
            return NGX_CONF_ERROR;
        }

        user->username.data = ngx_pnalloc(cf->pool, name_len);
        user->password_hash.data = ngx_pnalloc(cf->pool, hash_len);
        if (user->username.data == NULL || user->password_hash.data == NULL) {
            fclose(fp);
            return NGX_CONF_ERROR;
        }
        ngx_memcpy(user->username.data, line, name_len);
        ngx_memcpy(user->password_hash.data, colon + 1, hash_len);
        user->username.len = name_len;
        user->password_hash.len = hash_len;
    }

    fclose(fp);
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_xrootd_dashboard_commands[] = {

    { ngx_string("xrootd_dashboard"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_xrootd_dashboard_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_dashboard_loc_conf_t, enable),
      NULL },

    { ngx_string("xrootd_dashboard_password"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_xrootd_dashboard_set_password,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_dashboard_session_ttl"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_xrootd_dashboard_set_session_ttl,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_dashboard_cookie_path"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_xrootd_dashboard_set_cookie_path,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_dashboard_idle_threshold"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_dashboard_loc_conf_t, idle_threshold_ms),
      NULL },

    { ngx_string("xrootd_dashboard_stalled_threshold"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_dashboard_loc_conf_t, stalled_threshold_ms),
      NULL },

    { ngx_string("xrootd_dashboard_cluster_stale_after"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_dashboard_loc_conf_t, cluster_stale_after_ms),
      NULL },

    { ngx_string("xrootd_dashboard_users"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_xrootd_dashboard_set_users,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_xrootd_dashboard_module_ctx = {
    NULL,                                        /* preconfiguration    */
    NULL,                                        /* postconfiguration   */
    NULL,                                        /* create main conf    */
    NULL,                                        /* init main conf      */
    NULL,                                        /* create srv conf     */
    NULL,                                        /* merge srv conf      */
    ngx_http_xrootd_dashboard_create_loc_conf,   /* create loc conf     */
    ngx_http_xrootd_dashboard_merge_loc_conf     /* merge loc conf      */
};

ngx_module_t ngx_http_xrootd_dashboard_module = {
    NGX_MODULE_V1,
    &ngx_http_xrootd_dashboard_module_ctx,
    ngx_http_xrootd_dashboard_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

/* ---- Main content handler dispatcher ---- */

ngx_int_t
ngx_http_xrootd_dashboard_main_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_dashboard_loc_conf_t *conf;
    ngx_str_t                             uri;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_dashboard_module);
    if (!conf->enable) {
        return NGX_HTTP_NOT_FOUND;
    }

    uri = r->uri;

    if (dashboard_uri_eq(uri, "/xrootd/transfers")) {
        return ngx_http_xrootd_dashboard_api_handler(r,
            XROOTD_DASHBOARD_API_COMPAT_TRANSFERS);
    }

    if (dashboard_uri_eq(uri, "/xrootd/api/v1/transfers")) {
        return ngx_http_xrootd_dashboard_api_handler(r,
            XROOTD_DASHBOARD_API_V1_TRANSFERS);
    }

    if (dashboard_uri_prefix(uri, "/xrootd/api/v1/transfers/")) {
        return ngx_http_xrootd_dashboard_api_handler(r,
            XROOTD_DASHBOARD_API_V1_TRANSFER_DETAIL);
    }

    if (dashboard_uri_eq(uri, "/xrootd/api/v1/snapshot")) {
        return ngx_http_xrootd_dashboard_api_handler(r,
            XROOTD_DASHBOARD_API_V1_SNAPSHOT);
    }

    if (dashboard_uri_eq(uri, "/xrootd/api/v1/events")) {
        return ngx_http_xrootd_dashboard_api_handler(r,
            XROOTD_DASHBOARD_API_V1_EVENTS);
    }

    if (dashboard_uri_eq(uri, "/xrootd/api/v1/history")) {
        return ngx_http_xrootd_dashboard_api_handler(r,
            XROOTD_DASHBOARD_API_V1_HISTORY);
    }

    if (dashboard_uri_eq(uri, "/xrootd/api/v1/cluster")) {
        return ngx_http_xrootd_dashboard_api_handler(r,
            XROOTD_DASHBOARD_API_V1_CLUSTER);
    }

    if (dashboard_uri_eq(uri, "/xrootd/api/v1/cache")) {
        return ngx_http_xrootd_dashboard_api_handler(r,
            XROOTD_DASHBOARD_API_V1_CACHE);
    }

    if (uri.len > sizeof("/xrootd/api/v1/") - 1
        && ngx_memcmp(uri.data, "/xrootd/api/v1/",
                      sizeof("/xrootd/api/v1/") - 1) == 0)
    {
        return ngx_http_xrootd_dashboard_api_handler(r,
            XROOTD_DASHBOARD_API_V1_NOT_FOUND);
    }

    if (dashboard_uri_eq(uri, "/xrootd/login"))
    {
        return ngx_http_xrootd_dashboard_login_handler(r);
    }

    if (dashboard_uri_eq(uri, "/xrootd") || dashboard_uri_eq(uri, "/xrootd/")) {
        return ngx_http_xrootd_dashboard_page_handler(r);
    }

    return NGX_HTTP_NOT_FOUND;
}
