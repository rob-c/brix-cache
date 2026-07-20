#include "dashboard_http.h"
#include "api_admin.h"   /* Phase 23: brix_admin_dispatch + admin directives */
#include "core/http/http_headers.h"   /* brix_http_source_offer (AGPL sec.13) */
#include "core/compat/cstr.h"         /* brix_str_cbuf */
#include "core/config/http_common.h"  /* E-1: brix_strict_security via common conf */

#include "module_internal.h"          /* ngx_http_brix_dashboard_set_users */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * dashboard/module.c - nginx HTTP module definition for the live transfer monitor.
 *
 * WHAT: Defines the ngx_http_brix_dashboard_module nginx HTTP module.
 *       Provides two location-level directives:
 *         brix_dashboard on|off   - enable the dashboard at this location
 *         brix_dashboard_password "secret" - set the admin password
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
static void *ngx_http_brix_dashboard_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_brix_dashboard_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_brix_dashboard_set(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_brix_dashboard_set_password(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_brix_dashboard_set_session_ttl(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_brix_dashboard_set_cookie_path(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static void *
ngx_http_brix_dashboard_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_brix_dashboard_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) { return NULL; }

    conf->enable      = NGX_CONF_UNSET;
    conf->anonymous   = NGX_CONF_UNSET;
    conf->session_ttl = NGX_CONF_UNSET_UINT;
    conf->idle_threshold_ms = NGX_CONF_UNSET_MSEC;
    conf->stalled_threshold_ms = NGX_CONF_UNSET_MSEC;
    conf->cluster_stale_after_ms = NGX_CONF_UNSET_MSEC;
    conf->admin_require_both = NGX_CONF_UNSET;   /* admin_allow/secret: NULL via pcalloc */
    conf->admin_rl_enable    = NGX_CONF_UNSET;
    conf->admin_rl_write_pm  = NGX_CONF_UNSET_UINT;
    conf->admin_rl_read_pm   = NGX_CONF_UNSET_UINT;
    conf->vfs_browse = NGX_CONF_UNSET;
    conf->scan_max_files = NGX_CONF_UNSET_UINT;
    return conf;
}

/*
 * One confinement-root canonicalization request: the merged `root` value, this
 * level's `canon` buffer to fill, the parent's `prev_canon` to inherit from, the
 * directive name for the "not accessible" log line, and the config-error string
 * to surface when the path is too long. `canon`/`prev_canon` are char[PATH_MAX].
 */
typedef struct {
    ngx_str_t  *root;
    char       *canon;
    const char *prev_canon;
    const char *directive;
    char       *too_long_msg;
} dashboard_canon_root_t;

/*
 * WHAT: Resolve a confinement root directive's realpath into req->canon, or
 *       inherit the parent's already-resolved canon when this level left it unset.
 * WHY:  browse_root and scan_root share identical canonicalize-once-or-inherit
 *       logic (a configured-but-bad path fails config loudly, like an export
 *       root); one helper removes the duplicate block and its branch count.
 * HOW:  If canon is empty and root is set, copy root to a NUL-terminated buffer
 *       and realpath() it into canon; on failure log with directive + root and
 *       return NGX_CONF_ERROR (via *err). If canon is empty but the parent's is
 *       set, inherit it. Returns NGX_OK on success; NGX_ERROR with *err set to
 *       the config-error string on failure (too_long_msg for an over-length
 *       path). Empty root => feature off.
 */
static ngx_int_t
dashboard_merge_canon_root(ngx_conf_t *cf, const dashboard_canon_root_t *req,
    char **err)
{
    if (req->canon[0] == '\0' && req->root->len > 0) {
        char tmp[PATH_MAX];

        if (brix_str_cbuf(tmp, sizeof(tmp), req->root) == NULL) {
            *err = req->too_long_msg;
            return NGX_ERROR;
        }
        if (realpath(tmp, req->canon) == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                "%s \"%V\" is not accessible", req->directive, req->root);
            *err = NGX_CONF_ERROR;
            return NGX_ERROR;
        }
        return NGX_OK;
    }
    if (req->canon[0] == '\0' && req->prev_canon[0] != '\0') {
        ngx_memcpy(req->canon, req->prev_canon, PATH_MAX);
    }
    return NGX_OK;
}

static char *
ngx_http_brix_dashboard_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_brix_dashboard_loc_conf_t *prev = parent;
    ngx_http_brix_dashboard_loc_conf_t *conf = child;
    char                               *err = NULL;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->anonymous, prev->anonymous, 0);
    ngx_conf_merge_uint_value(conf->session_ttl, prev->session_ttl, 28800);
    ngx_conf_merge_msec_value(conf->idle_threshold_ms,
                              prev->idle_threshold_ms, 5000);
    ngx_conf_merge_msec_value(conf->stalled_threshold_ms,
                              prev->stalled_threshold_ms, 60000);
    ngx_conf_merge_msec_value(conf->cluster_stale_after_ms,
                              prev->cluster_stale_after_ms, 90000);
    ngx_conf_merge_str_value(conf->password, prev->password, "");
    ngx_conf_merge_str_value(conf->cookie_path, prev->cookie_path, "/brix");
    if (conf->users == NULL) {
        conf->users = prev->users;
    }
    /* Phase 23 admin API: inherit allow/secret; require_both defaults off. */
    if (conf->admin_allow == NULL) {
        conf->admin_allow = prev->admin_allow;
    }
    ngx_conf_merge_str_value(conf->admin_secret, prev->admin_secret, "");
    ngx_conf_merge_value(conf->admin_require_both, prev->admin_require_both, 0);

    /* Admin API per-IP throttle: on by default with generous limits (a runaway
     * client must not DoS the admin surface, but heavy legitimate querying —
     * dashboards, monitoring sweeps — must keep working).  Finalizing builds
     * the rules and provisions the dedicated SHM zone; skipped when the
     * dashboard is off here (no admin endpoint to protect) or the operator
     * said `brix_admin_rate_limit off`. */
    ngx_conf_merge_value(conf->admin_rl_enable, prev->admin_rl_enable, 1);
    ngx_conf_merge_uint_value(conf->admin_rl_write_pm,
                              prev->admin_rl_write_pm, 120);
    ngx_conf_merge_uint_value(conf->admin_rl_read_pm,
                              prev->admin_rl_read_pm, 1200);
    if (conf->enable && conf->admin_rl_enable
        && brix_admin_rl_finalize(cf, conf) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    /* Admin file-browser root: canonicalize once (realpath) into browse_root_canon
     * so request-time confinement has a stable anchor.  Empty => feature off.  A
     * configured-but-bad path fails config loudly (like an export root). */
    ngx_conf_merge_str_value(conf->browse_root, prev->browse_root, "");
    {
        dashboard_canon_root_t browse = {
            &conf->browse_root, conf->browse_root_canon,
            prev->browse_root_canon, "brix_dashboard_browse_root",
            "brix_dashboard_browse_root path too long"
        };
        if (dashboard_merge_canon_root(cf, &browse, &err) != NGX_OK) {
            return err;
        }
    }

    /* Storage-scan root: canonicalize once (realpath) into scan_root_canon, the
     * confinement anchor for the /scan endpoint.  Empty => feature off (404). */
    ngx_conf_merge_str_value(conf->scan_root, prev->scan_root, "");
    ngx_conf_merge_value(conf->vfs_browse, prev->vfs_browse, 0);
    ngx_conf_merge_uint_value(conf->scan_max_files, prev->scan_max_files, 100000);
    {
        dashboard_canon_root_t scan = {
            &conf->scan_root, conf->scan_root_canon, prev->scan_root_canon,
            "brix_scan_root", "brix_scan_root path too long"
        };
        if (dashboard_merge_canon_root(cf, &scan, &err) != NGX_OK) {
            return err;
        }
    }
    /* Cross-field invariant: a transfer cannot become "stalled" before it is
     * even "idle", so reject a config that inverts the two thresholds. */
    if (conf->stalled_threshold_ms < conf->idle_threshold_ms) {
        return "brix_dashboard_stalled_threshold must be greater than or equal to brix_dashboard_idle_threshold";
    }

    /* E-1: the dashboard exposes client identities, file paths and IPs; serving
     * it anonymously (no login) publishes all of that to any reader. Warn
     * always; refuse under strict security. The strict flag lives on the shared
     * common conf (the dashboard has no preamble of its own), so read it from
     * the common module's location conf, where directive inheritance already
     * resolved it. */
    if (conf->enable && conf->anonymous) {
        ngx_http_brix_common_conf_t *ucf =
            ngx_http_conf_get_module_loc_conf(cf, ngx_http_brix_common_module);
        ngx_flag_t strict = (ucf != NULL && ucf->common.strict_security == 1);

        if (brix_shared_security_gate(cf, strict,
                "dashboard served anonymously — client identities, paths and "
                "IPs are readable without a login",
                "brix_dashboard_anonymous off") != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}

/*
 * Handler for the `brix_dashboard on|off` directive.
 * Parses the boolean and installs the content handler when enabled.
 */
static char *
ngx_http_brix_dashboard_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    char                     *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) { return rv; }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_brix_dashboard_main_handler;
    return NGX_CONF_OK;
}

/*
 * Handler for the `brix_dashboard_password "value"` directive.
 * Just a string setter - the module.c does not need to know the password content.
 */
static char *
ngx_http_brix_dashboard_set_password(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_dashboard_loc_conf_t *lcf = conf;
    ngx_str_t                            *value;

    /* Single-user (password) and multi-user (users file) modes are mutually
     * exclusive — see auth.c, which keys off which one is set. */
    if (lcf->password.data != NULL) {
        return "is duplicate";
    }
    if (lcf->users != NULL) {
        return "cannot be used with brix_dashboard_users";
    }

    value = cf->args->elts;
    lcf->password = value[1];
    return NGX_CONF_OK;
}

static char *
ngx_http_brix_dashboard_set_session_ttl(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_dashboard_loc_conf_t *lcf = conf;
    ngx_str_t                            *value;
    time_t                                seconds;

    value = cf->args->elts;
    seconds = ngx_parse_time(&value[1], 1);
    /* seconds <= 0 already covers the NGX_ERROR (-1) parse-failure sentinel. */
    if (seconds <= 0) {
        return "invalid time value";
    }

    lcf->session_ttl = (ngx_uint_t) seconds;
    return NGX_CONF_OK;
}

/*
 * Validate a cookie Path attribute. Must be a non-empty absolute path, and must
 * contain no control bytes or ';' — those would let the value break out of the
 * Set-Cookie attribute and inject further attributes (header/cookie injection).
 */
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
ngx_http_brix_dashboard_set_cookie_path(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_dashboard_loc_conf_t *lcf = conf;
    ngx_str_t                            *value;

    value = cf->args->elts;
    if (dashboard_cookie_path_valid(&value[1]) != NGX_OK) {
        return "must be a non-empty absolute path without control characters or semicolons";
    }

    lcf->cookie_path = value[1];
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_brix_dashboard_commands[] = {

    { ngx_string("brix_dashboard"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_brix_dashboard_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_dashboard_loc_conf_t, enable),
      NULL },

    /* Anonymous (no-login) read-only tier: stats with PII/secrets redacted. */
    { ngx_string("brix_dashboard_anonymous"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_dashboard_loc_conf_t, anonymous),
      NULL },

    { ngx_string("brix_dashboard_password"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_brix_dashboard_set_password,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_dashboard_session_ttl"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_brix_dashboard_set_session_ttl,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_dashboard_cookie_path"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_brix_dashboard_set_cookie_path,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_dashboard_idle_threshold"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_dashboard_loc_conf_t, idle_threshold_ms),
      NULL },

    { ngx_string("brix_dashboard_stalled_threshold"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_dashboard_loc_conf_t, stalled_threshold_ms),
      NULL },

    { ngx_string("brix_dashboard_cluster_stale_after"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_dashboard_loc_conf_t, cluster_stale_after_ms),
      NULL },

    { ngx_string("brix_dashboard_users"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_brix_dashboard_set_users,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* Admin file browser root — empty (default) disables the file viewer. */
    { ngx_string("brix_dashboard_browse_root"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_dashboard_loc_conf_t, browse_root),
      NULL },

    /* Storage-scan root — empty (default) disables the /scan endpoint. */
    { ngx_string("brix_scan_root"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_dashboard_loc_conf_t, scan_root),
      NULL },

    /* VFS export browser endpoints (/api/v1/vfs*): admin-auth, read-only,
     * OFF by default — turning it on exposes stored user data through the
     * dashboard, so the operator must opt in. */
    { ngx_string("brix_dashboard_vfs_browse"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_dashboard_loc_conf_t, vfs_browse),
      NULL },

    /* Operator cap on files visited per scan request (default 100000). */
    { ngx_string("brix_scan_max_files"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_dashboard_loc_conf_t, scan_max_files),
      NULL },

    /* Phase 23: admin write API auth */    { ngx_string("brix_admin_allow"),       /* CIDR allowlist */
      NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      brix_admin_set_allow,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_admin_secret"),      /* bearer secret file path */
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_admin_set_secret,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_admin_require_both"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_dashboard_loc_conf_t, admin_require_both),
      NULL },

    { ngx_string("brix_admin_proxy_allow"), /* W6: dynamic-backend host allowlist */
      NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      brix_admin_set_proxy_allow,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_admin_rate_limit"),  /* off | <writes/min> [<reads/min>] */
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
      brix_admin_set_rate_limit,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_brix_dashboard_module_ctx = {
    NULL,                                        /* preconfiguration    */
    NULL,                                        /* postconfiguration   */
    NULL,                                        /* create main conf    */
    NULL,                                        /* init main conf      */
    NULL,                                        /* create srv conf     */
    NULL,                                        /* merge srv conf      */
    ngx_http_brix_dashboard_create_loc_conf,   /* create loc conf     */
    ngx_http_brix_dashboard_merge_loc_conf     /* merge loc conf      */
};

ngx_module_t ngx_http_brix_dashboard_module = {
    NGX_MODULE_V1,
    &ngx_http_brix_dashboard_module_ctx,
    ngx_http_brix_dashboard_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};
