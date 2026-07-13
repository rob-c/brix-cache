#include "dashboard_http.h"
#include "api_admin.h"   /* Phase 23: brix_admin_dispatch + admin directives */
#include "core/http/http_headers.h"   /* brix_http_source_offer (AGPL sec.13) */
#include "core/compat/cstr.h"         /* brix_str_cbuf */

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
static char *ngx_http_brix_dashboard_set_users(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

/* Exact URI match (length and bytes). */
static ngx_int_t
dashboard_uri_eq(ngx_str_t uri, const char *literal)
{
    size_t len = ngx_strlen(literal);

    return uri.len == len && ngx_memcmp(uri.data, literal, len) == 0;
}

/* Strict prefix match: uri must be STRICTLY longer than `literal` (uri.len >
 * len), so a bare collection path does not match its own "<path>/" prefix form —
 * letting _eq and _prefix routes coexist (e.g. ".../transfers" vs
 * ".../transfers/<id>"). */
static ngx_int_t
dashboard_uri_prefix(ngx_str_t uri, const char *literal)
{
    size_t len = ngx_strlen(literal);

    return uri.len > len && ngx_memcmp(uri.data, literal, len) == 0;
}

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

/*
 * WHAT: Directive setter for `brix_dashboard_users <file>` — load an
 *       htpasswd-style "username:hash" file into the loc-conf users array.
 * HOW:  Parse line by line at config time: strip trailing CR/LF in place, skip
 *       blank and '#'-comment lines, split on the first ':' (username before,
 *       crypt/plaintext hash after), and copy both halves into pool memory.
 *       A malformed entry (no ':', empty name, empty hash) aborts config load.
 * NOTE: Every early return after fopen() closes fp to avoid leaking the FILE*.
 */
/* Outcome of parsing one line of a brix_dashboard_users file. */
typedef enum {
    DASH_USER_LINE_SKIP = 0,   /* blank or '#'-comment: ignore, keep going */
    DASH_USER_LINE_OK,         /* one user pushed into the array           */
    DASH_USER_LINE_MALFORMED,  /* no ':', empty name, or empty hash        */
    DASH_USER_LINE_OOM         /* pool allocation / array push failed      */
} dashboard_user_line_t;

/*
 * WHAT: Parse ONE htpasswd-style "username:hash" line into a new user entry in
 *       `users`.  Blank and '#'-comment lines are skipped.
 * WHY:  Isolating the per-line logic keeps the file loop flat (open/read/close
 *       only) and removes its nested branch count, with no behavior change.
 * HOW:  Trim trailing CR/LF in place; skip blank/comment; split on the first
 *       ':' (reject absent / leading / empty-hash as MALFORMED); copy both
 *       halves into pool memory (OOM on any allocation failure). The '\0' NUL
 *       written over ':' makes `line` the username and colon+1 the hash.
 */
static dashboard_user_line_t
dashboard_parse_user_line(ngx_conf_t *cf, char *line, ngx_array_t *users)
{
    char                           *colon, *end;
    ngx_http_brix_dashboard_user_t *user;
    size_t                          name_len, hash_len;

    /* Trim trailing CR/LF in place. */
    end = line + strlen(line);
    while (end > line && (end[-1] == '\n' || end[-1] == '\r')) {
        *--end = '\0';
    }
    if (line[0] == '\0' || line[0] == '#') {
        return DASH_USER_LINE_SKIP;
    }

    /* Split on the first ':'. Reject if absent, leading (empty username),
     * or with nothing after it (empty hash). */
    colon = strchr(line, ':');
    if (colon == NULL || colon == line || colon[1] == '\0') {
        return DASH_USER_LINE_MALFORMED;
    }

    /* NUL the ':' so `line` is the username; colon+1 is the hash. */
    *colon = '\0';
    name_len = strlen(line);
    hash_len = strlen(colon + 1);

    user = ngx_array_push(users);
    if (user == NULL) {
        return DASH_USER_LINE_OOM;
    }

    user->username.data = ngx_pnalloc(cf->pool, name_len);
    user->password_hash.data = ngx_pnalloc(cf->pool, hash_len);
    if (user->username.data == NULL || user->password_hash.data == NULL) {
        return DASH_USER_LINE_OOM;
    }
    ngx_memcpy(user->username.data, line, name_len);
    ngx_memcpy(user->password_hash.data, colon + 1, hash_len);
    user->username.len = name_len;
    user->password_hash.len = hash_len;
    return DASH_USER_LINE_OK;
}

static char *
ngx_http_brix_dashboard_set_users(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_dashboard_loc_conf_t *lcf = conf;
    ngx_str_t                            *value;
    FILE                                 *fp;
    char                                  line[2048];
    char                                 *err = NULL;

    /* Mutually exclusive with single-user password mode (see auth.c). */
    if (lcf->password.len != 0) {
        return "cannot be used with brix_dashboard_password";
    }
    if (lcf->users != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;
    fp = fopen((const char *) value[1].data, "r");
    if (fp == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "brix_dashboard_users \"%V\" is not readable",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    lcf->users = ngx_array_create(cf->pool, 4,
        sizeof(ngx_http_brix_dashboard_user_t));
    if (lcf->users == NULL) {
        (void) fclose(fp);  /* read-only stream; nothing to recover on close */
        return NGX_CONF_ERROR;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        switch (dashboard_parse_user_line(cf, line, lcf->users)) {
        case DASH_USER_LINE_MALFORMED:
            err = "contains a malformed user entry";
            break;
        case DASH_USER_LINE_OOM:
            err = NGX_CONF_ERROR;
            break;
        default:            /* SKIP or OK: continue reading */
            continue;
        }
        (void) fclose(fp);  /* read-only stream; close failure irrelevant */
        return err;
    }

    (void) fclose(fp);  /* read-only stream; nothing to recover on close */
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

/*
 * Route-table dispatch (main_handler decomposition).
 *
 * Two ordered `static const` tables replace the former if-ladder while keeping
 * byte-identical routing.  Every match test is either `dashboard_uri_eq` (exact)
 * or `dashboard_uri_prefix` (strictly-longer prefix); both are mutually
 * exclusive across distinct literals, so within a table order does not change
 * which literal a URI matches.  The ORDER BETWEEN groups is what stays frozen:
 * concrete API/handler routes first, then the admin prefix, then the generic
 * "/api/v1/" catch-all, then the page/login tail — most-specific first.
 */

/* How a route row matches its literal against the request URI. */
typedef enum {
    DASH_MATCH_EQ = 0,   /* exact match  (dashboard_uri_eq)     */
    DASH_MATCH_PREFIX    /* strict prefix (dashboard_uri_prefix) */
} dashboard_match_kind_t;

/* A route that dispatches into the versioned JSON API by endpoint id. */
typedef struct {
    dashboard_match_kind_t         match;
    const char                    *literal;
    brix_dashboard_api_endpoint_e  endpoint;
} dashboard_api_route_t;

/* A route that dispatches to a dedicated per-endpoint handler (exact match). */
typedef struct {
    const char *literal;
    ngx_int_t (*handler)(ngx_http_request_t *r);
} dashboard_handler_route_t;

/*
 * Concrete versioned-API routes (compat + /api/v1/ *).  Exact rows are mutually
 * exclusive; the single PREFIX row (".../transfers/") is exclusive from the
 * exact ".../transfers" because prefix requires uri STRICTLY longer.
 */
static const dashboard_api_route_t dashboard_api_routes[] = {
    { DASH_MATCH_EQ,     "/brix/transfers",             BRIX_DASHBOARD_API_COMPAT_TRANSFERS },
    { DASH_MATCH_EQ,     "/brix/api/v1/transfers",      BRIX_DASHBOARD_API_V1_TRANSFERS },
    { DASH_MATCH_PREFIX, "/brix/api/v1/transfers/",     BRIX_DASHBOARD_API_V1_TRANSFER_DETAIL },
    { DASH_MATCH_EQ,     "/brix/api/v1/snapshot",       BRIX_DASHBOARD_API_V1_SNAPSHOT },
    { DASH_MATCH_EQ,     "/brix/api/v1/events",         BRIX_DASHBOARD_API_V1_EVENTS },
    { DASH_MATCH_EQ,     "/brix/api/v1/history",        BRIX_DASHBOARD_API_V1_HISTORY },
    { DASH_MATCH_EQ,     "/brix/api/v1/cluster",        BRIX_DASHBOARD_API_V1_CLUSTER },
    { DASH_MATCH_EQ,     "/brix/api/v1/cache",          BRIX_DASHBOARD_API_V1_CACHE },
    { DASH_MATCH_EQ,     "/brix/api/v1/ratelimit",      BRIX_DASHBOARD_API_V1_RATELIMIT },  /* Phase 25 */
    { DASH_MATCH_EQ,     "/brix/api/v1/cvmfs",          BRIX_DASHBOARD_API_V1_CVMFS },      /* phase-68 */
};

/*
 * Dedicated-handler routes (exact match).  All ALWAYS auth-only inside their
 * handler and 404 when the backing feature is unconfigured:
 *   config   text/plain config download (never anonymous)
 *   files/download    admin file browser, confined to browse_root
 *   vfs*     VFS export browser (brix_dashboard_vfs_browse), all via brix_vfs_*
 *   scan     storage scan/verify/fill engine, confined to scan_root
 * These must all precede the generic "/api/v1/" catch-all.
 */
static const dashboard_handler_route_t dashboard_handler_routes[] = {
    { "/brix/api/v1/config",       ngx_http_brix_dashboard_config_download_handler },
    { "/brix/api/v1/files",        ngx_http_brix_dashboard_files_handler },
    { "/brix/api/v1/download",     ngx_http_brix_dashboard_download_handler },
    { "/brix/api/v1/vfs",          ngx_http_brix_dashboard_vfs_exports_handler },
    { "/brix/api/v1/vfs/files",    ngx_http_brix_dashboard_vfs_files_handler },
    { "/brix/api/v1/vfs/download", ngx_http_brix_dashboard_vfs_download_handler },
    { "/brix/api/v1/scan",         ngx_http_brix_dashboard_scan_handler },
};

/*
 * WHAT: True when `uri` matches `route`'s literal under its match kind.
 * WHY:  Single predicate keeps the two dispatch loops branch-free of the
 *       eq-vs-prefix distinction, preserving the exact original semantics.
 * HOW:  Delegate to the same _eq/_prefix helpers the if-ladder used.
 */
static ngx_int_t
dashboard_api_route_matches(ngx_str_t uri, const dashboard_api_route_t *route)
{
    if (route->match == DASH_MATCH_PREFIX) {
        return dashboard_uri_prefix(uri, route->literal);
    }
    return dashboard_uri_eq(uri, route->literal);
}

/*
 * WHAT: Try the concrete versioned-API routes; on the first match, dispatch to
 *       the JSON API handler for that endpoint and store the result in *out.
 * WHY:  Collapses ten identical eq/prefix -> api_handler branches into one
 *       ordered scan without changing which URI hits which endpoint id.
 * HOW:  Linear scan of dashboard_api_routes (exact rows are mutually exclusive;
 *       order is irrelevant within them). Returns NGX_OK on a match, NGX_DECLINED
 *       when no API route applies so the caller falls through to later groups.
 */
static ngx_int_t
dashboard_dispatch_api_route(ngx_http_request_t *r, ngx_str_t uri,
    ngx_int_t *out)
{
    size_t i;

    for (i = 0; i < sizeof(dashboard_api_routes)
                        / sizeof(dashboard_api_routes[0]); i++) {
        if (dashboard_api_route_matches(uri, &dashboard_api_routes[i])) {
            *out = ngx_http_brix_dashboard_api_handler(r,
                dashboard_api_routes[i].endpoint);
            return NGX_OK;
        }
    }
    return NGX_DECLINED;
}

/*
 * WHAT: Try the dedicated-handler routes; on the first exact match, invoke that
 *       handler and store its result in *out.
 * WHY:  Collapses the config/files/download/vfs* / scan exact-match branches into
 *       one scan; all rows are exact and mutually exclusive.
 * HOW:  Linear scan of dashboard_handler_routes. Returns NGX_OK on a match,
 *       NGX_DECLINED otherwise (caller continues to the prefix/catch-all/tail).
 */
static ngx_int_t
dashboard_dispatch_handler_route(ngx_http_request_t *r, ngx_str_t uri,
    ngx_int_t *out)
{
    size_t i;

    for (i = 0; i < sizeof(dashboard_handler_routes)
                        / sizeof(dashboard_handler_routes[0]); i++) {
        if (dashboard_uri_eq(uri, dashboard_handler_routes[i].literal)) {
            *out = dashboard_handler_routes[i].handler(r);
            return NGX_OK;
        }
    }
    return NGX_DECLINED;
}

/* Main content handler dispatcher */
/*
 * WHAT: Content handler installed at the dashboard location; routes the request
 *       URI to the page, login, compat-JSON, versioned-API, or admin handler.
 * HOW:  Groups are tried MOST-SPECIFIC FIRST so exact matches win over prefix
 *       matches (e.g. ".../transfers" before ".../transfers/<id>", and the
 *       known v1 endpoints before the catch-all "/api/v1/" 404). Per-endpoint
 *       auth lives inside the called handlers, not here. Unmatched -> 404.
 */
ngx_int_t
ngx_http_brix_dashboard_main_handler(ngx_http_request_t *r)
{
    ngx_http_brix_dashboard_loc_conf_t *conf;
    ngx_str_t                           uri;
    ngx_int_t                           rc = NGX_DECLINED;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_dashboard_module);
    if (!conf->enable) {
        return NGX_HTTP_NOT_FOUND;
    }

    /* AGPL-3.0 sec.13: offer remote users the source (X-Source header). */
    brix_http_source_offer(r);

    uri = r->uri;

    if (dashboard_dispatch_api_route(r, uri, &rc) == NGX_OK) {
        return rc;
    }
    if (dashboard_dispatch_handler_route(r, uri, &rc) == NGX_OK) {
        return rc;
    }

    /* Phase 23: admin write API (auth + method routing inside dispatch). */
    if (uri.len >= sizeof("/brix/api/v1/admin/") - 1
        && ngx_memcmp(uri.data, "/brix/api/v1/admin/",
                      sizeof("/brix/api/v1/admin/") - 1) == 0)
    {
        return brix_admin_dispatch(r);
    }

    /* Catch-all for unknown /api/v1/ paths: return the API's structured 404
     * (must come AFTER every concrete v1 route above). */
    if (uri.len > sizeof("/brix/api/v1/") - 1
        && ngx_memcmp(uri.data, "/brix/api/v1/",
                      sizeof("/brix/api/v1/") - 1) == 0)
    {
        return ngx_http_brix_dashboard_api_handler(r,
            BRIX_DASHBOARD_API_V1_NOT_FOUND);
    }

    if (dashboard_uri_eq(uri, "/brix/login"))
    {
        return ngx_http_brix_dashboard_login_handler(r);
    }

    if (dashboard_uri_eq(uri, "/brix") || dashboard_uri_eq(uri, "/brix/")) {
        return ngx_http_brix_dashboard_page_handler(r);
    }

    return NGX_HTTP_NOT_FOUND;
}
