/*
 * module.c — ngx_http_brix_guard_module definition and configuration.
 *
 * WHAT: the directive table, per-location config lifecycle (create/merge —
 *   including building the guard_ruleset_t the handlers classify against),
 *   and postconfiguration that registers the ACCESS + LOG phase handlers.
 * WHY:  keeps all nginx-config plumbing in one file so the handlers
 *   (classify_handler.c / audit_handler.c) stay pure request logic.
 * HOW:  standard nginx HTTP module shape (mirrors src/protocols/srr/module.c);
 *   the ruleset is assembled once per location at merge time from profile +
 *   default signatures + operator directives, so request handling never
 *   parses config.
 */

#include "guard_http.h"

static void *ngx_http_brix_guard_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_brix_guard_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_brix_guard_postconf(ngx_conf_t *cf);
static char *ngx_http_brix_guard_audit_log_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_brix_guard_array_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


static ngx_command_t ngx_http_brix_guard_commands[] = {

    { ngx_string("brix_guard"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_guard_loc_conf_t, enable),
      NULL },

    { ngx_string("brix_guard_profile"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_guard_loc_conf_t, profile),
      NULL },

    { ngx_string("brix_guard_default_signatures"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_guard_loc_conf_t, default_sigs),
      NULL },

    { ngx_string("brix_guard_bounce_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_guard_loc_conf_t, bounce_status),
      NULL },

    { ngx_string("brix_guard_audit_log"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_brix_guard_audit_log_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_guard_signature"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_brix_guard_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_guard_loc_conf_t, extra_sigs),
      NULL },

    { ngx_string("brix_guard_valid_prefix"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_brix_guard_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_guard_loc_conf_t, prefixes),
      NULL },

    { ngx_string("brix_guard_valid_method"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_brix_guard_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_guard_loc_conf_t, methods),
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_brix_guard_module_ctx = {
    NULL,                                    /* preconfiguration    */
    ngx_http_brix_guard_postconf,          /* postconfiguration   */
    NULL,                                    /* create main conf    */
    NULL,                                    /* init main conf      */
    NULL,                                    /* create srv conf     */
    NULL,                                    /* merge srv conf      */
    ngx_http_brix_guard_create_loc_conf,   /* create loc conf     */
    ngx_http_brix_guard_merge_loc_conf     /* merge loc conf      */
};


ngx_module_t ngx_http_brix_guard_module = {
    NGX_MODULE_V1,
    &ngx_http_brix_guard_module_ctx,
    ngx_http_brix_guard_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};


/* ---- Open the audit log file for a location ----
 *
 * WHAT: `brix_guard_audit_log <path>` — resolves the path through nginx's
 *   shared open-file list (append mode, reopened on USR1) into
 *   lcf->audit_log. Returns NGX_CONF_OK or NGX_CONF_ERROR.
 *
 * WHY: ngx_conf_open_file gives every worker one O_APPEND fd (short writes
 *   stay atomic) and standard log-rotation semantics for free.
 *
 * HOW: 1. Reject a duplicate directive.
 *      2. ngx_conf_open_file(cf->cycle, &value[1]).
 */
static char *
ngx_http_brix_guard_audit_log_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_brix_guard_loc_conf_t *lcf = conf;
    ngx_str_t                        *value = cf->args->elts;

    (void) cmd;

    if (lcf->audit_log != NULL) {
        return "is duplicate";
    }
    lcf->audit_log = ngx_conf_open_file(cf->cycle, &value[1]);
    if (lcf->audit_log == NULL) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


/* ---- Append directive arguments to an ngx_str_t array ----
 *
 * WHAT: generic repeatable-directive setter: pushes every argument of the
 *   directive onto the ngx_array_t at cmd->offset, creating the array on
 *   first use. Serves brix_guard_signature / _valid_prefix (TAKE1) and
 *   _valid_method (1MORE).
 *
 * WHY: the three list directives differ only in which array they fill; one
 *   setter keeps the command table declarative.
 *
 * HOW: 1. Create the array when the field is still NGX_CONF_UNSET_PTR.
 *      2. Push each value[1..nelts) (conf strings are NUL-terminated and
 *         pool-owned, so the ruleset can borrow them).
 */
static char *
ngx_http_brix_guard_array_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char         *base = conf;
    ngx_array_t **list;
    ngx_str_t    *value = cf->args->elts;
    ngx_str_t    *entry;
    ngx_uint_t    arg_index;

    list = (ngx_array_t **) (base + cmd->offset);

    if (*list == NGX_CONF_UNSET_PTR || *list == NULL) {
        *list = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (*list == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    for (arg_index = 1; arg_index < cf->args->nelts; arg_index++) {
        entry = ngx_array_push(*list);
        if (entry == NULL) {
            return NGX_CONF_ERROR;
        }
        *entry = value[arg_index];
    }
    return NGX_CONF_OK;
}


/* ---- Map an HTTP method name to a guard op-class ----
 *
 * WHAT: returns the guard_op_class_t for a method-name string ("GET",
 *   "PROPFIND", ...); GUARD_OP_UNKNOWN for names outside the table.
 *
 * WHY: brix_guard_valid_method narrows the grammar per location; the
 *   mapping must agree with the request-time one in guard_http_req.c.
 *
 * HOW: 1. Walk a static name→op descriptor table, case-insensitive compare.
 */
static guard_op_class_t
method_name_to_op(const ngx_str_t *name)
{
    static const struct { const char *name; guard_op_class_t op; } table[] = {
        { "GET",      GUARD_OP_READ   }, { "HEAD",    GUARD_OP_READ   },
        { "PUT",      GUARD_OP_WRITE  }, { "POST",    GUARD_OP_WRITE  },
        { "DELETE",   GUARD_OP_DELETE }, { "PROPFIND", GUARD_OP_LIST  },
        { "OPTIONS",  GUARD_OP_INFO   },
    };
    size_t entry_index;

    for (entry_index = 0; entry_index < sizeof(table) / sizeof(table[0]);
         entry_index++)
    {
        if (name->len == ngx_strlen(table[entry_index].name)
            && ngx_strncasecmp(name->data,
                   (u_char *) table[entry_index].name, name->len) == 0)
        {
            return table[entry_index].op;
        }
    }
    return GUARD_OP_UNKNOWN;
}


/* ---- Build the location's ruleset from merged config ----
 *
 * WHAT: assembles lcf->ruleset: profile grammar defaults, built-in +
 *   operator signatures, operator namespace prefixes, and the optional
 *   method restriction. Returns NGX_CONF_OK.
 *
 * WHY: doing this once at merge time means the ACCESS/LOG handlers only ever
 *   read a finished ruleset — no per-request config interpretation.
 *
 * HOW: 1. guard_ruleset_init.
 *      2. Built-in scanner signatures unless disabled.
 *      3. Profile grammar defaults (conf strings are NUL-terminated).
 *      4. Operator signatures (substring kind) + prefixes.
 *      5. If methods were listed: reset op_allowed to exactly those ops.
 */
static char *
ngx_http_brix_guard_build_ruleset(ngx_conf_t *cf,
    ngx_http_brix_guard_loc_conf_t *lcf)
{
    ngx_str_t  *entries;
    ngx_uint_t  entry_index;

    guard_ruleset_init(&lcf->ruleset);

    if (lcf->default_sigs) {
        guard_ruleset_add_default_signatures(&lcf->ruleset);
    }

    guard_ruleset_load_profile(&lcf->ruleset,
        lcf->profile.len ? (const char *) lcf->profile.data : "");

    if (lcf->extra_sigs != NULL) {
        entries = lcf->extra_sigs->elts;
        for (entry_index = 0; entry_index < lcf->extra_sigs->nelts;
             entry_index++)
        {
            if (!guard_ruleset_add_signature(&lcf->ruleset, GUARD_SIG_SUBSTR,
                    (const char *) entries[entry_index].data,
                    entries[entry_index].len))
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "brix_guard_signature: more than %d signatures",
                    GUARD_MAX_SIGS);
                return NGX_CONF_ERROR;
            }
        }
    }

    if (lcf->prefixes != NULL) {
        entries = lcf->prefixes->elts;
        for (entry_index = 0; entry_index < lcf->prefixes->nelts;
             entry_index++)
        {
            if (!guard_ruleset_add_prefix(&lcf->ruleset,
                    (const char *) entries[entry_index].data,
                    entries[entry_index].len))
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "brix_guard_valid_prefix: more than %d prefixes",
                    GUARD_MAX_PREFIXES);
                return NGX_CONF_ERROR;
            }
        }
    }

    if (lcf->methods != NULL && lcf->methods->nelts > 0) {
        int op_index;

        for (op_index = 0; op_index <= GUARD_OP_UNKNOWN; op_index++) {
            lcf->ruleset.op_allowed[op_index] = 0;
        }
        entries = lcf->methods->elts;
        for (entry_index = 0; entry_index < lcf->methods->nelts;
             entry_index++)
        {
            guard_op_class_t op = method_name_to_op(&entries[entry_index]);

            if (op == GUARD_OP_UNKNOWN) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "brix_guard_valid_method: unknown method \"%V\"",
                    &entries[entry_index]);
                return NGX_CONF_ERROR;
            }
            lcf->ruleset.op_allowed[op] = 1;
        }
    }

    return NGX_CONF_OK;
}


/* ---- Create the per-location config ----
 *
 * WHAT: allocates ngx_http_brix_guard_loc_conf_t with every field in the
 *   nginx "unset" state so merge can inherit from the parent level.
 *
 * WHY: standard nginx conf lifecycle — anything not UNSET here would silently
 *   shadow parent-level directives.
 *
 * HOW: 1. ngx_pcalloc (zeroes ruleset + audit_log).
 *      2. Mark scalars NGX_CONF_UNSET, arrays NGX_CONF_UNSET_PTR.
 */
static void *
ngx_http_brix_guard_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_brix_guard_loc_conf_t *lcf;

    lcf = ngx_pcalloc(cf->pool, sizeof(*lcf));
    if (lcf == NULL) {
        return NULL;
    }
    lcf->enable        = NGX_CONF_UNSET;
    lcf->default_sigs  = NGX_CONF_UNSET;
    lcf->bounce_status = NGX_CONF_UNSET;
    lcf->extra_sigs    = NGX_CONF_UNSET_PTR;
    lcf->prefixes      = NGX_CONF_UNSET_PTR;
    lcf->methods       = NGX_CONF_UNSET_PTR;
    /* profile zeroed by pcalloc; audit_log NULL = inherit */
    return lcf;
}


/* ---- Merge parent/child configs + build the ruleset ----
 *
 * WHAT: applies inheritance and defaults (bounce 444, default signatures on),
 *   validates bounce_status is 403 or 444, then builds the location's
 *   ruleset. Returns NGX_CONF_OK / NGX_CONF_ERROR.
 *
 * WHY: the ruleset must be built after every directive at every level has
 *   been seen — merge time is the single point where that holds.
 *
 * HOW: 1. Merge each scalar/array/file field from the parent.
 *      2. Reject bounce codes other than 403/444 (anything else would turn
 *         the guard into an open redirect for confusing status codes).
 *      3. Build the ruleset only for enabled locations (disabled locations
 *         keep the zeroed ruleset and never classify).
 */
static char *
ngx_http_brix_guard_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_brix_guard_loc_conf_t *prev = parent;
    ngx_http_brix_guard_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->profile, prev->profile, "");
    ngx_conf_merge_value(conf->default_sigs, prev->default_sigs, 1);
    ngx_conf_merge_value(conf->bounce_status, prev->bounce_status, 444);
    ngx_conf_merge_ptr_value(conf->extra_sigs, prev->extra_sigs, NULL);
    ngx_conf_merge_ptr_value(conf->prefixes, prev->prefixes, NULL);
    ngx_conf_merge_ptr_value(conf->methods, prev->methods, NULL);
    if (conf->audit_log == NULL) {
        conf->audit_log = prev->audit_log;
    }

    if (conf->bounce_status != 403 && conf->bounce_status != 444) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_guard_bounce_status must be 403 or 444, got %i",
            conf->bounce_status);
        return NGX_CONF_ERROR;
    }

    if (!conf->enable) {
        return NGX_CONF_OK;
    }
    return ngx_http_brix_guard_build_ruleset(cf, conf);
}


/* ---- Register the ACCESS + LOG phase handlers ----
 *
 * WHAT: pushes ngx_http_brix_guard_access_handler onto the ACCESS phase
 *   and ngx_http_brix_guard_log_handler onto the LOG phase.
 *
 * WHY: ACCESS runs before proxy_pass content — the bounce keeps junk off the
 *   backend entirely; LOG runs after the response status is known — the only
 *   place outcome signals (404/401) exist.
 *
 * HOW: 1. ngx_array_push each handler onto the core main-conf phase arrays.
 *      2. Handlers self-disable per location via lcf->enable (DECLINED/OK).
 */
static ngx_int_t
ngx_http_brix_guard_postconf(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt       *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_brix_guard_access_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_brix_guard_log_handler;

    return NGX_OK;
}
