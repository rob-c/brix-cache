/*
 * oci_module.c — nginx wiring for the OCI Distribution plane.
 *
 * WHAT: the config lifecycle head (create_loc_conf + the UNSET sentinels the
 *       merge reads), the four directive setters that cannot be a stock slot
 *       writer, the `$oci_class` / `$oci_cache` log variables, the SHM-zone
 *       postconfiguration, the directive table and the module record.
 * WHY:  the shape is deliberately the cvmfs module's, because the lifecycle
 *       question is the same one: a location becomes a protocol endpoint the
 *       moment its enabling directive is parsed, and everything else — the
 *       metrics zone, the dashboard zones, the fill thread pool — must exist
 *       for that endpoint whether or not a stream{} block was ever configured.
 * HOW:  create sets sentinels and nothing else (the merge owns every default),
 *       the merge lives in oci_merge.c, and the two variables read the request
 *       ctx the handler fills — one enum, one name table, so the access log and
 *       the metric family can never tell different stories (Appendix J.6).
 */

#include "oci.h"
#include "oci_module_internal.h"

#include "core/compat/alloc_guard.h"
#include "core/config/config.h"            /* brix_metrics_ensure_zone */
#include "observability/dashboard/dashboard.h"
#include "protocols/shared/mirror_common.h"

static ngx_int_t ngx_http_brix_oci_postconfiguration(ngx_conf_t *cf);


/* Worker start: arm the registry's own GC sweep (§D15.5). The module owns
 * this rather than the core timer file because the timer only exists when a
 * location asked for it, and only this module knows that. */
static ngx_int_t
ngx_http_brix_oci_init_process(ngx_cycle_t *cycle)
{
    brix_oci_gc_arm_timer(cycle);
    return NGX_OK;
}


/*
 * Config lifecycle
 */

static void *
ngx_http_brix_oci_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_brix_oci_loc_conf_t *c;

    BRIX_PCALLOC_OR_RETURN(c, cf->pool, sizeof(*c), NULL);

    ngx_http_brix_shared_init(&c->common);

    c->mirror        = NGX_CONF_UNSET;
    c->insecure      = NGX_CONF_UNSET;
    c->manifest_ttl  = NGX_CONF_UNSET;
    c->registry      = NGX_CONF_UNSET;
    c->registry_anon = NGX_CONF_UNSET;
    c->max_blob      = NGX_CONF_UNSET_SIZE;
    c->upload_grace  = NGX_CONF_UNSET;
    c->gc_interval   = NGX_CONF_UNSET_MSEC;
    c->gc_grace      = NGX_CONF_UNSET;
    c->token_zone_set = NGX_CONF_UNSET;
    c->delegate        = NGX_CONF_UNSET;
    c->deleg_proof_ttl = NGX_CONF_UNSET;
    c->deleg_insecure  = NGX_CONF_UNSET;

    return c;
}


/* ---- directive setters --------------------------------------------------- */

/* "brix_oci_mirror <base-url>" — record the upstream AND make this location
 * the /v2/ endpoint. The URL is only stored here; parsing (and every refusal
 * that depends on it) happens at merge time, when inheritance has settled. */
static char *
oci_conf_mirror(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_oci_loc_conf_t *lcf = conf;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_str_t                    *value = cf->args->elts;

    (void) cmd;
    if (lcf->mirror != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    lcf->mirror     = 1;
    lcf->mirror_url = value[1];

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_brix_oci_handler;

    return NGX_CONF_OK;
}


/* "brix_oci_mirror_auth <user> <password-file>" — both halves land in the
 * loc conf as plain strings; the file is opened, permission-checked and read
 * at merge time so a bad credential is an nginx -t failure. */
static char *
oci_conf_mirror_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_oci_loc_conf_t *lcf = conf;
    ngx_str_t                    *value = cf->args->elts;

    (void) cmd;
    if (lcf->mirror_user.len > 0) {
        return "is duplicate";
    }
    if (value[1].len == 0 || value[2].len == 0) {
        return "requires a non-empty user and password file";
    }

    lcf->mirror_user   = value[1];
    lcf->mirror_pwfile = value[2];

    return NGX_CONF_OK;
}


/* "brix_oci_upstream_auth_realm <host>" — widen the realm trust boundary by
 * exactly one host, repeatably (§D15.11).
 *
 * The derived rule (upstream host, its registrable parent, a sibling under
 * that parent) covers every registry that hosts its own token service, and a
 * site whose registry delegates to an unrelated identity host would otherwise
 * be unmirrorable — which is how a check like this gets deleted rather than
 * configured. Each entry is validated HERE so a typo is an nginx -t failure
 * and not a refusal at 3am, and validated by the same authority parser a
 * realm goes through, so an entry can only name something a realm could
 * spell. There is no wildcard form on purpose. */
static char *
oci_conf_auth_realm(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_oci_loc_conf_t *lcf = conf;
    ngx_str_t                    *value = cf->args->elts;
    int                           rc;

    (void) cmd;
    if (lcf->auth_realms == NULL) {
        BRIX_PCALLOC_OR_RETURN(lcf->auth_realms, cf->pool,
                               sizeof(*lcf->auth_realms), NGX_CONF_ERROR);
    }

    rc = brix_oci_realm_list_add(lcf->auth_realms,
                                 (const char *) value[1].data, value[1].len);
    if (rc == -2) {
        return "has more entries than the allowlist holds";
    }
    if (rc == -3) {
        return "is a duplicate";
    }
    if (rc != 0) {
        return "must be one bare host - no scheme, no port, no wildcard";
    }

    return NGX_CONF_OK;
}


/* "brix_oci_registry on|off" — the flag plus the same handler install. */
static char *
oci_conf_registry(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    char                     *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_brix_oci_handler;

    return NGX_CONF_OK;
}


/* "brix_oci_token_zone <name> <size>" — sugar over the generic KV plane with
 * the D1.3 geometry pinned: a 32-byte sha256 key, a 4 KiB value. Pinning them
 * here rather than exposing key=/val= is the point of the sugar — a zone whose
 * value cap is under a real DockerHub JWT would silently cache nothing.
 *
 * The name is also written into the location config so it inherits down the
 * location tree by nginx's own rules: written in http{}, every mirror below
 * uses it; written in a location, only that subtree does. */
static char *
oci_conf_token_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_oci_loc_conf_t *lcf = conf;
    ngx_str_t                    *value = cf->args->elts;
    ngx_str_t                     name  = value[1];
    brix_kv_t                    *kv;
    ssize_t                       size;

    (void) cmd;

    lcf->token_zone_name = name;
    lcf->token_zone_set  = 1;

    size = ngx_parse_size(&value[2]);
    if (size == NGX_ERROR || size <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid brix_oci_token_zone size \"%V\"",
                           &value[2]);
        return NGX_CONF_ERROR;
    }

    if (brix_kv_find(&name) != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate brix_oci_token_zone \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    BRIX_PCALLOC_OR_RETURN(kv, cf->pool, sizeof(*kv), NGX_CONF_ERROR);

    if (brix_kv_configure(cf, kv, &name, (size_t) size,
                          BRIX_OCI_TOKEN_KEYLEN, BRIX_OCI_TOKEN_MAX,
                          &ngx_http_brix_oci_module) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* ---- $oci_class / $oci_cache --------------------------------------------- */

static ngx_int_t
oci_var_set(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    const char *val)
{
    size_t   n = ngx_strlen(val);
    u_char  *p = ngx_pnalloc(r->pool, n);

    if (p == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(p, val, n);
    v->data         = p;
    v->len          = n;
    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;
    return NGX_OK;
}


static ngx_int_t
oci_var_class(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_brix_oci_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_oci_module);

    (void) data;
    if (ctx == NULL || !ctx->classified) {
        return oci_var_set(r, v, "-");
    }
    return oci_var_set(r, v, brix_oci_class_str(ctx->req.cls));
}


/* The disposition enum is the metric label vocabulary (J.6): one source, so a
 * log line and a scrape can never disagree about what happened. `wait`,
 * `reval` and `stale` are deliberately NOT separate values in v1 — a coalesced
 * waiter and a revalidation both end as the fill that satisfied them, and
 * staleness is reported by the RFC 9111 Warning header on the response. */
static ngx_int_t
oci_var_cache(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_brix_oci_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_oci_module);
    static const char *names[BRIX_OCI_OUT_COUNT] = {
        "hit", "fill", "local", "refused", "error"
    };

    (void) data;
    if (ctx == NULL || ctx->disp >= BRIX_OCI_OUT_COUNT) {
        return oci_var_set(r, v, "-");
    }
    return oci_var_set(r, v, names[ctx->disp]);
}


static ngx_http_variable_t  ngx_http_brix_oci_vars[] = {
    { ngx_string("oci_class"), NULL, oci_var_class, 0, 0, 0 },
    { ngx_string("oci_cache"), NULL, oci_var_cache, 0, 0, 0 },
      ngx_http_null_variable
};


static ngx_int_t
ngx_http_brix_oci_preconfiguration(ngx_conf_t *cf)
{
    ngx_http_variable_t *v, *nv;

    for (v = ngx_http_brix_oci_vars; v->name.len; v++) {
        nv = ngx_http_add_variable(cf, &v->name, v->flags);
        if (nv == NULL) {
            return NGX_ERROR;
        }
        nv->get_handler = v->get_handler;
        nv->data        = v->data;
    }
    return NGX_OK;
}


/* The mirror and the registry are two arms of one module; either turns the
 * plane on, and both fill through the same pool. */
static ngx_flag_t
oci_plane_active(void *loc_conf)
{
    ngx_http_brix_oci_loc_conf_t *lcf = loc_conf;

    return lcf->mirror || lcf->registry;
}


/* Post-config: the HTTP-only node's zones, dashboard and fill pool (a mirror
 * deployment has no stream{} block to have created them). */
static ngx_int_t
ngx_http_brix_oci_postconfiguration(ngx_conf_t *cf)
{
    return brix_http_mirror_postconf(cf,
               ngx_http_brix_oci_module.ctx_index, oci_plane_active,
               "brix_oci");
}


static ngx_http_module_t ngx_http_brix_oci_module_ctx = {
    ngx_http_brix_oci_preconfiguration,   /* preconfiguration     */
    ngx_http_brix_oci_postconfiguration,  /* postconfiguration    */
    NULL,                                 /* create main conf     */
    NULL,                                 /* init main conf       */
    NULL,                                 /* create server conf   */
    NULL,                                 /* merge server conf    */
    ngx_http_brix_oci_create_loc_conf,    /* create location conf */
    ngx_http_brix_oci_merge_loc_conf,     /* merge location conf  */
};


static ngx_command_t ngx_http_brix_oci_commands[] = {

    /* ---- pull-through mirror (§0.6.1, directives_mirror.h) ---- */
#include "directives_mirror.h"

    /* ---- local registry (§0.6.2, directives_registry.h) ---- */
#include "directives_registry.h"

    ngx_null_command
};


ngx_module_t ngx_http_brix_oci_module = {
    NGX_MODULE_V1,
    &ngx_http_brix_oci_module_ctx,  /* module context     */
    ngx_http_brix_oci_commands,     /* module directives  */
    NGX_HTTP_MODULE,                /* module type        */
    NULL,                           /* init master        */
    NULL,                           /* init module        */
    ngx_http_brix_oci_init_process, /* init process       */
    NULL,                           /* init thread        */
    NULL,                           /* exit thread        */
    NULL,                           /* exit process       */
    NULL,                           /* exit master        */
    NGX_MODULE_V1_PADDING
};
