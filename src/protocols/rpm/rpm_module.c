/*
 * rpm_module.c — nginx wiring for the RPM/dnf mirror plane.
 *
 * WHAT: the config lifecycle head (create_loc_conf + the UNSET sentinels the
 *       merge reads), the one directive setter that cannot be a stock slot
 *       writer, the `$rpm_class` / `$rpm_cache` log variables, the SHM-zone
 *       postconfiguration, the directive table and the module record.
 * WHY:  the shape is deliberately the OCI module's, because the lifecycle
 *       question is the same one: a location becomes a mirror endpoint the
 *       moment its enabling directive is parsed, and everything else — the
 *       metrics zone, the dashboard zones, the fill thread pool — must exist
 *       for that endpoint whether or not a stream{} block was ever configured.
 * HOW:  create sets sentinels and nothing else (the merge owns every default),
 *       the merge lives in rpm_merge.c, and the two variables read the request
 *       ctx the handler fills — one enum, one name table, so the access log and
 *       the metric family can never tell different stories.
 */

#include "rpm.h"

#include "core/compat/alloc_guard.h"
#include "protocols/shared/mirror_common.h"


static void *
ngx_http_brix_rpm_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_brix_rpm_loc_conf_t *c;

    BRIX_PCALLOC_OR_RETURN(c, cf->pool, sizeof(*c), NULL);

    ngx_http_brix_shared_init(&c->common);

    c->mirror       = NGX_CONF_UNSET;
    c->insecure     = NGX_CONF_UNSET;
    c->prefetch     = NGX_CONF_UNSET;
    c->metadata_ttl = NGX_CONF_UNSET;

    return c;
}


/* "brix_rpm_mirror <base-url>" — record the upstream AND make this location
 * the mirror endpoint. The URL is only stored here; parsing (and every refusal
 * that depends on it) happens at merge time, when inheritance has settled. */
static char *
rpm_conf_mirror(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_rpm_loc_conf_t *lcf = conf;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_str_t                    *value = cf->args->elts;

    (void) cmd;
    if (lcf->mirror != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    lcf->mirror     = 1;
    lcf->mirror_url = value[1];

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_brix_rpm_handler;

    return NGX_CONF_OK;
}


/* ---- $rpm_class / $rpm_cache --------------------------------------------- */

static ngx_int_t
rpm_var_set(ngx_http_request_t *r, ngx_http_variable_value_t *v,
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
rpm_var_class(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_brix_rpm_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_rpm_module);

    (void) data;
    if (ctx == NULL || !ctx->classified) {
        return rpm_var_set(r, v, "-");
    }
    return rpm_var_set(r, v, brix_rpm_class_str(ctx->req.cls));
}


/* The disposition enum is the metric label vocabulary: one source, so a log
 * line and a scrape can never disagree about what happened. */
static ngx_int_t
rpm_var_cache(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_brix_rpm_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_rpm_module);
    static const char *names[BRIX_RPM_OUT_COUNT] = {
        "hit", "fill", "local", "refused", "error"
    };

    (void) data;
    if (ctx == NULL || ctx->disp >= BRIX_RPM_OUT_COUNT) {
        return rpm_var_set(r, v, "-");
    }
    return rpm_var_set(r, v, names[ctx->disp]);
}


/* phase-106 W1-a: dual registration — see the note in cvmfs/module.c. */
static ngx_http_variable_t  ngx_http_brix_rpm_vars[] = {
    { ngx_string("rpm_class"), NULL, rpm_var_class, 0, 0, 0 },
    { ngx_string("rpm_cache"), NULL, rpm_var_cache, 0, 0, 0 },
    { ngx_string("brix_rpm_class"), NULL, rpm_var_class, 0, 0, 0 },
    { ngx_string("brix_rpm_cache"), NULL, rpm_var_cache, 0, 0, 0 },
      ngx_http_null_variable
};


static ngx_int_t
ngx_http_brix_rpm_preconfiguration(ngx_conf_t *cf)
{
    ngx_http_variable_t *v, *nv;

    for (v = ngx_http_brix_rpm_vars; v->name.len; v++) {
        nv = ngx_http_add_variable(cf, &v->name, v->flags);
        if (nv == NULL) {
            return NGX_ERROR;
        }
        nv->get_handler = v->get_handler;
        nv->data        = v->data;
    }
    return NGX_OK;
}


/* One directive turns this plane on: brix_rpm_mirror. */
static ngx_flag_t
rpm_plane_active(void *loc_conf)
{
    ngx_http_brix_rpm_loc_conf_t *lcf = loc_conf;

    return lcf->mirror;
}


/* Post-config: the HTTP-only node's zones, dashboard and fill pool (a mirror
 * deployment has no stream{} block to have created them). */
static ngx_int_t
ngx_http_brix_rpm_postconfiguration(ngx_conf_t *cf)
{
    return brix_http_mirror_postconf(cf,
               ngx_http_brix_rpm_module.ctx_index, rpm_plane_active,
               "brix_rpm");
}


static ngx_http_module_t ngx_http_brix_rpm_module_ctx = {
    ngx_http_brix_rpm_preconfiguration,   /* preconfiguration     */
    ngx_http_brix_rpm_postconfiguration,  /* postconfiguration    */
    NULL,                                 /* create main conf     */
    NULL,                                 /* init main conf       */
    NULL,                                 /* create server conf   */
    NULL,                                 /* merge server conf    */
    ngx_http_brix_rpm_create_loc_conf,    /* create location conf */
    ngx_http_brix_rpm_merge_loc_conf,     /* merge location conf  */
};


static ngx_command_t ngx_http_brix_rpm_commands[] = {

    /* Marks the location as a mirror of <base-url> AND installs the content
     * handler — the location IS the repository endpoint. */
    { ngx_string("brix_rpm_mirror"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      rpm_conf_mirror,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* Freshness window for the MUTABLE half of a repository: repomd.xml and
     * anything createrepo did not name after its own checksum. Digest-named
     * metadata and packages are immutable and ignore it. */
    { ngx_string("brix_rpm_metadata_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
        | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_rpm_loc_conf_t, metadata_ttl),
      NULL },

    /* Warm the metadata a client asks for next (primary + filelists) as soon
     * as a new repomd.xml names them. Off by default: it spends upstream
     * bandwidth on an index nobody may follow up on, which is a trade only
     * the operator of the repository's clients can make. */
    { ngx_string("brix_rpm_prefetch"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
        | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_rpm_loc_conf_t, prefetch),
      NULL },

    /* Test fixtures only: permits a cleartext http:// upstream base. */
    { ngx_string("brix_rpm_mirror_insecure"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_rpm_loc_conf_t, insecure),
      NULL },

    ngx_null_command
};


ngx_module_t ngx_http_brix_rpm_module = {
    NGX_MODULE_V1,
    &ngx_http_brix_rpm_module_ctx,  /* module context     */
    ngx_http_brix_rpm_commands,     /* module directives  */
    NGX_HTTP_MODULE,                /* module type        */
    NULL,                           /* init master        */
    NULL,                           /* init module        */
    NULL,                           /* init process       */
    NULL,                           /* init thread        */
    NULL,                           /* exit thread        */
    NULL,                           /* exit process       */
    NULL,                           /* exit master        */
    NGX_MODULE_V1_PADDING
};
