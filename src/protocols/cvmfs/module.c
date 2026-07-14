/*
 * module.c — nginx directive table, config lifecycle, and HTTP module context
 * for the dedicated cvmfs:// protocol plane.
 *
 * WHAT: The module's nginx wiring, mirroring src/protocols/s3/module.c:
 *   1. Config lifecycle head: create_loc_conf allocates
 *      ngx_http_brix_cvmfs_loc_conf_t (shared preamble + cvmfs knobs) and
 *      sets the UNSET sentinels; the merge is delegated to sibling files
 *      (see below).
 *   2. Handler install (ngx_http_brix_cvmfs_set): the "brix_cvmfs"
 *      directive parses its flag and installs ngx_http_brix_cvmfs_handler
 *      as the location's content handler — the location IS the protocol
 *      endpoint; no WebDAV dispatch is involved.
 *   3. Directive table: the brix_cvmfs_* family (split into the two
 *      directives_*.inc fragments) and its enums.
 *   4. nginx $cvmfs_* variables + pre/post-configuration + init-process
 *      and the ngx_module_t definition.
 *
 * WHY: cvmfs:// is a first-class protocol. A CVMFS site cache is read-only
 *      by construction (allow_write is forced off) and typically a PURE cache
 *      node: no local export tree. When no root is configured the root
 *      anchors at "/" (the same pure-cache-node semantics the stream plane
 *      uses): the location serves the "/" namespace, filling from the http
 *      origin backend into the cache store.
 *
 * HOW: create follows the s3 module's manual common.* init idiom (established
 *      phase-64 gotcha: no shared_init). The location merge grew past the
 *      file-size gate and is split across three siblings, wired here through
 *      cvmfs_module_internal.h: cvmfs_module_merge.c owns the merge-field
 *      helpers + the ngx_http_brix_cvmfs_merge_loc_conf orchestrator installed
 *      in the module context; cvmfs_module_build.c owns the enabled-branch
 *      export/backend/cache build; cvmfs_module_georank.c owns the geographic
 *      origin-ranking and coordinate/allow-list directive setters referenced by
 *      the directive table. Postconfiguration resolves the thread pool per
 *      server exactly as s3 does — the cache fill/offload helpers need it.
 */

#include "cvmfs.h"
#include "cvmfs_module_internal.h"         /* cross-file seam: georank/merge/build */
#include "core/config/config.h"           /* brix_metrics_ensure_zone */
#include "core/config/root_prepare.h"
#include "core/config/http_rootfd.h"
#include "core/config/http_common.h"       /* unified brix_* directive adoption */
#include "core/compat/alloc_guard.h"
#include "fs/cache/verify.h"               /* brix_cache_verify_mode_e */
#include "fs/vfs/vfs_backend_registry.h"
#include "origin_geo.h"
#include "fs/backend/http/sd_http.h"       /* SD_HTTP_EP_MAX */
#include "auth/token/issuer_registry.h"    /* scvmfs bearer registry (T22) */
#include "fs/backend/cache/sd_cache.h"     /* unwrap for $cvmfs_origin (T16) */
#include "fs/cache/origin/s3_transport.h"  /* brix_origin_trace_set (trace) */

#include <stdlib.h>                        /* strtod (coord parsing) */

static ngx_int_t ngx_http_brix_cvmfs_postconfiguration(ngx_conf_t *cf);

/*
 * Config lifecycle
 */

static void *
ngx_http_brix_cvmfs_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_brix_cvmfs_loc_conf_t *c;

    BRIX_PCALLOC_OR_RETURN(c, cf->pool, sizeof(*c), NULL);

    ngx_http_brix_shared_init(&c->common);

    c->cvmfs.enable         = NGX_CONF_UNSET;
    c->cvmfs.manifest_ttl   = NGX_CONF_UNSET;
    c->cvmfs.negative_ttl   = NGX_CONF_UNSET;
    c->cvmfs.upstream_allow = NGX_CONF_UNSET_PTR;
    c->cvmfs.upstream_max   = NGX_CONF_UNSET_UINT;
    c->cvmfs.origin_select  = NGX_CONF_UNSET_UINT;
    c->cvmfs.origin_coords  = NGX_CONF_UNSET_PTR;
    c->cvmfs.rtt_interval   = NGX_CONF_UNSET;
    c->cvmfs.client_hold    = NGX_CONF_UNSET;
    c->cvmfs.fill_max_life  = NGX_CONF_UNSET;
    c->cvmfs.trace          = NGX_CONF_UNSET;
    c->cvmfs.origin_connect_timeout = NGX_CONF_UNSET;
    c->cvmfs.origin_stall_timeout   = NGX_CONF_UNSET;
    c->cvmfs.origin_stall_bytes     = NGX_CONF_UNSET_UINT;
    c->cvmfs.origin_attempt_timeout = NGX_CONF_UNSET;
    c->cvmfs.origin_reuse_conn      = NGX_CONF_UNSET;
    c->cvmfs.fill_retry_policy      = NGX_CONF_UNSET_UINT;
    c->cvmfs.shared_cache           = NGX_CONF_UNSET;
    c->cvmfs.unified_origin         = NGX_CONF_UNSET;
    c->cvmfs.geo_answer             = NGX_CONF_UNSET_UINT;
    c->cvmfs.geo_cache_ttl          = NGX_CONF_UNSET;
    c->cvmfs.geo_max_servers        = NGX_CONF_UNSET_UINT;
    c->scvmfs               = NGX_CONF_UNSET;
    c->scvmfs_authz         = NGX_CONF_UNSET_UINT;

    return c;
}

/* ---- T16: nginx variables ($cvmfs_class / $cvmfs_cache / $cvmfs_origin) ---
 * Backed by the request ctx the handler fills; "-" outside cvmfs requests.
 * $cvmfs_origin queries the http driver's last-answering endpoint (display
 * only — approximate under concurrent fills, exact in the common case). */

static ngx_int_t
cvmfs_var_set(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    const char *val)
{
    size_t  n = ngx_strlen(val);
    u_char *p = ngx_pnalloc(r->pool, n);

    if (p == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(p, val, n);
    v->data = p;
    v->len = n;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t
cvmfs_var_class(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    static const char *names[] = { "cas", "manifest", "geo", "reject" };

    (void) data;
    if (ctx == NULL || ctx->url.cls > CVMFS_URL_REJECT) {
        return cvmfs_var_set(r, v, "-");
    }
    return cvmfs_var_set(r, v, names[ctx->url.cls]);
}

static ngx_int_t
cvmfs_var_cache(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    static const char *names[] = { "-", "hit", "fill", "neg" };

    (void) data;
    if (ctx == NULL || ctx->cache_status > BRIX_CVMFS_CACHE_NEG) {
        return cvmfs_var_set(r, v, "-");
    }
    return cvmfs_var_set(r, v, names[ctx->cache_status]);
}

static ngx_int_t
cvmfs_var_origin(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_brix_cvmfs_loc_conf_t *lcf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_cvmfs_module);
    ngx_http_brix_cvmfs_ctx_t      *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    brix_sd_instance_t             *inst;
    char                              buf[300];
    const char                       *root;

    (void) data;
    if (ctx == NULL || ctx->cache_status != BRIX_CVMFS_CACHE_FILL
        || lcf == NULL)
    {
        return cvmfs_var_set(r, v, "-");
    }
    root = (ctx->up_root != NULL) ? ctx->up_root : lcf->common.root_canon;
    inst = brix_vfs_backend_resolve(root, r->connection->log);
    while (inst != NULL && ngx_strcmp(inst->driver->name, "http") != 0) {
        inst = brix_sd_cache_source_instance(inst);
    }
    if (inst == NULL || sd_http_last_origin(inst, buf, sizeof(buf)) != 0) {
        return cvmfs_var_set(r, v, "-");
    }
    return cvmfs_var_set(r, v, buf);
}

static ngx_http_variable_t  ngx_http_brix_cvmfs_vars[] = {
    { ngx_string("cvmfs_class"),  NULL, cvmfs_var_class,  0, 0, 0 },
    { ngx_string("cvmfs_cache"),  NULL, cvmfs_var_cache,  0, 0, 0 },
    { ngx_string("cvmfs_origin"), NULL, cvmfs_var_origin, 0, 0, 0 },
      ngx_http_null_variable
};

static ngx_int_t
ngx_http_brix_cvmfs_preconfiguration(ngx_conf_t *cf)
{
    ngx_http_variable_t *v, *nv;

    for (v = ngx_http_brix_cvmfs_vars; v->name.len; v++) {
        nv = ngx_http_add_variable(cf, &v->name, v->flags);
        if (nv == NULL) {
            return NGX_ERROR;
        }
        nv->get_handler = v->get_handler;
        nv->data = v->data;
    }
    return NGX_OK;
}

/*
 * Post-config: resolve the async-I/O thread pool per server (fill/offload
 * helpers need it) — identical mechanics to the s3 module.
 */
static ngx_int_t
ngx_http_brix_cvmfs_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t         *cmcf;
    ngx_http_core_srv_conf_t         **cscfp;
    ngx_http_brix_cvmfs_loc_conf_t  *lcf;
    static ngx_str_t                   default_pool_name = ngx_string("default");
    ngx_str_t                         *pool_name;
    ngx_uint_t                         s;

    /* An HTTP-only cvmfs node has no stream block, so the SHM zones normally
     * created by the stream postconfiguration must be ensured here: the
     * metrics table (or every counter INC is a silent no-op) AND the
     * dashboard transfer/events/history zones (or every live-transfer
     * record silently fails and the dashboard stays empty). Both are
     * idempotent — ngx_shared_memory_add returns an existing zone. */
    if (brix_metrics_ensure_zone(cf) != NGX_OK) {
        return NGX_ERROR;
    }
    if (brix_configure_dashboard(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_conf_ctx_t *ctx = cscfp[s]->ctx;

        lcf = ctx->loc_conf[ngx_http_brix_cvmfs_module.ctx_index];
        if (lcf == NULL || !lcf->cvmfs.enable) {
            continue;
        }

        pool_name = (lcf->common.thread_pool_name.len > 0)
                    ? &lcf->common.thread_pool_name
                    : &default_pool_name;

        lcf->common.thread_pool = ngx_thread_pool_get(cf->cycle, pool_name);
        if (lcf->common.thread_pool == NULL) {
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "brix_cvmfs: thread pool \"%V\" not found - "
                "async cache fills disabled (add a thread_pool directive)",
                pool_name);
        }
    }

    return NGX_OK;
}

static ngx_http_module_t ngx_http_brix_cvmfs_module_ctx = {
    ngx_http_brix_cvmfs_preconfiguration,  /* preconfiguration     */
    ngx_http_brix_cvmfs_postconfiguration, /* postconfiguration    */
    NULL,                                    /* create main conf     */
    NULL,                                    /* init main conf       */
    NULL,                                    /* create server conf   */
    NULL,                                    /* merge server conf    */
    ngx_http_brix_cvmfs_create_loc_conf,   /* create location conf */
    ngx_http_brix_cvmfs_merge_loc_conf,    /* merge location conf  */
};

/* "brix_cvmfs on" — parse the flag AND make this location a dedicated
 * CVMFS protocol endpoint (same install point the s3 module uses). */
static char *
ngx_http_brix_cvmfs_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    char                     *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_brix_cvmfs_handler;

    return NGX_CONF_OK;
}

/*
 * Directives
 */

/* brix_cache_verify (HTTP form) is now owned by ngx_http_brix_common_module,
 * which registers the identical off|cvmfs-cas enum; this module adopts the
 * merged value via brix_http_common_adopt(). */

static ngx_conf_enum_t  brix_scvmfs_authz_enum[] = {
    { ngx_string("none"),   BRIX_SCVMFS_AUTHZ_NONE },
    { ngx_string("bearer"), BRIX_SCVMFS_AUTHZ_BEARER },
    { ngx_null_string, 0 }
};

static ngx_conf_enum_t  brix_cvmfs_select_enum[] = {
    { ngx_string("static"), BRIX_CVMFS_SELECT_STATIC },
    { ngx_string("geo"),    BRIX_CVMFS_SELECT_GEO },
    { ngx_string("rtt"),    BRIX_CVMFS_SELECT_RTT },
    { ngx_null_string, 0 }
};

static ngx_conf_enum_t  brix_cvmfs_retry_policy_enum[] = {
    { ngx_string("failover"),      BRIX_CVMFS_RETRY_FAILOVER },
    { ngx_string("force-primary"), BRIX_CVMFS_RETRY_FORCE_PRIMARY },
    { ngx_null_string, 0 }
};

static ngx_conf_enum_t  brix_cvmfs_geo_answer_enum[] = {
    { ngx_string("off"), BRIX_CVMFS_GEO_PASSTHROUGH },
    { ngx_string("rtt"), BRIX_CVMFS_GEO_RTT },
    { ngx_null_string, 0 }
};

static ngx_command_t ngx_http_brix_cvmfs_commands[] = {

    /* ---- origin resilience directives (split into directives_resilience.inc) ---- */
#include "directives_resilience.inc"

    /* ---- cvmfs core + scvmfs + tier directives (split into directives_core.inc) ---- */
#include "directives_core.inc"

    ngx_null_command
};

/* Worker init: arm the T19 RTT probe timers for every registered export. */
static ngx_int_t
ngx_http_brix_cvmfs_init_process(ngx_cycle_t *cycle)
{
    return brix_cvmfs_rtt_init_worker(cycle);
}

ngx_module_t ngx_http_brix_cvmfs_module = {
    NGX_MODULE_V1,
    &ngx_http_brix_cvmfs_module_ctx,  /* module context     */
    ngx_http_brix_cvmfs_commands,     /* module directives  */
    NGX_HTTP_MODULE,                    /* module type        */
    NULL,                               /* init master        */
    NULL,                               /* init module        */
    ngx_http_brix_cvmfs_init_process, /* init process       */
    NULL,                               /* init thread        */
    NULL,                               /* exit thread        */
    NULL,                               /* exit process       */
    NULL,                               /* exit master        */
    NGX_MODULE_V1_PADDING
};
