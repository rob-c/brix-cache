/*
 * module.c — nginx directive table, config lifecycle, and HTTP module context
 * for the dedicated cvmfs:// protocol plane.
 *
 * WHAT: Three responsibilities, mirroring src/protocols/s3/module.c:
 *   1. Config lifecycle (create_loc_conf / merge_loc_conf): allocates
 *      ngx_http_xrootd_cvmfs_loc_conf_t (shared preamble + cvmfs knobs),
 *      merges main→srv→loc, and when enable=1 anchors the export root,
 *      registers the composable storage backend + cache/stage tiers.
 *   2. Handler install (ngx_http_xrootd_cvmfs_set): the "xrootd_cvmfs"
 *      directive parses its flag and installs ngx_http_xrootd_cvmfs_handler
 *      as the location's content handler — the location IS the protocol
 *      endpoint; no WebDAV dispatch is involved.
 *   3. Directive table: the xrootd_cvmfs_* family, including the two
 *      per-protocol tier directives over the shared preamble.
 *
 * WHY: cvmfs:// is a first-class protocol. A CVMFS site cache is read-only
 *      by construction (allow_write is forced off) and typically a PURE cache
 *      node: no local export tree. When no root is configured the root
 *      anchors at "/" (the same pure-cache-node semantics the stream plane
 *      uses): the location serves the "/" namespace, filling from the http
 *      origin backend into the cache store.
 *
 * HOW: create/merge follow the s3 module's manual common.* init/merge idiom
 *      (established phase-64 gotcha: no shared_init). Postconfiguration
 *      resolves the thread pool per server exactly as s3 does — the cache
 *      fill/offload helpers need it.
 */

#include "cvmfs.h"
#include "core/config/config.h"           /* xrootd_metrics_ensure_zone */
#include "core/config/root_prepare.h"
#include "core/config/http_rootfd.h"
#include "core/compat/alloc_guard.h"
#include "fs/cache/verify.h"               /* xrootd_cache_verify_mode_e */
#include "fs/vfs/vfs_backend_registry.h"
#include "origin_geo.h"
#include "fs/backend/http/sd_http.h"       /* SD_HTTP_EP_MAX */
#include "auth/token/issuer_registry.h"    /* scvmfs bearer registry (T22) */
#include "fs/backend/cache/sd_cache.h"     /* unwrap for $cvmfs_origin (T16) */

#include <stdlib.h>                        /* strtod (coord parsing) */

static ngx_int_t ngx_http_xrootd_cvmfs_postconfiguration(ngx_conf_t *cf);
static char *cvmfs_geo_rank_config(ngx_conf_t *cf,
    ngx_http_xrootd_cvmfs_loc_conf_t *conf);

/*
 * Config lifecycle
 */

static void *
ngx_http_xrootd_cvmfs_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_xrootd_cvmfs_loc_conf_t *c;

    XROOTD_PCALLOC_OR_RETURN(c, cf->pool, sizeof(*c), NULL);

    c->common.enable      = NGX_CONF_UNSET;
    c->common.allow_write = NGX_CONF_UNSET;
    c->common.read_only   = NGX_CONF_UNSET;
    c->common.compress    = NGX_CONF_UNSET;
    xrootd_pmark_conf_init(&c->common.pmark);
    /* phase-64 tier grammar scalars (str/array fields stay zeroed by pcalloc) */
    c->common.stage_enable      = NGX_CONF_UNSET;
    c->common.stage_flush_async = NGX_CONF_UNSET_UINT;
    c->common.cache_max_object  = NGX_CONF_UNSET;
    c->common.cache_evict_at    = NGX_CONF_UNSET_UINT;
    c->common.cache_evict_to    = NGX_CONF_UNSET_UINT;
    c->common.cache_meta_mode   = NGX_CONF_UNSET_UINT;
    c->common.cache_batch_cinfo = NGX_CONF_UNSET_UINT;
    c->common.cache_index_cache = NGX_CONF_UNSET_SIZE;
    c->common.cache_slice_size  = NGX_CONF_UNSET_SIZE;
    c->common.cache_verify_mode = NGX_CONF_UNSET_UINT;
    c->common.pblock_block_size = NGX_CONF_UNSET_SIZE;
    c->common.rootfd            = -1;

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
    c->scvmfs               = NGX_CONF_UNSET;
    c->scvmfs_authz         = NGX_CONF_UNSET_UINT;

    return c;
}

/* Parse "<lat>:<lon>" into two doubles. 0 on success. */
static int
cvmfs_parse_latlon(const ngx_str_t *v, double *lat, double *lon)
{
    char  buf[64], *colon, *end;

    if (v->len == 0 || v->len >= sizeof(buf)) {
        return -1;
    }
    ngx_memcpy(buf, v->data, v->len);
    buf[v->len] = '\0';
    colon = strchr(buf, ':');
    if (colon == NULL) {
        return -1;
    }
    *colon = '\0';
    *lat = strtod(buf, &end);
    if (end == buf || *end != '\0' || *lat < -90.0 || *lat > 90.0) {
        return -1;
    }
    *lon = strtod(colon + 1, &end);
    if (end == colon + 1 || *end != '\0' || *lon < -180.0 || *lon > 180.0) {
        return -1;
    }
    return 0;
}

/* xrootd_cvmfs_upstream_allow <host> [host ...] — append EVERY argument to
 * the allowlist. The stock ngx_conf_set_str_array_slot keeps only the first
 * argument per directive, so a site list written on one line silently
 * allowed just its first Stratum-1 (observed in the field: every other
 * Tier-1 answered 403 and clients failed over to — and pinned on — the sole
 * surviving host). Both forms now work: one directive per host, or one
 * directive listing them all. */
static char *
cvmfs_conf_upstream_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_cvmfs_loc_conf_t *c = conf;
    ngx_str_t                        *value, *slot;
    ngx_uint_t                        i;

    (void) cmd;

    if (c->cvmfs.upstream_allow == NGX_CONF_UNSET_PTR) {
        c->cvmfs.upstream_allow = ngx_array_create(cf->pool, 4,
                                                   sizeof(ngx_str_t));
        if (c->cvmfs.upstream_allow == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        slot = ngx_array_push(c->cvmfs.upstream_allow);
        if (slot == NULL) {
            return NGX_CONF_ERROR;
        }
        *slot = value[i];
    }
    return NGX_CONF_OK;
}

/* Geo mode (T19): every configured endpoint must have coordinates and
 * xrootd_cvmfs_here must be set — rank once by great-circle distance and
 * record the ranks on the backend entry (applied at instance build). */
static char *
cvmfs_geo_rank_config(ngx_conf_t *cf, ngx_http_xrootd_cvmfs_loc_conf_t *conf)
{
    double                here_lat, here_lon;
    double                metric[SD_HTTP_EP_MAX];
    int                   ranks[SD_HTTP_EP_MAX];
    const char           *host;
    int                   port, idx, n;
    xrootd_cvmfs_coord_t *coords;
    ngx_uint_t            i;

    if (conf->cvmfs.here.len == 0
        || cvmfs_parse_latlon(&conf->cvmfs.here, &here_lat, &here_lon) != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cvmfs_origin_select geo requires xrootd_cvmfs_here "
            "<lat>:<lon>");
        return NGX_CONF_ERROR;
    }
    if (conf->cvmfs.origin_coords == NULL
        || conf->cvmfs.origin_coords->nelts == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cvmfs_origin_select geo requires one "
            "xrootd_cvmfs_origin_coords per configured origin");
        return NGX_CONF_ERROR;
    }
    coords = conf->cvmfs.origin_coords->elts;

    for (n = 0; n < SD_HTTP_EP_MAX; n++) {
        int matched = 0;

        if (xrootd_vfs_backend_http_endpoint_at(conf->common.root_canon, n,
                                                &host, &port) != 0)
        {
            break;
        }
        for (i = 0; i < conf->cvmfs.origin_coords->nelts; i++) {
            size_t hl = ngx_strlen(host);

            if (coords[i].host.len != hl
                || ngx_strncasecmp(coords[i].host.data, (u_char *) host, hl)
                   != 0)
            {
                continue;
            }
            if (coords[i].port != 0 && (int) coords[i].port != port) {
                continue;
            }
            metric[n] = xrootd_cvmfs_haversine_km(here_lat, here_lon,
                                                  coords[i].lat,
                                                  coords[i].lon);
            matched = 1;
            break;
        }
        if (!matched) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_cvmfs_origin_select geo: no xrootd_cvmfs_origin_coords "
                "for origin %s:%d", host, port);
            return NGX_CONF_ERROR;
        }
    }
    if (n == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cvmfs_origin_select geo requires an http(s) "
            "xrootd_cvmfs_storage_backend");
        return NGX_CONF_ERROR;
    }
    for (idx = n; idx < SD_HTTP_EP_MAX; idx++) {
        ranks[idx] = 0;
    }
    xrootd_cvmfs_rank_by_metric(metric, n, ranks);
    xrootd_vfs_backend_set_http_ranks(conf->common.root_canon, ranks,
                                      SD_HTTP_EP_MAX);
    return NGX_CONF_OK;
}

/* xrootd_cvmfs_origin_coords <host[:port]> <lat>:<lon> — geographic position
 * of one origin (multi). An entry with a port matches only that endpoint. */
static char *
ngx_http_xrootd_cvmfs_set_coords(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf = conf;
    ngx_str_t                        *value = cf->args->elts;
    xrootd_cvmfs_coord_t             *c;
    u_char                           *colon;

    (void) cmd;
    if (lcf->cvmfs.origin_coords == NGX_CONF_UNSET_PTR
        || lcf->cvmfs.origin_coords == NULL)
    {
        lcf->cvmfs.origin_coords =
            ngx_array_create(cf->pool, 4, sizeof(xrootd_cvmfs_coord_t));
        if (lcf->cvmfs.origin_coords == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    c = ngx_array_push(lcf->cvmfs.origin_coords);
    if (c == NULL) {
        return NGX_CONF_ERROR;
    }

    c->host = value[1];
    c->port = 0;
    colon = ngx_strlchr(value[1].data, value[1].data + value[1].len, ':');
    if (colon != NULL) {
        ngx_int_t p = ngx_atoi(colon + 1,
                               (size_t) (value[1].data + value[1].len
                                         - (colon + 1)));

        if (p < 1 || p > 65535) {
            return "has an invalid port";
        }
        c->port = (in_port_t) p;
        c->host.len = (size_t) (colon - value[1].data);
    }
    if (cvmfs_parse_latlon(&value[2], &c->lat, &c->lon) != 0) {
        return "has invalid <lat>:<lon> coordinates";
    }
    return NGX_CONF_OK;
}

static char *
ngx_http_xrootd_cvmfs_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_xrootd_cvmfs_loc_conf_t *prev = parent;
    ngx_http_xrootd_cvmfs_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->common.enable,      prev->common.enable,      0);
    ngx_conf_merge_value(conf->common.allow_write, prev->common.allow_write, 0);
    ngx_conf_merge_value(conf->common.read_only,   prev->common.read_only,   0);
    ngx_conf_merge_value(conf->common.compress,    prev->common.compress,    0);
    ngx_conf_merge_str_value(conf->common.root,    prev->common.root,        "");
    ngx_conf_merge_str_value(conf->common.thread_pool_name,
                             prev->common.thread_pool_name, "");
    ngx_conf_merge_str_value(conf->common.storage_backend,
                             prev->common.storage_backend, "");
    ngx_conf_merge_str_value(conf->common.storage_credential,
                             prev->common.storage_credential, "");
    ngx_conf_merge_size_value(conf->common.pblock_block_size,
                              prev->common.pblock_block_size, 0);
    /* phase-64 tier grammar */
    ngx_conf_merge_str_value(conf->common.cache_store, prev->common.cache_store,
                             "");
    if (conf->common.cache_store_args == NULL) {
        conf->common.cache_store_args = prev->common.cache_store_args;
    }
    ngx_conf_merge_value(conf->common.stage_enable, prev->common.stage_enable, 0);
    ngx_conf_merge_str_value(conf->common.stage_store, prev->common.stage_store,
                             "");
    if (conf->common.stage_store_args == NULL) {
        conf->common.stage_store_args = prev->common.stage_store_args;
    }
    ngx_conf_merge_uint_value(conf->common.stage_flush_async,
                              prev->common.stage_flush_async, 0);
    ngx_conf_merge_off_value(conf->common.cache_max_object,
                             prev->common.cache_max_object, 0);
    ngx_conf_merge_uint_value(conf->common.cache_evict_at,
                              prev->common.cache_evict_at, 90);
    ngx_conf_merge_uint_value(conf->common.cache_evict_to,
                              prev->common.cache_evict_to, 80);
    ngx_conf_merge_uint_value(conf->common.cache_meta_mode,
                              prev->common.cache_meta_mode, 0);
    ngx_conf_merge_uint_value(conf->common.cache_batch_cinfo,
                              prev->common.cache_batch_cinfo, 2);
    ngx_conf_merge_size_value(conf->common.cache_index_cache,
                              prev->common.cache_index_cache, 0);
    ngx_conf_merge_size_value(conf->common.cache_slice_size,
                              prev->common.cache_slice_size, 0);
    ngx_conf_merge_uint_value(conf->common.cache_verify_mode,
                              prev->common.cache_verify_mode,
                              XROOTD_CACHE_VERIFY_OFF);
    if (xrootd_pmark_conf_merge(cf, &prev->common.pmark, &conf->common.pmark)
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->cvmfs.enable, prev->cvmfs.enable, 0);
    ngx_conf_merge_sec_value(conf->cvmfs.manifest_ttl, prev->cvmfs.manifest_ttl,
                             61);
    ngx_conf_merge_sec_value(conf->cvmfs.negative_ttl, prev->cvmfs.negative_ttl,
                             10);
    ngx_conf_merge_str_value(conf->cvmfs.quarantine_dir,
                             prev->cvmfs.quarantine_dir, "");
    ngx_conf_merge_ptr_value(conf->cvmfs.upstream_allow,
                             prev->cvmfs.upstream_allow, NULL);
    ngx_conf_merge_uint_value(conf->cvmfs.upstream_max, prev->cvmfs.upstream_max,
                              8);
    ngx_conf_merge_uint_value(conf->cvmfs.origin_select,
                              prev->cvmfs.origin_select,
                              XROOTD_CVMFS_SELECT_STATIC);
    ngx_conf_merge_ptr_value(conf->cvmfs.origin_coords,
                             prev->cvmfs.origin_coords, NULL);
    ngx_conf_merge_str_value(conf->cvmfs.here, prev->cvmfs.here, "");
    ngx_conf_merge_sec_value(conf->cvmfs.rtt_interval, prev->cvmfs.rtt_interval,
                             60);
    ngx_conf_merge_sec_value(conf->cvmfs.client_hold, prev->cvmfs.client_hold,
                             25);
    ngx_conf_merge_sec_value(conf->cvmfs.fill_max_life,
                             prev->cvmfs.fill_max_life, 300);
    ngx_conf_merge_value(conf->scvmfs, prev->scvmfs, 0);
    ngx_conf_merge_uint_value(conf->scvmfs_authz, prev->scvmfs_authz,
                              XROOTD_SCVMFS_AUTHZ_NONE);
    ngx_conf_merge_str_value(conf->scvmfs_token_issuers,
                             prev->scvmfs_token_issuers, "");
    if (conf->scvmfs_registry == NULL) {
        conf->scvmfs_registry = prev->scvmfs_registry;
    }

    /* scvmfs (T22, EXPERIMENTAL) is a LAYER on cvmfs — structural, checked
     * at config time. Bearer mode needs the issuer registry to exist. */
    if (conf->scvmfs) {
        if (!conf->cvmfs.enable) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_scvmfs requires xrootd_cvmfs on");
            return NGX_CONF_ERROR;
        }
        if (conf->scvmfs_authz == XROOTD_SCVMFS_AUTHZ_BEARER) {
            if (conf->scvmfs_token_issuers.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_scvmfs_authz bearer requires "
                    "xrootd_scvmfs_token_issuers <scitokens.cfg>");
                return NGX_CONF_ERROR;
            }
            if (conf->scvmfs_registry == NULL) {
                xrootd_token_registry_t *reg = NULL;

                if (xrootd_token_registry_build(cf,
                        (const char *) conf->scvmfs_token_issuers.data,
                        XROOTD_AUTHZ_CAPABILITY, &reg) != NGX_OK)
                {
                    return NGX_CONF_ERROR;
                }
                conf->scvmfs_registry = reg;
            }
        }
    }

    if (conf->cvmfs.enable) {
        xrootd_export_root_opts_t root_opts;

        /* CVMFS is a read-only protocol: no directive can enable writes. */
        conf->common.allow_write = 0;

        /* "posix:<path>" backend names the local export tree (composable
         * xrootd_root replacement) — same rewrite every protocol applies. */
        xrootd_storage_backend_posix_root(&conf->common);

        /* Pure cache node (the normal CVMFS shape): no local export tree —
         * anchor the namespace at "/" exactly like the stream plane's pure
         * cache node; the location serves the "/" namespace, filling from
         * the http backend into the cache store. */
        if (conf->common.root.len == 0) {
            ngx_str_set(&conf->common.root, "/");
        }

        root_opts.directive_name = "xrootd_cvmfs";
        root_opts.allow_write    = 0;
        root_opts.required       = 1;
        root_opts.canon_size     = sizeof(conf->common.root_canon);
        if (xrootd_prepare_export_root(cf, &conf->common.root, &root_opts,
                                       conf->common.root_canon) != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }

        /* Persistent confinement rootfd (openat2 RESOLVE_BENEATH anchor). */
        if (xrootd_http_open_rootfd(cf, &conf->common) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }

        /* Register the composable storage backend (phase-63): the http(s)
         * Stratum-1 origin URL routes every VFS op to sd_http. */
        if (xrootd_vfs_backend_config_str(cf, conf->common.root_canon,
                &conf->common.storage_backend, conf->common.pblock_block_size,
                XROOTD_AF_AUTO)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        /* Verify-mismatch evidence lands in the protocol's quarantine dir;
         * MANIFEST-class fills get the protocol's TTL stamped (T12). */
        conf->common.cache_quarantine_dir = conf->cvmfs.quarantine_dir;
        conf->common.cache_manifest_ttl   = conf->cvmfs.manifest_ttl;
        /* T20 never-drop deadlines for the shared fill machinery */
        conf->common.cache_client_hold    = conf->cvmfs.client_hold;
        conf->common.cache_fill_max_life  = conf->cvmfs.fill_max_life;

        /* Phase-64: compose the cache/stage tiers over the backend. */
        if (xrootd_tier_register_stores(cf, &conf->common) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        /* T19 origin selection: geo ranks compute once at config time;
         * rtt registers the per-worker probe; static keeps configured
         * order (all ranks 0 — the pick is order-stable on ties). */
        if (conf->cvmfs.origin_select == XROOTD_CVMFS_SELECT_GEO) {
            if (cvmfs_geo_rank_config(cf, conf) != NGX_CONF_OK) {
                return NGX_CONF_ERROR;
            }
        } else if (conf->cvmfs.origin_select == XROOTD_CVMFS_SELECT_RTT) {
            xrootd_cvmfs_rtt_register(conf->common.root_canon,
                                      conf->cvmfs.rtt_interval,
                                      &conf->common.thread_pool_name);
        }
    }

    return NGX_CONF_OK;
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
    ngx_http_xrootd_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_cvmfs_module);
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
    ngx_http_xrootd_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_cvmfs_module);
    static const char *names[] = { "-", "hit", "fill", "neg" };

    (void) data;
    if (ctx == NULL || ctx->cache_status > XROOTD_CVMFS_CACHE_NEG) {
        return cvmfs_var_set(r, v, "-");
    }
    return cvmfs_var_set(r, v, names[ctx->cache_status]);
}

static ngx_int_t
cvmfs_var_origin(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf =
        ngx_http_get_module_loc_conf(r, ngx_http_xrootd_cvmfs_module);
    ngx_http_xrootd_cvmfs_ctx_t      *ctx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_cvmfs_module);
    xrootd_sd_instance_t             *inst;
    char                              buf[300];
    const char                       *root;

    (void) data;
    if (ctx == NULL || ctx->cache_status != XROOTD_CVMFS_CACHE_FILL
        || lcf == NULL)
    {
        return cvmfs_var_set(r, v, "-");
    }
    root = (ctx->up_root != NULL) ? ctx->up_root : lcf->common.root_canon;
    inst = xrootd_vfs_backend_resolve(root, r->connection->log);
    while (inst != NULL && ngx_strcmp(inst->driver->name, "http") != 0) {
        inst = xrootd_sd_cache_source_instance(inst);
    }
    if (inst == NULL || sd_http_last_origin(inst, buf, sizeof(buf)) != 0) {
        return cvmfs_var_set(r, v, "-");
    }
    return cvmfs_var_set(r, v, buf);
}

static ngx_http_variable_t  ngx_http_xrootd_cvmfs_vars[] = {
    { ngx_string("cvmfs_class"),  NULL, cvmfs_var_class,  0, 0, 0 },
    { ngx_string("cvmfs_cache"),  NULL, cvmfs_var_cache,  0, 0, 0 },
    { ngx_string("cvmfs_origin"), NULL, cvmfs_var_origin, 0, 0, 0 },
      ngx_http_null_variable
};

static ngx_int_t
ngx_http_xrootd_cvmfs_preconfiguration(ngx_conf_t *cf)
{
    ngx_http_variable_t *v, *nv;

    for (v = ngx_http_xrootd_cvmfs_vars; v->name.len; v++) {
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
ngx_http_xrootd_cvmfs_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t         *cmcf;
    ngx_http_core_srv_conf_t         **cscfp;
    ngx_http_xrootd_cvmfs_loc_conf_t  *lcf;
    static ngx_str_t                   default_pool_name = ngx_string("default");
    ngx_str_t                         *pool_name;
    ngx_uint_t                         s;

    /* An HTTP-only cvmfs node has no stream block, so the metrics SHM zone
     * (normally created by the stream postconfiguration) must be ensured
     * here or every counter INC is a silent no-op. Idempotent. */
    if (xrootd_metrics_ensure_zone(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_conf_ctx_t *ctx = cscfp[s]->ctx;

        lcf = ctx->loc_conf[ngx_http_xrootd_cvmfs_module.ctx_index];
        if (lcf == NULL || !lcf->cvmfs.enable) {
            continue;
        }

        pool_name = (lcf->common.thread_pool_name.len > 0)
                    ? &lcf->common.thread_pool_name
                    : &default_pool_name;

        lcf->common.thread_pool = ngx_thread_pool_get(cf->cycle, pool_name);
        if (lcf->common.thread_pool == NULL) {
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "xrootd_cvmfs: thread pool \"%V\" not found - "
                "async cache fills disabled (add a thread_pool directive)",
                pool_name);
        }
    }

    return NGX_OK;
}

static ngx_http_module_t ngx_http_xrootd_cvmfs_module_ctx = {
    ngx_http_xrootd_cvmfs_preconfiguration,  /* preconfiguration     */
    ngx_http_xrootd_cvmfs_postconfiguration, /* postconfiguration    */
    NULL,                                    /* create main conf     */
    NULL,                                    /* init main conf       */
    NULL,                                    /* create server conf   */
    NULL,                                    /* merge server conf    */
    ngx_http_xrootd_cvmfs_create_loc_conf,   /* create location conf */
    ngx_http_xrootd_cvmfs_merge_loc_conf,    /* merge location conf  */
};

/* "xrootd_cvmfs on" — parse the flag AND make this location a dedicated
 * CVMFS protocol endpoint (same install point the s3 module uses). */
static char *
ngx_http_xrootd_cvmfs_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    char                     *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_xrootd_cvmfs_handler;

    return NGX_CONF_OK;
}

/*
 * Directives
 */

/* xrootd_cache_verify (HTTP form): the composed tier verifies fills against a
 * digest. Only the self-verifying cvmfs-cas mode is meaningful on the HTTP
 * plane today (best-effort/require need an origin-digest hook the sd_http
 * fill does not have). The stream plane registers its own directive of the
 * same name — different block types, no conflict. */
static ngx_conf_enum_t  xrootd_cvmfs_verify_enum[] = {
    { ngx_string("off"),       XROOTD_CACHE_VERIFY_OFF },
    { ngx_string("cvmfs-cas"), XROOTD_CACHE_VERIFY_CVMFS_CAS },
    { ngx_null_string, 0 }
};

static ngx_conf_enum_t  xrootd_scvmfs_authz_enum[] = {
    { ngx_string("none"),   XROOTD_SCVMFS_AUTHZ_NONE },
    { ngx_string("bearer"), XROOTD_SCVMFS_AUTHZ_BEARER },
    { ngx_null_string, 0 }
};

static ngx_conf_enum_t  xrootd_cvmfs_select_enum[] = {
    { ngx_string("static"), XROOTD_CVMFS_SELECT_STATIC },
    { ngx_string("geo"),    XROOTD_CVMFS_SELECT_GEO },
    { ngx_string("rtt"),    XROOTD_CVMFS_SELECT_RTT },
    { ngx_null_string, 0 }
};

static ngx_command_t ngx_http_xrootd_cvmfs_commands[] = {

    { ngx_string("xrootd_cvmfs_origin_select"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.origin_select),
      xrootd_cvmfs_select_enum },

    { ngx_string("xrootd_cvmfs_origin_coords"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
      ngx_http_xrootd_cvmfs_set_coords,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_cvmfs_here"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.here),
      NULL },

    { ngx_string("xrootd_cvmfs_client_hold"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.client_hold),
      NULL },

    { ngx_string("xrootd_cvmfs_fill_max_life"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.fill_max_life),
      NULL },

    { ngx_string("xrootd_cvmfs_rtt_interval"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.rtt_interval),
      NULL },

    /* ---- scvmfs:// (T22, EXPERIMENTAL) — the secure layer ON cvmfs ---- */

    { ngx_string("xrootd_scvmfs"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, scvmfs),
      NULL },

    { ngx_string("xrootd_scvmfs_authz"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, scvmfs_authz),
      xrootd_scvmfs_authz_enum },

    { ngx_string("xrootd_scvmfs_token_issuers"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, scvmfs_token_issuers),
      NULL },

    { ngx_string("xrootd_cache_verify"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, common.cache_verify_mode),
      xrootd_cvmfs_verify_enum },

    { ngx_string("xrootd_cvmfs"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_xrootd_cvmfs_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.enable),
      NULL },

    { ngx_string("xrootd_cvmfs_manifest_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.manifest_ttl),
      NULL },

    { ngx_string("xrootd_cvmfs_negative_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.negative_ttl),
      NULL },

    { ngx_string("xrootd_cvmfs_quarantine_dir"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.quarantine_dir),
      NULL },

    { ngx_string("xrootd_cvmfs_upstream_allow"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      cvmfs_conf_upstream_allow,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.upstream_allow),
      NULL },

    { ngx_string("xrootd_cvmfs_upstream_max"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.upstream_max),
      NULL },

    /* ---- per-protocol tier directives over the shared preamble ---- */

    { ngx_string("xrootd_cvmfs_storage_backend"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, common.storage_backend),
      NULL },

    { ngx_string("xrootd_cvmfs_cache_store"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234,
      xrootd_conf_set_store_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, common.cache_store),
      (void *) offsetof(ngx_http_xrootd_cvmfs_loc_conf_t,
                        common.cache_store_args) },

    { ngx_string("xrootd_cvmfs_thread_pool"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, common.thread_pool_name),
      NULL },

    ngx_null_command
};

/* Worker init: arm the T19 RTT probe timers for every registered export. */
static ngx_int_t
ngx_http_xrootd_cvmfs_init_process(ngx_cycle_t *cycle)
{
    return xrootd_cvmfs_rtt_init_worker(cycle);
}

ngx_module_t ngx_http_xrootd_cvmfs_module = {
    NGX_MODULE_V1,
    &ngx_http_xrootd_cvmfs_module_ctx,  /* module context     */
    ngx_http_xrootd_cvmfs_commands,     /* module directives  */
    NGX_HTTP_MODULE,                    /* module type        */
    NULL,                               /* init master        */
    NULL,                               /* init module        */
    ngx_http_xrootd_cvmfs_init_process, /* init process       */
    NULL,                               /* init thread        */
    NULL,                               /* exit thread        */
    NULL,                               /* exit process       */
    NULL,                               /* exit master        */
    NGX_MODULE_V1_PADDING
};
