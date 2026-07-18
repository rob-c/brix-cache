/*
 * vfs_backend_registry.c — per-export storage-backend resolution: the entry
 * table, source build + decorator composition, and the resolve entry points.
 * Config-time directive parsing lives in vfs_backend_config.c (phase-38 split).
 */
#include "vfs_backend_internal.h"
#include "fs/backend/xroot/sd_xroot.h"   /* remote root:// backend (brix_sd_xroot_create) */
#include "fs/backend/http/sd_http.h"     /* HTTP source backend (brix_sd_http_create) */
#include "fs/backend/remote/sd_remote.h" /* read-only S3 source backend (brix_sd_remote_create) */
#include "fs/backend/rados/sd_ceph.h"    /* Ceph/RADOS backend (BRIX_HAVE_CEPH) */
#include "fs/backend/stage/sd_stage.h"   /* C-2/C-6 write-back stage decorator */
#include "fs/backend/cache/sd_cache.h"   /* phase-64 read-cache decorator */
#include "fs/backend/frm/sd_frm.h"       /* phase-64 SP5 nearline (tape) backend */
#include "fs/tier/tier.h"                /* phase-64 tier cfg/build + the cache/stage setters */
#include "fs/cache/origin/s3_transport.h" /* brix_s3_origin_curl_transport (libcurl) */
#include "observability/metrics/metrics.h"        /* phase-68 T16 failover hook */
#include "observability/metrics/metrics_macros.h"

#include <string.h>


static brix_vfs_backend_entry_t  brix_vfs_backends[BRIX_VFS_BACKEND_MAX];
static ngx_uint_t                  brix_vfs_backend_count;

/* Find a registered entry by exact root_canon, or NULL. */
brix_vfs_backend_entry_t *
brix_vfs_backend_entry_find(const char *root_canon)
{
    ngx_uint_t i;

    if (root_canon == NULL || root_canon[0] == '\0') {
        return NULL;
    }
    for (i = 0; i < brix_vfs_backend_count; i++) {
        if (ngx_strcmp(brix_vfs_backends[i].root_canon, root_canon) == 0) {
            return &brix_vfs_backends[i];
        }
    }
    return NULL;
}

/* See vfs_backend_registry.h — HTTP endpoint of an http backend, for the
 * protocol-side uncached passthroughs that address the fill origin directly. */
int
brix_vfs_backend_http_endpoint(const char *root_canon,
    const char **host, int *port, int *tls, const char **base)
{
    brix_vfs_backend_entry_t *e = brix_vfs_backend_entry_find(root_canon);

    if (e == NULL || ngx_strcmp(e->backend, "http") != 0) {
        return -1;
    }
    *host = e->origin_host;
    *port = e->origin_port;
    *tls  = e->origin_tls;
    *base = e->origin_path;
    return 0;
}

/* Find or create the entry for root_canon. A cache/stage tier may be registered
 * for a default-POSIX export that has no backend entry yet, so create one (backend
 * "" = default POSIX source). NULL when the table is full. */
brix_vfs_backend_entry_t *
brix_vfs_backend_entry_get_or_create(const char *root_canon)
{
    brix_vfs_backend_entry_t *e = brix_vfs_backend_entry_find(root_canon);

    if (e != NULL) {
        return e;
    }
    if (root_canon == NULL || root_canon[0] == '\0'
        || brix_vfs_backend_count >= BRIX_VFS_BACKEND_MAX)
    {
        return NULL;
    }
    e = &brix_vfs_backends[brix_vfs_backend_count++];
    ngx_memzero(e, sizeof(*e));
    ngx_cpystrn((u_char *) e->root_canon, (u_char *) root_canon,
                sizeof(e->root_canon));
    return e;
}

/*
 * Decorator-composition steps for brix_vfs_backend_entry_build.
 *
 * WHAT: each helper takes the current top-of-stack instance + the entry + log,
 *       and returns the (possibly) wrapped instance — the legacy staging shim,
 *       the explicit stage tier, and the read-cache tier respectively.
 * WHY:  the composition orchestrator was an 18-CCN function whose branches were
 *       three near-identical decorator blocks; extracting one helper per tier
 *       lets the orchestrator read as a flat wrap sequence (§8 compose small
 *       functions).
 * HOW:  a helper that cannot build/init its decorator returns the input `top`
 *       unchanged (degraded decorator skipped so the export still serves from the
 *       tier below), preserving the pre-split behavior and every log string.
 */

/* Legacy local-staging shim (brix_storage_staging): buffer on a posix store
 * rooted at the export root and flush to the source on commit. Superseded by an
 * explicit stage tier, so skip it when one is configured. */
static brix_sd_instance_t *
brix_vbr_wrap_staging_shim(brix_sd_instance_t *top,
    brix_vfs_backend_entry_t *e, ngx_log_t *log)
{
    int                   sderr = 0;
    brix_sd_instance_t *store;
    brix_sd_instance_t *dec;

    if (!e->staging || e->stage_tier.configured
        || top->driver->staged_open == NULL)
    {
        return top;
    }

    store = brix_sd_instance_create(log, "posix",
                                      (void *) e->root_canon, &sderr);
    dec = (store != NULL)
        ? brix_sd_stage_create(top, store, NULL, e->root_canon, log) : NULL;

    if (dec != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: write-back stage decorator composed over \"%s\"",
            e->root_canon);
        return dec;
    }
    ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
        "brix: stage shim init failed for \"%s\" - source direct",
        e->root_canon);
    return top;
}

/* Phase-64 explicit stage tier (sd_stage over an explicit stage store). */
static brix_sd_instance_t *
brix_vbr_wrap_stage_tier(brix_sd_instance_t *top,
    brix_vfs_backend_entry_t *e, ngx_log_t *log)
{
    brix_sd_instance_t *store;
    brix_sd_instance_t *dec;

    if (!e->stage_tier.configured) {
        return top;
    }

    store = brix_tier_build(&e->stage_tier, log);
    dec = (store != NULL)
        ? brix_sd_stage_create(top, store, &e->stage_policy, e->root_canon,
                                 log) : NULL;

    if (dec != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: write-stage tier (%s) composed over \"%s\"",
            e->stage_tier.driver, e->root_canon);
        return dec;
    }
    return top;
}

/* Phase-64 read-cache tier (sd_cache, outermost). */
static brix_sd_instance_t *
brix_vbr_wrap_cache_tier(brix_sd_instance_t *top,
    brix_vfs_backend_entry_t *e, ngx_log_t *log)
{
    brix_sd_instance_t *store;
    const char           *local_root;
    brix_sd_instance_t *dec;

    if (!e->cache_tier.configured) {
        return top;
    }

    store = brix_tier_build(&e->cache_tier, log);
    local_root = (ngx_strcmp(e->cache_tier.driver, "posix") == 0
                  && e->cache_tier.path[0] != '\0') ? e->cache_tier.path : NULL;
    dec = (store != NULL)
        ? brix_sd_cache_create(top, store, &e->cache_policy, local_root, log)
        : NULL;

    if (dec != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: read-cache tier (%s) composed over \"%s\"",
            e->cache_tier.driver, e->root_canon);

        /* Phase-85 F7: build + attach the optional cold store tier. Degraded
         * (build failure) means hot-tier-only — the export still serves. */
        if (e->cold_tier.configured) {
            brix_sd_instance_t *cold = brix_tier_build(&e->cold_tier, log);

            if (cold != NULL) {
                brix_sd_cache_set_cold(dec, cold);
                ngx_log_error(NGX_LOG_NOTICE, log, 0,
                    "brix: cold cache tier (%s) attached under \"%s\"",
                    e->cold_tier.driver, e->root_canon);
            } else {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                    "brix: cold cache tier build failed for \"%s\" - "
                    "running hot tier only", e->root_canon);
            }
        }

        /* Phase-85 F8: build the sibling-mesh ring. Each non-self member
         * becomes an http fill source over the same tier grammar the stores
         * use; a member whose build fails stays NULL (its keys fall through
         * to the origin) — the mesh degrades, never blocks the export. */
        if (e->n_peer_ring > 0) {
            brix_sd_cache_peer_t  peers[BRIX_SD_CACHE_MAX_PEERS];
            brix_tier_cfg_t       pcfg;
            int                     i;

            ngx_memzero(peers, sizeof(peers));
            for (i = 0; i < e->n_peer_ring; i++) {
                (void) snprintf(peers[i].label, sizeof(peers[i].label),
                    "%s:%d", e->peer_ring[i].host, e->peer_ring[i].port);
                if (i == e->peer_self) {
                    continue;              /* own slot: never self-fetch */
                }
                ngx_memzero(&pcfg, sizeof(pcfg));
                pcfg.role = BRIX_TIER_CACHE;
                ngx_cpystrn((u_char *) pcfg.driver, (u_char *) "http",
                    sizeof(pcfg.driver));
                ngx_cpystrn((u_char *) pcfg.host,
                    (u_char *) e->peer_ring[i].host, sizeof(pcfg.host));
                pcfg.port       = e->peer_ring[i].port;
                pcfg.configured = 1;
                peers[i].inst = brix_tier_build(&pcfg, log);
                if (peers[i].inst == NULL) {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                        "brix: mesh sibling %s build failed for \"%s\" - "
                        "its keys fall through to the origin",
                        peers[i].label, e->root_canon);
                }
            }
            brix_sd_cache_set_peers(dec, peers, e->n_peer_ring, e->peer_self);
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "brix: sibling mesh (%d members, self=%s) attached under "
                "\"%s\"", e->n_peer_ring, peers[e->peer_self].label,
                e->root_canon);
        }
        return dec;
    }
    return top;
}

/* Lazily build + memoize the entry's COMPOSED storage stack (per worker). The
 * registry is the single composition point: build the source, then wrap it
 * bottom-up in the stage decorator and the read-cache decorator (cache outermost,
 * phase-64 section 5). A degraded decorator (a store that is "needs development"
 * or fails to init) is skipped so the export still serves from the tier below. */
static brix_sd_instance_t *
brix_vfs_backend_entry_build(brix_vfs_backend_entry_t *e, ngx_log_t *log)
{
    brix_sd_instance_t *top;

    if (e->inst != NULL) {
        return e->inst;                /* already built in this worker */
    }
    /* The built stack is memoized for the worker's whole life, and drivers
     * keep the log they are built with for later diagnostics (sd_http logs
     * selection/failover from fill threads). A request-time resolver hands
     * us its connection log, which dies with the connection — build with
     * the cycle log instead so stored pointers never go stale. */
    if (ngx_cycle != NULL && ngx_cycle->log != NULL) {
        log = ngx_cycle->log;
    }
    top = brix_vfs_backend_build_source(e, log);
    if (top == NULL) {
        return NULL;
    }

    top = brix_vbr_wrap_staging_shim(top, e, log);
    top = brix_vbr_wrap_stage_tier(top, e, log);
    top = brix_vbr_wrap_cache_tier(top, e, log);

    e->inst = top;
    return e->inst;
}

ngx_uint_t
brix_vfs_backend_export_count(void)
{
    return brix_vfs_backend_count;
}

ngx_int_t
brix_vfs_backend_export_info(ngx_uint_t i, brix_vfs_backend_info_t *out)
{
    brix_vfs_backend_entry_t *e;

    if (out == NULL || i >= brix_vfs_backend_count) {
        return NGX_ERROR;
    }
    e = &brix_vfs_backends[i];
    out->root_canon = e->root_canon;
    out->backend    = (e->backend[0] != '\0') ? e->backend : "posix";
    out->host       = e->origin_host;
    out->port       = e->origin_port;
    out->tls        = e->origin_tls;
    out->staging    = e->staging;
    out->has_token  = (e->origin_token[0] != '\0');
    out->has_proxy  = (e->origin_x509_proxy[0] != '\0');
    return NGX_OK;
}

brix_sd_instance_t *
brix_vfs_backend_resolve(const char *root_canon, ngx_log_t *log)
{
    ngx_uint_t i;

    if (root_canon == NULL || root_canon[0] == '\0'
        || brix_vfs_backend_count == 0)
    {
        return NULL;
    }

    for (i = 0; i < brix_vfs_backend_count; i++) {
        brix_vfs_backend_entry_t *e = &brix_vfs_backends[i];

        if (ngx_strcmp(e->root_canon, root_canon) != 0) {
            continue;
        }
        return brix_vfs_backend_entry_build(e, log);
    }
    return NULL;
}

brix_sd_instance_t *
brix_vfs_backend_resolve_for_path(const char *abs_path, const char **root_out,
    ngx_log_t *log)
{
    brix_vfs_backend_entry_t *best = NULL;
    size_t                      best_len = 0;
    ngx_uint_t                  i;

    if (abs_path == NULL || abs_path[0] == '\0'
        || brix_vfs_backend_count == 0)
    {
        return NULL;
    }

    /* Longest registered export root that is a prefix of abs_path: a match is the
     * root itself or root + "/..." (so "/exp" never matches "/export/x"). */
    for (i = 0; i < brix_vfs_backend_count; i++) {
        brix_vfs_backend_entry_t *e = &brix_vfs_backends[i];
        size_t                      rl = ngx_strlen(e->root_canon);

        if (ngx_strncmp(abs_path, e->root_canon, rl) != 0) {
            continue;
        }
        if (abs_path[rl] != '/' && abs_path[rl] != '\0') {
            continue;                  /* shares a prefix but a different name */
        }
        if (rl > best_len) {
            best_len = rl;
            best     = e;
        }
    }
    if (best == NULL) {
        return NULL;
    }
    if (root_out != NULL) {
        *root_out = best->root_canon;
    }
    return brix_vfs_backend_entry_build(best, log);
}
