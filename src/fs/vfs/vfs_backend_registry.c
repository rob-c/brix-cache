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


/* T16: the ngx-side failover-accounting hook injected into sd_http (the
 * driver is pure C and cannot touch the SHM metrics itself). */
static void
brix_vfs_http_failover_note(void)
{
    BRIX_CVMFS_METRIC_INC(origin_failovers_total);
}

/* Endpoint health TRANSITIONS (sd_http EWMA hysteresis) as single-line
 * operator events: which Stratum-1/origin flapped, and when it came back.
 * Fires from fill worker threads — the cycle log is the stable target. */
static void
brix_vfs_http_health_note(const char *host, int port, int healthy)
{
    if (healthy) {
        ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
            "xrootd-origin: event=recovered host=%s port=%d — endpoint "
            "answering again; rank-preferred routing resumes", host, port);
    } else {
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
            "xrootd-origin: event=degraded host=%s port=%d — transport "
            "failures pushed this endpoint's fail score over threshold; "
            "reads prefer alternates until a half-open probe succeeds",
            host, port);
    }
}

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

/* Build the entry's RAW source driver instance (no decorators, no memoization). The
 * instance is malloc/pool-owned, worker-safe; SQLite connections are per-worker so
 * this is only ever called after fork. Returns NULL (logged) on init failure. */
static brix_sd_instance_t *
brix_vfs_backend_build_source(brix_vfs_backend_entry_t *e, ngx_log_t *log)
{
    brix_sd_instance_t *inst;

    /* Default / explicit POSIX source. Phase-64: an export whose backend is the
     * default POSIX tree but which carries a cache/stage tier still needs a
     * buildable source instance to decorate. */
    if (e->backend[0] == '\0' || ngx_strcmp(e->backend, "posix") == 0) {
        int err = 0;

        inst = brix_sd_instance_create(ngx_cycle->pool, log, "posix",
                                         (void *) e->root_canon, &err);
        if (inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, err,
                "xrootd: posix source init failed for export \"%s\"",
                e->root_canon);
        }
        return inst;
    }

    /* Remote root:// backend: the in-process origin wire client (read + write +
     * staged_open, auth via ztn/gsi). */
    if (ngx_strcmp(e->backend, "xroot") == 0) {
        inst = brix_sd_xroot_create_origin(e->origin_host, e->origin_port,
                 e->origin_tls, e->origin_family,
                 (e->origin_token[0] != '\0') ? e->origin_token : NULL,
                 (e->origin_x509_proxy[0] != '\0') ? e->origin_x509_proxy : NULL,
                 (e->origin_ca_dir[0] != '\0') ? e->origin_ca_dir : NULL,
                 (e->origin_sss_keytab[0] != '\0') ? e->origin_sss_keytab : NULL,
                 log);
        if (inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "xrootd: remote root:// backend init failed for export \"%s\"",
                e->root_canon);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: remote root:// storage backend ready at \"%s\"",
                e->root_canon);
        }
        return inst;
    }

#if BRIX_HAVE_CEPH
    /* Ceph/RADOS object backend: flat, block-only key space, data in a pool with
     * no local directory namespace (the pure-librados reference). */
    if (ngx_strcmp(e->backend, "ceph") == 0) {
        brix_sd_ceph_conf_t conf;
        int                   sderr = 0;

        ngx_memzero(&conf, sizeof(conf));
        conf.pool       = e->ceph_pool;
        conf.conf_file  = (e->ceph_conf[0] != '\0') ? e->ceph_conf : NULL;
        conf.key_prefix = (e->ceph_key_prefix[0] != '\0') ? e->ceph_key_prefix
                                                          : NULL;

        inst = brix_sd_instance_create(ngx_cycle->pool, log, e->backend,
                                         &conf, &sderr);
        if (inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, sderr,
                "xrootd: %s backend init failed for export \"%s\" (pool=%s)",
                e->backend, e->root_canon, e->ceph_pool);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: %s storage backend ready at \"%s\" (pool=%s)",
                e->backend, e->root_canon, e->ceph_pool);
        }
        return inst;
    }

    /* cephfsro: read-only CephFS served directly from RADOS (meta + data pools). */
    if (ngx_strcmp(e->backend, "cephfsro") == 0) {
        brix_sd_cephfs_ro_conf_t conf;
        int                        sderr = 0;

        ngx_memzero(&conf, sizeof(conf));
        conf.meta_pool       = e->ceph_pool;
        conf.data_pool       = e->ceph_data_pool;
        conf.conf_file       = (e->ceph_conf[0] != '\0') ? e->ceph_conf : NULL;
        conf.assume_quiesced = e->cephfs_quiesced;
        conf.live            = e->cephfs_live;

        inst = brix_sd_instance_create(ngx_cycle->pool, log, "cephfsro",
                                         &conf, &sderr);
        if (inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, sderr,
                "xrootd: cephfsro backend init failed for export \"%s\" "
                "(meta=%s data=%s)", e->root_canon, e->ceph_pool,
                e->ceph_data_pool);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: cephfsro (read-only CephFS) backend ready at \"%s\" "
                "(meta=%s data=%s)", e->root_canon, e->ceph_pool,
                e->ceph_data_pool);
        }
        return inst;
    }
#endif

    /* Nearline (tape/MSS) backend (phase-64 SP5): sd_frm over the selected MSS
     * adapter. A cache tier in front (G8) is the recall target. */
    if (ngx_strcmp(e->backend, "tape") == 0) {
        inst = brix_sd_frm_create(
            (e->origin_host[0] != '\0') ? e->origin_host : NULL,
            e->origin_path, log);
        if (inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "xrootd: tape (frm) backend init failed for export \"%s\"",
                e->root_canon);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: nearline (tape) storage backend ready at \"%s\" "
                "(adapter=%s base=%s)", e->root_canon,
                (e->origin_host[0] != '\0') ? e->origin_host : "stub",
                e->origin_path);
        }
        return inst;
    }

    /* HTTP(S) source backend (read-only): the shared S3/libcurl transport does the
     * HEAD/Range-GET; sd_http carries no libcurl itself. */
    if (ngx_strcmp(e->backend, "http") == 0) {
        brix_sd_http_cfg_t    cfg;
        brix_sd_http_ep_cfg_t extra[7];
        int                     i;

        ngx_memzero(&cfg, sizeof(cfg));
        cfg.host       = e->origin_host;
        cfg.port       = e->origin_port;
        cfg.tls        = e->origin_tls;
        cfg.base_path  = e->origin_path;
        cfg.transport  = &brix_s3_origin_curl_transport;
        cfg.timeout_ms = 60000;
        cfg.bearer_token = (e->origin_token[0] != '\0') ? e->origin_token : NULL;
        cfg.failover_note = brix_vfs_http_failover_note;   /* T16 */
        cfg.health_note   = brix_vfs_http_health_note;
        /* phase-68 T11: the remaining pipe-separated failover origins */
        for (i = 0; i < e->n_http_extra && i < 7; i++) {
            extra[i].host      = e->http_extra[i].host;
            extra[i].port      = e->http_extra[i].port;
            extra[i].tls       = e->http_extra[i].tls;
            extra[i].base_path = e->http_extra[i].base;
        }
        cfg.extra   = extra;
        cfg.n_extra = (e->n_http_extra < 7) ? e->n_http_extra : 7;

        inst = brix_sd_http_create(&cfg, log);
        if (inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "xrootd: http backend init failed for export \"%s\"",
                e->root_canon);
        } else {
            if (e->has_http_ranks) {
                sd_http_set_ranks(inst, e->http_ranks, 8);   /* T19 geo/static */
            }
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: http storage backend ready at \"%s\"", e->root_canon);
        }
        return inst;
    }

    /* Read-only S3 source backend (phase-64): the export's bytes live in a remote
     * bucket, served over the shared libcurl S3 transport (signed Range GET). The
     * remote driver is CAP_RANGE_READ only, so this primary is read-only — exactly
     * like an http:// primary. origin_path carries the bucket. */
    if (ngx_strcmp(e->backend, "s3") == 0) {
        brix_sd_remote_cfg_t cfg;

        ngx_memzero(&cfg, sizeof(cfg));
        cfg.scheme = BRIX_SD_REMOTE_S3;
        ngx_cpystrn((u_char *) cfg.host, (u_char *) e->origin_host,
                    sizeof(cfg.host));
        cfg.port = e->origin_port;
        cfg.tls  = e->origin_tls;
        ngx_cpystrn((u_char *) cfg.bucket, (u_char *) e->origin_path,
                    sizeof(cfg.bucket));
        cfg.timeout_ms = 60000;
        cfg.transport  = &brix_s3_origin_curl_transport;
        /* §14: SigV4 credentials from the attached brix_credential (s3_* fields);
         * empty ⇒ anonymous (public bucket). Region defaults to us-east-1. */
        ngx_cpystrn((u_char *) cfg.access_key,
                    (u_char *) e->origin_s3_access_key, sizeof(cfg.access_key));
        ngx_cpystrn((u_char *) cfg.secret_key,
                    (u_char *) e->origin_s3_secret_key, sizeof(cfg.secret_key));
        ngx_cpystrn((u_char *) cfg.region,
                    (u_char *) (e->origin_s3_region[0] != '\0'
                                ? e->origin_s3_region : "us-east-1"),
                    sizeof(cfg.region));

        inst = brix_sd_remote_create(&cfg, log);
        if (inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "xrootd: s3 backend init failed for export \"%s\" (bucket=%s)",
                e->root_canon, e->origin_path);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: s3 storage backend ready at \"%s\" (host=%s bucket=%s)",
                e->root_canon, e->origin_host, e->origin_path);
        }
        return inst;
    }
#if BRIX_HAVE_SQLITE
    {
        brix_sd_pblock_conf_t conf;
        int                     sderr = 0;

        ngx_memzero(&conf, sizeof(conf));
        conf.root            = e->root_canon;
        conf.busy_timeout_ms = 5000;
        conf.block_size      = e->block_size;

        inst = brix_sd_instance_create(ngx_cycle->pool, log, "pblock",
                                         &conf, &sderr);
        if (inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, sderr,
                "xrootd: pblock backend init failed for export \"%s\"",
                e->root_canon);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: pblock storage backend ready at \"%s\" "
                "(block_size=%uz)", e->root_canon, (size_t) e->block_size);
        }
        return inst;
    }
#else
    (void) log;
    return NULL;
#endif
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

    /* Legacy local-staging shim (brix_storage_staging): buffer on a posix store
     * rooted at the export root and flush to the source on commit. Superseded by an
     * explicit stage tier, so skip it when one is configured. */
    if (e->staging && !e->stage_tier.configured
        && top->driver->staged_open != NULL)
    {
        int                   sderr = 0;
        brix_sd_instance_t *store =
            brix_sd_instance_create(ngx_cycle->pool, log, "posix",
                                      (void *) e->root_canon, &sderr);
        brix_sd_instance_t *dec = (store != NULL)
            ? brix_sd_stage_create(top, store, NULL, e->root_canon, log) : NULL;

        if (dec != NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: write-back stage decorator composed over \"%s\"",
                e->root_canon);
            top = dec;
        } else {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "xrootd: stage shim init failed for \"%s\" - source direct",
                e->root_canon);
        }
    }

    /* Phase-64 explicit stage tier (sd_stage over an explicit stage store). */
    if (e->stage_tier.configured) {
        brix_sd_instance_t *store = brix_tier_build(&e->stage_tier, log);
        brix_sd_instance_t *dec = (store != NULL)
            ? brix_sd_stage_create(top, store, &e->stage_policy, e->root_canon,
                                     log) : NULL;

        if (dec != NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: write-stage tier (%s) composed over \"%s\"",
                e->stage_tier.driver, e->root_canon);
            top = dec;
        }
    }

    /* Phase-64 read-cache tier (sd_cache, outermost). */
    if (e->cache_tier.configured) {
        brix_sd_instance_t *store = brix_tier_build(&e->cache_tier, log);
        const char           *local_root =
            (ngx_strcmp(e->cache_tier.driver, "posix") == 0
             && e->cache_tier.path[0] != '\0') ? e->cache_tier.path : NULL;
        brix_sd_instance_t *dec = (store != NULL)
            ? brix_sd_cache_create(top, store, &e->cache_policy, local_root, log)
            : NULL;

        if (dec != NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: read-cache tier (%s) composed over \"%s\"",
                e->cache_tier.driver, e->root_canon);
            top = dec;
        }
    }

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
