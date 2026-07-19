/*
 * vfs_backend_registry_source.c — RAW per-tier-kind source builders for the
 * backend registry: one builder per storage-backend kind, the name→builder
 * descriptor table, and the brix_vfs_backend_build_source orchestrator.
 * Split VERBATIM from vfs_backend_registry.c (file-size split); the entry
 * table, decorator composition, and resolve entry points stay there.
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

/*
 * Per-tier-kind source builders.
 *
 * WHAT: one static builder per storage-backend kind. Each takes the resolved
 *       export entry + a log, constructs the RAW driver instance for that kind
 *       (no decorators, no memoization), logs the ready/failed line, and returns
 *       the instance or NULL.
 * WHY:  brix_vfs_backend_build_source was a 36-CCN if-ladder over the backend
 *       name; splitting each arm into a named builder selected by a descriptor
 *       table flattens it to a single table scan (§8 table-driven dispatch).
 * HOW:  the builders share the brix_vbr_source_fn signature so a static const
 *       descriptor array can map backend name → builder. The default POSIX kind
 *       (name "" or "posix") and the final pblock fallback are handled by the
 *       orchestrator, not the table.
 *
 * All log strings, config-error text, and construction order are byte-frozen
 * from the pre-split ladder.
 */
typedef brix_sd_instance_t *(*brix_vbr_source_fn)(brix_vfs_backend_entry_t *e,
    ngx_log_t *log);

/* Default / explicit POSIX source. Phase-64: an export whose backend is the
 * default POSIX tree but which carries a cache/stage tier still needs a
 * buildable source instance to decorate. */
static brix_sd_instance_t *
brix_vbr_build_posix(brix_vfs_backend_entry_t *e, ngx_log_t *log)
{
    int                   err = 0;
    brix_sd_instance_t *inst;

    inst = brix_sd_instance_create(log, "posix",
                                     (void *) e->root_canon, &err);
    if (inst == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, err,
            "brix: posix source init failed for export \"%s\"",
            e->root_canon);
    }
    return inst;
}

/* Remote root:// backend: the in-process origin wire client (read + write +
 * staged_open, auth via ztn/gsi). */
static brix_sd_instance_t *
brix_vbr_build_xroot(brix_vfs_backend_entry_t *e, ngx_log_t *log)
{
    brix_sd_instance_t *inst;
    brix_sd_xroot_origin_cfg_t cfg = {
        .host       = e->origin_host,
        .port       = e->origin_port,
        .tls        = e->origin_tls,
        .af_policy  = e->origin_family,
        .bearer     = (e->origin_token[0] != '\0') ? e->origin_token : NULL,
        .x509_proxy = (e->origin_x509_proxy[0] != '\0')
            ? e->origin_x509_proxy : NULL,
        .x509_key   = (e->origin_x509_key[0] != '\0')
            ? e->origin_x509_key : NULL,
        .ca_dir     = (e->origin_ca_dir[0] != '\0') ? e->origin_ca_dir : NULL,
        .sss_keytab = (e->origin_sss_keytab[0] != '\0')
            ? e->origin_sss_keytab : NULL,
    };

    inst = brix_sd_xroot_create_origin(&cfg, log);
    if (inst == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
            "brix: remote root:// backend init failed for export \"%s\"",
            e->root_canon);
    } else {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: remote root:// storage backend ready at \"%s\"",
            e->root_canon);
    }
    return inst;
}

#if BRIX_HAVE_CEPH
/* Ceph/RADOS object backend: flat, block-only key space, data in a pool with
 * no local directory namespace (the pure-librados reference). */
static brix_sd_instance_t *
brix_vbr_build_ceph(brix_vfs_backend_entry_t *e, ngx_log_t *log)
{
    brix_sd_ceph_conf_t conf;
    int                   sderr = 0;
    brix_sd_instance_t *inst;

    ngx_memzero(&conf, sizeof(conf));
    conf.pool       = e->ceph_pool;
    conf.conf_file  = (e->ceph_conf[0] != '\0') ? e->ceph_conf : NULL;
    conf.key_prefix = (e->ceph_key_prefix[0] != '\0') ? e->ceph_key_prefix
                                                      : NULL;

    inst = brix_sd_instance_create(log, e->backend,
                                     &conf, &sderr);
    if (inst == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, sderr,
            "brix: %s backend init failed for export \"%s\" (pool=%s)",
            e->backend, e->root_canon, e->ceph_pool);
    } else {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: %s storage backend ready at \"%s\" (pool=%s)",
            e->backend, e->root_canon, e->ceph_pool);
    }
    return inst;
}

/* cephfsro: read-only CephFS served directly from RADOS (meta + data pools). */
static brix_sd_instance_t *
brix_vbr_build_cephfsro(brix_vfs_backend_entry_t *e, ngx_log_t *log)
{
    brix_sd_cephfs_ro_conf_t conf;
    int                        sderr = 0;
    brix_sd_instance_t      *inst;

    ngx_memzero(&conf, sizeof(conf));
    conf.meta_pool       = e->ceph_pool;
    conf.data_pool       = e->ceph_data_pool;
    conf.conf_file       = (e->ceph_conf[0] != '\0') ? e->ceph_conf : NULL;
    conf.assume_quiesced = e->cephfs_quiesced;
    conf.live            = e->cephfs_live;

    inst = brix_sd_instance_create(log, "cephfsro",
                                     &conf, &sderr);
    if (inst == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, sderr,
            "brix: cephfsro backend init failed for export \"%s\" "
            "(meta=%s data=%s)", e->root_canon, e->ceph_pool,
            e->ceph_data_pool);
    } else {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: cephfsro (read-only CephFS) backend ready at \"%s\" "
            "(meta=%s data=%s)", e->root_canon, e->ceph_pool,
            e->ceph_data_pool);
    }
    return inst;
}
#endif

/* Nearline (tape/MSS) backend (phase-64 SP5): sd_frm over the selected MSS
 * adapter. A cache tier in front (G8) is the recall target. */
static brix_sd_instance_t *
brix_vbr_build_tape(brix_vfs_backend_entry_t *e, ngx_log_t *log)
{
    brix_sd_instance_t *inst;

    inst = brix_sd_frm_create(
        (e->origin_host[0] != '\0') ? e->origin_host : NULL,
        e->origin_path, log);
    if (inst == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
            "brix: tape (frm) backend init failed for export \"%s\"",
            e->root_canon);
    } else {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: nearline (tape) storage backend ready at \"%s\" "
            "(adapter=%s base=%s)", e->root_canon,
            (e->origin_host[0] != '\0') ? e->origin_host : "stub",
            e->origin_path);
    }
    return inst;
}

/* HTTP(S) source backend (read-only): the shared S3/libcurl transport does the
 * HEAD/Range-GET; sd_http carries no libcurl itself. */
static brix_sd_instance_t *
brix_vbr_build_http(brix_vfs_backend_entry_t *e, ngx_log_t *log)
{
    brix_sd_http_cfg_t    cfg;
    brix_sd_http_ep_cfg_t extra[7];
    int                     i;
    brix_sd_instance_t   *inst;

    ngx_memzero(&cfg, sizeof(cfg));
    cfg.host       = e->origin_host;
    cfg.port       = e->origin_port;
    cfg.tls        = e->origin_tls;
    cfg.base_path  = e->origin_path;
    cfg.transport  = &brix_s3_origin_curl_transport;
    cfg.timeout_ms = BRIX_SD_HTTP_DEFAULT_TIMEOUT_MS;
    cfg.bearer_token = (e->origin_token[0] != '\0') ? e->origin_token : NULL;
    /* §14/C-3: verify the https origin against the operator-configured CA
     * (file or hashed dir); "" ⇒ system bundle (public-CA origin). */
    cfg.ca_path      = (e->origin_ca_dir[0] != '\0') ? e->origin_ca_dir : NULL;
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
            "brix: http backend init failed for export \"%s\"",
            e->root_canon);
    } else {
        if (e->has_http_ranks) {
            sd_http_set_ranks(inst, e->http_ranks, 8);   /* T19 geo/static */
        }
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: http storage backend ready at \"%s\"", e->root_canon);
    }
    return inst;
}

/* Read-only S3 source backend (phase-64): the export's bytes live in a remote
 * bucket, served over the shared libcurl S3 transport (signed Range GET). The
 * remote driver is CAP_RANGE_READ only, so this primary is read-only — exactly
 * like an http:// primary. origin_path carries the bucket. */
static brix_sd_instance_t *
brix_vbr_build_s3(brix_vfs_backend_entry_t *e, ngx_log_t *log)
{
    brix_sd_remote_cfg_t cfg;
    brix_sd_instance_t *inst;

    ngx_memzero(&cfg, sizeof(cfg));
    cfg.scheme = BRIX_SD_REMOTE_S3;
    ngx_cpystrn((u_char *) cfg.host, (u_char *) e->origin_host,
                sizeof(cfg.host));
    cfg.port = e->origin_port;
    cfg.tls  = e->origin_tls;
    ngx_cpystrn((u_char *) cfg.bucket, (u_char *) e->origin_path,
                sizeof(cfg.bucket));
    cfg.timeout_ms = BRIX_SD_HTTP_DEFAULT_TIMEOUT_MS;
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
            "brix: s3 backend init failed for export \"%s\" (bucket=%s)",
            e->root_canon, e->origin_path);
    } else {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: s3 storage backend ready at \"%s\" (host=%s bucket=%s)",
            e->root_canon, e->origin_host, e->origin_path);
    }
    return inst;
}

#if BRIX_HAVE_SQLITE
/* Fallback pblock source: an export whose backend name matched no explicit kind
 * is served from the per-block SQLite store rooted at the export. Preserves the
 * pre-split ladder's default tail. */
static brix_sd_instance_t *
brix_vbr_build_pblock(brix_vfs_backend_entry_t *e, ngx_log_t *log)
{
    brix_sd_pblock_conf_t conf;
    int                     sderr = 0;
    brix_sd_instance_t   *inst;

    ngx_memzero(&conf, sizeof(conf));
    conf.root            = e->root_canon;
    conf.busy_timeout_ms = 5000;
    conf.block_size      = e->block_size;
    /* Never create pblock blobs/catalog.db as root — drop to an unprivileged
     * account (the worker `user <acct>;`, else "nobody") first. Gate on the
     * worker: a config/master-time build must NOT drop (it would strip the master
     * of the privilege it needs to open logs and fork workers). */
    conf.enforce_unprivileged = (ngx_process == NGX_PROCESS_WORKER);

    inst = brix_sd_instance_create(log, "pblock",
                                     &conf, &sderr);
    if (inst == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, sderr,
            "brix: pblock backend init failed for export \"%s\"",
            e->root_canon);
    } else {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: pblock storage backend ready at \"%s\" "
            "(block_size=%uz)", e->root_canon, (size_t) e->block_size);
    }
    return inst;
}
#endif

/* Descriptor mapping an explicit backend name to its source builder. The default
 * POSIX kind and the pblock fallback are handled directly by the orchestrator, so
 * they are not table entries. */
typedef struct {
    const char           *name;
    brix_vbr_source_fn  build;
} brix_vbr_source_desc_t;

static const brix_vbr_source_desc_t  brix_vbr_source_table[] = {
    { "xroot",    brix_vbr_build_xroot },
#if BRIX_HAVE_CEPH
    { "ceph",     brix_vbr_build_ceph },
    { "cephfsro", brix_vbr_build_cephfsro },
#endif
    { "tape",     brix_vbr_build_tape },
    { "http",     brix_vbr_build_http },
    { "s3",       brix_vbr_build_s3 },
};

/* Build the entry's RAW source driver instance (no decorators, no memoization). The
 * instance is malloc/pool-owned, worker-safe; SQLite connections are per-worker so
 * this is only ever called after fork. Returns NULL (logged) on init failure.
 *
 * The default POSIX source (backend "" or "posix") is dispatched first; any other
 * named backend is looked up in brix_vbr_source_table; an unrecognised name falls
 * through to the pblock fallback (or NULL when SQLite is unavailable). */
brix_sd_instance_t *
brix_vfs_backend_build_source(brix_vfs_backend_entry_t *e, ngx_log_t *log)
{
    size_t k;

    if (e->backend[0] == '\0' || ngx_strcmp(e->backend, "posix") == 0) {
        return brix_vbr_build_posix(e, log);
    }

    for (k = 0; k < sizeof(brix_vbr_source_table)
                    / sizeof(brix_vbr_source_table[0]); k++)
    {
        if (ngx_strcmp(e->backend, brix_vbr_source_table[k].name) == 0) {
            return brix_vbr_source_table[k].build(e, log);
        }
    }

#if BRIX_HAVE_SQLITE
    return brix_vbr_build_pblock(e, log);
#else
    (void) log;
    return NULL;
#endif
}
