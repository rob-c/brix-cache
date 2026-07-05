/*
 * metrics/metrics_cvmfs.h
 *
 * Per-process CVMFS (cvmfs://) protocol metrics (phase-68): the traffic-class
 * enum, the bounded per-repository (fqrn) and per-upstream (Stratum-1) slot
 * tables, and the aggregate cvmfs metrics struct embedded in the per-server
 * metrics block.  Split out of metrics.h so each observability domain owns a
 * focused, independently reviewable header (the whole cluster is referenced
 * only by ngx_brix_srv_metrics_t via the embedded `cvmfs` member).
 */

#ifndef NGX_BRIX_METRICS_CVMFS_H
#define NGX_BRIX_METRICS_CVMFS_H

#include <ngx_core.h>

/*
 * Per-process CVMFS protocol metrics (phase-68). Class labels are a fixed
 * 4-value set, so cardinality is bounded by construction; repo names and
 * object paths MUST NOT become label values.
 */
typedef enum {
    BRIX_CVMFS_CLASS_CAS = 0,
    BRIX_CVMFS_CLASS_MANIFEST,
    BRIX_CVMFS_CLASS_GEO,
    BRIX_CVMFS_CLASS_REJECT,
    BRIX_CVMFS_CLASS_COUNT
} brix_cvmfs_class_metric_e;

/* ---- per-repository (fqrn) counters --------------------------------------
 * A site serves O(20) repositories, so the fqrn is a usable label — but the
 * name arrives FROM THE WIRE, so the label set must be BOUNDED or a scanner
 * minting random repo names explodes both the SHM and the Prometheus series
 * space. A fixed slot table holds the first BRIX_CVMFS_REPO_SLOTS-1
 * distinct fqrns seen; everything past capacity folds into the reserved
 * last slot, exported as repo="_other". Slots register lock-free
 * (state: EMPTY -> CAS -> CLAIMED(write name) -> READY); a claim race can
 * duplicate a name across two slots, so RESOLUTION always returns the
 * LOWEST-index READY match and the exporter skips later duplicates — all
 * increments and all output converge on one slot per name. */
#define BRIX_CVMFS_REPO_SLOTS     32
#define BRIX_CVMFS_REPO_NAME_MAX  64

#define BRIX_CVMFS_REPO_EMPTY    0u
#define BRIX_CVMFS_REPO_CLAIMED  1u
#define BRIX_CVMFS_REPO_READY    2u

typedef struct {
    ngx_atomic_t  state;                 /* EMPTY / CLAIMED / READY           */
    char          name[BRIX_CVMFS_REPO_NAME_MAX];  /* fqrn, NUL-terminated  */

    ngx_atomic_t  requests_total[BRIX_CVMFS_CLASS_COUNT]; /* by class      */
    ngx_atomic_t  files_accessed_total;  /* CAS objects served OK (hit+fill)  */
    ngx_atomic_t  cache_hits_total;      /* served from the local store       */
    ngx_atomic_t  cache_misses_total;    /* needed an origin fill             */
    ngx_atomic_t  fills_total;           /* fills that published              */
    ngx_atomic_t  fill_failures_total;   /* fills that failed definitively    */
    ngx_atomic_t  verify_failures_total; /* CAS mismatches (quarantined)      */
    ngx_atomic_t  negative_hits_total;   /* 404s absorbed by the worker memo  */
    ngx_atomic_t  bytes_served_hit_total;  /* LAN out, from cache             */
    ngx_atomic_t  bytes_served_fill_total; /* LAN out, via a fresh fill       */
    ngx_atomic_t  origin_bytes_total;      /* WAN in, pulled from Stratum-1s  */
} ngx_brix_cvmfs_repo_metrics_t;

/* ---- per-upstream (Stratum-1) counters -----------------------------------
 * "Which of my origins am I pulling from, and how much?" — the RAL-vs-CERN
 * question. The upstream "host:port" arrives FROM THE WIRE / config, so the
 * label set is BOUNDED exactly like the repo table (INVARIANT #8): a fixed
 * slot table holds the first BRIX_CVMFS_UPSTREAM_SLOTS-1 distinct hosts;
 * the reserved last slot is exported upstream="_other". Registration and
 * convergence use the same lock-free EMPTY->CLAIMED->READY lowest-index
 * scheme as the repo table. */
#define BRIX_CVMFS_UPSTREAM_SLOTS     16   /* >= a site's Stratum-1 allowlist */
#define BRIX_CVMFS_UPSTREAM_NAME_MAX  300  /* matches sd_http last_origin buf */

/* Fill-duration histogram: cumulative-le upper bounds in MILLISECONDS. The
 * exporter renders them as Prometheus seconds buckets (/1000) plus an
 * implicit +Inf. They bracket a LAN-adjacent fill (ms) through a cold-WAN
 * fill (seconds). */
#define BRIX_CVMFS_UP_HBUCKETS  6
static const long brix_cvmfs_up_bucket_ms[BRIX_CVMFS_UP_HBUCKETS] = {
    5, 25, 100, 500, 2000, 10000
};

typedef struct {
    ngx_atomic_t  state;                 /* EMPTY / CLAIMED / READY (repo enum) */
    char          name[BRIX_CVMFS_UPSTREAM_NAME_MAX]; /* "host:port", NUL     */

    ngx_atomic_t  requests_total;        /* fill attempts against this origin  */
    ngx_atomic_t  fills_total;           /* attempts that published            */
    ngx_atomic_t  fill_failures_total;   /* attempts that failed               */
    ngx_atomic_t  failovers_total;       /* attempts served by a non-primary   */
    ngx_atomic_t  origin_bytes_total;    /* WAN in from this origin            */
    ngx_atomic_t  dur_bucket[BRIX_CVMFS_UP_HBUCKETS]; /* non-cumulative       */
    ngx_atomic_t  dur_count;             /* histogram observations             */
    ngx_atomic_t  dur_sum_ms;            /* histogram sum (ms; /1000 on export) */
} ngx_brix_cvmfs_upstream_metrics_t;

typedef struct {
    ngx_atomic_t  requests_total[BRIX_CVMFS_CLASS_COUNT]; /* by traffic class */
    ngx_atomic_t  negative_hits_total;   /* 404s absorbed by the worker memo   */
    ngx_atomic_t  fills_total;           /* origin fills that published        */
    ngx_atomic_t  fill_failures_total;   /* fills that failed definitively     */
    ngx_atomic_t  verify_failures_total; /* CAS mismatches (quarantined)       */
    ngx_atomic_t  origin_failovers_total;/* second-endpoint attempts (T11)     */
    ngx_atomic_t  secure_requests_total; /* scvmfs preamble passes (T22)       */
    ngx_atomic_t  bytes_served_hit_total;  /* LAN out, served from cache       */
    ngx_atomic_t  bytes_served_fill_total; /* LAN out, served via a fresh fill */
    ngx_atomic_t  origin_bytes_total;      /* WAN in, pulled from Stratum-1s   */

    ngx_brix_cvmfs_repo_metrics_t repos[BRIX_CVMFS_REPO_SLOTS];
    ngx_brix_cvmfs_upstream_metrics_t upstreams[BRIX_CVMFS_UPSTREAM_SLOTS];
} ngx_brix_cvmfs_metrics_t;

/*
 * Resolve the fqrn `name`/`len` to its SHM repo-metrics slot, registering it
 * on first sight; past capacity returns the reserved "_other" slot. NULL when
 * the metrics SHM is unmapped. Lock-free; safe from fill worker threads.
 * (metrics/cvmfs.c)
 */
ngx_brix_cvmfs_repo_metrics_t *brix_cvmfs_repo_slot(const char *name,
    size_t len);

/*
 * Record one origin fill attempt against upstream "host:port" (NUL-terminated):
 * requests++ always; on ok, fills++ + origin_bytes += bytes + the duration
 * observation; else fill_failures++; failovers++ when a non-primary endpoint
 * served it. No-op when the metrics SHM is unmapped or host is NULL/empty.
 * Lock-free; safe from fill worker threads. (metrics/cvmfs.c)
 */
void brix_cvmfs_upstream_record(const char *host, int ok, off_t bytes,
    long dur_ms, int failover);

#endif /* NGX_BRIX_METRICS_CVMFS_H */
