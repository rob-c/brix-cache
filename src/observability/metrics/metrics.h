/*
 * metrics/metrics.h
 *
 * Shared memory layout for Prometheus-style metrics exposed by the
 * nginx-xrootd stream module.  One slot per server block (up to
 * XROOTD_METRICS_MAX_SERVERS).  Both the stream module and the HTTP
 * metrics module reference this header.
 */

#ifndef NGX_XROOTD_METRICS_H
#define NGX_XROOTD_METRICS_H

#include <limits.h>
#include <stdint.h>
#include <ngx_core.h>

#include "unified.h"

/* Hard cap on exported stream listeners sharing the metrics zone. */
#define XROOTD_METRICS_MAX_SERVERS  16

/*
 * Operation indices — order must match xrootd_op_names[] in
 * metrics/export.c.
 *
 * The stream side increments op_ok/op_err by these numeric slots; the HTTP
 * exporter later turns the same slot number back into a Prometheus label.
 * That means this list is effectively a small ABI between the two modules.
 */
#define XROOTD_OP_LOGIN     0
#define XROOTD_OP_AUTH      1
#define XROOTD_OP_STAT      2
#define XROOTD_OP_OPEN_RD   3
#define XROOTD_OP_OPEN_WR   4
#define XROOTD_OP_READ      5
#define XROOTD_OP_WRITE     6
#define XROOTD_OP_SYNC      7
#define XROOTD_OP_CLOSE     8
#define XROOTD_OP_DIRLIST   9
#define XROOTD_OP_MKDIR    10
#define XROOTD_OP_RMDIR    11
#define XROOTD_OP_RM       12
#define XROOTD_OP_MV       13
#define XROOTD_OP_CHMOD    14
#define XROOTD_OP_TRUNCATE    15
#define XROOTD_OP_PING        16
#define XROOTD_OP_QUERY_CKSUM 17  /* kXR_query / kXR_QChecksum */
#define XROOTD_OP_QUERY_SPACE 17  /* kXR_query / kXR_QSpace    */
#define XROOTD_OP_READV       18  /* kXR_readv                 */
#define XROOTD_OP_PGREAD      19  /* kXR_pgread                */
#define XROOTD_OP_WRITEV      20  /* kXR_writev                */
#define XROOTD_OP_LOCATE      21  /* kXR_locate                */
#define XROOTD_OP_STATX       22  /* kXR_statx                 */
#define XROOTD_OP_FATTR       23  /* kXR_fattr                 */
#define XROOTD_OP_QUERY_STATS 24  /* kXR_query / kXR_QStats    */
#define XROOTD_OP_QUERY_XATTR 25  /* kXR_query / kXR_Qxattr    */
#define XROOTD_OP_QUERY_FINFO 26  /* kXR_query / kXR_QFinfo    */
#define XROOTD_OP_QUERY_FSINFO 27 /* kXR_query / kXR_QFSinfo   */
#define XROOTD_OP_SET          28 /* kXR_set                    */
#define XROOTD_OP_QUERY_VISA   29 /* kXR_query / kXR_Qvisa     */
#define XROOTD_OP_QUERY_OPAQUE 30 /* kXR_query / kXR_Qopaque   */
#define XROOTD_OP_QUERY_OPAQUF 31 /* kXR_query / kXR_Qopaquf   */
#define XROOTD_OP_QUERY_OPAQUG 32 /* kXR_query / kXR_Qopaqug   */
#define XROOTD_OP_QUERY_CKSCAN 33 /* kXR_query / kXR_Qckscan   */
#define XROOTD_OP_CLONE        34 /* kXR_clone                 */
#define XROOTD_OP_CHKPOINT     35 /* kXR_chkpoint              */
/* Number of entries in op_ok[] / op_err[] and xrootd_op_names[]. */
#define XROOTD_NOPS           37

/*
 * Cache-line alignment for the hottest shared-memory counters.  64 bytes is the
 * cache-line size on all x86-64 and current aarch64 server parts; over-aligning
 * on a part with a smaller line is harmless.  Used to stop high-frequency
 * per-operation counters from false-sharing with neighbouring fields written by
 * other cores/worker processes.
 */
#define XROOTD_METRIC_CACHELINE 64
#define XROOTD_METRIC_ALIGNED   __attribute__((aligned(XROOTD_METRIC_CACHELINE)))

/*
 * Fixed WebDAV label slots.  These are exported by name in metrics/export.c;
 * keep the order aligned with the string tables there.
 */
#define XROOTD_WEBDAV_METHOD_OPTIONS  0
#define XROOTD_WEBDAV_METHOD_HEAD     1
#define XROOTD_WEBDAV_METHOD_GET      2
#define XROOTD_WEBDAV_METHOD_PUT      3
#define XROOTD_WEBDAV_METHOD_DELETE   4
#define XROOTD_WEBDAV_METHOD_MKCOL    5
#define XROOTD_WEBDAV_METHOD_COPY     6
#define XROOTD_WEBDAV_METHOD_PROPFIND 7
#define XROOTD_WEBDAV_METHOD_OTHER    8
#define XROOTD_WEBDAV_NMETHODS        9

#define XROOTD_HTTP_STATUS_1XX     0
#define XROOTD_HTTP_STATUS_2XX     1
#define XROOTD_HTTP_STATUS_3XX     2
#define XROOTD_HTTP_STATUS_4XX     3
#define XROOTD_HTTP_STATUS_5XX     4
#define XROOTD_HTTP_STATUS_OTHER   5
#define XROOTD_HTTP_NSTATUS        6

#define XROOTD_WEBDAV_AUTH_RESULT_NONE       0
#define XROOTD_WEBDAV_AUTH_RESULT_CERT_OK    1
#define XROOTD_WEBDAV_AUTH_RESULT_TOKEN_OK   2
#define XROOTD_WEBDAV_AUTH_RESULT_ANONYMOUS  3
#define XROOTD_WEBDAV_AUTH_RESULT_REJECTED   4
#define XROOTD_WEBDAV_NAUTH_RESULTS          5

#define XROOTD_WEBDAV_RANGE_FULL          0
#define XROOTD_WEBDAV_RANGE_PARTIAL       1
#define XROOTD_WEBDAV_RANGE_UNSATISFIED   2
#define XROOTD_WEBDAV_NRANGE_RESULTS      3

#define XROOTD_WEBDAV_PUT_EMPTY      0
#define XROOTD_WEBDAV_PUT_MEMORY     1
#define XROOTD_WEBDAV_PUT_SPOOLED    2
#define XROOTD_WEBDAV_PUT_THREADED   3
#define XROOTD_WEBDAV_NPUT_MODES     4

#define XROOTD_WEBDAV_PROPFIND_DEPTH_0      0
#define XROOTD_WEBDAV_PROPFIND_DEPTH_1      1
#define XROOTD_WEBDAV_PROPFIND_DEPTH_INF    2
#define XROOTD_WEBDAV_NPROPFIND_DEPTHS      3

#define XROOTD_WEBDAV_TPC_PULL_STARTED       0
#define XROOTD_WEBDAV_TPC_PULL_SUCCESS       1
#define XROOTD_WEBDAV_TPC_CURL_STARTED       2  /* shared by pull and push */
#define XROOTD_WEBDAV_TPC_CURL_SUCCESS       3  /* shared by pull and push */
#define XROOTD_WEBDAV_TPC_CURL_ERROR         4  /* shared by pull and push */
#define XROOTD_WEBDAV_TPC_PUSH_STARTED       5
#define XROOTD_WEBDAV_TPC_PUSH_SUCCESS       6
#define XROOTD_WEBDAV_TPC_BAD_REQUEST        7
#define XROOTD_WEBDAV_TPC_COMMIT_ERROR       8
#define XROOTD_WEBDAV_NTPC_EVENTS            9

#define XROOTD_WEBDAV_CORS_NO_ORIGIN   0
#define XROOTD_WEBDAV_CORS_ALLOWED     1
#define XROOTD_WEBDAV_CORS_DENIED      2
#define XROOTD_WEBDAV_CORS_PREFLIGHT   3
#define XROOTD_WEBDAV_NCORS_EVENTS     4

#define XROOTD_WEBDAV_TPC_CRED_STARTED       0
#define XROOTD_WEBDAV_TPC_CRED_SUCCESS       1
#define XROOTD_WEBDAV_TPC_CRED_ERROR         2
#define XROOTD_WEBDAV_TPC_CRED_UNKNOWN_MODE  3
#define XROOTD_WEBDAV_TPC_CRED_PARSE_ERROR   4
#define XROOTD_WEBDAV_NTPC_CRED_EVENTS       5

/*
 * Fixed S3-compatible endpoint label slots.  Keep these deliberately small:
 * S3 bucket names, object keys, access keys, and principals must never become
 * Prometheus label values.
 */
#define XROOTD_S3_METHOD_GET      0
#define XROOTD_S3_METHOD_HEAD     1
#define XROOTD_S3_METHOD_PUT      2
#define XROOTD_S3_METHOD_DELETE   3
#define XROOTD_S3_METHOD_LIST     4
#define XROOTD_S3_METHOD_POST     5
#define XROOTD_S3_METHOD_OPTIONS  6
#define XROOTD_S3_METHOD_OTHER    7
#define XROOTD_S3_NMETHODS        8

#define XROOTD_S3_AUTH_ANONYMOUS       0
#define XROOTD_S3_AUTH_SIGV4_OK        1
#define XROOTD_S3_AUTH_MISSING         2
#define XROOTD_S3_AUTH_MALFORMED       3
#define XROOTD_S3_AUTH_BAD_KEY         4
#define XROOTD_S3_AUTH_BAD_DATE        5
#define XROOTD_S3_AUTH_SIG_MISMATCH    6
#define XROOTD_S3_AUTH_INTERNAL_ERROR  7
#define XROOTD_S3_NAUTH_RESULTS        8

#define XROOTD_S3_RANGE_FULL          0
#define XROOTD_S3_RANGE_PARTIAL       1
#define XROOTD_S3_RANGE_UNSATISFIED   2
#define XROOTD_S3_NRANGE_RESULTS      3

#define XROOTD_S3_PUT_EMPTY      0
#define XROOTD_S3_PUT_MEMORY     1
#define XROOTD_S3_PUT_SPOOLED    2
#define XROOTD_S3_PUT_MIXED      3
#define XROOTD_S3_NPUT_MODES     4

#define XROOTD_S3_EVENT_INVALID_URI         0
#define XROOTD_S3_EVENT_ACCESS_DENIED       1
#define XROOTD_S3_EVENT_NO_SUCH_KEY         2
#define XROOTD_S3_EVENT_WRITE_DISABLED      3
#define XROOTD_S3_EVENT_METHOD_NOT_ALLOWED  4
#define XROOTD_S3_EVENT_INTERNAL_ERROR      5
#define XROOTD_S3_EVENT_DIR_SENTINEL        6
#define XROOTD_S3_EVENT_DELETE_MISSING      7
#define XROOTD_S3_NEVENTS                   8

/*
 * FRM tape-stage counters (phase-35).  Low-cardinality only — stage outcomes by
 * coarse reason and a seconds-scale latency histogram; never a path/DN/reqid as a
 * label (INVARIANT #8).
 */
#define XROOTD_FRM_FAIL_COPYCMD   0   /* copycmd exited non-zero            */
#define XROOTD_FRM_FAIL_DISPATCH  1   /* stage agent gone / broken pipe     */
#define XROOTD_FRM_FAIL_TIMEOUT   2   /* copy_timeout exceeded              */
#define XROOTD_FRM_FAIL_VERIFY    3   /* size/checksum mismatch (Phase 4 F5)*/
#define XROOTD_FRM_FAIL_OTHER     4
#define XROOTD_FRM_NFAIL          5

/* Stage-latency histogram upper bounds in SECONDS (recall = seconds..hours):
 * 1, 10, 30, 60, 300, 1800, 3600, +Inf — 8 buckets. */
#define XROOTD_FRM_LATENCY_BUCKETS  8

/*
 * Per-process WebDAV metrics.  All fields are ngx_atomic_t so they are safe to
 * increment from any worker without a mutex.  Indexed arrays use the
 * XROOTD_WEBDAV_METHOD_*, XROOTD_HTTP_STATUS_*, XROOTD_WEBDAV_AUTH_RESULT_*,
 * etc. constants defined above.
 */
typedef struct {
    ngx_atomic_t  requests_total[XROOTD_WEBDAV_NMETHODS];  /* requests by HTTP method */
    ngx_atomic_t  responses_total[XROOTD_WEBDAV_NMETHODS][XROOTD_HTTP_NSTATUS]; /* responses by method × status class */
    ngx_atomic_t  auth_total[XROOTD_WEBDAV_NAUTH_RESULTS]; /* auth outcomes by result code */

    ngx_atomic_t  bytes_rx_total;   /* bytes received (PUT body) */
    ngx_atomic_t  bytes_tx_total;   /* bytes sent (GET body) */

    /* Per-IP-version bandwidth — avoids high-cardinality label explosion. */
    ngx_atomic_t  bytes_rx_ipv4_total;
    ngx_atomic_t  bytes_tx_ipv4_total;
    ngx_atomic_t  bytes_rx_ipv6_total;
    ngx_atomic_t  bytes_tx_ipv6_total;

    ngx_atomic_t  range_total[XROOTD_WEBDAV_NRANGE_RESULTS];  /* Range request outcomes */
    ngx_atomic_t  put_body_total[XROOTD_WEBDAV_NPUT_MODES];   /* PUT receive mode used */
    ngx_atomic_t  propfind_depth_total[XROOTD_WEBDAV_NPROPFIND_DEPTHS]; /* PROPFIND Depth: header value */
    ngx_atomic_t  propfind_entries_total;  /* total directory entries listed */
    ngx_atomic_t  tpc_total[XROOTD_WEBDAV_NTPC_EVENTS];   /* HTTP-TPC curl pull events */
    ngx_atomic_t  tpc_cred_total[XROOTD_WEBDAV_NTPC_CRED_EVENTS]; /* HTTP-TPC cred delegation */
    ngx_atomic_t  cors_total[XROOTD_WEBDAV_NCORS_EVENTS]; /* CORS preflight/allowed/denied */
} ngx_xrootd_webdav_metrics_t;

/*
 * Per-process S3-compatible API metrics.  Same atomicity rules as WebDAV above.
 * Key design note: S3 bucket names, object keys, access key IDs, and principals
 * MUST NOT become Prometheus label values — only the coarse method/status/auth
 * result codes are safe to export as labels.
 */
typedef struct {
    ngx_atomic_t  requests_total[XROOTD_S3_NMETHODS];  /* requests by S3 method */
    ngx_atomic_t  responses_total[XROOTD_S3_NMETHODS][XROOTD_HTTP_NSTATUS]; /* responses by method × status class */
    ngx_atomic_t  auth_total[XROOTD_S3_NAUTH_RESULTS]; /* SigV4 auth outcomes */

    ngx_atomic_t  bytes_rx_total;  /* bytes received (PutObject body) */
    ngx_atomic_t  bytes_tx_total;  /* bytes sent (GetObject body) */

    /* Per-IP-version bandwidth — avoids high-cardinality label explosion. */
    ngx_atomic_t  bytes_rx_ipv4_total;
    ngx_atomic_t  bytes_tx_ipv4_total;
    ngx_atomic_t  bytes_rx_ipv6_total;
    ngx_atomic_t  bytes_tx_ipv6_total;

    ngx_atomic_t  range_total[XROOTD_S3_NRANGE_RESULTS];  /* Range request outcomes */
    ngx_atomic_t  put_body_total[XROOTD_S3_NPUT_MODES];   /* PutObject receive mode */
    ngx_atomic_t  events_total[XROOTD_S3_NEVENTS];        /* misc error/event counts */

    ngx_atomic_t  list_contents_total;         /* objects returned by ListObjects */
    ngx_atomic_t  list_common_prefixes_total;  /* common-prefix groups returned */
    ngx_atomic_t  list_truncated_total;        /* ListObjects responses truncated */
} ngx_xrootd_s3_metrics_t;

/*
 * Per-process CVMFS protocol metrics (phase-68). Class labels are a fixed
 * 4-value set, so cardinality is bounded by construction; repo names and
 * object paths MUST NOT become label values.
 */
typedef enum {
    XROOTD_CVMFS_CLASS_CAS = 0,
    XROOTD_CVMFS_CLASS_MANIFEST,
    XROOTD_CVMFS_CLASS_GEO,
    XROOTD_CVMFS_CLASS_REJECT,
    XROOTD_CVMFS_CLASS_COUNT
} xrootd_cvmfs_class_metric_e;

/* ---- per-repository (fqrn) counters --------------------------------------
 * A site serves O(20) repositories, so the fqrn is a usable label — but the
 * name arrives FROM THE WIRE, so the label set must be BOUNDED or a scanner
 * minting random repo names explodes both the SHM and the Prometheus series
 * space. A fixed slot table holds the first XROOTD_CVMFS_REPO_SLOTS-1
 * distinct fqrns seen; everything past capacity folds into the reserved
 * last slot, exported as repo="_other". Slots register lock-free
 * (state: EMPTY -> CAS -> CLAIMED(write name) -> READY); a claim race can
 * duplicate a name across two slots, so RESOLUTION always returns the
 * LOWEST-index READY match and the exporter skips later duplicates — all
 * increments and all output converge on one slot per name. */
#define XROOTD_CVMFS_REPO_SLOTS     32
#define XROOTD_CVMFS_REPO_NAME_MAX  64

#define XROOTD_CVMFS_REPO_EMPTY    0u
#define XROOTD_CVMFS_REPO_CLAIMED  1u
#define XROOTD_CVMFS_REPO_READY    2u

typedef struct {
    ngx_atomic_t  state;                 /* EMPTY / CLAIMED / READY           */
    char          name[XROOTD_CVMFS_REPO_NAME_MAX];  /* fqrn, NUL-terminated  */

    ngx_atomic_t  requests_total[XROOTD_CVMFS_CLASS_COUNT]; /* by class      */
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
} ngx_xrootd_cvmfs_repo_metrics_t;

typedef struct {
    ngx_atomic_t  requests_total[XROOTD_CVMFS_CLASS_COUNT]; /* by traffic class */
    ngx_atomic_t  negative_hits_total;   /* 404s absorbed by the worker memo   */
    ngx_atomic_t  fills_total;           /* origin fills that published        */
    ngx_atomic_t  fill_failures_total;   /* fills that failed definitively     */
    ngx_atomic_t  verify_failures_total; /* CAS mismatches (quarantined)       */
    ngx_atomic_t  origin_failovers_total;/* second-endpoint attempts (T11)     */
    ngx_atomic_t  secure_requests_total; /* scvmfs preamble passes (T22)       */
    ngx_atomic_t  bytes_served_hit_total;  /* LAN out, served from cache       */
    ngx_atomic_t  bytes_served_fill_total; /* LAN out, served via a fresh fill */
    ngx_atomic_t  origin_bytes_total;      /* WAN in, pulled from Stratum-1s   */

    ngx_xrootd_cvmfs_repo_metrics_t repos[XROOTD_CVMFS_REPO_SLOTS];
} ngx_xrootd_cvmfs_metrics_t;

/*
 * Resolve the fqrn `name`/`len` to its SHM repo-metrics slot, registering it
 * on first sight; past capacity returns the reserved "_other" slot. NULL when
 * the metrics SHM is unmapped. Lock-free; safe from fill worker threads.
 * (metrics/cvmfs.c)
 */
ngx_xrootd_cvmfs_repo_metrics_t *xrootd_cvmfs_repo_slot(const char *name,
    size_t len);

/*
 * Per-process FRM tape-stage metrics (phase-35).  All ngx_atomic_t, lock-free.
 * The whole block is process-global (one tape queue per node), so it lives
 * directly in the root metrics object rather than per-listener.  All fields are
 * declared up front (across Phases 1-4) so the SHM struct ABI grows only once.
 */
typedef struct {
    ngx_atomic_t  requests_total;       /* stage requests admitted (new records)  */
    ngx_atomic_t  dedup_hits_total;     /* opens collapsed onto an in-flight stage */
    ngx_atomic_t  reject_inflight_total;/* admissions refused: queue at capacity   */
    ngx_atomic_t  stage_success_total;  /* recalls that completed ONLINE           */
    ngx_atomic_t  stage_fail_total[XROOTD_FRM_NFAIL]; /* failed recalls by reason  */
    ngx_atomic_t  in_flight;            /* gauge: requests QUEUED+STAGING right now */
    ngx_atomic_t  evict_total;          /* kXR_evict / Tape-REST release marks      */
    ngx_atomic_t  waitresp_total;       /* Phase 3: kXR_waitresp parks issued       */
    ngx_atomic_t  asynresp_total;       /* Phase 3: kXR_attn asynresp deliveries    */
    ngx_atomic_t  cmsd_have_total;      /* Phase 4 F1: now-resident paths registered*/
    ngx_atomic_t  migrate_total;        /* Phase 4 F6: migrate-out attempts (stub)  */
    ngx_atomic_t  purge_total;          /* Phase 4 F6: purge decisions logged (stub)*/
    /* Coarse seconds-scale latency histogram, stored NON-cumulative in SHM and
     * cumulated into Prometheus le-buckets at scrape time. */
    ngx_atomic_t  stage_latency_bucket[XROOTD_FRM_LATENCY_BUCKETS];
    ngx_atomic_t  stage_latency_count;
    ngx_atomic_t  stage_latency_sum_sec;
} ngx_xrootd_frm_metrics_t;

/* Maximum upstream endpoints tracked per listener for per-upstream labels. */
#define XROOTD_PROXY_MAX_UPSTREAMS       16
/* Max bytes in "host:port\0" upstream label string. */
#define XROOTD_PROXY_UPSTREAM_LABEL_LEN  64

/*
 * Per-upstream counter slice — same fields as the aggregate, indexed by the
 * upstream's position in xrootd_proxy_upstream[].  label[] is written once
 * at first-connection time (before it can be read by any exporter thread).
 */
typedef struct {
    char          label[XROOTD_PROXY_UPSTREAM_LABEL_LEN]; /* "host:port\0" */
    ngx_atomic_t  upstream_connects_total;
    ngx_atomic_t  upstream_connect_errors;
    ngx_atomic_t  upstream_auth_errors;
    ngx_atomic_t  opens_total;
    ngx_atomic_t  open_errors;
    ngx_atomic_t  reads_total;
    ngx_atomic_t  read_bytes_total;
    ngx_atomic_t  writes_total;
    ngx_atomic_t  write_bytes_total;
    ngx_atomic_t  closes_total;
    ngx_atomic_t  abandoned_handles_total;
    ngx_atomic_t  reconnects_total;
    ngx_atomic_t  path_ops_total;
    ngx_atomic_t  path_op_errors_total;
    ngx_atomic_t  wait_responses_total;
} ngx_xrootd_proxy_upstream_metrics_t;

/*
 * Per-server proxy counter block.  Tracks outbound upstream connections and
 * forwarded operations for servers that have xrootd_proxy on.
 */
typedef struct {
    ngx_atomic_t  upstream_connects_total;   /* successful TCP (or TLS) connects    */
    ngx_atomic_t  upstream_connect_errors;   /* TCP connect / TLS handshake errors  */
    ngx_atomic_t  upstream_auth_errors;      /* upstream login/auth rejected        */
    ngx_atomic_t  opens_total;              /* kXR_open forwarded OK               */
    ngx_atomic_t  open_errors;              /* kXR_open forwarded, upstream errored */
    ngx_atomic_t  reads_total;             /* kXR_read/pgread/readv forwarded OK  */
    ngx_atomic_t  read_bytes_total;        /* bytes returned to client via proxy  */
    ngx_atomic_t  writes_total;            /* kXR_write/pgwrite/writev forwarded OK */
    ngx_atomic_t  write_bytes_total;       /* bytes written upstream via proxy    */
    ngx_atomic_t  closes_total;            /* kXR_close forwarded OK              */
    ngx_atomic_t  abandoned_handles_total; /* open handles freed on disconnect    */
    ngx_atomic_t  reconnects_total;        /* idle upstream reconnect attempts    */
    ngx_atomic_t  path_ops_total;          /* path-based mutations forwarded OK   */
    ngx_atomic_t  path_op_errors_total;    /* path-based mutations upstream errored */
    ngx_atomic_t  wait_responses_total;    /* kXR_wait responses absorbed by proxy */

    /* Per-upstream breakdown (upstream_idx → slice).  Populated at first use. */
    ngx_xrootd_proxy_upstream_metrics_t  upstreams[XROOTD_PROXY_MAX_UPSTREAMS];
} ngx_xrootd_proxy_metrics_t;

/*
 * Why the stale-dirty cache reaper removed a cached file — the `reason` label on
 * xrootd_cache_dirty_reaped_total. Derived per file from its .cinfo write-back
 * state (xrootd_cache_cinfo_state):
 *   ABANDONED  — DIRTY, aged past xrootd_cache_dirty_max_age, and NEVER written
 *                back (flush_gen==0): the un-flushed bytes are discarded → loss.
 *   INCOMPLETE — DIRTY, aged, but the file HAD a prior successful write-back
 *                (flush_gen>0) and was re-dirtied: only the trailing dirty
 *                episode is discarded (earlier data reached the origin).
 *   COMPLETED  — CLEAN and fully written back (flush_gen>0), last flush aged out:
 *                a finished write-back staging copy reclaimed with NO data loss.
 *                (A read-through fill has flush_gen==0 and is left for eviction.)
 * Keep COUNT last; it sizes the per-reason counter array below.
 */
typedef enum {
    XROOTD_CACHE_REAP_ABANDONED = 0,
    XROOTD_CACHE_REAP_INCOMPLETE,
    XROOTD_CACHE_REAP_COMPLETED,
    XROOTD_CACHE_REAP_REASON_COUNT
} xrootd_cache_reap_reason_t;

/*
 * Per-server counter block.  Lives in shared memory; accessed by all
 * worker processes.  All integer fields are ngx_atomic_t so workers
 * can increment them without locks.
 *
 * auth[] and port are written once at config init time (before workers
 * fork) so no locking is needed for them.
 */
typedef struct {
    /* Connection and traffic counters exported as Prometheus counters/gauges. */
    ngx_atomic_t  connections_total;       /* connections accepted (lifetime) */
    ngx_atomic_t  connections_active;      /* currently open connections      */
    ngx_atomic_t  bytes_rx_total;          /* bytes received (write payloads) */
    ngx_atomic_t  bytes_tx_total;          /* bytes sent (read data)          */

    /* Per-protocol byte counters for stream-layer traffic breakdown. */
    ngx_atomic_t  proto_root_bytes_rx_total;   /* kXR_read/pgread/readv data     */
    ngx_atomic_t  proto_root_bytes_tx_total;   /* kXR_write/pgwrite/writev data  */

    /* Per-IP-version bandwidth counters — avoids high-cardinality label explosion. */
    ngx_atomic_t  bytes_rx_ipv4_total;         /* received from IPv4 clients      */
    ngx_atomic_t  bytes_tx_ipv4_total;         /* sent to IPv4 clients            */
    ngx_atomic_t  bytes_rx_ipv6_total;         /* received from IPv6 clients      */
    ngx_atomic_t  bytes_tx_ipv6_total;         /* sent to IPv6 clients            */

    /* Wire-level counters used for framing/debug/performance diagnosis. */
    ngx_atomic_t  wire_bytes_rx_total;      /* raw bytes received on socket    */
    ngx_atomic_t  wire_bytes_tx_total;      /* raw bytes written on socket     */
    ngx_atomic_t  request_frames_total;     /* parsed client request headers   */
    ngx_atomic_t  request_payload_bytes_total; /* declared request payload bytes */
    ngx_atomic_t  oversized_payloads_total; /* requests rejected as too large  */
    ngx_atomic_t  response_frames_total;    /* response send attempts          */
    ngx_atomic_t  response_write_stalls_total; /* socket send returned AGAIN    */
    ngx_atomic_t  response_write_errors_total; /* socket send/send_chain errors */

    /*
     * Indexed by XROOTD_OP_*; success/error are kept separate for export.
     *
     * These two arrays are the highest-frequency writes in the struct (every
     * completed operation bumps one slot).  Cache-line-align each so the hot
     * op_ok block does not false-share a line with the preceding scalar
     * counters, and so the hot success array does not bounce against the
     * mostly-cold op_err array.  The struct lives at a page-aligned SHM base,
     * so XROOTD_METRIC_CACHELINE alignment lands on a real 64-byte boundary
     * shared across worker processes.  (Per-slot padding to fully isolate
     * individual ops is deferred until high-core benchmarks justify the bloat:
     * 37 slots x 64 B x 2 arrays.)
     */
    XROOTD_METRIC_ALIGNED ngx_atomic_t op_ok [XROOTD_NOPS]; /* successful ops */
    XROOTD_METRIC_ALIGNED ngx_atomic_t op_err[XROOTD_NOPS]; /* failed ops     */

    /* Cache eviction counters, non-zero only for cache-enabled listeners. */
    ngx_atomic_t  cache_evictions_total;      /* files unlinked by eviction  */
    ngx_atomic_t  cache_evicted_bytes_total;  /* bytes reclaimed by eviction */
    ngx_atomic_t  cache_eviction_errors_total;/* eviction/stat/unlink errors */
    /* Files removed by the stale-dirty reaper, split by WHY (see
     * xrootd_cache_reap_reason_t): [ABANDONED]=un-flushed dirty discarded (loss),
     * [INCOMPLETE]=re-dirtied after a prior flush (partial loss), [COMPLETED]=a
     * finished write-back staging copy reclaimed (no loss). Counted over the
     * unified cache state root shared by the read-through AND write-through caches,
     * so it is reported for any active cache (gated on in_use, like the wt_
     * counters). Exported as xrootd_cache_dirty_reaped_total{reason="..."}. */
    ngx_atomic_t  cache_dirty_reaped[XROOTD_CACHE_REAP_REASON_COUNT];

    /* Write-through health counters. */
    ngx_atomic_t  wt_dirty_handles;
    ngx_atomic_t  wt_flush_pending;
    ngx_atomic_t  wt_flush_success_total;
    ngx_atomic_t  wt_flush_error_total;
    ngx_atomic_t  wt_flush_bytes_total;

    /* Path depth violation counter — requests rejected due to excessive component count.
     * Prevents CPU exhaustion from malicious symlink traversal chains or deep nesting. */
    ngx_atomic_t  path_depth_violations_total;

    /* §7 XrdSsi service counters (low-cardinality: no per-request labels). */
    ngx_atomic_t  ssi_requests_total;          /* SSI requests dispatched */
    ngx_atomic_t  ssi_errors_total;            /* SSI error responses */
    ngx_atomic_t  ssi_alerts_pushed_total;     /* out-of-band alerts pushed */
    ngx_atomic_t  ssi_attn_push_failures_total;/* failed kXR_attn pushes */

    /*
     * Identity for the listener bound to this slot.
     * The stream module assigns one slot per enabled server during startup.
     */
    ngx_uint_t    port;                    /* TCP listen port (0 = unknown)   */
    char          auth[8];                 /* "anon\0" or "gsi\0"             */
    ngx_uint_t    in_use;                  /* 1 = slot has been assigned      */

    /*
     * Cache labels/config copied from stream srv_conf once a listener accepts
     * traffic.  The HTTP metrics exporter uses cache_root for live statvfs()
     * gauges and the threshold for the configured high-water mark gauge.
     */
    ngx_uint_t    cache_enabled;            /* 1 when xrootd_cache is on       */
    ngx_uint_t    cache_eviction_threshold; /* occupancy ratio in ppm          */
    char          cache_root[PATH_MAX];     /* NUL-terminated cache root       */

    /* Proxy counters — non-zero only for listeners with xrootd_proxy on. */
    ngx_xrootd_proxy_metrics_t  proxy;

    /*
     * Phase 31 W4 — transfer-heap memory budget (SHM pool, shared across
     * workers for this server block).  xfer_heap_in_use is the live sum of bytes
     * held in per-connection transfer scratch buffers (read/write scratch + recv
     * payload); reconciled idempotently by xrootd_budget_sync() so it cannot
     * drift negative.  budget_waits_total counts reads deferred with kXR_wait
     * because they would have pushed in_use past xrootd_memory_budget.
     */
    ngx_atomic_t  xfer_heap_in_use;       /* bytes held in transfer scratch buffers */
    ngx_atomic_t  xfer_heap_high_water;   /* peak xfer_heap_in_use observed          */
    ngx_atomic_t  budget_waits_total;     /* reads deferred with kXR_wait (over budget) */

    /*
     * Phase 39 — network-fault resilience timeout counters (low-cardinality,
     * no path/UUID labels).  Each counts connections the steady-state deadline
     * machinery reaped; all stay 0 unless the operator enables the matching
     * directive (xrootd_handshake_timeout / xrootd_read_timeout / xrootd_send_timeout).
     */
    ngx_atomic_t  handshake_timeouts_total; /* pre-auth handshake deadline fired   */
    ngx_atomic_t  read_pdu_timeouts_total;  /* steady-state read deadline fired    */
    ngx_atomic_t  send_drain_timeouts_total;/* response-drain deadline fired       */
    ngx_atomic_t  connections_rejected_total; /* refused at xrootd_max_connections */

    /*
     * Phase 44 — optional io_uring disk-I/O backend (all 0 unless a worker
     * fronting this listener brought up the ring and submitted ops through it).
     * active is a 0/1 gauge set the first time the listener uses io_uring; ops vs
     * fallback give the ring-utilisation ratio for mapped (read/write/single-
     * group readv/writev) ops — unmapped ops (pgread/dirlist) are not counted.
     */
    ngx_atomic_t  io_uring_active;          /* gauge: 1 = listener used io_uring   */
    ngx_atomic_t  io_uring_ops_total;       /* mapped ops submitted via io_uring   */
    ngx_atomic_t  io_uring_fallback_total;  /* mapped ops that fell back to pool    */
} ngx_xrootd_srv_metrics_t;

/* ---- Per-VO traffic tracking (bounded LRU, low-cardinality) ---- */
#define XROOTD_VO_MAX_TRACKED     32
#define XROOTD_VO_NAME_LEN        16

typedef struct {
    char          name[XROOTD_VO_NAME_LEN];
    ngx_atomic_t  bytes_tx_total;
    ngx_atomic_t  bytes_rx_total;
    ngx_atomic_t  requests_total;
} ngx_xrootd_vo_slot_t;

typedef struct {
    ngx_xrootd_vo_slot_t  slots[XROOTD_VO_MAX_TRACKED];
    ngx_uint_t            slot_count;
    ngx_atomic_t          overflow_total;
} ngx_xrootd_vo_global_t;

/* ---- Unique user identity tracking (bounded LRU, hash-based) ---- */
#define XROOTD_USERS_MAX_TRACKED  1024

typedef struct {
    uint32_t      id_hash;
    time_t        first_seen;
    ngx_atomic_t  sessions_total;
} ngx_xrootd_user_slot_t;

typedef struct {
    ngx_xrootd_user_slot_t  slots[XROOTD_USERS_MAX_TRACKED];
    ngx_atomic_t            unique_count;
    ngx_atomic_t            total_unique;
    ngx_atomic_t            evictions_total;
} ngx_xrootd_user_global_t;

/*
 * Phase 6 unified observability counters.  These counters are intentionally
 * op-centric and protocol-labeled; legacy per-protocol counters remain
 * exported until callers can cut over their dashboards.
 */
typedef struct {
    ngx_atomic_t  io_bytes_read[XROOTD_PROTO_COUNT];
    ngx_atomic_t  io_bytes_written[XROOTD_PROTO_COUNT];
    ngx_atomic_t  io_ops_total[XROOTD_PROTO_COUNT]
                                  [XROOTD_METRIC_OP_COUNT]
                                  [XROOTD_ERR_COUNT];
    ngx_atomic_t  io_latency_bucket[XROOTD_PROTO_COUNT]
                                      [XROOTD_METRIC_OP_COUNT]
                                      [XROOTD_IO_LATENCY_BUCKETS];
    ngx_atomic_t  io_latency_count[XROOTD_PROTO_COUNT]
                                      [XROOTD_METRIC_OP_COUNT];
    ngx_atomic_t  io_latency_sum_usec[XROOTD_PROTO_COUNT]
                                         [XROOTD_METRIC_OP_COUNT];

    ngx_atomic_t  cache_hits[XROOTD_PROTO_COUNT];
    ngx_atomic_t  cache_misses[XROOTD_PROTO_COUNT];
    ngx_atomic_t  cache_bytes_evicted[XROOTD_PROTO_COUNT];

    /* Watermark-driven LRU reaper (reap_watermark.c). Process-wide, connection-
     * less: the background timer has no per-proto/per-server context. usage_ratio
     * is a GAUGE in ppm (0-1e6), emitted as a 0-1 ratio; the rest are counters. */
    ngx_atomic_t  cache_usage_ratio_ppm;         /* gauge: cache_root occupancy, ppm */
    ngx_atomic_t  cache_watermark_purges;        /* counter: purge runs that did work */
    ngx_atomic_t  cache_watermark_evicted_files; /* counter: files reaped by the reaper */
    ngx_atomic_t  cache_watermark_evicted_bytes; /* counter: bytes reaped by the reaper */

    /* Write-back-staging backpressure (stage_admit.c). usage_ratio is a GAUGE in
     * ppm (staging filesystem occupancy); the throttle counters split by action. */
    ngx_atomic_t  wt_stage_usage_ratio_ppm;      /* gauge: staging fs occupancy, ppm */
    ngx_atomic_t  wt_stage_throttled_wait;       /* counter: writes delayed (soft band) */
    ngx_atomic_t  wt_stage_throttled_reject;     /* counter: writes rejected (hard cap) */

    ngx_atomic_t  auth_total[XROOTD_PROTO_COUNT]
                            [XROOTD_METRIC_AUTH_COUNT]
                            [XROOTD_METRIC_AUTH_STATUS_COUNT];

    ngx_atomic_t  tpc_transfers[XROOTD_PROTO_COUNT]
                               [XROOTD_METRIC_TPC_DIRECTION_COUNT]
                               [XROOTD_ERR_COUNT];
    ngx_atomic_t  tpc_bytes[XROOTD_PROTO_COUNT]
                           [XROOTD_METRIC_TPC_DIRECTION_COUNT];
} ngx_xrootd_unified_metrics_t;

/*
 * Root shared-memory object stored in ngx_xrootd_shm_zone->data.
 * A fixed-size array keeps indexing simple and avoids extra allocation once
 * workers are running.
 */
typedef struct {
    ngx_xrootd_srv_metrics_t     servers[XROOTD_METRICS_MAX_SERVERS];
    ngx_xrootd_webdav_metrics_t  webdav;
    ngx_xrootd_s3_metrics_t      s3;
    ngx_xrootd_cvmfs_metrics_t   cvmfs;   /* phase-68 cvmfs:// protocol plane */
    ngx_xrootd_unified_metrics_t unified;
    ngx_xrootd_frm_metrics_t     frm;

    /* Server registry diagnostics. */
    ngx_atomic_t  registry_full_total;

    /* Phase 22 — active health-check counters (cluster group). */
    ngx_atomic_t  hc_probes_total;     /* probes started */
    ngx_atomic_t  hc_pass_total;       /* probes that passed */
    ngx_atomic_t  hc_fail_total;       /* probes that failed/timed out */
    ngx_atomic_t  hc_blacklist_total;  /* servers blacklisted via health check */

    /* Phase 24 — traffic-mirror counters (low cardinality, no labels). */
    ngx_atomic_t  mirror_http_total;             /* shadow HTTP responded */
    ngx_atomic_t  mirror_http_errors_total;      /* shadow HTTP connect/proto fail */
    ngx_atomic_t  mirror_http_dropped_total;     /* HTTP sampling/filter skip */
    ngx_atomic_t  mirror_http_divergence_total;  /* shadow status class != primary */
    ngx_atomic_t  mirror_stream_total;           /* shadow XRootD responded */
    ngx_atomic_t  mirror_stream_errors_total;    /* shadow XRootD connect/proto fail */
    ngx_atomic_t  mirror_stream_dropped_total;   /* stream sampling/filter skip */
    ngx_atomic_t  mirror_stream_divergence_total;/* shadow status != primary */

    /* Phase 25 — advanced rate limiting / traffic shaping counters. */
    ngx_atomic_t  rl_throttled_http_total;   /* HTTP/WebDAV requests answered 429   */
    ngx_atomic_t  rl_throttled_stream_total; /* stream requests answered kXR_wait   */
    ngx_atomic_t  rl_eviction_total;         /* LRU node evictions from a RL zone   */
    ngx_atomic_t  rl_zone_full_errors;       /* alloc failures (zone exhausted)     */

    /* Phase 27 F4 — session-registry anti-exhaustion. */
    ngx_atomic_t  session_registry_full_total; /* logins rejected: table full + nothing reapable */
    ngx_atomic_t  session_evict_total;         /* idle sessions reaped to admit a new login */

    /* Phase 34 — SciTags packet marking (low cardinality, no labels). */
    ngx_atomic_t  pmark_flows_started_total;   /* flows that mapped + were marked      */
    ngx_atomic_t  pmark_flows_ended_total;     /* flows that emitted an end firefly    */
    ngx_atomic_t  pmark_firefly_sent_total;    /* firefly datagrams sent OK            */
    ngx_atomic_t  pmark_firefly_dropped_total; /* firefly sendto failures (fail-open)  */
    ngx_atomic_t  pmark_flowlabel_set_total;   /* IPv6 flow labels stamped             */
    ngx_atomic_t  pmark_flowlabel_failed_total;/* flow-label setsockopt refusals       */
    ngx_atomic_t  pmark_map_unresolved_total;  /* opens with no (exp,act) mapping      */

    /* Phase 51 — cross-protocol resilience observability (low cardinality). */
    ngx_atomic_t  cms_read_timeouts_total;      /* A1: client manager-silence reconnects */
    ngx_atomic_t  cms_login_timeouts_total;     /* A1: server LOGIN-handshake deadline fired */
    ngx_atomic_t  cms_idle_closes_total;        /* A1: server post-login idle watchdog closed */
    ngx_atomic_t  cms_cap_rejections_total;     /* A1: accept refused (global or per-IP cap) */
    ngx_atomic_t  cms_frame_yields_total;       /* A2: read-loop yielded (flood fairness) */
    ngx_atomic_t  ocsp_timeouts_total;          /* E1: OCSP fetch hit the socket deadline */
    ngx_atomic_t  auth_l1_hits_total;           /* E2: auth-gate verdict served from L1 */
    ngx_atomic_t  auth_l1_misses_total;         /* E2: auth-gate L1 miss (fell to L2/eval) */
    ngx_atomic_t  acc_nss_breaker_open_total;   /* E3: NSS group-lookup breaker tripped open */
    ngx_atomic_t  acc_dns_breaker_open_total;   /* E3: reverse-DNS breaker tripped open */

    ngx_xrootd_vo_global_t    vo_global;
    ngx_xrootd_user_global_t  user_tracking;

    /*
     * Config/reload diagnostics, published by the master in init_module once per
     * config load (xrootd_config_version_publish()).  Lives in SHM so the HTTP
     * /healthz handler can read it, and so config_generation survives reload
     * (the metrics zone re-attaches).  config_generation counts loads (1 at first
     * start, +1 on every `nginx -s reload`); config_hash is an FNV-1a fingerprint
     * of the main config file (0 if it could not be read).
     */
    ngx_atomic_t  config_generation;
    uint64_t      config_hash;

} ngx_xrootd_metrics_t;

/*
 * Global pointer to the shared zone — set by the stream module during
 * postconfiguration; read by the HTTP metrics module at request time.
 */
extern ngx_shm_zone_t *ngx_xrootd_shm_zone;

/*
 * config.c — publish the config/reload fingerprint into the metrics SHM.  Call
 * once per config load from the module's init_module hook (after shared memory
 * is mapped): bumps config_generation and stores the FNV-1a hash of the main
 * config file, then logs a NOTICE.  No-op when no metrics zone exists.
 */
void  xrootd_config_version_publish(ngx_cycle_t *cycle);

/* tracking.c — per-VO traffic and unique user identity counting. */
ngx_int_t  xrootd_track_vo_activity(ngx_xrootd_metrics_t *shm,
    const char *vo_name, size_t bytes_tx, size_t bytes_rx);
ngx_int_t  xrootd_track_unique_user(ngx_xrootd_metrics_t *shm,
    const char *identity, size_t identity_len);

#include "metrics_macros.h"

#endif /* NGX_XROOTD_METRICS_H */
