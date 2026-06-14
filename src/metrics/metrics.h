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

    /* Write-through health counters. */
    ngx_atomic_t  wt_dirty_handles;
    ngx_atomic_t  wt_flush_pending;
    ngx_atomic_t  wt_flush_success_total;
    ngx_atomic_t  wt_flush_error_total;
    ngx_atomic_t  wt_flush_bytes_total;

    /* Path depth violation counter — requests rejected due to excessive component count.
     * Prevents CPU exhaustion from malicious symlink traversal chains or deep nesting. */
    ngx_atomic_t  path_depth_violations_total;

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
    ngx_xrootd_unified_metrics_t unified;

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

    ngx_xrootd_vo_global_t    vo_global;
    ngx_xrootd_user_global_t  user_tracking;

} ngx_xrootd_metrics_t;

/*
 * Global pointer to the shared zone — set by the stream module during
 * postconfiguration; read by the HTTP metrics module at request time.
 */
extern ngx_shm_zone_t *ngx_xrootd_shm_zone;

/* tracking.c — per-VO traffic and unique user identity counting. */
ngx_int_t  xrootd_track_vo_activity(ngx_xrootd_metrics_t *shm,
    const char *vo_name, size_t bytes_tx, size_t bytes_rx);
ngx_int_t  xrootd_track_unique_user(ngx_xrootd_metrics_t *shm,
    const char *identity, size_t identity_len);

#include "metrics_macros.h"

#endif /* NGX_XROOTD_METRICS_H */
