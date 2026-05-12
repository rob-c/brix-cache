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
#define XROOTD_OP_QUERY_SPACE 18  /* kXR_query / kXR_QSpace    */
#define XROOTD_OP_READV       19  /* kXR_readv                 */
#define XROOTD_OP_PGREAD      20  /* kXR_pgread                */
#define XROOTD_OP_WRITEV      21  /* kXR_writev                */
#define XROOTD_OP_LOCATE      22  /* kXR_locate                */
#define XROOTD_OP_STATX       23  /* kXR_statx                 */
#define XROOTD_OP_FATTR       24  /* kXR_fattr                 */
#define XROOTD_OP_QUERY_STATS 25  /* kXR_query / kXR_QStats    */
#define XROOTD_OP_QUERY_XATTR 26  /* kXR_query / kXR_Qxattr    */
#define XROOTD_OP_QUERY_FINFO 27  /* kXR_query / kXR_QFinfo    */
#define XROOTD_OP_QUERY_FSINFO 28 /* kXR_query / kXR_QFSinfo   */
#define XROOTD_OP_SET          29 /* kXR_set                    */
#define XROOTD_OP_QUERY_VISA   30 /* kXR_query / kXR_Qvisa     */
#define XROOTD_OP_QUERY_OPAQUE 31 /* kXR_query / kXR_Qopaque   */
#define XROOTD_OP_QUERY_OPAQUF 32 /* kXR_query / kXR_Qopaquf   */
#define XROOTD_OP_QUERY_OPAQUG 33 /* kXR_query / kXR_Qopaqug   */
#define XROOTD_OP_QUERY_CKSCAN 34 /* kXR_query / kXR_Qckscan   */
#define XROOTD_OP_CLONE        35 /* kXR_clone                 */
#define XROOTD_OP_CHKPOINT     36 /* kXR_chkpoint              */
/* Number of entries in op_ok[] / op_err[] and xrootd_op_names[]. */
#define XROOTD_NOPS           37

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

#define XROOTD_WEBDAV_FD_CACHE_HIT       0
#define XROOTD_WEBDAV_FD_CACHE_MISS      1
#define XROOTD_WEBDAV_FD_CACHE_INSERT    2
#define XROOTD_WEBDAV_FD_CACHE_UPDATE    3
#define XROOTD_WEBDAV_FD_CACHE_EVICT     4
#define XROOTD_WEBDAV_FD_CACHE_STALE     5
#define XROOTD_WEBDAV_NFD_CACHE_EVENTS   6

#define XROOTD_WEBDAV_PROPFIND_DEPTH_0      0
#define XROOTD_WEBDAV_PROPFIND_DEPTH_1      1
#define XROOTD_WEBDAV_NPROPFIND_DEPTHS      2

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
#define XROOTD_S3_METHOD_OTHER    6
#define XROOTD_S3_NMETHODS        7

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
    ngx_atomic_t  fd_cache_total[XROOTD_WEBDAV_NFD_CACHE_EVENTS]; /* fd-cache hit/miss/evict */
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

    /* Indexed by XROOTD_OP_*; success/error are kept separate for export. */
    ngx_atomic_t  op_ok [XROOTD_NOPS];    /* successful ops by index         */
    ngx_atomic_t  op_err[XROOTD_NOPS];    /* failed ops by index             */

    /* Cache eviction counters, non-zero only for cache-enabled listeners. */
    ngx_atomic_t  cache_evictions_total;      /* files unlinked by eviction  */
    ngx_atomic_t  cache_evicted_bytes_total;  /* bytes reclaimed by eviction */
    ngx_atomic_t  cache_eviction_errors_total;/* eviction/stat/unlink errors */

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
#define XROOTD_USERS_MAX_TRACKED  512

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
 * Root shared-memory object stored in ngx_xrootd_shm_zone->data.
 * A fixed-size array keeps indexing simple and avoids extra allocation once
 * workers are running.
 */
typedef struct {
    ngx_xrootd_srv_metrics_t     servers[XROOTD_METRICS_MAX_SERVERS];
    ngx_xrootd_webdav_metrics_t  webdav;
    ngx_xrootd_s3_metrics_t      s3;

    /* Server registry diagnostics. */
    ngx_atomic_t  registry_full_total;

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

static ngx_inline ngx_xrootd_metrics_t *
xrootd_metrics_shared(void)
{
    if (ngx_xrootd_shm_zone == NULL
        || ngx_xrootd_shm_zone->data == NULL
        || ngx_xrootd_shm_zone->data == (void *) 1)
    {
        return NULL;
    }

    return (ngx_xrootd_metrics_t *) ngx_xrootd_shm_zone->data;
}

#define XROOTD_ATOMIC_INC(counter)                                           \
    do {                                                                     \
        ngx_atomic_fetch_add((counter), 1);                                  \
    } while (0)

#define XROOTD_ATOMIC_DEC(counter)                                           \
    do {                                                                     \
        ngx_atomic_fetch_add((counter), (ngx_atomic_int_t) -1);              \
    } while (0)

#define XROOTD_ATOMIC_ADD(counter, amount)                                   \
    do {                                                                     \
        size_t _xrootd_metric_amount = (size_t) (amount);                    \
        if (_xrootd_metric_amount > 0) {                                     \
            ngx_atomic_fetch_add((counter), _xrootd_metric_amount);          \
        }                                                                    \
    } while (0)

#define XROOTD_SRV_METRIC_INC(ctx, field)                                    \
    do {                                                                     \
        if ((ctx) != NULL && (ctx)->metrics != NULL) {                       \
            XROOTD_ATOMIC_INC(&(ctx)->metrics->field);                       \
        }                                                                    \
    } while (0)

#define XROOTD_SRV_METRIC_ADD(ctx, field, amount)                            \
    do {                                                                     \
        if ((ctx) != NULL && (ctx)->metrics != NULL) {                       \
            XROOTD_ATOMIC_ADD(&(ctx)->metrics->field, (amount));             \
        }                                                                    \
    } while (0)

#define XROOTD_WEBDAV_METRIC_INC(field)                                      \
    do {                                                                     \
        ngx_xrootd_metrics_t *_xrootd_metrics = xrootd_metrics_shared();     \
        if (_xrootd_metrics != NULL) {                                       \
            XROOTD_ATOMIC_INC(&_xrootd_metrics->webdav.field);               \
        }                                                                    \
    } while (0)

#define XROOTD_WEBDAV_METRIC_ADD(field, amount)                              \
    do {                                                                     \
        ngx_xrootd_metrics_t *_xrootd_metrics = xrootd_metrics_shared();     \
        if (_xrootd_metrics != NULL) {                                       \
            XROOTD_ATOMIC_ADD(&_xrootd_metrics->webdav.field, (amount));     \
        }                                                                    \
    } while (0)

#define XROOTD_S3_METRIC_INC(field)                                          \
    do {                                                                     \
        ngx_xrootd_metrics_t *_xrootd_metrics = xrootd_metrics_shared();     \
        if (_xrootd_metrics != NULL) {                                       \
            XROOTD_ATOMIC_INC(&_xrootd_metrics->s3.field);                   \
        }                                                                    \
    } while (0)

#define XROOTD_S3_METRIC_ADD(field, amount)                                  \
    do {                                                                     \
        ngx_xrootd_metrics_t *_xrootd_metrics = xrootd_metrics_shared();     \
        if (_xrootd_metrics != NULL) {                                       \
            XROOTD_ATOMIC_ADD(&_xrootd_metrics->s3.field, (amount));         \
        }                                                                    \
    } while (0)

/* Proxy metrics — use these from proxy/ sources.  ctx->metrics may be NULL. */
#define XROOTD_PROXY_METRIC_INC(ctx, field)                                  \
    do {                                                                     \
        if ((ctx) != NULL && (ctx)->metrics != NULL) {                       \
            XROOTD_ATOMIC_INC(&(ctx)->metrics->proxy.field);                 \
        }                                                                    \
    } while (0)

#define XROOTD_PROXY_METRIC_ADD(ctx, field, amount)                          \
    do {                                                                     \
        if ((ctx) != NULL && (ctx)->metrics != NULL) {                       \
            XROOTD_ATOMIC_ADD(&(ctx)->metrics->proxy.field, (amount));       \
        }                                                                    \
    } while (0)

/*
 * Per-upstream breakdown macros.  proxy_ptr must be xrootd_proxy_ctx_t *.
 * These increment the per-upstream slice at proxy_ptr->upstream_idx alongside
 * the aggregate; call XROOTD_PROXY_METRIC_INC first, then one of these.
 */
#define XROOTD_PROXY_UP_INC(proxy_ptr, field)                                \
    do {                                                                     \
        int _ui = (proxy_ptr)->upstream_idx;                                 \
        if (_ui >= 0 && _ui < XROOTD_PROXY_MAX_UPSTREAMS                    \
            && (proxy_ptr)->client_ctx != NULL                               \
            && (proxy_ptr)->client_ctx->metrics != NULL)                     \
        {                                                                    \
            XROOTD_ATOMIC_INC(                                               \
                &(proxy_ptr)->client_ctx->metrics->proxy.upstreams[_ui].field); \
        }                                                                    \
    } while (0)

#define XROOTD_PROXY_UP_ADD(proxy_ptr, field, amount)                        \
    do {                                                                     \
        int _ui = (proxy_ptr)->upstream_idx;                                 \
        if (_ui >= 0 && _ui < XROOTD_PROXY_MAX_UPSTREAMS                    \
            && (proxy_ptr)->client_ctx != NULL                               \
            && (proxy_ptr)->client_ctx->metrics != NULL)                     \
        {                                                                    \
            XROOTD_ATOMIC_ADD(                                               \
                &(proxy_ptr)->client_ctx->metrics->proxy.upstreams[_ui].field, \
                (amount));                                                   \
        }                                                                    \
    } while (0)

#endif /* NGX_XROOTD_METRICS_H */
