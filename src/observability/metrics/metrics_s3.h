/*
 * metrics/metrics_s3.h
 *
 * Per-process S3-compatible API metrics: the fixed low-cardinality label slots
 * (method / SigV4-auth-result / range / PUT-mode / event) and the counter
 * struct.  Split out of metrics.h so each observability domain owns a focused,
 * independently reviewable header; referenced by ngx_brix_srv_metrics_t via the
 * embedded `s3` member.  Shares the HTTP status-class slots with the WebDAV
 * domain via metrics_http_labels.h.
 */

#ifndef NGX_BRIX_METRICS_S3_H
#define NGX_BRIX_METRICS_S3_H

#include <ngx_core.h>

#include "metrics_http_labels.h"

/*
 * Fixed S3-compatible endpoint label slots.  Keep these deliberately small:
 * S3 bucket names, object keys, access keys, and principals must never become
 * Prometheus label values.
 */
#define BRIX_S3_METHOD_GET      0
#define BRIX_S3_METHOD_HEAD     1
#define BRIX_S3_METHOD_PUT      2
#define BRIX_S3_METHOD_DELETE   3
#define BRIX_S3_METHOD_LIST     4
#define BRIX_S3_METHOD_POST     5
#define BRIX_S3_METHOD_OPTIONS  6
#define BRIX_S3_METHOD_OTHER    7
#define BRIX_S3_NMETHODS        8

#define BRIX_S3_AUTH_ANONYMOUS       0
#define BRIX_S3_AUTH_SIGV4_OK        1
#define BRIX_S3_AUTH_MISSING         2
#define BRIX_S3_AUTH_MALFORMED       3
#define BRIX_S3_AUTH_BAD_KEY         4
#define BRIX_S3_AUTH_BAD_DATE        5
#define BRIX_S3_AUTH_SIG_MISMATCH    6
#define BRIX_S3_AUTH_INTERNAL_ERROR  7
#define BRIX_S3_NAUTH_RESULTS        8

#define BRIX_S3_RANGE_FULL          0
#define BRIX_S3_RANGE_PARTIAL       1
#define BRIX_S3_RANGE_UNSATISFIED   2
#define BRIX_S3_NRANGE_RESULTS      3

#define BRIX_S3_PUT_EMPTY      0
#define BRIX_S3_PUT_MEMORY     1
#define BRIX_S3_PUT_SPOOLED    2
#define BRIX_S3_PUT_MIXED      3
#define BRIX_S3_NPUT_MODES     4

#define BRIX_S3_EVENT_INVALID_URI         0
#define BRIX_S3_EVENT_ACCESS_DENIED       1
#define BRIX_S3_EVENT_NO_SUCH_KEY         2
#define BRIX_S3_EVENT_WRITE_DISABLED      3
#define BRIX_S3_EVENT_METHOD_NOT_ALLOWED  4
#define BRIX_S3_EVENT_INTERNAL_ERROR      5
#define BRIX_S3_EVENT_DIR_SENTINEL        6
#define BRIX_S3_EVENT_DELETE_MISSING      7
#define BRIX_S3_NEVENTS                   8

/*
 * Per-process S3-compatible API metrics.  Same atomicity rules as WebDAV.
 * Key design note: S3 bucket names, object keys, access key IDs, and principals
 * MUST NOT become Prometheus label values — only the coarse method/status/auth
 * result codes are safe to export as labels.
 */
typedef struct {
    ngx_atomic_t  requests_total[BRIX_S3_NMETHODS];  /* requests by S3 method */
    ngx_atomic_t  responses_total[BRIX_S3_NMETHODS][BRIX_HTTP_NSTATUS]; /* responses by method × status class */
    ngx_atomic_t  auth_total[BRIX_S3_NAUTH_RESULTS]; /* SigV4 auth outcomes */

    ngx_atomic_t  bytes_rx_total;  /* bytes received (PutObject body) */
    ngx_atomic_t  bytes_tx_total;  /* bytes sent (GetObject body) */

    /* Per-IP-version bandwidth — avoids high-cardinality label explosion. */
    ngx_atomic_t  bytes_rx_ipv4_total;
    ngx_atomic_t  bytes_tx_ipv4_total;
    ngx_atomic_t  bytes_rx_ipv6_total;
    ngx_atomic_t  bytes_tx_ipv6_total;

    ngx_atomic_t  range_total[BRIX_S3_NRANGE_RESULTS];  /* Range request outcomes */
    ngx_atomic_t  put_body_total[BRIX_S3_NPUT_MODES];   /* PutObject receive mode */
    ngx_atomic_t  events_total[BRIX_S3_NEVENTS];        /* misc error/event counts */

    ngx_atomic_t  list_contents_total;         /* objects returned by ListObjects */
    ngx_atomic_t  list_common_prefixes_total;  /* common-prefix groups returned */
    ngx_atomic_t  list_truncated_total;        /* ListObjects responses truncated */
} ngx_brix_s3_metrics_t;

#endif /* NGX_BRIX_METRICS_S3_H */
