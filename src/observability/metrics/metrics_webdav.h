/*
 * metrics/metrics_webdav.h
 *
 * Per-process WebDAV (davs://) metrics: the fixed low-cardinality label slots
 * (method / auth-result / range / PUT-mode / PROPFIND-depth / TPC / CORS / TPC-
 * cred) and the counter struct.  Split out of metrics.h so each observability
 * domain owns a focused, independently reviewable header; referenced by
 * ngx_brix_srv_metrics_t via the embedded `webdav` member.  Shares the HTTP
 * status-class slots with the S3 domain via metrics_http_labels.h.
 */

#ifndef NGX_BRIX_METRICS_WEBDAV_H
#define NGX_BRIX_METRICS_WEBDAV_H

#include <ngx_core.h>

#include "metrics_http_labels.h"

/*
 * Fixed WebDAV label slots.  These are exported by name in metrics/export.c;
 * keep the order aligned with the string tables there.
 */
#define BRIX_WEBDAV_METHOD_OPTIONS  0
#define BRIX_WEBDAV_METHOD_HEAD     1
#define BRIX_WEBDAV_METHOD_GET      2
#define BRIX_WEBDAV_METHOD_PUT      3
#define BRIX_WEBDAV_METHOD_DELETE   4
#define BRIX_WEBDAV_METHOD_MKCOL    5
#define BRIX_WEBDAV_METHOD_COPY     6
#define BRIX_WEBDAV_METHOD_PROPFIND 7
#define BRIX_WEBDAV_METHOD_OTHER    8
#define BRIX_WEBDAV_NMETHODS        9

#define BRIX_WEBDAV_AUTH_RESULT_NONE       0
#define BRIX_WEBDAV_AUTH_RESULT_CERT_OK    1
#define BRIX_WEBDAV_AUTH_RESULT_TOKEN_OK   2
#define BRIX_WEBDAV_AUTH_RESULT_ANONYMOUS  3
#define BRIX_WEBDAV_AUTH_RESULT_REJECTED   4
#define BRIX_WEBDAV_NAUTH_RESULTS          5

#define BRIX_WEBDAV_RANGE_FULL          0
#define BRIX_WEBDAV_RANGE_PARTIAL       1
#define BRIX_WEBDAV_RANGE_UNSATISFIED   2
#define BRIX_WEBDAV_NRANGE_RESULTS      3

#define BRIX_WEBDAV_PUT_EMPTY      0
#define BRIX_WEBDAV_PUT_MEMORY     1
#define BRIX_WEBDAV_PUT_SPOOLED    2
#define BRIX_WEBDAV_PUT_THREADED   3
#define BRIX_WEBDAV_NPUT_MODES     4

#define BRIX_WEBDAV_PROPFIND_DEPTH_0      0
#define BRIX_WEBDAV_PROPFIND_DEPTH_1      1
#define BRIX_WEBDAV_PROPFIND_DEPTH_INF    2
#define BRIX_WEBDAV_NPROPFIND_DEPTHS      3

#define BRIX_WEBDAV_TPC_PULL_STARTED       0
#define BRIX_WEBDAV_TPC_PULL_SUCCESS       1
#define BRIX_WEBDAV_TPC_CURL_STARTED       2  /* shared by pull and push */
#define BRIX_WEBDAV_TPC_CURL_SUCCESS       3  /* shared by pull and push */
#define BRIX_WEBDAV_TPC_CURL_ERROR         4  /* shared by pull and push */
#define BRIX_WEBDAV_TPC_PUSH_STARTED       5
#define BRIX_WEBDAV_TPC_PUSH_SUCCESS       6
#define BRIX_WEBDAV_TPC_BAD_REQUEST        7
#define BRIX_WEBDAV_TPC_COMMIT_ERROR       8
#define BRIX_WEBDAV_NTPC_EVENTS            9

#define BRIX_WEBDAV_CORS_NO_ORIGIN   0
#define BRIX_WEBDAV_CORS_ALLOWED     1
#define BRIX_WEBDAV_CORS_DENIED      2
#define BRIX_WEBDAV_CORS_PREFLIGHT   3
#define BRIX_WEBDAV_NCORS_EVENTS     4

#define BRIX_WEBDAV_TPC_CRED_STARTED       0
#define BRIX_WEBDAV_TPC_CRED_SUCCESS       1
#define BRIX_WEBDAV_TPC_CRED_ERROR         2
#define BRIX_WEBDAV_TPC_CRED_UNKNOWN_MODE  3
#define BRIX_WEBDAV_TPC_CRED_PARSE_ERROR   4
#define BRIX_WEBDAV_NTPC_CRED_EVENTS       5

/*
 * Per-process WebDAV metrics.  All fields are ngx_atomic_t so they are safe to
 * increment from any worker without a mutex.  Indexed arrays use the
 * BRIX_WEBDAV_METHOD_*, BRIX_HTTP_STATUS_*, BRIX_WEBDAV_AUTH_RESULT_*,
 * etc. constants defined above.
 */
typedef struct {
    ngx_atomic_t  requests_total[BRIX_WEBDAV_NMETHODS];  /* requests by HTTP method */
    ngx_atomic_t  responses_total[BRIX_WEBDAV_NMETHODS][BRIX_HTTP_NSTATUS]; /* responses by method × status class */
    ngx_atomic_t  auth_total[BRIX_WEBDAV_NAUTH_RESULTS]; /* auth outcomes by result code */

    ngx_atomic_t  bytes_rx_total;   /* bytes received (PUT body) */
    ngx_atomic_t  bytes_tx_total;   /* bytes sent (GET body) */

    /* Per-IP-version bandwidth — avoids high-cardinality label explosion. */
    ngx_atomic_t  bytes_rx_ipv4_total;
    ngx_atomic_t  bytes_tx_ipv4_total;
    ngx_atomic_t  bytes_rx_ipv6_total;
    ngx_atomic_t  bytes_tx_ipv6_total;

    ngx_atomic_t  range_total[BRIX_WEBDAV_NRANGE_RESULTS];  /* Range request outcomes */
    ngx_atomic_t  put_body_total[BRIX_WEBDAV_NPUT_MODES];   /* PUT receive mode used */
    ngx_atomic_t  propfind_depth_total[BRIX_WEBDAV_NPROPFIND_DEPTHS]; /* PROPFIND Depth: header value */
    ngx_atomic_t  propfind_entries_total;  /* total directory entries listed */
    ngx_atomic_t  tpc_total[BRIX_WEBDAV_NTPC_EVENTS];   /* HTTP-TPC curl pull events */
    ngx_atomic_t  tpc_cred_total[BRIX_WEBDAV_NTPC_CRED_EVENTS]; /* HTTP-TPC cred delegation */
    ngx_atomic_t  cors_total[BRIX_WEBDAV_NCORS_EVENTS]; /* CORS preflight/allowed/denied */
} ngx_brix_webdav_metrics_t;

#endif /* NGX_BRIX_METRICS_WEBDAV_H */
