/*
 * metrics/metrics_proxy.h
 *
 * Per-server root:// reverse-proxy metrics: the aggregate counter block plus a
 * bounded per-upstream slice table (labelled "host:port"), for servers running
 * brix_proxy on.  Split out of metrics.h so each observability domain owns a
 * focused, independently reviewable header; referenced by ngx_brix_srv_metrics_t
 * via the embedded `proxy` member and by the proxy metric-increment macros.
 */

#ifndef NGX_BRIX_METRICS_PROXY_H
#define NGX_BRIX_METRICS_PROXY_H

#include <ngx_core.h>

/* Maximum upstream endpoints tracked per listener for per-upstream labels. */
#define BRIX_PROXY_MAX_UPSTREAMS       16
/* Max bytes in "host:port\0" upstream label string. */
#define BRIX_PROXY_UPSTREAM_LABEL_LEN  64

/*
 * Per-upstream counter slice — same fields as the aggregate, indexed by the
 * upstream's position in brix_proxy_upstream[].  label[] is written once
 * at first-connection time (before it can be read by any exporter thread).
 */
typedef struct {
    char          label[BRIX_PROXY_UPSTREAM_LABEL_LEN]; /* "host:port\0" */
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
} ngx_brix_proxy_upstream_metrics_t;

/*
 * Per-server proxy counter block.  Tracks outbound upstream connections and
 * forwarded operations for servers that have brix_proxy on.
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
    ngx_brix_proxy_upstream_metrics_t  upstreams[BRIX_PROXY_MAX_UPSTREAMS];
} ngx_brix_proxy_metrics_t;

#endif /* NGX_BRIX_METRICS_PROXY_H */
