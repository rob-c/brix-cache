#pragma once

#include "proxy.h"

/* Maximum upstream response body we will buffer (16 MiB — matches max write payload) */
#define XROOTD_PROXY_MAX_BODY  (16 * 1024 * 1024)

/* Sentinel: fh_map slot is free */
#define XROOTD_PROXY_FH_FREE  (-1)

/* Max path length stored per handle for audit logging. */
#define XROOTD_PROXY_PATH_MAX  512

/* Maximum kXR_wait responses we will absorb before relaying to the client. */
#define XROOTD_PROXY_MAX_WAIT_RETRIES  5
/* Cap on upstream-supplied wait seconds; prevents runaway timers. */
#define XROOTD_PROXY_MAX_WAIT_SECS    30

/* Maximum idle connections to keep in the pool. */
#define XROOTD_PROXY_POOL_SIZE       32
/* Maximum time a connection can stay idle in the pool. */
#define XROOTD_PROXY_POOL_KEEPALIVE  60

/* Health tracking constants. */
#define XROOTD_PROXY_MAX_FAILS       3
#define XROOTD_PROXY_FAIL_TIMEOUT    10

/*
 * Per-handle entry in the file handle map.
 */
typedef struct {
    int          upstream_fh;                   /* upstream handle; -1 = free */
    char         path[XROOTD_PROXY_PATH_MAX];   /* path supplied at open      */
    ngx_msec_t   open_msec;                     /* ngx_current_msec at open   */
    uint64_t     bytes_read;                    /* bytes relayed to client    */
    uint64_t     bytes_written;                 /* bytes forwarded upstream   */
} xrootd_proxy_fh_entry_t;

/* ---- upstream-side state machine ---- */

typedef enum {
    XRD_PX_CONNECTING = 0,  /* TCP connect() in progress           */
    XRD_PX_TLS_HANDSHAKE,   /* TLS handshake with upstream         */
    XRD_PX_BOOTSTRAP,       /* handshake / protocol / login phase  */
    XRD_PX_IDLE,            /* connected, ready to forward         */
    XRD_PX_FORWARDING,      /* request forwarded, awaiting reply   */
} xrootd_proxy_up_state_t;

typedef enum {
    XRD_PX_BS_HANDSHAKE = 0,  /* reading server hello (12 bytes via 8+4) */
    XRD_PX_BS_PROTOCOL,       /* reading kXR_protocol response           */
    XRD_PX_BS_LOGIN,          /* reading kXR_login response              */
    XRD_PX_BS_AUTH,           /* reading kXR_auth response (token fwd)   */
    XRD_PX_BS_DONE,           /* bootstrap complete                      */
} xrootd_proxy_bs_t;

/* ---- connection pooling ---- */

typedef struct {
    ngx_queue_t        queue;
    ngx_connection_t  *conn;
    ngx_uint_t         upstream_idx;
    ngx_uint_t         auth_type;
    u_char             token_hash[16];  /* MD5 of bearer token for pooling */
    time_t             idle_since;
    ngx_event_t        ping_ev;         /* kXR_ping keepalive timer */
} xrootd_proxy_pooled_conn_t;

/* ---- upstream health status (per-worker) ---- */

typedef struct {
    ngx_uint_t         fails;
    time_t             checked;
    ngx_uint_t         down;
} xrootd_proxy_up_status_t;

/* ---- per-connection proxy state ---- */

struct xrootd_proxy_ctx_s {
    /* upstream TCP socket */
    ngx_connection_t        *conn;
    xrootd_proxy_up_state_t  state;
    xrootd_proxy_bs_t        bs_phase;

    /* server config — needed in connect/events without carrying it everywhere */
    ngx_stream_xrootd_srv_conf_t  *conf;

    /* upstream response accumulation */
    u_char    rhdr[XRD_RESPONSE_HDR_LEN];
    size_t    rhdr_pos;
    uint16_t  resp_status;
    uint32_t  resp_dlen;
    u_char   *resp_body;      /* heap-allocated (ngx_alloc); freed after relay */
    size_t    resp_body_pos;

    /* upstream write buffer */
    u_char   *wbuf;
    size_t    wbuf_len;
    size_t    wbuf_pos;

    /* back-references to client session */
    xrootd_ctx_t     *client_ctx;
    ngx_connection_t *client_conn;

    /* metadata for the currently in-flight forwarded request */
    uint16_t  fwd_reqid;        /* opcode we forwarded                      */
    u_char    fwd_streamid[2];  /* client's streamid, echoed in response    */
    int       fwd_local_fh;     /* local fh for this op (-1 if none)        */
    int       fwd_streaming;    /* 1 = relaying kXR_oksofar stream          */
    size_t    fwd_payload_len;  /* outbound payload bytes (for write stats) */

    /* request saved during upstream bootstrap (NULL after dispatch) */
    u_char   *saved_req;       /* full 24-byte header + payload; heap-alloc */
    size_t    saved_req_len;
    int       saved_local_fh;  /* pre-allocated local fh for a deferred open */

    /* 1 while we are doing a synthetic kXR_open on behalf of a bound secondary */
    int       fwd_is_lazy_open;

    /* remaining upstream reconnect budget (decremented on each idle reconnect) */
    int       reconnect_left;

    /* which entry in conf->proxy_upstreams was selected at connect time; -1 = legacy single */
    int       upstream_idx;

    /* 1 if this connection was pulled from the pool and doesn't need bootstrap */
    unsigned  from_pool:1;

    /* path-based op audit: captured at forward time, written on final response */
    char      fwd_path[XROOTD_PROXY_PATH_MAX];   /* primary path (rm/mkdir/mv/chmod/trunc) */
    char      fwd_path2[XROOTD_PROXY_PATH_MAX];  /* dest path for kXR_mv                  */
    uint8_t   fwd_path_audit;                     /* 1 = write path audit record on response */

    /* kXR_wait retry: transparent to the client */
    u_char       *wait_retry_req;      /* copy of in-flight request for retry   */
    size_t        wait_retry_req_len;
    int           wait_retry_local_fh; /* fwd_local_fh saved alongside the copy */
    int           wait_retry_count;    /* kXR_wait responses absorbed so far    */
    ngx_event_t   wait_ev;            /* timer that fires when kXR_wait expires */

    /* kXR_redirect follow-through: transparently reconnect to another server */
    ngx_str_t     redirect_host;
    uint16_t      redirect_port;
    int           redirect_count;     /* number of redirects followed so far    */

    /* Queue of local fhs still needing lazy-open for a multi-handle kXR_readv.
     * After each lazy-open completes, the next fh is dequeued and opened.
     * When empty, the saved readv is dispatched with all fhs resolved. */
    int       lazy_open_pending_fhs[XROOTD_MAX_FILES];
    int       lazy_open_pending_count;

    /* file handle translation: fh_map[local_idx].upstream_fh = upstream handle
     * upstream_fh == XROOTD_PROXY_FH_FREE (-1) means the slot is unallocated */
    xrootd_proxy_fh_entry_t  fh_map[XROOTD_MAX_FILES];
};

/* ---- internal function declarations ---- */

/* connect.c */
ngx_int_t xrootd_proxy_connect(xrootd_proxy_ctx_t *proxy,
    ngx_connection_t *client_conn,
    ngx_stream_xrootd_srv_conf_t *conf);
void xrootd_proxy_abort(xrootd_proxy_ctx_t *proxy, const char *reason);
ngx_int_t xrootd_proxy_flush(xrootd_proxy_ctx_t *proxy);
#if (NGX_SSL)
/* Called by write_handler when TLS is requested after async TCP connect. */
void xrootd_proxy_tls_handshake_done(ngx_connection_t *uconn);
#endif

/* Worker-local health status array — defined in pool.c, used in connect.c */
extern xrootd_proxy_up_status_t *proxy_up_status;

/* Pool management */
void xrootd_proxy_pool_init(void);
ngx_connection_t *xrootd_proxy_pool_get(xrootd_proxy_ctx_t *proxy,
    ngx_stream_xrootd_srv_conf_t *conf, int *idx_out);
void xrootd_proxy_pool_put(xrootd_proxy_ctx_t *proxy);

/* Health management */
void xrootd_proxy_up_status_init(ngx_stream_xrootd_srv_conf_t *conf);
void xrootd_proxy_up_mark_failed(xrootd_proxy_ctx_t *proxy);
void xrootd_proxy_up_mark_ok(xrootd_proxy_ctx_t *proxy);

/* events.c */
void xrootd_proxy_write_handler(ngx_event_t *wev);
void xrootd_proxy_read_handler(ngx_event_t *rev);

/* forward.c */
ngx_int_t xrootd_proxy_forward_request(xrootd_proxy_ctx_t *proxy,
    xrootd_ctx_t *ctx, ngx_connection_t *c);
void      xrootd_proxy_relay_to_client(xrootd_proxy_ctx_t *proxy);
int       xrootd_proxy_alloc_local_fh(xrootd_proxy_ctx_t *proxy);
/* Emit a JSON audit record for fh_map[local_fh]; safe to call on any slot. */
void      proxy_write_audit(xrootd_proxy_ctx_t *proxy, int local_fh);
/*
 * Dispatch the saved_req that was queued during bootstrap.
 * Handles lazy-open for bound-secondary kXR_read with an unresolved handle.
 * Called from events.c when bootstrap completes.
 */
ngx_int_t xrootd_proxy_dispatch_pending(xrootd_proxy_ctx_t *proxy);
/*
 * Timer callback: re-issues a saved kXR_open after the upstream kXR_wait
 * countdown has elapsed.
 */
void xrootd_proxy_wait_handler(ngx_event_t *ev);
