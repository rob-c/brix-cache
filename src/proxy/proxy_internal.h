#pragma once

#include "proxy.h"

/*
 * WHAT: Internal declarations for the transparent XRootD proxy module — state machine enums,
 *       per-connection context struct, file handle map entry, pooled connection metadata, upstream
 *       health status, constants, and internal function signatures organized by source file.
 *       This header bridges proxy.h (public API) with implementation files across connect.c, events.c,
 *       forward.c, pool.c, and their sub-fragments.
 *
 * WHY:  The proxy operates a multi-phase upstream connection lifecycle (connecting → TLS handshake →
 *       bootstrap → idle → forwarding) tracked via xrootd_proxy_up_state_t + xrootd_proxy_bs_t enums.
 *       Each client-proxy session maintains a full context struct with write buffers, response accumulators,
 *       fh translation map, lazy-open queue, wait-retry state, redirect follow-through, and splice zero-copy
 *       plumbing. Pooled connections carry auth type/token hash/upstream index metadata for matching reuse.
 *       Health status per upstream enables fail detection and automatic skip of DOWN servers.
 *       Constants define pool size limits, keepalive intervals, retry budgets, and path length caps.
 *
 * HOW:  Structs defined inline with field comments explaining each member's purpose. Enums map state phases
 *       to numeric values for efficient comparison in event handlers. Function declarations grouped by source
 *       file (connect.c, events.c, forward.c) with inline WHAT comments where logic is non-obvious. The opaque
 *       typedef xrootd_proxy_ctx_t references the full struct definition here; public API in proxy.h declares
 *       only the externally visible functions.
 */

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
    u_char             token_hash[16];   /* MD5 of bearer token for pooling */
    time_t             idle_since;
    ngx_msec_t         keepalive_interval; /* snapshot of conf->proxy_keepalive_interval */
    ngx_event_t        ping_ev;            /* kXR_ping keepalive timer */
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
    int                      no_pool;

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
    /* Phase 39 (PXY-3): 1 = wbuf is raw heap (ngx_alloc) and MUST be ngx_free'd
     * when the send completes; 0 = wbuf is pool-allocated (bootstrap frames) and
     * must NOT be freed (the pool owns it).  xrootd_proxy_wbuf_release() honours
     * this so the deferred-completion path (events_write.c) frees a forwarded
     * request exactly once instead of leaking it per request. */
    unsigned  wbuf_owned:1;

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

    /* zero-copy splice state (kXR_read / kXR_pgread without TLS) */
    int    splice_pipe[2];       /* kernel pipe fds; [-1,-1] when not open */
    int    splice_active;        /* 1 while splicing a response body */
    size_t splice_total;         /* body bytes to transfer this response */
    size_t splice_upstream;      /* bytes moved: upstream_fd → pipe[1]  */
    size_t splice_downstream;    /* bytes moved: pipe[0]   → client_fd  */
};

/* ---- internal function declarations ---- */

/* connect.c */

/* Select an upstream (redirect > pool > round-robin > single), resolve DNS, open a
 * non-blocking socket, start the async connect, and arm bootstrap. On a pool hit
 * dispatches/resumes immediately. Borrows proxy/client_conn/conf (not owned).
 * Returns NGX_OK once a connect is in flight or completed (TLS/bootstrap continue via
 * event callbacks); NGX_ERROR after calling xrootd_proxy_cleanup() on hard failure. */
ngx_int_t xrootd_proxy_connect(xrootd_proxy_ctx_t *proxy,
    ngx_connection_t *client_conn,
    ngx_stream_xrootd_srv_conf_t *conf);
/* Handle an upstream error: log, mark the upstream failed. If idle with no open
 * handles and reconnect budget remains, transparently reconnect (client unaware);
 * otherwise tear the session down. reason is a borrowed static/log string. */
void      xrootd_proxy_abort(xrootd_proxy_ctx_t *proxy, const char *reason);
/* Drain proxy->wbuf to the upstream socket via uconn->send (TLS or plain), advancing
 * wbuf_pos. NGX_OK when fully sent, NGX_AGAIN on partial send (caller re-arms write),
 * NGX_ERROR on socket error. Does not free the buffer. */
ngx_int_t xrootd_proxy_flush(xrootd_proxy_ctx_t *proxy);

/* Phase 39 (PXY-3): release the upstream write buffer once its send has fully
 * completed.  Frees it iff it is heap-owned (a forwarded/relayed request from
 * ngx_alloc); pool-allocated bootstrap frames are merely detached (the pool owns
 * them).  Idempotent and NULL-safe.  Call this on EVERY send-complete path so a
 * deferred (backpressured / slow-consumer) request is not leaked. */
static ngx_inline void
xrootd_proxy_wbuf_release(xrootd_proxy_ctx_t *proxy)
{
    if (proxy->wbuf_owned && proxy->wbuf != NULL) {
        ngx_free(proxy->wbuf);
    }
    proxy->wbuf       = NULL;
    proxy->wbuf_owned = 0;
}

#if (NGX_SSL)
/* Called by write_handler when TLS is requested after async TCP connect. */
void xrootd_proxy_tls_handshake_done(ngx_connection_t *uconn);
#endif

/* Worker-local health status array — defined in pool.c, used in connect.c */
extern xrootd_proxy_up_status_t *proxy_up_status;

/* Pool management */
/* Init the worker-local idle-connection queue and counter. Call once at startup. */
void xrootd_proxy_pool_init(void);
/* Take a reusable, already-authenticated upstream connection out of the pool, matched
 * by health-aware round-robin upstream index + auth type (+ bearer-token MD5 in forward
 * mode). Returns the connection (caller takes ownership, must set c->data) and writes
 * the chosen upstream index to *idx_out; NULL when no match — caller must connect fresh. */
ngx_connection_t *xrootd_proxy_pool_get(xrootd_proxy_ctx_t *proxy,
    ngx_stream_xrootd_srv_conf_t *conf, int *idx_out);
/* Return proxy->conn to the pool for reuse if it is idle and not redirected; detaches it
 * from the ctx, allocs a pooled-conn record with auth/index/token-hash/keepalive timer,
 * and evicts the oldest entry when the pool is full. No-op if not poolable. */
void xrootd_proxy_pool_put(xrootd_proxy_ctx_t *proxy);

/* Health management */
/* Allocate/zero the worker-local per-upstream health array sized to the configured
 * upstream count (>=1). Idempotent: reuses the array if already large enough. */
void xrootd_proxy_up_status_init(ngx_stream_xrootd_srv_conf_t *conf);
/* Bump the fail counter for proxy's current upstream and stamp the check time; marks the
 * upstream DOWN once it reaches XROOTD_PROXY_MAX_FAILS. No-op if the status array is unsized. */
void xrootd_proxy_up_mark_failed(xrootd_proxy_ctx_t *proxy);
/* Clear DOWN and reset the fail counter for proxy's current upstream (logs the UP
 * transition). No-op if the status array is unsized. */
void xrootd_proxy_up_mark_ok(xrootd_proxy_ctx_t *proxy);

/* events.c */

/* ---- public API: xrootd_proxy_write_handler() — upstream write event callback ----
 * WHAT: Event handler for the upstream connection's write event; drains proxy->wbuf through the socket (TLS or plain),
 *       re-arms write event on partial sends, frees fully-transmitted buffers. Transitions state from CONNECTING/BOOTSTRAP/
 *       FORWARDING as bytes are consumed. On completion arms read event for response data. */

/* ---- public API: xrootd_proxy_read_handler() — upstream read event callback ----
 * WHAT: Event handler for the upstream connection's read event; accumulates response headers and body into rhdr/resp_body,
 *       dispatches based on current state (bootstrap phase reads handshake/protocol/login/auth responses, forwarding reads
 *       opcode results). On bootstrap completion calls handle_bootstrap(); on forwarding completes relay_to_client(). */

void xrootd_proxy_write_handler(ngx_event_t *wev);
void xrootd_proxy_read_handler(ngx_event_t *rev);

/* events_bootstrap.c — called from events_read.c on bootstrap completion. */
void xrootd_proxy_handle_bootstrap(xrootd_proxy_ctx_t *proxy);

/* events_splice.c — zero-copy splice path for plain-text kXR_read responses. */
/* Pump the in-progress splice: move upstream-fd -> pipe and pipe -> client-fd, updating
 * splice_upstream/splice_downstream until splice_total bytes are relayed. Re-armable from
 * both upstream-readable and client-writable events; no-op once either conn is gone. */
void      xrootd_proxy_splice_pump(xrootd_proxy_ctx_t *proxy);
/* Try to start a zero-copy splice for the current kXR_read/kXR_pgread response: lazily
 * creates the kernel pipe, sends the response header, then pumps. NGX_OK if splicing has
 * started (caller must NOT allocate resp_body or read the body); NGX_DECLINED when not
 * eligible (TLS on either side, wrong opcode/status, zero dlen, or pipe2 failure) so the
 * caller falls back to the buffered path. */
ngx_int_t xrootd_proxy_try_splice(xrootd_proxy_ctx_t *proxy);

/* forward.c */
/* Build the upstream request from the client's current frame (ctx->hdr_buf + payload),
 * applying fhandle translation, path rewriting, audit capture and kXR_wait-retry setup,
 * then send it. Allocates the request buffer (ngx_alloc, freed on send/cleanup) and may
 * pre-allocate a local fh for kXR_open. NGX_OK on send/queue; NGX_ERROR after the helper
 * has already replied to the client with a kXR error. Borrows ctx and c. */
ngx_int_t xrootd_proxy_forward_request(xrootd_proxy_ctx_t *proxy,
    xrootd_ctx_t *ctx, ngx_connection_t *c);
/* Relay the accumulated upstream response (resp_status/resp_dlen/resp_body) back to the
 * client, transparently handling lazy-open completion, kXR_wait retry, kXR_redirect
 * follow-through, upstream->local fhandle translation, path audit and oksofar streaming.
 * Consumes/frees resp_body as part of relaying. */
void      xrootd_proxy_relay_to_client(xrootd_proxy_ctx_t *proxy);
/* Return the index of the first free fh_map slot (upstream_fh == FREE), giving the proxy
 * its own local handle namespace; -1 if all XROOTD_MAX_FILES slots are in use. */
int       xrootd_proxy_alloc_local_fh(xrootd_proxy_ctx_t *proxy);
/* Emit a JSON audit record for fh_map[local_fh]; safe to call on any slot. */
void      proxy_write_audit(xrootd_proxy_ctx_t *proxy, int local_fh);

/* forward_rewrite_helpers.c — path/fh rewriting (called from forward_request.c). */
/* Apply the proxy_path_strip -> proxy_path_add prefix swap to the single path at
 * [path_off, path_off+path_len) inside the request buffer req of length total; the new
 * total is written to *total_out and the request's 4-byte dlen header is fixed up.
 * Returns req when the prefix does not match (in-place same-length rewrite included), or
 * a NEW ngx_alloc buffer when the result is longer. NOTE: on the realloc path the original
 * req is NOT freed here (caller owns/replaces it); on OOM returns req unchanged. */
u_char *proxy_rewrite_path(ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, u_char *req, size_t total,
    size_t path_off, size_t path_len, size_t *total_out);
/* Rewrite every newline-separated path in a kXR_prepare payload with the same prefix swap,
 * fixing up the dlen header; *total_out gets the new length. Returns req if nothing
 * matched (or OOM), else a NEW buffer — and in that case ngx_free()s the old req itself
 * (ownership transferred), unlike proxy_rewrite_path. */
u_char *proxy_rewrite_prepare_payload(ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, u_char *req, size_t total,
    size_t *total_out);
/* In place, replace the 1-byte local fhandle at buf[offset] with its upstream handle from
 * fh_map. Returns 0 on success, -1 if the local handle is out of range or maps to a free
 * slot (caller should reject the request). */
int proxy_translate_fh(xrootd_proxy_ctx_t *proxy, u_char *buf, size_t offset);
/*
 * Issue a synthetic kXR_open on the upstream for a handle that was opened
 * lazily (open-on-read).  Called from both forward.c and forward_relay.c.
 */
ngx_int_t xrootd_proxy_lazy_open(xrootd_proxy_ctx_t *proxy,
    xrootd_ctx_t *ctx, ngx_connection_t *c,
    int local_fh, u_char *read_req, size_t read_req_len);
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
