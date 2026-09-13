#ifndef BRIX_PROXY_PROXY_INTERNAL_H
#define BRIX_PROXY_PROXY_INTERNAL_H

#include "proxy.h"
#include "net/tap/tap.h"   /* Phase-4a observation tap */

/*
 * WHAT: Internal declarations for the transparent XRootD proxy module — state machine enums,
 *       per-connection context struct, file handle map entry, pooled connection metadata, upstream
 *       health status, constants, and internal function signatures organized by source file.
 *       This header bridges proxy.h (public API) with implementation files across connect.c, events.c,
 *       forward.c, pool.c, and their sub-fragments.
 *
 * WHY:  The proxy operates a multi-phase upstream connection lifecycle (connecting → TLS handshake →
 *       bootstrap → idle → forwarding) tracked via brix_proxy_up_state_t + brix_proxy_bs_t enums.
 *       Each client-proxy session maintains a full context struct with write buffers, response accumulators,
 *       fh translation map, lazy-open queue, wait-retry state, redirect follow-through, and splice zero-copy
 *       plumbing. Pooled connections carry auth type/token hash/upstream index metadata for matching reuse.
 *       Health status per upstream enables fail detection and automatic skip of DOWN servers.
 *       Constants define pool size limits, keepalive intervals, retry budgets, and path length caps.
 *
 * HOW:  Structs defined inline with field comments explaining each member's purpose. Enums map state phases
 *       to numeric values for efficient comparison in event handlers. Function declarations grouped by source
 *       file (connect.c, events.c, forward.c) with inline WHAT comments where logic is non-obvious. The opaque
 *       typedef brix_proxy_ctx_t references the full struct definition here; public API in proxy.h declares
 *       only the externally visible functions.
 */

/* Maximum upstream response body we will buffer (16 MiB — matches max write payload) */
#define BRIX_PROXY_MAX_BODY  (16 * 1024 * 1024)

/* Longest CMS-selected host a session can be pinned to (registry.h host[256]) */
#define BRIX_PROXY_PIN_HOST_MAX  256

/* fh_map slot lifecycle (phase-115 W2.6).
 *
 * The upstream's fhandle is four OPAQUE bytes: a server is free to issue
 * {0xff,0,0,0} or any other bit pattern.  So the slot's STATE cannot be
 * encoded inside its VALUE — the previous scheme, which kept only body[0] in
 * an int and reserved -1 and 255 within it, could not tell a real handle of
 * 0xff apart from its own "open pending" marker, and truncated every handle
 * with a non-zero byte in 1..3.  State and value are separate fields now. */
#define BRIX_PROXY_FH_FREE     0   /* slot unallocated                      */
#define BRIX_PROXY_FH_PENDING  1   /* open forwarded, awaiting the response */
#define BRIX_PROXY_FH_BOUND    2   /* upstream_fh holds the server's handle */

/* Max path length stored per handle for audit logging. */
#define BRIX_PROXY_PATH_MAX  512

/* Maximum kXR_wait responses we will absorb before relaying to the client. */
#define BRIX_PROXY_MAX_WAIT_RETRIES  5
/* Cap on upstream-supplied wait seconds; prevents runaway timers. */
#define BRIX_PROXY_MAX_WAIT_SECS    30

/* Maximum idle connections to keep in the pool. */
/* NOTE: BRIX_PROXY_POOL_SIZE defined in tunables.h (512) */
/* Maximum time a connection can stay idle in the pool. */
#define BRIX_PROXY_POOL_KEEPALIVE  60

/* Health tracking constants. */
#define BRIX_PROXY_MAX_FAILS       3
#define BRIX_PROXY_FAIL_TIMEOUT    10

/* Max consecutive upstream-bootstrap failures tolerated on a single client
 * connection before the proxy stops retrying and fails the request.  Bounds the
 * reconnect loop a permanently-rejecting upstream would otherwise drive (see
 * brix_ctx_t.proxy_fail_count).  Comfortably above proxy_reconnect_attempts so
 * legitimate transient retries are never cut short. */
#define BRIX_PROXY_MAX_CONN_FAILS  8

/*
 * Per-handle entry in the file handle map.
 */
typedef struct {
    u_char       upstream_fh[4];                /* raw handle; valid iff BOUND */
    int          fh_state;                      /* BRIX_PROXY_FH_*            */
    char         path[BRIX_PROXY_PATH_MAX];   /* path supplied at open      */
    ngx_msec_t   open_msec;                     /* ngx_current_msec at open   */
    uint64_t     bytes_read;                    /* bytes relayed to client    */
    uint64_t     bytes_written;                 /* bytes forwarded upstream   */
} brix_proxy_fh_entry_t;

/* ---- upstream-side state machine ---- */

typedef enum {
    XRD_PX_CONNECTING = 0,  /* TCP connect() in progress           */
    XRD_PX_TLS_HANDSHAKE,   /* TLS handshake with upstream         */
    XRD_PX_BOOTSTRAP,       /* handshake / protocol / login phase  */
    XRD_PX_IDLE,            /* connected, ready to forward         */
    XRD_PX_FORWARDING,      /* request forwarded, awaiting reply   */
} brix_proxy_up_state_t;

typedef enum {
    XRD_PX_BS_HANDSHAKE = 0,  /* reading server hello (12 bytes via 8+4) */
    XRD_PX_BS_PROTOCOL,       /* reading kXR_protocol response           */
    XRD_PX_BS_LOGIN,          /* reading kXR_login response              */
    XRD_PX_BS_AUTH,           /* reading kXR_auth response (token fwd)   */
    XRD_PX_BS_DONE,           /* bootstrap complete                      */
} brix_proxy_bs_t;

/* ---- connection pooling ---- */

typedef struct {
    ngx_queue_t        queue;
    ngx_connection_t  *conn;
    /* The server block that opened and authenticated this connection.  A pooled
     * connection is only ever handed back to a session of the SAME block: the
     * upstream list, TLS settings, auth mechanism, login policy and SSS identity
     * mode all live there, and upstream_idx indexes THAT block's list -- index 0
     * of one server block is a different origin from index 0 of another. */
    ngx_stream_brix_srv_conf_t *conf;
    ngx_uint_t         upstream_idx;
    /* MD5 of the client identity presented on this upstream leg (see
     * proxy_pool_ident): a connection carrying one client's token, forwarded SSS
     * entity or passthrough login name is never reused for a different one. */
    u_char             ident_hash[16];
    time_t             idle_since;
    ngx_msec_t         keepalive_interval; /* snapshot of conf->proxy.keepalive_interval */
    ngx_event_t        ping_ev;            /* kXR_ping keepalive timer */
} brix_proxy_pooled_conn_t;

/* ---- upstream health status (per-worker) ---- */

typedef struct {
    ngx_uint_t         fails;
    time_t             checked;
    ngx_uint_t         down;
} brix_proxy_up_status_t;

/* ---- per-connection proxy state ---- */

struct brix_proxy_ctx_s {
    /* upstream TCP socket */
    ngx_connection_t        *conn;
    brix_proxy_up_state_t  state;
    brix_proxy_bs_t        bs_phase;
    int                      no_pool;
    /* This session is being aborted by OUR OWN policy (the upstream was never
     * asked and said nothing), so the abort must not be charged against the
     * upstream's health.  Without it an anonymous client looping against a
     * `brix_tap_proxy_sss_identity client` front -- whose forwarding refusal is
     * exactly such a policy abort -- marks the origin DOWN after
     * BRIX_PROXY_MAX_FAILS and blackholes every other session on the worker. */
    int                      policy_refusal;

    /* server config — needed in connect/events without carrying it everywhere */
    ngx_stream_brix_srv_conf_t  *conf;

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
     * must NOT be freed (the pool owns it).  brix_proxy_wbuf_release() honours
     * this so the deferred-completion path (events_write.c) frees a forwarded
     * request exactly once instead of leaking it per request. */
    unsigned  wbuf_owned:1;

    /* back-references to client session */
    brix_ctx_t     *client_ctx;
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

    /* which entry in conf->proxy.upstreams was selected at connect time; -1 = legacy single */
    int       upstream_idx;

    /* 1 if this connection was pulled from the pool and doesn't need bootstrap */
    unsigned  from_pool:1;

    /* path-based op audit: captured at forward time, written on final response */
    char      fwd_path[BRIX_PROXY_PATH_MAX];   /* primary path (rm/mkdir/mv/chmod/trunc) */
    char      fwd_path2[BRIX_PROXY_PATH_MAX];  /* dest path for kXR_mv                  */
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

    /* Phase-115 W2.1 (brix_cms_response proxy): the CMS-selected data server
     * this session is pinned to.  pinned_host points into pinned_buf (a fixed
     * copy, so re-pinning an idle session allocates nothing); consulted by
     * pc_select_endpoint after a kXR_redirect follow-through and instead of
     * the configured upstream list, and excludes the session from the shared
     * connection pool.  Empty (len 0) on a plain brix_tap_proxy session. */
    ngx_str_t     pinned_host;
    uint16_t      pinned_port;
    u_char        pinned_buf[BRIX_PROXY_PIN_HOST_MAX];

    /* Queue of local fhs still needing lazy-open for a multi-handle kXR_readv.
     * After each lazy-open completes, the next fh is dequeued and opened.
     * When empty, the saved readv is dispatched with all fhs resolved. */
    int       lazy_open_pending_fhs[BRIX_MAX_FILES];
    int       lazy_open_pending_count;

    /* file handle translation: fh_map[local_idx] holds the upstream's raw
     * 4-byte fhandle, valid only while fh_state == BRIX_PROXY_FH_BOUND */
    brix_proxy_fh_entry_t  fh_map[BRIX_MAX_FILES];

    /* zero-copy splice state (kXR_read / kXR_pgread without TLS) */
    int    splice_pipe[2];       /* kernel pipe fds; [-1,-1] when not open */
    int    splice_active;        /* 1 while splicing a response body */
    int    splice_fallback;      /* 1 = under-draining splice handed the REMAINDER
                                  *     of this body to the buffered recv relay; the
                                  *     8-byte header + splice_downstream bytes were
                                  *     already sent, so the remainder is relayed RAW */
    size_t splice_total;         /* body bytes to transfer this response */
    size_t splice_upstream;      /* bytes moved: upstream_fd → pipe[1]  */
    size_t splice_downstream;    /* bytes moved: pipe[0]   → client_fd  */

    /* Phase-4a observation tap: a stable log copy (no session appender — see the
     * Phase-3 relay note) + the fan-out ctx with the audit sink registered, fed
     * from forward_request (C2U) and relay_to_client (U2C). */
    brix_tap_ctx_t  tap;
    ngx_log_t         tap_log;
    int               tap_inited;

    /* phase-116: the in-flight upstream resolve.  brix_proxy_connect() starts
     * it through the async brix DNS driver under the server block's policy;
     * the answer arrives inline (literal / cache hit) or later on the event
     * loop, and cleanup/reset cancel it so the handler never outlives the
     * session.  dns_rc carries an inline outcome back to the starter. */
    brix_dns_req_t    dns_req;
    ngx_int_t         dns_rc;
    unsigned          dns_inflight:1;
    unsigned          dns_inline:1;
};

/* Phase-4a tap: stable-log JSON audit sink + lazy per-connection init. */
void brix_proxy_tap_audit_sink(void *ctx, const brix_tap_frame_t *f,
    brix_tap_dir_t dir, const u_char *payload, size_t payload_len);
void brix_proxy_tap_init(brix_proxy_ctx_t *proxy, ngx_connection_t *c);

/* Phase-4b GSI delegation: connect+login to the upstream AS THE USER in a thread
 * (reusing the blocking in-process GSI client with the client's delegated proxy),
 * then hand the authenticated fd to the async relay. Returns NGX_OK (login posted;
 * completes later) or NGX_ERROR. Requires a thread_pool + a captured delegated
 * proxy (ctx->gsi.deleg_proxy_pem). */
ngx_int_t brix_proxy_gsi_connect_async(brix_proxy_ctx_t *proxy,
    ngx_stream_brix_srv_conf_t *conf, ngx_str_t *host, uint16_t port);

/* ---- internal function declarations ---- */

/* connect.c */

/* Select an upstream (redirect > pool > round-robin > single), resolve it through
 * the async brix DNS driver, open a non-blocking socket, start the async connect,
 * and arm bootstrap. On a pool hit dispatches/resumes immediately. Borrows
 * proxy/client_conn/conf (not owned). Returns NGX_OK once a resolve or connect is
 * in flight or completed (DNS/TLS/bootstrap continue via event callbacks — a
 * later failure goes through brix_proxy_abort()); NGX_ERROR after calling
 * brix_proxy_cleanup() on a hard failure that happened inline. */
ngx_int_t brix_proxy_connect(brix_proxy_ctx_t *proxy,
    ngx_connection_t *client_conn,
    ngx_stream_brix_srv_conf_t *conf);
/* Cancel an in-flight upstream resolve (no-op when none): its completion
 * handler never runs afterwards. Called by cleanup, reset and a re-connect. */
void      brix_proxy_cleanup_dns(brix_proxy_ctx_t *proxy);
/* Handle an upstream error: log, mark the upstream failed. If idle with no open
 * handles and reconnect budget remains, transparently reconnect (client unaware);
 * otherwise tear the session down. reason is a borrowed static/log string. */
void      brix_proxy_abort(brix_proxy_ctx_t *proxy, const char *reason);
/* Drop the upstream connection (and any half-read response / saved request)
 * and rewind the proxy to the start of the bootstrap state machine, keeping
 * the proxy ctx, its fh_map and its client binding.  The caller then decides
 * whether to brix_proxy_connect() again (idle reconnect, idle re-pin). */
void      brix_proxy_reset_upstream(brix_proxy_ctx_t *proxy);
/* Drain proxy->wbuf to the upstream socket via uconn->send (TLS or plain), advancing
 * wbuf_pos. NGX_OK when fully sent, NGX_AGAIN on partial send (caller re-arms write),
 * NGX_ERROR on socket error. Does not free the buffer. */
ngx_int_t brix_proxy_flush(brix_proxy_ctx_t *proxy);

/* Phase 39 (PXY-3): release the upstream write buffer once its send has fully
 * completed.  Frees it iff it is heap-owned (a forwarded/relayed request from
 * ngx_alloc); pool-allocated bootstrap frames are merely detached (the pool owns
 * them).  Idempotent and NULL-safe.  Call this on EVERY send-complete path so a
 * deferred (backpressured / slow-consumer) request is not leaked. */
static ngx_inline void
brix_proxy_wbuf_release(brix_proxy_ctx_t *proxy)
{
    if (proxy->wbuf_owned && proxy->wbuf != NULL) {
        ngx_free(proxy->wbuf);
    }
    proxy->wbuf       = NULL;
    proxy->wbuf_owned = 0;
}

#if (NGX_SSL)
/* Called by write_handler when TLS is requested after async TCP connect. */
void brix_proxy_tls_handshake_done(ngx_connection_t *uconn);
#endif

/* Build the 68-byte upstream bootstrap buffer (client hello + kXR_protocol +
 * kXR_login) into buf; username NULL/empty defaults to "xrd". Returns byte
 * count written. Defined in connect_upstream_bootstrap.c. */
size_t brix_proxy_build_bootstrap(u_char *buf, const char *username);

/*
 * Chosen upstream target: host/port plus the resolved sockaddr that the
 * async connect() will use.  Purely a value carrier passed between the
 * endpoint-selection, resolve, and arm-events phases — it holds NO ngx_log_t
 * pointer, so it is safe to stack-allocate per connect (see the stale-handler
 * SIGSEGV postmortem: never park a c->log in a long-lived struct).
 */
typedef struct {
    ngx_str_t               *host;      /* borrowed: conf / redirect / ups elt */
    ngx_int_t                port;
    struct sockaddr_storage  addr;
    socklen_t                addrlen;
    int                      fd;        /* resolved socket for this target */
} brix_proxy_target_t;

/* Choose the upstream endpoint: redirect > CMS pin > pooled connection >
 * healthy round-robin member > single configured host. NGX_DECLINED = *tgt
 * filled, go resolve/connect; NGX_OK = a pooled connection was adopted
 * (connect complete); NGX_ERROR = every upstream is down. Defined in
 * connect_upstream_select.c. */
ngx_int_t brix_proxy_select_endpoint(brix_proxy_ctx_t *proxy,
    ngx_connection_t *client_conn, ngx_stream_brix_srv_conf_t *conf,
    brix_proxy_target_t *tgt);

/* Worker-local health status array — defined in pool.c, used in connect.c */
extern brix_proxy_up_status_t *proxy_up_status;

/* Pool management */
/* Init the worker-local idle-connection queue and counter. Call once at startup. */
/* The front-side client's identity as an SSS entity to forward upstream
 * (brix_tap_proxy_sss_identity client); NGX_DECLINED when the session has none.
 * Defined in events_bootstrap_auth.c, digested by the pool. */
ngx_int_t brix_proxy_sss_client_entity(const brix_proxy_ctx_t *proxy,
    brix_sss_entity_t *ent);

void brix_proxy_pool_init(void);

/* Drain and free every idle pooled upstream connection (called at worker exit
 * from the shutdown sweeper so a draining worker releases upstream sockets at
 * once instead of holding them to worker_shutdown_timeout). */
void brix_proxy_pool_shutdown(void);
/* Take a reusable, already-authenticated upstream connection out of the pool, matched
 * by health-aware round-robin upstream index + auth type (+ bearer-token MD5 in forward
 * mode). Returns the connection (caller takes ownership, must set c->data) and writes
 * the chosen upstream index to *idx_out; NULL when no match — caller must connect fresh. */
ngx_connection_t *brix_proxy_pool_get(brix_proxy_ctx_t *proxy,
    ngx_stream_brix_srv_conf_t *conf, int *idx_out);
/* Return proxy->conn to the pool for reuse if it is idle and not redirected; detaches it
 * from the ctx, allocs a pooled-conn record with auth/index/token-hash/keepalive timer,
 * and evicts the oldest entry when the pool is full. No-op if not poolable. */
void brix_proxy_pool_put(brix_proxy_ctx_t *proxy);

/* Health management */
/* Allocate/zero the worker-local per-upstream health array sized to the configured
 * upstream count (>=1). Idempotent: reuses the array if already large enough. */
void brix_proxy_up_status_init(ngx_stream_brix_srv_conf_t *conf);
/* Bump the fail counter for proxy's current upstream and stamp the check time; marks the
 * upstream DOWN once it reaches BRIX_PROXY_MAX_FAILS. No-op if the status array is unsized. */
void brix_proxy_up_mark_failed(brix_proxy_ctx_t *proxy);
/* Clear DOWN and reset the fail counter for proxy's current upstream (logs the UP
 * transition). No-op if the status array is unsized. */
void brix_proxy_up_mark_ok(brix_proxy_ctx_t *proxy);

/* events.c */

/* ---- public API: brix_proxy_write_handler() — upstream write event callback ----
 *
 * WHAT:
 *   Event handler for the upstream connection's write event.
 *
 * ACTIONS:
 *   - Drains proxy->wbuf through the socket (TLS or plain)
 *   - Re-arms write event on partial sends
 *   - Frees fully-transmitted buffers
 *   - Transitions state from CONNECTING/BOOTSTRAP/FORWARDING as bytes consumed
 *   - On completion: arms read event for response data
 */

/* ---- public API: brix_proxy_read_handler() — upstream read event callback ----
 *
 * WHAT:
 *   Event handler for the upstream connection's read event.
 *
 * ACTIONS:
 *   - Accumulates response headers and body into rhdr/resp_body
 *   - Dispatches based on current state:
 *     - Bootstrap phase: reads handshake/protocol/login/auth responses
 *     - Forwarding: reads opcode results
 *   - On bootstrap completion: calls handle_bootstrap()
 *   - On forwarding: completes relay_to_client()
 */

void brix_proxy_write_handler(ngx_event_t *wev);
void brix_proxy_read_handler(ngx_event_t *rev);

/* events_bootstrap.c — called from events_read.c on bootstrap completion. */
void brix_proxy_handle_bootstrap(brix_proxy_ctx_t *proxy);

/* events_splice.c — zero-copy splice path for plain-text kXR_read responses. */
/* Pump the in-progress splice: move upstream-fd -> pipe and pipe -> client-fd, updating
 * splice_upstream/splice_downstream until splice_total bytes are relayed. Re-armable from
 * both upstream-readable and client-writable events; no-op once either conn is gone. */
void      brix_proxy_splice_pump(brix_proxy_ctx_t *proxy);
/* Try to start a zero-copy splice for the current kXR_read/kXR_pgread response: lazily
 * creates the kernel pipe, sends the response header, then pumps. NGX_OK if splicing has
 * started (caller must NOT allocate resp_body or read the body); NGX_DECLINED when not
 * eligible (TLS on either side, wrong opcode/status, zero dlen, or pipe2 failure) so the
 * caller falls back to the buffered path. */
ngx_int_t brix_proxy_try_splice(brix_proxy_ctx_t *proxy);
/* Finish a splice→buffered fallback: the read handler has accumulated the remaining
 * body bytes (after an under-draining splice) into resp_body; relay them RAW to the
 * client (the header is already on the wire) and run the normal post-transfer
 * finish.  Called from the read handler when proxy->splice_fallback is set. */
void      brix_proxy_splice_fallback_finish(brix_proxy_ctx_t *proxy);

/* forward.c */
/* Build the upstream request from the client's current frame (ctx->recv.hdr_buf + payload),
 * applying fhandle translation, path rewriting, audit capture and kXR_wait-retry setup,
 * then send it. Allocates the request buffer (ngx_alloc, freed on send/cleanup) and may
 * pre-allocate a local fh for kXR_open. NGX_OK on send/queue AND when the request was
 * rejected with a kXR_error already queued to the client (session continues); NGX_ERROR
 * only on a hard failure. Borrows ctx and c. */
ngx_int_t brix_proxy_forward_request(brix_proxy_ctx_t *proxy,
    brix_ctx_t *ctx, ngx_connection_t *c);

/* forward_fh_translate.c — file handle translation helpers (called from forward_request.c). */
/* Translate file handle for opcodes with a single fhandle at body[0], plus kXR_chkpoint
 * kXR_ckpXeq nested requests. Returns NGX_OK, NGX_DONE (bound-secondary lazy-open initiated),
 * NGX_ABORT (request rejected via proxy_reject_request — req freed, kXR_error queued), or
 * NGX_ERROR. When NGX_DONE is returned, req ownership has transferred to lazy_open. */
ngx_int_t brix_proxy_fh_translate_single(brix_proxy_ctx_t *proxy,
    brix_ctx_t *ctx, ngx_connection_t *c, u_char *req, size_t total,
    uint16_t reqid, size_t body_len);
/* Translate file handles in readv or writev descriptor arrays. Returns NGX_OK, NGX_DONE
 * (bound-secondary lazy-open queue initiated), NGX_ABORT (request rejected — req freed,
 * kXR_error queued), or NGX_ERROR. When NGX_DONE is returned, req ownership has transferred
 * to lazy_open. */
ngx_int_t brix_proxy_fh_translate_vector(brix_proxy_ctx_t *proxy,
    brix_ctx_t *ctx, ngx_connection_t *c, u_char *req, size_t total,
    uint16_t reqid, uint32_t cur_dlen);

/* Relay the accumulated upstream response (resp_status/resp_dlen/resp_body) back to the
 * client, transparently handling lazy-open completion, kXR_wait retry, kXR_redirect
 * follow-through, upstream->local fhandle translation, path audit and oksofar streaming.
 * Consumes/frees resp_body as part of relaying. */
void      brix_proxy_relay_to_client(brix_proxy_ctx_t *proxy);
/* Return the index of the first free fh_map slot (fh_state == FREE), giving the proxy
 * its own local handle namespace; -1 if all BRIX_MAX_FILES slots are in use. */

/* brix_proxy_fh_bind — record the upstream's fhandle from an open response
 * body of dlen bytes.  A short body zero-pads rather than reading past it. */
static ngx_inline void
brix_proxy_fh_bind(brix_proxy_fh_entry_t *e, const u_char *body, size_t dlen)
{
    size_t  n = sizeof(e->upstream_fh);

    ngx_memzero(e->upstream_fh, n);
    if (body != NULL && dlen > 0) {
        ngx_memcpy(e->upstream_fh, body, dlen < n ? dlen : n);
    }
    e->fh_state = BRIX_PROXY_FH_BOUND;
}

/* brix_proxy_fh_put — write a bound slot's upstream fhandle into a request. */
static ngx_inline void
brix_proxy_fh_put(const brix_proxy_fh_entry_t *e, u_char *dst)
{
    ngx_memcpy(dst, e->upstream_fh, sizeof(e->upstream_fh));
}

int       brix_proxy_alloc_local_fh(brix_proxy_ctx_t *proxy);
/* Emit a JSON audit record for fh_map[local_fh]; safe to call on any slot. */
void      proxy_write_audit(brix_proxy_ctx_t *proxy, int local_fh);

/* forward_rewrite_helpers.c — path/fh rewriting (called from forward_request.c). */
/* Apply the proxy_path_strip -> proxy_path_add prefix swap to the single path at
 * [path_off, path_off+path_len) inside the request buffer req of length total; the new
 * total is written to *total_out and the request's 4-byte dlen header is fixed up.
 * Returns req when the prefix does not match (in-place same-length rewrite included), or
 * a NEW ngx_alloc buffer when the result is longer. NOTE: on the realloc path the original
 * req is NOT freed here (caller owns/replaces it); on OOM returns req unchanged. */
u_char *proxy_rewrite_path(ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, u_char *req, size_t total,
    size_t path_off, size_t path_len, size_t *total_out);
/* Rewrite every newline-separated path in a kXR_prepare payload with the same prefix swap,
 * fixing up the dlen header; *total_out gets the new length. Returns req if nothing
 * matched (or OOM), else a NEW buffer — and in that case ngx_free()s the old req itself
 * (ownership transferred), unlike proxy_rewrite_path. */
u_char *proxy_rewrite_prepare_payload(ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, u_char *req, size_t total,
    size_t *total_out);
/* In place, replace the 1-byte local fhandle at buf[offset] with its upstream handle from
 * fh_map. Returns 0 on success, -1 if the local handle is out of range or maps to a free
 * slot (caller should reject the request). */
int proxy_translate_fh(brix_proxy_ctx_t *proxy, u_char *buf, size_t offset);
/* Reject an in-flight forwarded request: free the request buffer and queue a kXR_error
 * back to the client. Returns NGX_ABORT when the error response was queued (the request
 * is fully handled — the session lives on but NOTHING may touch req again), or NGX_ERROR
 * when queueing the error itself failed. NEVER returns NGX_OK: brix_send_error() returns
 * NGX_OK on a queued error, and returning that directly from a translate handler made
 * brix_proxy_forward_request() keep forwarding the freed buffer (use-after-free +
 * double-free via wbuf_owned). */
ngx_int_t proxy_reject_request(brix_ctx_t *ctx, ngx_connection_t *c,
    u_char *req, uint16_t errcode, const char *msg);
/*
 * Issue a synthetic kXR_open on the upstream for a handle that was opened
 * lazily (open-on-read).  Called from both forward.c and forward_relay.c.
 */
ngx_int_t brix_proxy_lazy_open(brix_proxy_ctx_t *proxy,
    brix_ctx_t *ctx, ngx_connection_t *c,
    int local_fh, u_char *read_req, size_t read_req_len);
/*
 * Dispatch the saved_req that was queued during bootstrap.
 * Handles lazy-open for bound-secondary kXR_read with an unresolved handle.
 * Called from events.c when bootstrap completes.
 */
ngx_int_t brix_proxy_dispatch_pending(brix_proxy_ctx_t *proxy);
/*
 * Timer callback: re-issues a saved kXR_open after the upstream kXR_wait
 * countdown has elapsed.
 */
void brix_proxy_wait_handler(ngx_event_t *ev);

#endif /* BRIX_PROXY_PROXY_INTERNAL_H */
