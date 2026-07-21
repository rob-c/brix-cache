#ifndef BRIX_UPSTREAM_INTERNAL_H
/*
 * WHAT: Internal upstream redirector state definitions — bootstrap phase enum,
 *      connection state enum, and brix_upstream_s struct layout. This header is
 *      shared across all upstream source files so each function can access the
 *      same type definitions without pulling in the full nginx module headers.
 *
 * WHY: Transparent proxy mode requires a multi-phase bootstrap sequence (handshake,
 * protocol, TLS upgrade, login) followed by request/response cycles. The upstream
 * context struct tracks wire buffer positions, response accumulators, client
 * reference, and saved opcode state end-to-end. Splitting internal types into their
 * own header keeps upstream.h slim as the public API while all implementation files
 * share one consistent type definition.
 *
 * HOW: Three sections in this header:
 *   Bootstrap phase enum (brix_up_bs_t) — ordered phases from handshake through
 *     authmore to done. Each phase maps to a point in the bootstrap byte sequence.
 *   Connection state enum (brix_up_state_t) — high-level states: connecting,
 *     bootstrap, request, async. Used for logging and state machine transitions.
 *   Struct brix_upstream_s — wire buffer accumulators (rhdr/rhdr_pos/resp_*),
 *     write buffer (wbuf/wbuf_len/wbuf_pos), timer event, client reference pointers,
 *     saved opcode fields, authmore counter. Function declarations for internal API.
 */
#define BRIX_UPSTREAM_INTERNAL_H

#include "upstream.h"

#define BRIX_UP_WAIT_MAX   60

/* Outbound bootstrap auth (phase-57 §F4/W1.4.a): bound the kXR_authmore exchange
 * so a hostile or misconfigured origin can never drive an unbounded auth loop.
 * Single-round ztn/token auth uses 1; the bound leaves headroom for a future
 * multi-round (GSI) continuation on the cache-fill path without another change. */
#define XRD_OBA_MAX_ROUNDS   8

typedef enum {
    XRD_UP_BS_HANDSHAKE = 0,
    XRD_UP_BS_PROTOCOL,
    XRD_UP_BS_TLS,    /* waiting for outbound TLS handshake to complete (kXR_gotoTLS) */
    XRD_UP_BS_LOGIN,
    XRD_UP_BS_AUTH,   /* waiting for kXR_auth (token/ztn) response */
    XRD_UP_BS_DONE,
} brix_up_bs_t;

typedef enum {
    XRD_UP_CONNECTING = 0,
    XRD_UP_BOOTSTRAP,
    XRD_UP_REQUEST,
    XRD_UP_ASYNC,
} brix_up_state_t;

struct brix_upstream_s {
    ngx_connection_t   *conn;
    brix_up_state_t   state;
    brix_up_bs_t      bs_phase;

    u_char   rhdr[XRD_RESPONSE_HDR_LEN];
    size_t   rhdr_pos;
    uint16_t resp_status;
    uint32_t resp_dlen;
    u_char  *resp_body;
    size_t   resp_body_pos;

    u_char  *wbuf;
    size_t   wbuf_len;
    size_t   wbuf_pos;

    ngx_event_t timer;

    brix_ctx_t     *client_ctx;
    ngx_connection_t *client_conn;

    uint16_t  req_opcode;
    u_char    req_streamid[2];
    char      req_path[BRIX_MAX_PATH];
    uint16_t  req_options;
    uint16_t  req_open_mode;

    ngx_uint_t  authmore_count;  /* number of kXR_authmore exchanges so far */
};

/* Tear down the upstream (frees timer + TCP conn, detaches client ctx) and send a
 * kXR_ServerError frame to the client at the saved stream ID, then re-arm the client
 * read so it can retry. `reason` is the error text (borrowed, also logged); `up` must
 * have a live client_ctx/client_conn. After this call `up` is dead — do not reuse. */
void brix_upstream_abort(brix_upstream_t *up, const char *reason);

/* Serialize the full plaintext bootstrap (12-byte handshake + kXR_protocol +
 * kXR_login frames) into `buf`. Caller owns `buf` and must size it for all three
 * frames; no validation, never fails. The pre-sent login is discarded by the server
 * if it answers kXR_gotoTLS (login is then re-sent over TLS). */
void brix_upstream_build_bootstrap(u_char *buf);

/* Same, but with an explicit kXR_protocol capability byte (kXR_ableTLS et al.)
 * for callers that can complete a kXR_gotoTLS upgrade — a brix server only
 * answers gotoTLS to clients that advertised TLS capability. */
void brix_upstream_build_bootstrap_flags(u_char *buf, uint8_t protocol_flags);

/* Fill a single kXR_login frame in caller-provided `req` (used to re-send login over
 * TLS after a gotoTLS upgrade). Zeroes then populates the struct; never fails. */
void brix_upstream_build_login(ClientLoginRequest *req);

/* Relay one accumulated upstream reply (in up->resp_*) back to the client, re-wrapped
 * with the client's stream ID. Dispatches by status: redirect/ok forward + cleanup +
 * resume client read; wait schedules a retry timer; waitresp switches to ASYNC; error
 * maps to a client error frame; unexpected status aborts. May call brix_upstream_abort
 * (then `up` is dead) on alloc/arm failure or malformed frames. */
void brix_upstream_forward_response(brix_upstream_t *up);

/* Advance the bootstrap state machine for one accumulated reply (handshake → protocol
 * → optional TLS → login → optional ztn auth → done). On reaching DONE, calls
 * brix_upstream_send_request; otherwise resets the response accumulator and re-arms
 * the read (posting a synthetic event for epoll-ET coalesced replies). Aborts `up` on
 * any non-ok status or missing TLS/token config required by the server. */
void brix_upstream_handle_bootstrap_response(brix_upstream_t *up);

/* nginx readable-event callback (ev->data is the upstream conn): accumulates one full
 * ServerResponseHdr + body across re-entries (state in rhdr_pos/resp_body_pos), capping
 * the body alloc, then dispatches by up->state (bootstrap vs request/async). Cleans up
 * silently if the client session is gone; aborts on timeout/peer-close/oversized body. */
void brix_upstream_read_handler(ngx_event_t *rev);

/* kXR_wait retry-timer callback (ev->data is the upstream): re-sends the saved client
 * request via send_request. Cleans up if the client session died; aborts on resend
 * failure (only while up->conn still live). */
void brix_upstream_wait_timer_handler(ngx_event_t *ev);

/* nginx writable-event callback (wev->data is the upstream conn): doubles as connect
 * completion — on CONNECTING it checks SO_ERROR then transitions to BOOTSTRAP. Drains
 * any remaining wbuf via flush; once fully sent, arms the read side. Cleans up if the
 * client session is gone; aborts on connect/write timeout or write error. */
void brix_upstream_write_handler(ngx_event_t *wev);

/* Non-blocking write loop draining up->wbuf[wbuf_pos..wbuf_len) to the upstream.
 * Returns NGX_OK (fully sent, read event armed), NGX_AGAIN (partial — write event
 * armed, caller re-enters via write handler), or NGX_ERROR (send/event-arm failure;
 * caller must abort). Does not free wbuf; the buffer must outlive partial writes. */
ngx_int_t brix_upstream_flush(brix_upstream_t *up);

/* Serialize the saved client request (up->req_*) into a fresh pool buffer and flush it,
 * switching up->state to XRD_UP_REQUEST. Only kXR_locate/kXR_open/kXR_stat are supported.
 * Returns flush()'s result (NGX_OK/NGX_AGAIN) or NGX_ERROR on unsupported opcode or
 * alloc failure. Resets the response accumulator. */
ngx_int_t brix_upstream_send_request(brix_upstream_t *up);

#if (NGX_SSL)
/* Generic outbound kXR_gotoTLS upgrade (phase-22 Step F sharing seam): wrap an
 * already-connected outbound TCP conn in a client SSL connection with the given
 * SNI, install `handler` as the handshake-done callback, and start the
 * handshake (invoking `handler` synchronously if the handshake does not yield
 * NGX_AGAIN). The caller owns all protocol state; `handler` receives the conn
 * and must consult conn->ssl->handshaked + SSL_get_verify_result() itself.
 * Returns NGX_OK once the handshake is initiated, NGX_ERROR if the SSL
 * connection cannot be created. */
ngx_int_t brix_outbound_start_tls(ngx_ssl_t *ssl_ctx, ngx_connection_t *c,
    const char *sni, void (*handler)(ngx_connection_t *c));

/* Wrap the live upstream TCP conn in a client SSL connection (SNI = upstream_tls_name
 * else upstream_host), install the handshake-done callback, set bs_phase = XRD_UP_BS_TLS,
 * and start the handshake (completing synchronously if it does not yield NGX_AGAIN).
 * `conf` must have a non-NULL upstream_tls_ctx. Returns NGX_OK once the handshake is
 * initiated, NGX_ERROR if the SSL connection cannot be created; login is re-sent over
 * TLS from the callback, not here. */
ngx_int_t brix_upstream_start_tls(brix_upstream_t *up,
    ngx_stream_brix_srv_conf_t *conf);
#endif

/* Read conf->upstream_token_file synchronously (cap 64 KiB) and send a kXR_auth "ztn"
 * frame to the upstream, echoing the client's stream ID; sets bs_phase = XRD_UP_BS_AUTH
 * and resets the response accumulator. Returns NGX_OK (frame sent or partial — write/read
 * events armed for completion) or NGX_ERROR on file-read/alloc/event-arm failure (caller
 * must abort). Frame is pool-allocated; the token is read into a stack buffer. */
ngx_int_t brix_upstream_send_token_auth(brix_upstream_t *up,
    ngx_stream_brix_srv_conf_t *conf);

#endif
