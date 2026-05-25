#ifndef XROOTD_UPSTREAM_INTERNAL_H
/*
 * WHAT: Internal upstream redirector state definitions — bootstrap phase enum,
 *      connection state enum, and xrootd_upstream_s struct layout. This header is
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
 *   Bootstrap phase enum (xrootd_up_bs_t) — ordered phases from handshake through
 *     authmore to done. Each phase maps to a point in the bootstrap byte sequence.
 *   Connection state enum (xrootd_up_state_t) — high-level states: connecting,
 *     bootstrap, request, async. Used for logging and state machine transitions.
 *   Struct xrootd_upstream_s — wire buffer accumulators (rhdr/rhdr_pos/resp_*),
 *     write buffer (wbuf/wbuf_len/wbuf_pos), timer event, client reference pointers,
 *     saved opcode fields, authmore counter. Function declarations for internal API.
 */
#define XROOTD_UPSTREAM_INTERNAL_H

#include "upstream.h"

#define XROOTD_UP_WAIT_MAX   60

typedef enum {
    XRD_UP_BS_HANDSHAKE = 0,
    XRD_UP_BS_PROTOCOL,
    XRD_UP_BS_TLS,    /* waiting for outbound TLS handshake to complete (kXR_gotoTLS) */
    XRD_UP_BS_LOGIN,
    XRD_UP_BS_AUTH,   /* waiting for kXR_auth (token/ztn) response */
    XRD_UP_BS_DONE,
} xrootd_up_bs_t;

typedef enum {
    XRD_UP_CONNECTING = 0,
    XRD_UP_BOOTSTRAP,
    XRD_UP_REQUEST,
    XRD_UP_ASYNC,
} xrootd_up_state_t;

struct xrootd_upstream_s {
    ngx_connection_t   *conn;
    xrootd_up_state_t   state;
    xrootd_up_bs_t      bs_phase;

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

    xrootd_ctx_t     *client_ctx;
    ngx_connection_t *client_conn;

    uint16_t  req_opcode;
    u_char    req_streamid[2];
    char      req_path[XROOTD_MAX_PATH];
    uint16_t  req_options;
    uint16_t  req_open_mode;

    ngx_uint_t  authmore_count;  /* number of kXR_authmore exchanges so far */
};

void xrootd_upstream_abort(xrootd_upstream_t *up, const char *reason);
void xrootd_upstream_build_bootstrap(u_char *buf);
void xrootd_upstream_build_login(ClientLoginRequest *req);
void xrootd_upstream_forward_response(xrootd_upstream_t *up);
void xrootd_upstream_handle_bootstrap_response(xrootd_upstream_t *up);
void xrootd_upstream_read_handler(ngx_event_t *rev);
void xrootd_upstream_wait_timer_handler(ngx_event_t *ev);
void xrootd_upstream_write_handler(ngx_event_t *wev);
ngx_int_t xrootd_upstream_flush(xrootd_upstream_t *up);
ngx_int_t xrootd_upstream_send_request(xrootd_upstream_t *up);

#if (NGX_SSL)
ngx_int_t xrootd_upstream_start_tls(xrootd_upstream_t *up,
    ngx_stream_xrootd_srv_conf_t *conf);
#endif

ngx_int_t xrootd_upstream_send_token_auth(xrootd_upstream_t *up,
    ngx_stream_xrootd_srv_conf_t *conf);

#endif
