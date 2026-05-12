#ifndef XROOTD_UPSTREAM_INTERNAL_H
#define XROOTD_UPSTREAM_INTERNAL_H

#include "upstream.h"

#define XROOTD_UP_WAIT_MAX   60

typedef enum {
    XRD_UP_BS_HANDSHAKE = 0,
    XRD_UP_BS_PROTOCOL,
    XRD_UP_BS_LOGIN,
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
};

void xrootd_upstream_abort(xrootd_upstream_t *up, const char *reason);
void xrootd_upstream_build_bootstrap(u_char *buf);
void xrootd_upstream_forward_response(xrootd_upstream_t *up);
void xrootd_upstream_handle_bootstrap_response(xrootd_upstream_t *up);
void xrootd_upstream_read_handler(ngx_event_t *rev);
void xrootd_upstream_wait_timer_handler(ngx_event_t *ev);
void xrootd_upstream_write_handler(ngx_event_t *wev);
ngx_int_t xrootd_upstream_flush(xrootd_upstream_t *up);
ngx_int_t xrootd_upstream_send_request(xrootd_upstream_t *up);

#endif

