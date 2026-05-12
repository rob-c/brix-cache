#ifndef XROOTD_CMS_SERVER_H
#define XROOTD_CMS_SERVER_H

/*
 * cms/server.h — CMS server-side handler types and API.
 *
 * This module listens on the CMS management port (default 1213) and accepts
 * incoming connections from XRootD data servers.  On login it registers the
 * data server in the shared server registry (src/manager/registry.h); on each
 * heartbeat it refreshes load metrics; on disconnect it unregisters.
 *
 * Directive: xrootd_cms_server on;   (inside a stream server {} block)
 * Optional:  xrootd_cms_server_interval 60;   (ping interval in seconds)
 */

#include "cms_internal.h"
#include "../manager/registry.h"

/* Per-connection state for an accepted CMS data-server connection. */
typedef struct {
    ngx_connection_t  *c;
    char               host[256];                    /* remote IP (NUL-terminated) */
    uint16_t           port;                         /* XRootD data port from LOGIN */
    char               paths[XROOTD_SRV_MAX_PATHS];  /* colon-delimited export list */
    uint32_t           free_mb;
    uint32_t           util_pct;
    ngx_uint_t         logged_in;
    ngx_event_t        ping_timer;
    ngx_msec_t         interval_ms;                  /* ping interval in ms */
    u_char             inbuf[NGX_XROOTD_CMS_MAX_FRAME];
    size_t             in_pos;
    size_t             in_need;
} xrootd_cms_srv_ctx_t;

/* Per-server-block config for the CMS server module. */
typedef struct {
    ngx_flag_t  enable;
    time_t      interval;   /* ping interval in seconds; default 60 */
} ngx_stream_xrootd_cms_srv_conf_t;

/* Module descriptor declared in server_module.c. */
extern ngx_module_t  ngx_stream_xrootd_cms_srv_module;

/* server_handler.c */
void xrootd_cms_srv_handler(ngx_stream_session_t *s);

/* server_recv.c */
void xrootd_cms_srv_read(ngx_event_t *ev);
void xrootd_cms_srv_write(ngx_event_t *ev);
void xrootd_cms_srv_close(xrootd_cms_srv_ctx_t *ctx);

/* server_send.c */
ngx_int_t xrootd_cms_srv_send_ping(xrootd_cms_srv_ctx_t *ctx);

#endif /* XROOTD_CMS_SERVER_H */
