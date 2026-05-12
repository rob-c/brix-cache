#ifndef XROOTD_CONN_HANDLER_H
#define XROOTD_CONN_HANDLER_H

#include "../ngx_xrootd_module.h"

/* Stream session entry point — installed by postconfiguration. */
void ngx_stream_xrootd_handler(ngx_stream_session_t *s);

/* Read and write event callbacks for the nginx event loop. */
void ngx_stream_xrootd_recv(ngx_event_t *rev);
void ngx_stream_xrootd_send(ngx_event_t *wev);

#endif /* XROOTD_CONN_HANDLER_H */
