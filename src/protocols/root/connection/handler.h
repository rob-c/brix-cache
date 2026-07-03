#ifndef BRIX_CONN_HANDLER_H
#define BRIX_CONN_HANDLER_H

#include "core/ngx_brix_module.h"

/* Stream session entry point — installed by postconfiguration. */
void ngx_stream_brix_handler(ngx_stream_session_t *s);

/* Read and write event callbacks for the nginx event loop. */
void ngx_stream_brix_recv(ngx_event_t *rev);
void ngx_stream_brix_send(ngx_event_t *wev);

#endif /* BRIX_CONN_HANDLER_H */
