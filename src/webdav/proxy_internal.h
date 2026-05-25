#ifndef XROOTD_WEBDAV_PROXY_INTERNAL_H
#define XROOTD_WEBDAV_PROXY_INTERNAL_H

/*
 * WHAT: Internal header for WebDAV upstream proxy mode — declares the per-request context struct (webdav_proxy_ctx_t) and six nginx upstream lifecycle callbacks that handle request creation, status line parsing, header forwarding, error abort, and completion cleanup. These functions are registered as u->create_request/u->reinit_request/u->process_header/u->abort_request/u->finalize_request hooks in proxy.c's webdav_proxy_handler().
 *
 * WHY: nginx upstream API requires lifecycle callbacks to manage the proxy request flow — create_request generates the backend HTTP request body, process_header parses status line and headers from backend response, abort_request cleans up on error, finalize_request handles completion. The per-request context struct (webdav_proxy_ctx_t) carries state across these callbacks via ngx_http_set_ctx(r, ctx, module). This header is internal (not webdav.h) because proxy mode only activates when xrootd_webdav_proxy=on in location config.
 *
 * HOW: Declares webdav_proxy_ctx_t with status field tracking backend HTTP response status; declares six callback prototypes matching nginx upstream API signatures — create_request/reinit_request return ngx_int_t for success/error, process_status_line/process_header return ngx_int_t, abort_request/finalize_request are void cleanup functions. */
#include "webdav.h"

typedef struct {
    ngx_http_status_t  status;
} webdav_proxy_ctx_t;

ngx_int_t webdav_proxy_create_request(ngx_http_request_t *r);
ngx_int_t webdav_proxy_reinit_request(ngx_http_request_t *r);
ngx_int_t webdav_proxy_process_status_line(ngx_http_request_t *r);
ngx_int_t webdav_proxy_process_header(ngx_http_request_t *r);
void webdav_proxy_abort_request(ngx_http_request_t *r);
void webdav_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

#endif /* XROOTD_WEBDAV_PROXY_INTERNAL_H */
