/*
 * src/response/async.h — Public interface for async/attn response handlers.
 */

#pragma once

#include <nginx.h>
#include "../types/connection.h"

/* Send an unsolicited kXR_attn notification to the client */
ngx_int_t xrootd_send_attn(xrootd_ctx_t *ctx, ngx_connection_t *c,
                          int actnum, const char *msg, size_t msglen);

/* Async operation handlers (all deprecated, return kXR_Unsupported) */
ngx_int_t xrootd_handle_async_ab(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_async_di(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_async_ms(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_async_rd(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_async_wt(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_async_av(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_async_unav(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_async_go(xrootd_ctx_t *ctx, ngx_connection_t *c);
