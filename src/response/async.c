/*
 * src/response/async.c — Async operation handlers (deprecated, for protocol completeness).
 *
 * WHAT: Handlers for deprecated async operations (5000–5008). All return
 *       kXR_Unsupported since these operations are marked "No longer supported"
 *       in canonical XRootD v5.2.0. The implementation is minimal but complete.
 *
 * WHY: Protocol compliance. While deprecated, proper handling ensures robust
 *      backward compatibility and correct error messages to legacy clients.
 *
 * NOTE: Native kXR_attn (4001) generation is already supported via the proxy
 *       relay mechanism in proxy/events_read.c. This module completes the
 *       protocol by declaring all async operations as unsupported.
 */

#include "ngx_xrootd_module.h"

/* Async operation handlers — all deprecated, return kXR_Unsupported */

ngx_int_t
xrootd_handle_async_ab(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    return xrootd_send_error(ctx, c, kXR_Unsupported,
                            "kXR_asyncab (5000) is no longer supported");
}

ngx_int_t
xrootd_handle_async_di(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    return xrootd_send_error(ctx, c, kXR_Unsupported,
                            "kXR_asyncdi (5001) is no longer supported");
}

ngx_int_t
xrootd_handle_async_ms(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    return xrootd_send_error(ctx, c, kXR_Unsupported,
                            "kXR_asyncms (5002) is no longer supported");
}

ngx_int_t
xrootd_handle_async_rd(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    return xrootd_send_error(ctx, c, kXR_Unsupported,
                            "kXR_asyncrd (5003) is no longer supported");
}

ngx_int_t
xrootd_handle_async_wt(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    return xrootd_send_error(ctx, c, kXR_Unsupported,
                            "kXR_asyncwt (5004) is no longer supported");
}

ngx_int_t
xrootd_handle_async_av(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    return xrootd_send_error(ctx, c, kXR_Unsupported,
                            "kXR_asyncav (5005) is no longer supported");
}

ngx_int_t
xrootd_handle_async_unav(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    return xrootd_send_error(ctx, c, kXR_Unsupported,
                            "kXR_asyncunav (5006) is no longer supported");
}

ngx_int_t
xrootd_handle_async_go(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    return xrootd_send_error(ctx, c, kXR_Unsupported,
                            "kXR_asyncgo (5007) is no longer supported");
}
