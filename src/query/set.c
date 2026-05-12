#include "../ngx_xrootd_module.h"

/*
 * kXR_set (3018) — client sends advisory configuration hints to the server.
 *
 * The modifier byte selects what is being set:
 *   kXR_set_appid (0x00) — application-ID string for monitoring/logging
 *   kXR_set_clttl (0x01) — session keep-alive TTL hint (seconds, ASCII decimal)
 *   anything else         — treated as a no-op advisory
 *
 * Per the XRootD spec, servers MUST respond kXR_ok to any kXR_set request,
 * including modifier values they do not recognise.  No file-system access is
 * performed.  The payload is logged at debug level for observability.
 */
ngx_int_t
xrootd_handle_set(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientSetRequest *req;
    char              detail[128];
    u_char            modifier;
    const char       *mod_name;
    char              payload_snippet[64];

    req      = (ClientSetRequest *) ctx->hdr_buf;
    modifier = (u_char) req->modifier;

    switch (modifier) {
    case kXR_set_appid: mod_name = "appid"; break;
    case kXR_set_clttl: mod_name = "clttl"; break;
    default:            mod_name = "unknown"; break;
    }

    payload_snippet[0] = '\0';
    if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
        size_t snap = ctx->cur_dlen < sizeof(payload_snippet) - 1
                      ? (size_t) ctx->cur_dlen
                      : sizeof(payload_snippet) - 1;
        ngx_memcpy(payload_snippet, ctx->payload, snap);
        payload_snippet[snap] = '\0';
        /* strip trailing newline/NUL for display */
        while (snap > 0
               && (payload_snippet[snap - 1] == '\n'
                   || payload_snippet[snap - 1] == '\0'))
        {
            payload_snippet[--snap] = '\0';
        }
    }

    snprintf(detail, sizeof(detail), "modifier=0x%02x(%s) val=\"%s\"",
             (unsigned) modifier, mod_name, payload_snippet);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_set %s", detail);

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_SET, "SET", "-", detail, 0);
}
