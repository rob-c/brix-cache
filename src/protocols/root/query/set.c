#include "core/ngx_xrootd_module.h"

#include <stdlib.h>

/*
 * kXR_set (3018) — client sends advisory configuration hints to the server.
 *
 * WHAT: Handles the SET opcode where a client provides optional metadata about
 *       its identity or session parameters. The modifier byte determines which
 *       hint type is being sent; unrecognized modifiers are accepted with kXR_ok.
 *
 * WHY: CMS grid infrastructure sends "cms.space" appid reports to advertise
 *      disk capacity at storage nodes. Session TTL hints (clttl) let clients
 *      suggest keep-alive duration. The server accepts all SET requests per spec,
 *      enabling monitoring and operational visibility without strict enforcement.
 *
 * HOW: Parse modifier byte from the request header → switch on known values
 *      (appid, clttl) → handle payload for recognized types → log details at
 *      debug/info level → always return kXR_ok regardless of modifier value.
 */

/*
 * CMS space report constants.
 *
 * The "cms.space" appid payload format is: "cms.space <total_bytes> <free_bytes>"
 * where both values are ASCII decimal unsigned integers. Used by the CMS grid
 * to advertise storage node capacity in kXR_set(appid) requests.
 */
#define CMS_SPACE_PREFIX     "cms.space"
#define CMS_SPACE_PREFIX_LEN (sizeof(CMS_SPACE_PREFIX) - 1)

/*
 * xrootd_set_handle_cms_space — parse and log CMS space-availability report.
 *
 * WHAT: Extracts total and free byte counts from a "cms.space" payload string,
 *       then logs the capacity breakdown at INFO level for operational visibility.
 *
 * WHY: The CMS grid sends kXR_set(appid) with "cms.space <total> <free>" payloads
 *      to advertise storage node disk availability. This function parses those
 *      reports so operators can monitor capacity via nginx access logs.
 *
 * HOW: Skip the "cms.space" prefix, parse two ASCII decimal unsigned integers
 *      separated by a space using strtoull, validate separator presence between
 *      them, compute used = total - free, log at INFO level. Returns silently on
 *      malformed payload (warn logged).
 */
static void
xrootd_set_handle_cms_space(ngx_connection_t *c, const char *payload,
                             size_t payload_len)
{
    /* Expected format: "cms.space <total_bytes> <free_bytes>" */
    const char        *p;
    char              *end;
    unsigned long long total_bytes, free_bytes;

    p = payload + CMS_SPACE_PREFIX_LEN;
    while (p < payload + payload_len && *p == ' ') {
        p++;
    }

    total_bytes = strtoull(p, &end, 10);
    if (end == p || *end != ' ') {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: kXR_set cms.space: malformed payload");
        return;
    }
    p = end;
    while (*p == ' ') {
        p++;
    }
    free_bytes = strtoull(p, &end, 10);
    if (end == p) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: kXR_set cms.space: missing free_bytes");
        return;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "xrootd: cms.space report: total=%lluB free=%lluB "
                  "used=%lluB",
                  total_bytes, free_bytes,
                  (total_bytes > free_bytes) ? total_bytes - free_bytes : 0ULL);
}

/*
 * xrootd_handle_set — handle kXR_set (3018) opcode.
 *
 * WHAT: Dispatches the SET opcode based on its modifier byte, handling known
 *       hint types (appid with CMS space reports, clttl session TTL) and
 *       returning kXR_ok for all modifiers including unrecognized ones.
 *
 * WHY: The XRootD protocol allows clients to send advisory hints about their
 *      identity or session parameters. The server accepts all SET requests per
 *      spec — it does not enforce TTL or validate appid format strictly, but
 *      logs recognized types for operational visibility (CMS space reports at
 *      INFO level, other modifiers at debug level).
 *
 * HOW: Extract modifier byte from request header → switch on known values
 *      (kXR_set_appid → parse CMS space payload; kXR_set_clttl → log silently)
 *      → default → accept with kXR_ok. Always return kXR_ok regardless of
 *      modifier value. Payload snippet logged at debug level for all types.
 *
 * Parameters:
 *   ctx — xrootd connection context containing parsed request header and payload
 *   c   — nginx connection for logging
 */
ngx_int_t
xrootd_handle_set(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    xrdw_set_req_t    req;
    char              detail[128];
    u_char            modifier;
    const char       *mod_name;
    char              payload_snippet[64];
    size_t            payload_len;
    const char       *payload;

    xrdw_set_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &req);
    modifier = (u_char) req.modifier;

    switch (modifier) {
    case kXR_set_appid: mod_name = "appid"; break;
    case kXR_set_clttl: mod_name = "clttl"; break;
    default:            mod_name = "unknown"; break;
    }

    payload_len = (size_t) ctx->cur_dlen;
    payload     = (ctx->cur_dlen > 0 && ctx->payload != NULL)
                  ? (const char *) ctx->payload : "";

    payload_snippet[0] = '\0';
    if (payload_len > 0) {
        size_t snap = payload_len < sizeof(payload_snippet) - 1
                      ? payload_len : sizeof(payload_snippet) - 1;
        ngx_memcpy(payload_snippet, payload, snap);
        payload_snippet[snap] = '\0';
        /* strip trailing newline/NUL for display */
        while (snap > 0
               && (payload_snippet[snap - 1] == '\n'
                   || payload_snippet[snap - 1] == '\0'))
        {
            payload_snippet[--snap] = '\0';
        }
    }

    /* CMS space report: modifier=appid, payload starts with "cms.space" */
    if (modifier == kXR_set_appid
        && payload_len > CMS_SPACE_PREFIX_LEN
        && ngx_strncmp(payload, CMS_SPACE_PREFIX, CMS_SPACE_PREFIX_LEN) == 0)
    {
        xrootd_set_handle_cms_space(c, payload, payload_len);
        XROOTD_RETURN_OK(ctx, c, XROOTD_OP_SET, "SET", "-", "cms.space", 0);
    }

    snprintf(detail, sizeof(detail), "modifier=0x%02x(%s) val=\"%s\"",
             (unsigned) modifier, mod_name, payload_snippet);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_set %s", detail);

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_SET, "SET", "-", detail, 0);
}
