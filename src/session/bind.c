#include "../ngx_xrootd_module.h"
#include "registry.h"

/*
 * kXR_bind — attach a secondary TCP data channel to an existing session.
 *
 * Secondary connections are used by xrdcp for parallel data transfer.  The
 * client establishes a primary connection (handshake + kXR_login + auth),
 * then opens additional TCP connections that skip login and send kXR_bind
 * with the primary session's sessid.
 *
 * The server assigns a pathid (1–253) to the secondary.  The client then
 * tags kXR_read/kXR_write payloads with this pathid to indicate which data
 * channel the request arrived on (allowing the server to load-balance or
 * multiplex across channels).
 *
 * Bound connections are intentionally narrower than full sessions: they may
 * read primary-published handles, but they may not open, close, write, stat,
 * or otherwise manipulate files independently.  The primary remains the
 * authority that decides which handles exist; secondaries are data channels.
 */

static ngx_uint_t  xrootd_next_pathid = 0;

ngx_int_t
xrootd_handle_bind(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientBindRequest *req;
    u_char             pathid;
    u_char            *buf;
    size_t             total;
    ngx_uint_t         token_auth = 0;

    (void) conf;

    req = (ClientBindRequest *) ctx->hdr_buf;

    /*
     * The primary connection inserts its session registry entry at the point
     * where the session is allowed to perform file I/O: anonymous login for
     * auth=none, or successful kXR_auth for authenticated deployments.
     */
    if (!xrootd_session_lookup(req->sessid,
                               ctx->dn, sizeof(ctx->dn),
                               ctx->vo_list, sizeof(ctx->vo_list),
                               &token_auth))
    {
        xrootd_log_access(ctx, c, "BIND", "-", "-",
                          0, kXR_NotAuthorized,
                          "sessid not found in session registry", 0);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "bind sessid not recognised");
    }
    ctx->token_auth = (int) token_auth;

    /* Assign a path ID.  Pathid 0 is reserved for the primary; we cycle 1–253. */
    if (++xrootd_next_pathid > 253) {
        xrootd_next_pathid = 1;
    }
    pathid = (u_char) xrootd_next_pathid;

    /* Bind the session: record the primary's sessid and inherit auth state. */
    ngx_memcpy(ctx->bound_sessid, req->sessid, XROOTD_SESSION_ID_LEN);
    ctx->is_bound  = 1;
    ctx->pathid    = (int) pathid;
    ctx->logged_in = 1;   /* secondary skips kXR_login */
    ctx->auth_done = 1;   /* identity inherited from registry lookup above */

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_bind: pathid=%d sessid=%02xd%02xd...",
                   (int) pathid,
                   (unsigned) req->sessid[0],
                   (unsigned) req->sessid[1]);

    total = XRD_RESPONSE_HDR_LEN + 1;
    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok, 1,
                          (ServerResponseHdr *) buf);
    buf[XRD_RESPONSE_HDR_LEN] = pathid;

    xrootd_log_access(ctx, c, "BIND", "-", "-", 1, 0, NULL, 0);

    return xrootd_queue_response(ctx, c, buf, total);
}
