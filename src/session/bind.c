#include "../ngx_xrootd_module.h"
#include "registry.h"

/* ------------------------------------------------------------------ */
/* Session Binding — kXR_bind handler                                     */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_bind opcode — attaching a secondary TCP data channel to an existing session. Secondary connections allow xrdcp clients to establish parallel data transfer channels for read operations, bypassing the primary connection bottleneck. The client first establishes a primary connection (handshake + login + auth), then opens additional TCP connections that skip authentication and send kXR_bind with the primary session's sessid.
 *
 * WHY: Parallel data channels enable high-throughput reads by allowing multiple concurrent read requests to arrive on different sockets simultaneously. The server assigns each secondary a pathid (1–253) which clients use to tag their kXR_read payloads, enabling load-balancing across channels. Bound connections are intentionally narrower than full sessions — they may only read primary-published handles but cannot open, close, write, or stat files independently. The primary connection remains the authority that decides which handles exist; secondaries are purely data channels.
 *
 * HOW: Two-phase binding → session registry lookup (verify sessid exists in primary's session entry) — inherit token_auth state from primary — assign pathid cycling 1–253 — record bound_sessid + set is_bound=1 + logged_in=1 + auth_done=1 (identity inherited from registry lookup, secondary skips kXR_login) — return kXR_ok with single-byte pathid body payload. */

/* ------------------------------------------------------------------ */
/* Section: Secondary Connection Scope                                    */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Bound connections have restricted capabilities compared to full sessions. They may read primary-published handles (via pathid-tagged kXR_read), but cannot open, close, write, stat, or otherwise manipulate files independently. This restriction ensures the primary connection remains the sole authority for file handle lifecycle decisions — secondaries are purely data channels for parallel reads.
 *
 * WHY: Prevents race conditions and security issues where secondary connections could create new handles or mutate files without coordination with the primary session. The primary establishes which handles exist via kXR_open; secondaries read from those handles only, using their pathid to tag requests so the server can multiplex responses across channels. */

/* ------------------------------------------------------------------ */
/* Section: Path ID Allocation                                            */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_next_pathid is a static counter cycling 1–253 for secondary connection identification. Pathid 0 is reserved exclusively for the primary connection; secondaries receive values starting at 1 and wrap around after reaching 253 to prevent exhaustion in long-running deployments with many parallel channels.
 *
 * WHY: Each secondary connection needs a unique identifier so clients can tag their kXR_read payloads with the correct pathid, allowing the server to route responses back to the originating socket. The 1–253 range provides sufficient capacity for typical xrdcp parallel read patterns without requiring complex allocation schemes or session cleanup. */

/* ---- Function: xrootd_handle_bind() ----
 *
 * WHAT: Handles the kXR_bind opcode — attaches a secondary TCP data channel to an existing primary session by performing registry lookup, pathid assignment, and state inheritance. Returns kXR_ok with single-byte pathid body payload (1–253). Secondary connections skip kXR_login and inherit logged_in/auth_done=1 from the primary's session registry entry, but are restricted to read-only operations on primary-published handles only.
 *
 * WHY: Enables parallel data transfer for high-throughput reads by allowing multiple concurrent read requests to arrive on different sockets simultaneously. The pathid allows clients to tag kXR_read payloads so the server can multiplex responses across channels. Bound connections have intentionally narrower capabilities — they may only read primary-published handles but cannot open, close, write, or stat files independently, ensuring the primary remains sole authority for file handle lifecycle decisions.
 *
 * HOW: Two-phase binding → session registry lookup (verify sessid exists in primary entry) — inherit token_auth from primary — assign pathid cycling 1–253 — record bound_sessid + set is_bound=1 + logged_in=1 + auth_done=1 (identity inherited, secondary skips login) — return kXR_ok with single-byte pathid body payload. */

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
    if (ctx->identity != NULL) {
        if (token_auth) {
            if (xrootd_identity_set_subject(ctx->identity, c->pool, ctx->dn,
                                            XROOTD_AUTHN_TOKEN) != NGX_OK
                || xrootd_identity_set_cstr(c->pool, &ctx->identity->dn,
                                            ctx->dn) != NGX_OK)
            {
                return NGX_ERROR;
            }
        } else if (xrootd_identity_set_dn(ctx->identity, c->pool, ctx->dn,
                                          XROOTD_AUTHN_GSI) != NGX_OK)
        {
            return NGX_ERROR;
        }
        if (xrootd_identity_set_vos_csv(ctx->identity, c->pool,
                                        ctx->vo_list) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

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
