/*
 * bind.c — kXR_bind opcode: attach a secondary data channel to a session.
 */

#include "core/ngx_brix_module.h"
#include "registry.h"
#include "offload_registry.h"   /* §1.1 per-worker (sessid,pathid)->conn map */
#include "core/compat/alloc_guard.h"

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

static ngx_uint_t  brix_next_pathid = 0;

/* Handle kXR_bind — attach a secondary TCP data channel to an existing primary
 * session: look the session up in the registry and assign a pathid (1-253; 0 is
 * the primary).  Bound connections are capability-restricted (e.g. read primary-
 * published handles via pathid-tagged kXR_read). */
ngx_int_t
brix_handle_bind(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    xrdw_sessid_req_t  req;
    u_char             pathid;
    u_char            *buf;
    size_t             total;
    ngx_uint_t         token_auth = 0;

    /*
     * brix_data_substreams off: refuse the bind so the client streams every
     * request — and its data — inline on the primary connection (pathid 0).  A
     * data path is an optimisation, not a requirement (go-hep session.go), so a
     * refused bind is a clean fallback; this is the supported posture when
     * fronting a client that would otherwise stream WRITE payloads on a secondary
     * connection, which BriX does not yet service as a cross-connection data-path.
     */
    if (!conf->common.data_substreams) {
        brix_log_access(ctx, c, "BIND", "-", "-", 0, kXR_Unsupported,
                          "data substreams disabled (brix_data_substreams off)", 0);
        return brix_send_error(ctx, c, kXR_Unsupported,
                                 "data substreams disabled on this server");
    }

    xrdw_sessid_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);

    /*
     * The primary connection inserts its session registry entry at the point
     * where the session is allowed to perform file I/O: anonymous login for
     * auth=none, or successful kXR_auth for authenticated deployments.
     */
    if (!brix_session_lookup(req.sessid,
                               ctx->login.dn, sizeof(ctx->login.dn),
                               ctx->login.vo_list, sizeof(ctx->login.vo_list),
                               &token_auth))
    {
        brix_log_access(ctx, c, "BIND", "-", "-",
                          0, kXR_NotAuthorized,
                          "sessid not found in session registry", 0);
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "bind sessid not recognised");
    }
    ctx->token.auth = (int) token_auth;
    if (ctx->identity != NULL) {
        if (token_auth) {
            if (brix_identity_set_subject(ctx->identity, c->pool, ctx->login.dn,
                                            BRIX_AUTHN_TOKEN) != NGX_OK
                || brix_identity_set_cstr(c->pool, &ctx->identity->dn,
                                            ctx->login.dn) != NGX_OK)
            {
                return NGX_ERROR;
            }
        } else if (brix_identity_set_dn(ctx->identity, c->pool, ctx->login.dn,
                                          BRIX_AUTHN_GSI) != NGX_OK)
        {
            return NGX_ERROR;
        }
        if (brix_identity_set_vos_csv(ctx->identity, c->pool,
                                        ctx->login.vo_list) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    /* Assign a path ID.  Pathid 0 is reserved for the primary; we cycle 1–253. */
    if (++brix_next_pathid > 253) {
        brix_next_pathid = 1;
    }
    pathid = (u_char) brix_next_pathid;

    /* Bind the session: record the primary's sessid and inherit auth state. */
    ngx_memcpy(ctx->bound_sessid, req.sessid, BRIX_SESSION_ID_LEN);
    ctx->is_bound  = 1;
    ctx->pathid    = (int) pathid;
    ctx->login.logged_in = 1;   /* secondary skips kXR_login */
    ctx->login.auth_done = 1;   /* identity inherited from registry lookup above */

    /* §1.2: publish the pathid on the session's registry entry so ANY worker
     * can validate pathid-tagged requests against the session's live binds
     * (stock refuses an unbound pathid with kXR_ArgInvalid). Cleared again in
     * the disconnect path when this secondary goes away. */
    brix_session_pathid_bind(req.sessid, (unsigned) pathid);

    /* §1.1 response offloading: record this secondary's per-worker connection so
     * a later read/readv handler can route a pathid-tagged response out its
     * socket. Best-effort — a full table just means this channel keeps using the
     * control stream (never an error). Cleared in the disconnect path. */
    (void) brix_offload_register(ctx->bound_sessid, (unsigned) pathid, c);

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: kXR_bind: pathid=%d sessid=%02xd%02xd...",
                   (int) pathid,
                   (unsigned) req.sessid[0],
                   (unsigned) req.sessid[1]);

    total = XRD_RESPONSE_HDR_LEN + 1;
    BRIX_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_ok, 1,
                          (ServerResponseHdr *) buf);
    buf[XRD_RESPONSE_HDR_LEN] = pathid;

    brix_log_access(ctx, c, "BIND", "-", "-", 1, 0, NULL, 0);

    return brix_queue_response(ctx, c, buf, total);
}
