#include "server.h"
#include "frame_io.h"

/*
 * brix_cms_srv_send_frame — thin wrapper for server-side frame dispatch.
 *
 * WHAT: Delegates CMS frame transmission to the shared helper in frame_io.c,
 *      passing ctx->c as the target socket. WHY: Keeps server_send.c callers
 *      insulated from the connection pointer — they operate on ctx and delegate
 *      wire I/O without knowing which connection object is used. HOW: Single
 *      return line forwarding all parameters plus ctx->c to brix_cms_send_frame(). */

static ngx_int_t
brix_cms_srv_send_frame(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    u_char code, u_char modifier, const u_char *payload, size_t payload_len)
{
    return brix_cms_send_frame(ctx->c, streamid, code, modifier, payload,
                                 payload_len);
}

/* brix_cms_srv_send_ping — send a header-only kYR_ping (streamid=0) to a
 * registered data-server; the server_recv.c timer fires it every interval_ms
 * (default 60s) so the manager confirms the node is alive (stale registrations
 * would route clients to dead nodes). */

ngx_int_t
brix_cms_srv_send_ping(brix_cms_srv_ctx_t *ctx)
{
    return brix_cms_srv_send_frame(ctx, 0, CMS_RR_PING, 0, NULL, 0);
}

/* brix_cms_srv_send_xauth — send the kYR_xauth security challenge (the manager
 * half of XrdCmsSecurity::Authenticate): payload = the NUL-terminated parms string
 * (e.g. "&P=sss"). The node replies with its own kYR_xauth carrying an sss
 * credential, verified before registration. */
ngx_int_t
brix_cms_srv_send_xauth(brix_cms_srv_ctx_t *ctx,
    const u_char *parms, size_t len)
{
    return brix_cms_srv_send_frame(ctx, 0, CMS_RR_XAUTH, 0, parms, len);
}

/* brix_cms_srv_send_pong — answer a node's liveness kYR_ping with a header-only
 * kYR_pong (streamid=0), matching stock cmsd do_Ping's static CmsPongRequest. */
ngx_int_t
brix_cms_srv_send_pong(brix_cms_srv_ctx_t *ctx)
{
    return brix_cms_srv_send_frame(ctx, 0, CMS_RR_PONG, 0, NULL, 0);
}

/* brix_cms_srv_send_disc — echo a header-only kYR_disc back to a node that asked
 * to disconnect, before the manager closes the link (stock cmsd do_Disc). */
ngx_int_t
brix_cms_srv_send_disc(brix_cms_srv_ctx_t *ctx)
{
    return brix_cms_srv_send_frame(ctx, 0, CMS_RR_DISC, 0, NULL, 0);
}

/* brix_cms_srv_send_status — answer a kYR_update with a header-only kYR_status
 * carrying state-modifier bits (stock cmsd do_Update → CmsState::sendState),
 * advertising the manager active so the peer keeps it eligible. */
ngx_int_t
brix_cms_srv_send_status(brix_cms_srv_ctx_t *ctx, u_char modifier)
{
    return brix_cms_srv_send_frame(ctx, 0, CMS_RR_STATUS, modifier, NULL, 0);
}

/* brix_cms_srv_send_data — reply CMS_RSP_DATA with an opaque payload, echoing the
 * request streamid; byte-exact with cmsd's do_StatFS/do_Stats data replies (Plane A
 * query path). */
ngx_int_t
brix_cms_srv_send_data(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t len)
{
    return brix_cms_srv_send_frame(ctx, streamid, CMS_RSP_DATA, 0,
                                     payload, len);
}
