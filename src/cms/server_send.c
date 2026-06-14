#include "server.h"
#include "frame_io.h"

/*
 * xrootd_cms_srv_send_frame — thin wrapper for server-side frame dispatch.
 *
 * WHAT: Delegates CMS frame transmission to the shared helper in frame_io.c,
 *      passing ctx->c as the target socket. WHY: Keeps server_send.c callers
 *      insulated from the connection pointer — they operate on ctx and delegate
 *      wire I/O without knowing which connection object is used. HOW: Single
 *      return line forwarding all parameters plus ctx->c to xrootd_cms_send_frame(). */

static ngx_int_t
xrootd_cms_srv_send_frame(xrootd_cms_srv_ctx_t *ctx, uint32_t streamid,
    u_char code, u_char modifier, const u_char *payload, size_t payload_len)
{
    return xrootd_cms_send_frame(ctx->c, streamid, code, modifier, payload,
                                 payload_len);
}

/* ---- xrootd_cms_srv_send_ping — send periodic liveness probe to registered data-server ----
 * WHAT: Sends a kYR_pong ping frame to the connected CMS data-server client. This is the heartbeat mechanism that keeps the connection alive and confirms the data server is still responding. WHY: The CMS manager needs periodic confirmation that registered data servers are active — stale registrations would route clients to dead nodes. The ping timer in server_recv.c fires every `interval_ms` seconds (default 60s) to send these probes. HOW: Single-line frame builder: streamid=0, code=CMS_RR_PING, modifier=0, payload=NULL (empty). Returns error from xrootd_cms_srv_send_frame if connection closed or write fails. */

ngx_int_t
xrootd_cms_srv_send_ping(xrootd_cms_srv_ctx_t *ctx)
{
    return xrootd_cms_srv_send_frame(ctx, 0, CMS_RR_PING, 0, NULL, 0);
}

/* ---- xrootd_cms_srv_send_xauth — send the security challenge (kYR_xauth) ----
 * WHAT: Sends a kYR_xauth frame carrying the manager's security parameters to a
 *       connecting data node, requesting it present a credential.  WHY: This is
 *       the manager half of the real cmsd login security handshake
 *       (XrdCmsSecurity::Authenticate) — the node replies with another
 *       kYR_xauth frame containing its sss credential, which we verify before
 *       registering it.  HOW: streamid=0, code=CMS_RR_XAUTH, modifier=0,
 *       payload = the NUL-terminated parms string (e.g. "&P=sss"). */
ngx_int_t
xrootd_cms_srv_send_xauth(xrootd_cms_srv_ctx_t *ctx,
    const u_char *parms, size_t len)
{
    return xrootd_cms_srv_send_frame(ctx, 0, CMS_RR_XAUTH, 0, parms, len);
}
