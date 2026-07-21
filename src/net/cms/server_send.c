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

/*
 * brix_cms_srv_send_load — kYR_load reply to a node's kYR_usage query.
 *
 * WHAT: Sends a CMS_RR_LOAD frame echoing the request streamid, carrying the
 *      6-byte load vector (cpu,net,xeq,mem,pag,dsk) and the aggregate free
 *      space in MB. WHY: Stock cmsd answers do_Usage with its current load
 *      report so a querying node/peer can weigh this manager; phase-89 W1
 *      brings the manager side to parity. HOW: Byte-exact with the node-side
 *      heartbeat in send.c — theLoad is a bare [2-byte len][6 bytes] Pup
 *      char-blob (NO scalar tag), dskFree a tagged int; total dlen = 13.
 */
ngx_int_t
brix_cms_srv_send_load(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char load6[6], uint32_t free_mb)
{
    u_char    payload[16];
    u_char   *cursor;

    cursor = payload;
    ngx_brix_cms_put16(cursor, 6);          /* blob length: 6 load bytes */
    cursor += 2;
    ngx_memcpy(cursor, load6, 6);
    cursor += 6;
    cursor = ngx_brix_cms_put_int(cursor, free_mb);

    return brix_cms_srv_send_frame(ctx, streamid, CMS_RR_LOAD, 0,
                                     payload, (size_t) (cursor - payload));
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

/* brix_cms_srv_send_state — Phase-89 W3: probe "do you hold <path>?" with a
 * kYR_state carrying the raw NUL-terminated path (modifier RAW, matching what
 * our own node side parses in cms_frame_state and what cmsd emits).  The node
 * answers kYR_have echoing the streamid — which keys the pending-locate entry
 * of the parked client — or stays silent for a file it does not hold. */
ngx_int_t
brix_cms_srv_send_state(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const char *path)
{
    size_t  len = ngx_strlen(path);

    return brix_cms_srv_send_frame(ctx, streamid, CMS_RR_STATE, CMS_MOD_RAW,
                                     (const u_char *) path, len + 1);
}
