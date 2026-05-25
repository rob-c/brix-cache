#include "cms_internal.h"
#include "frame_io.h"
#include "../manager/registry.h"

#include <unistd.h>

/*
 * ngx_xrootd_cms_send_frame — thin wrapper around xrootd_cms_send_frame().
 *
 * WHAT: Delegates CMS frame transmission to the shared helper in frame_io.c,
 *      passing ctx->connection as the target socket. WHY: Keeps send.c callers
 *      insulated from the connection pointer — they operate on ctx and delegate
 *      wire I/O without knowing which connection object is used. HOW: Single
 *      return line forwarding all parameters plus ctx->connection to
 *      xrootd_cms_send_frame(). */

static ngx_int_t
ngx_xrootd_cms_send_frame(ngx_xrootd_cms_ctx_t *ctx, uint32_t streamid,
    u_char code, u_char modifier, const u_char *payload, size_t payload_len)
{
    return xrootd_cms_send_frame(ctx->connection, streamid, code, modifier,
                                 payload, payload_len);
}

/*
 * ngx_xrootd_cms_send_login — initial CMS login frame with server capabilities.
 *
 * WHAT: Builds and sends the first CMS frame after establishing a TCP connection,
 *      reporting version, mode (client/manager), PID, filesystem space stats,
 *      listen port, exported paths, and reserved fields. WHY: The CMS manager
 *      needs this information to decide whether to route client requests here;
 *      without login the server is invisible in the cluster registry. HOW: Call
 *      stat_space() for total_gb/free_mb/util_pct (aggregate if manager mode),
 *      pack type/value payload fields in wire order via put_short/put_int, append
 *      exported paths from cms_export_paths(), send frame with CMS_RR_LOGIN code. */

ngx_int_t
ngx_xrootd_cms_send_login(ngx_xrootd_cms_ctx_t *ctx)
{
    u_char     payload[1024];
    u_char    *payload_cursor;
    ngx_str_t  paths;
    size_t     path_len;
    uint32_t   total_gb;
    uint32_t   free_mb;
    uint32_t   util_pct;

    paths = ngx_xrootd_cms_export_paths(ctx->conf);
    path_len = paths.len;
    if (path_len > 512) {
        path_len = 512;
    }

    total_gb = 0;
    free_mb = 0;
    util_pct = 0;
    (void) ngx_xrootd_cms_stat_space(ctx->conf, &total_gb, &free_mb,
                                     &util_pct);

    if (ctx->conf->manager_mode) {
        uint32_t agg_free = 0, agg_util = 0;
        xrootd_srv_aggregate_space(&agg_free, &agg_util);
        if (agg_free > 0 || agg_util > 0) {
            free_mb  = agg_free;
            util_pct = agg_util;
        }
    }

    /*
     * CMS login uses a packed type/value payload, not a C struct.  Keep writes
     * in wire order so the field sequence can be checked against the protocol
     * notes without mentally following pointer arithmetic.
     */
    payload_cursor = payload;
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor,
                                              CMS_LOGIN_VERSION);
    payload_cursor = ngx_xrootd_cms_put_int(
        payload_cursor,
        CMS_LOGIN_MODE
        | (ctx->conf->manager_mode ? CMS_LOGIN_MODE_MANAGER : 0));
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor,
                                            (uint32_t) getpid());
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor, total_gb);
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor, free_mb);
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor,
                                            NGX_XROOTD_CMS_MIN_FREE_MB);
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor, 1);
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor,
                                              (uint16_t) util_pct);
    payload_cursor = ngx_xrootd_cms_put_short(
        payload_cursor, (uint16_t) ctx->conf->listen_port);

    /* Reserved protocol fields currently sent as zero. */
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor, 0);
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor, 0);
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor,
                                              (uint16_t) path_len);

    if (path_len > 0) {
        ngx_memcpy(payload_cursor, paths.data, path_len);
        payload_cursor += path_len;
    }

    /* Empty manager host/port trailer fields. */
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor, 0);
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor, 0);

    return ngx_xrootd_cms_send_frame(ctx, 0, CMS_RR_LOGIN, 0, payload,
                                     (size_t) (payload_cursor - payload));
}

/*
 * ngx_xrootd_cms_send_load — periodic load heartbeat report.
 *
 * WHAT: Builds and sends a CMS_LOAD frame reporting current free disk space in MB,
 *      optionally aggregated across all servers when in manager mode. WHY: The CMS
 *      manager uses load reports to distribute client requests proportionally to
 *      available capacity; stale or missing reports cause the manager to stop routing
 *      here. HOW: Call stat_space() for free_mb (aggregate via xrootd_srv_aggregate_space
 *      if manager mode), pack payload as put_short(6) + 6 zero bytes + put_int(free_mb),
 *      send with CMS_RR_LOAD code. */

ngx_int_t
ngx_xrootd_cms_send_load(ngx_xrootd_cms_ctx_t *ctx)
{
    u_char    payload[32];
    u_char   *payload_cursor;
    uint32_t  free_mb;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->cycle->log, 0,
                   "xrootd: send_load: conn=%p", ctx->connection);

    free_mb = 0;
    (void) ngx_xrootd_cms_stat_space(ctx->conf, NULL, &free_mb, NULL);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->cycle->log, 0,
                   "xrootd: send_load: free_mb=%uD", free_mb);

    if (ctx->conf->manager_mode) {
        uint32_t agg_free = 0, agg_util = 0;
        xrootd_srv_aggregate_space(&agg_free, &agg_util);
        if (agg_free > 0) {
            free_mb = agg_free;
        }
    }

    payload_cursor = payload;
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor, 6);
    ngx_memzero(payload_cursor, 6);
    payload_cursor += 6;
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor, free_mb);

    return ngx_xrootd_cms_send_frame(ctx, 0, CMS_RR_LOAD, 0, payload,
                                     (size_t) (payload_cursor - payload));
}

/*
 * ngx_xrootd_cms_send_avail — availability reply to CMS SPACE request.
 *
 * WHAT: Builds and sends a CMS_AVAIL frame with current free_mb and util_pct in response
 *      to a received CMS_SPACE opcode from the manager. WHY: The manager queries space on
 *      demand (via kYR_space) and expects an immediate avail reply; this function mirrors
 *      the synchronous request-response pattern for space reporting. HOW: Call stat_space()
 *      for free_mb/util_pct, aggregate if manager mode, pack as put_int(free_mb) +
 *      put_int(util_pct), send with CMS_RR_AVAIL code and the requesting streamid. */

ngx_int_t
ngx_xrootd_cms_send_avail(ngx_xrootd_cms_ctx_t *ctx, uint32_t streamid)
{
    u_char    payload[16];
    u_char   *payload_cursor;
    uint32_t  free_mb;
    uint32_t  util_pct;

    free_mb = 0;
    util_pct = 0;
    (void) ngx_xrootd_cms_stat_space(ctx->conf, NULL, &free_mb, &util_pct);

    if (ctx->conf->manager_mode) {
        uint32_t agg_free = 0, agg_util = 0;
        xrootd_srv_aggregate_space(&agg_free, &agg_util);
        if (agg_free > 0 || agg_util > 0) {
            free_mb  = agg_free;
            util_pct = agg_util;
        }
    }

    payload_cursor = payload;
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor, free_mb);
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor, util_pct);

    return ngx_xrootd_cms_send_frame(ctx, streamid, CMS_RR_AVAIL, 0, payload,
                                     (size_t) (payload_cursor - payload));
}

/*
 * ngx_xrootd_cms_send_pong — empty reply to CMS PING probe.
 *
 * WHAT: Sends a zero-payload frame with CMS_RR_PONG code acknowledging the manager's
 *      periodic liveness check. WHY: The CMS manager sends PING frames at regular intervals;
 *      a missing pong indicates the server connection has died and triggers disconnect/retry.
 *      HOW: Single-line dispatch to send_frame with empty payload (NULL, 0). */

ngx_int_t
ngx_xrootd_cms_send_pong(ngx_xrootd_cms_ctx_t *ctx, uint32_t streamid)
{
    return ngx_xrootd_cms_send_frame(ctx, streamid, CMS_RR_PONG, 0, NULL, 0);
}

/*
 * ngx_xrootd_cms_next_streamid — monotonic stream ID allocator.
 *
 * WHAT: Returns the next available stream ID for outgoing CMS frames, wrapping from
 *      UINT32_MAX back to 1 on overflow. WHY: Each CMS frame must carry a unique streamid
 *      so the manager can correlate requests with responses; wrapping ensures continuous
 *      allocation without running out of IDs over long-lived connections. HOW: Increment
 *      ctx->next_streamid, wrap at UINT32_MAX → 1, return current value. */

uint32_t
ngx_xrootd_cms_next_streamid(ngx_xrootd_cms_ctx_t *ctx)
{
    if (ctx->next_streamid == UINT32_MAX) {
        ctx->next_streamid = 1;
    } else {
        ctx->next_streamid++;
    }
    return ctx->next_streamid;
}

/*
 * ngx_xrootd_cms_send_locate — client-side locate request to CMS manager.
 *
 * WHAT: Sends a CMS_LOCATE frame asking the manager which server should serve a given path.
 * WHY: When a client issues kYR_locate and this server is not the data owner, it forwards
 *      the lookup to the CMS manager which resolves the owning server and returns a redirect.
 * HOW: Copy path (NUL-terminated) into payload buffer bounded by XROOTD_SRV_MAX_PATHS,
 *      send with CMS_RR_LOCATE code and the originating streamid. */

ngx_int_t
ngx_xrootd_cms_send_locate(ngx_xrootd_cms_ctx_t *ctx,
    uint32_t streamid, const char *path)
{
    u_char  payload[XROOTD_SRV_MAX_PATHS];
    size_t  plen;

    plen = ngx_strlen(path) + 1;   /* include NUL terminator */
    if (plen > sizeof(payload)) {
        return NGX_ERROR;
    }

    ngx_memcpy(payload, path, plen);
    return ngx_xrootd_cms_send_frame(ctx, streamid, CMS_RR_LOCATE, 0,
                                     payload, plen);
}
