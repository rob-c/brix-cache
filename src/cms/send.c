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

/* ngx_xrootd_cms_send_error — reply to a forwarded op that failed * WHAT: Sends a kYR_error reply frame: [4B big-endian ecode][text + NUL],
 *       echoing the request streamid.  WHY: byte-exact with cmsd
 *       XrdCmsProtocol::Reply_Error — a data node answers a failed forwarded
 *       namespace op (Plane B) this way; success stays silent.  HOW: pack the
 *       error code then the NUL-terminated text into a stack buffer and dispatch
 *       a CMS_RSP_ERROR frame.  text is truncated to fit the frame cap. */
ngx_int_t
ngx_xrootd_cms_send_error(ngx_xrootd_cms_ctx_t *ctx, uint32_t streamid,
    uint32_t ecode, const char *text)
{
    u_char  buf[256];
    size_t  tlen;

    tlen = (text != NULL) ? ngx_strlen(text) : 0;
    if (tlen > sizeof(buf) - 5) {       /* 4B ecode + text + NUL */
        tlen = sizeof(buf) - 5;
    }
    ngx_xrootd_cms_put32(buf, ecode);
    if (tlen > 0) {
        ngx_memcpy(buf + 4, text, tlen);
    }
    buf[4 + tlen] = '\0';
    return ngx_xrootd_cms_send_frame(ctx, streamid, CMS_RSP_ERROR, 0,
                                     buf, 4 + tlen + 1);
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
    u_char      payload[1024];
    u_char     *payload_cursor;
    u_char      sid[256];
    u_char      pathbuf[640];
    u_char      hostbuf[200];
    u_char     *pp;
    ngx_str_t   paths;
    size_t      sid_len;
    size_t      path_len;
    size_t      i;
    size_t      seg_start;
    uint32_t    total_gb;
    uint32_t    free_mb;
    uint32_t    util_pct;
    u_char      ptype;

    /*
     * Build the exported-path list in the real XrdCms wire format: newline-
     * separated "<type> <path>" entries, type 'w' if writable else 'r'
     * (e.g. "all.export / r/w" -> "w /").  xrootd_cms_paths may carry several
     * colon-separated namespace prefixes ("/data:/atlas").
     */
    paths = ngx_xrootd_cms_export_paths(ctx->conf);
    ptype = ctx->conf->common.allow_write ? (u_char) 'w' : (u_char) 'r';
    pp = pathbuf;
    seg_start = 0;
    /*
     * Loop runs to i == paths.len (one past the last byte) so the final
     * segment is flushed by the same branch that handles a ':' delimiter — no
     * separate post-loop emit needed.  The "+ 4" slack in the bound check
     * reserves room for the per-segment framing this iteration may append:
     * one '\n' separator + the type char + a space (3) plus a margin byte.
     */
    for (i = 0; i <= paths.len; i++) {
        if (i == paths.len || paths.data[i] == ':') {
            size_t seglen = i - seg_start;
            if (seglen > 0
                && (size_t) (pp - pathbuf) + seglen + 4 < sizeof(pathbuf))
            {
                if (pp != pathbuf) {
                    *pp++ = '\n';
                }
                *pp++ = ptype;
                *pp++ = ' ';
                ngx_memcpy(pp, paths.data + seg_start, seglen);
                pp += seglen;
            }
            seg_start = i + 1;
        }
    }
    path_len = (size_t) (pp - pathbuf);

    /*
     * Server identity "<host>:<dport>" — opaque to the manager but must be
     * stable and reasonably unique for this node.
     */
    if (gethostname((char *) hostbuf, sizeof(hostbuf)) != 0) {
        ngx_memcpy(hostbuf, "nginx", sizeof("nginx"));
    }
    hostbuf[sizeof(hostbuf) - 1] = '\0';
    sid_len = (size_t) (ngx_snprintf(sid, sizeof(sid), "%s:%d", hostbuf,
                                     (int) ctx->conf->listen_port) - sid);

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
     * kYR_login payload — XrdOucPup wire order (CmsLoginData):
     *   Version sh, Mode int, HoldTime int, tSpace int, fSpace int, mSpace int,
     *   fsNum sh, fsUtil sh, dPort sh, sPort sh, [Fence],
     *   SID str, Paths str, ifList str, envCGI str.
     * Scalars carry a 0x80/0xa0 type tag; strings are bare [len][data+NUL].
     * The frame header datalen (set by send_frame) is the total payload length.
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
    /* tSpace/fSpace: total disk (GB) and free (MB) reported to the manager. */
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor, total_gb);
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor, free_mb);
    /*
     * mSpace: minimum-free threshold (MB).  Constant, not a live measurement —
     * it is the policy floor below which the manager should stop selecting us.
     */
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor,
                                            NGX_XROOTD_CMS_MIN_FREE_MB);
    /* fsNum: number of exported filesystems — we present a single namespace. */
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor, 1);
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor,
                                              (uint16_t) util_pct);
    /*
     * dPort: the data port clients are redirected to (our listen port).
     * sPort follows as 0 — we run no separate subscriber/admin port, so the
     * field is present in wire order but advertised as unused.
     */
    payload_cursor = ngx_xrootd_cms_put_short(
        payload_cursor, (uint16_t) ctx->conf->listen_port);
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor, 0); /* sPort */

    /*
     * Trailing Pup strings in wire order: SID, Paths, then ifList and envCGI.
     * The two NULL/0 puts emit empty (but present) ifList and envCGI strings —
     * the manager still expects the length-prefixed slots, so they cannot be
     * omitted even though we have nothing to advertise there.
     */
    payload_cursor = ngx_xrootd_cms_put_string(payload_cursor, sid, sid_len);
    payload_cursor = ngx_xrootd_cms_put_string(payload_cursor, pathbuf,
                                               path_len);
    payload_cursor = ngx_xrootd_cms_put_string(payload_cursor, NULL, 0);
    payload_cursor = ngx_xrootd_cms_put_string(payload_cursor, NULL, 0);

    return ngx_xrootd_cms_send_frame(ctx, 0, CMS_RR_LOGIN, 0, payload,
                                     (size_t) (payload_cursor - payload));
}

/*
 * ngx_xrootd_cms_send_status — announce traffic state after login.
 *
 * WHAT: Sends a header-only kYR_status frame with modifier Resume|noStage so the
 *      manager marks this disk-only node active and eligible for selection.  A
 *      real cmsd data server emits this right after login; without it the manager
 *      keeps the node suspended and never redirects clients to it.
 */

ngx_int_t
ngx_xrootd_cms_send_status(ngx_xrootd_cms_ctx_t *ctx)
{
    return ngx_xrootd_cms_send_frame(ctx, 0, CMS_RR_STATUS,
                                     CMS_ST_RESUME | CMS_ST_NOSTAGE, NULL, 0);
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

    /*
     * kYR_load payload (CmsLoadRequest / lodArgs): theLoad is a Pup char-blob
     * of 6 load bytes (cpu,net,xeq,mem,pag,dsk) — a bare [2-byte len][data] with
     * NO scalar type tag — followed by dskFree as a tagged int.  Zero load bytes
     * report an idle node; the manager only uses them for balancing.
     */
    /*
     * Hand-packed (put16 + manual cursor advance) rather than via put_string:
     * put16 only writes the 2-byte length, so the cursor must be advanced by
     * hand past both the length and the 6 data bytes before the tagged dskFree
     * int is appended via put_int.
     */
    payload_cursor = payload;
    ngx_xrootd_cms_put16(payload_cursor, 6);    /* blob length: 6 load bytes */
    payload_cursor += 2;                          /* skip the 2-byte length */
    ngx_memzero(payload_cursor, 6);             /* cpu,net,xeq,mem,pag,dsk = 0 */
    payload_cursor += 6;                          /* advance past the 6 bytes */
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

/*
 * ngx_xrootd_cms_send_have — tell the manager this node holds <path>.
 *
 * WHAT: Sends a kYR_have frame (modifier RAW|Online) with the raw, NUL-terminated
 *      path in response to a manager kYR_state query.  WHY: real XrdCms selection
 *      is on-demand — the manager broadcasts kYR_state to subscribed servers and
 *      only redirects a client to a node that answers kYR_have for the requested
 *      path.  The streamid echoes the state request so the manager correlates it.
 *      The payload is raw (not Pup-encoded), matching the manager's kYR_state.
 */

ngx_int_t
ngx_xrootd_cms_send_have(ngx_xrootd_cms_ctx_t *ctx, uint32_t streamid,
    const char *path, size_t path_len)
{
    u_char  payload[XROOTD_SRV_MAX_PATHS];

    if (path_len + 1 > sizeof(payload)) {
        return NGX_ERROR;
    }

    ngx_memcpy(payload, path, path_len);
    payload[path_len] = '\0';

    return ngx_xrootd_cms_send_frame(ctx, streamid, CMS_RR_HAVE,
                                     CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                     payload, path_len + 1);
}
