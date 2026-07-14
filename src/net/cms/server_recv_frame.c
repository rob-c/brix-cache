/*
 * cms/server_recv_frame.c — CMS server-side opcode handlers + dispatch table.
 *
 * WHAT: The per-opcode frame handlers for an accepted CMS data-server
 * connection (LOGIN, kYR_xauth, LOAD, AVAIL/SPACE, PONG, PING, DISC, UPDATE,
 * STATFS, GONE, CNS, and the unknown-opcode fallback), the login-completion
 * step, the periodic ping timer, and the data-driven opcode → handler route
 * table consumed by cms_srv_process_frame().
 *
 * WHY: Split out of the former monolithic server_recv.c (Phase-79 file-size
 * split).  Grouping "what each opcode does" behind a single dispatch table keeps
 * the wire-framing state machine (server_recv.c) and the pure decoders
 * (server_recv_parse.c) each single-purpose.  Handlers reach the lifecycle
 * helpers and the payload parsers through server_recv_internal.h; only
 * cms_srv_process_frame is exported (declared there and thus non-static).
 *
 * HOW: Each handler shares one signature so the route table can dispatch by
 * opcode; a handler that tears the connection down leaves ctx->c NULL for the
 * read loop to observe.  cms_srv_process_frame scans the table, falling through
 * to cms_srv_frame_unknown for codes we do not act on.
 */

#include "server.h"
#include "server_recv_internal.h"
#include "router.h"                       /* table-driven opcode routing */
#include "rrdata.h"                       /* Pup decode + statfs reply encode */
#include "net/manager/registry.h"          /* aggregate space for statfs reply */
#include "cns.h"                          /* §6 CNS inventory + event codec */

/* Ping timer */

static void
brix_cms_srv_ping_timer(ngx_event_t *ev)
{
    brix_cms_srv_ctx_t  *ctx = ev->data;

    if (brix_cms_srv_send_ping(ctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                      "brix: CMS server: ping to %s failed, closing",
                      ctx->host);
        cms_srv_set_end_hint(ctx, BRIX_SESS_END_ERROR);
        brix_cms_srv_close(ctx);
        return;
    }

    ngx_add_timer(&ctx->ping_timer, ctx->interval_ms);
}

/* Frame dispatcher */

/*
 * cms_srv_complete_login — register the data server and arm heartbeats.
 *
 * Called once the LOGIN frame has been parsed AND (when sss is configured) the
 * kYR_xauth credential has been verified.  Splitting this out lets the sss path
 * defer registration until authentication succeeds without duplicating the
 * register/log/timer sequence.
 */
static void
cms_srv_complete_login(brix_cms_srv_ctx_t *ctx)
{
    brix_srv_register(ctx->host, ctx->port, ctx->paths,
                         ctx->free_mb, ctx->util_pct);
    ctx->logged_in = 1;
    cms_srv_log_registration(ctx);

    /* Arm the periodic ping now that the data server is logged in. */
    ctx->ping_timer.handler = brix_cms_srv_ping_timer;
    ngx_add_timer(&ctx->ping_timer, ctx->interval_ms);

    /*
     * WS3: switch the read deadline from the LOGIN handshake bound to the
     * post-login idle watchdog.  Re-armed on every received frame in
     * brix_cms_srv_read; if the node goes silent for idle_timeout_ms it is
     * closed + unregistered + blacklisted (reaps a black-holed node the ping
     * send cannot detect).  0 = disabled.
     */
    if (ctx->idle_timeout_ms > 0 && ctx->c != NULL) {
        ngx_add_timer(ctx->c->read, ctx->idle_timeout_ms);
    } else if (ctx->c != NULL && ctx->c->read->timer_set) {
        ngx_del_timer(ctx->c->read);   /* idle watchdog disabled — drop login timer */
    }

    /* ctx->c is non-NULL for a frame being processed (a close nulls it and
     * returns), but match the ctx->c guards above for consistency. */
    if (ctx->c != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->c->log, 0,
                      "brix: CMS server: registered %s:%d paths=[%s] "
                      "free_mb=%uD util_pct=%uD",
                      ctx->host, (int) ctx->port, ctx->paths,
                      ctx->free_mb, ctx->util_pct);
    }
}

/* Per-opcode frame handlers.  All share one signature so the dispatcher can be
 * a data-driven route table (mirrors recv.c's client-side shape); handlers
 * that need no payload/streamid simply ignore those arguments.  A handler that
 * closes the connection leaves ctx->c NULL — the read loop checks that. */

typedef void (*cms_srv_frame_pt)(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len);

/*
 * cms_srv_frame_login — LOGIN: parse the CmsLoginData payload; on parse
 * failure log + close.  W1a — if sss cluster auth is required, do NOT register
 * yet.  Mirror the real cmsd manager (XrdCmsLogin::Admit): after the LOGIN
 * frame arrives, send our security parms and wait for the node's kYR_xauth
 * credential before admitting it into the registry.
 */
static void
cms_srv_frame_login(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    if (!cms_srv_parse_login(ctx, payload, payload_len)) {
        ngx_log_error(NGX_LOG_WARN, ctx->c->log, 0,
                      "brix: CMS server: malformed LOGIN from %s",
                      ctx->host);
        cms_srv_log_auth_fail(ctx, "invalid");
        cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
        return;
    }

    if (ctx->auth_state == CMS_AUTH_REQUESTED) {
        static const u_char sss_parms[] = "&P=sss";
        if (brix_cms_srv_send_xauth(ctx, sss_parms,
                                      sizeof(sss_parms)) != NGX_OK)
        {
            cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
            return;
        }
        ctx->auth_state = CMS_AUTH_CHALLENGED;
        return;
    }

    cms_srv_complete_login(ctx);
}

/*
 * cms_srv_frame_xauth — kYR_xauth: verify the node's sss credential and admit
 * it.  Only meaningful while we are waiting for a credential; anything else
 * (or a bad signature) is an auth failure and closes the connection.
 */
static void
cms_srv_frame_xauth(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    if (ctx->auth_state != CMS_AUTH_CHALLENGED) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->c->log, 0,
                      "brix: CMS server: unexpected kYR_xauth from %s",
                      ctx->host);
        cms_srv_log_auth_fail(ctx, "invalid");
        cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
        return;
    }
    if (brix_cms_srv_verify_xauth(ctx, payload, payload_len) != NGX_OK) {
        cms_srv_log_auth_fail(ctx, "bad-signature");
        cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
        return;
    }
    ctx->auth_state = CMS_AUTH_DONE;
    cms_srv_complete_login(ctx);
}

/*
 * cms_srv_frame_load — LOAD: refresh the node's free-space figure in the
 * registry (util_pct unchanged — LOAD carries no utilisation).  Pre-login
 * frames are ignored.
 */
static void
cms_srv_frame_load(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    uint32_t  free_mb;

    if (!ctx->logged_in) {
        return;
    }
    free_mb = cms_srv_parse_load_free_mb(payload, payload_len);
    brix_srv_update_load(ctx->host, ctx->port, free_mb, ctx->util_pct);
    ctx->free_mb = free_mb;
}

/*
 * cms_srv_frame_avail — AVAIL/SPACE: refresh both free-space and utilisation
 * in the registry (the two opcodes share this payload shape).  Pre-login
 * frames are ignored.
 */
static void
cms_srv_frame_avail(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    uint32_t  free_mb, util_pct;

    if (!ctx->logged_in) {
        return;
    }
    cms_srv_parse_avail(payload, payload_len, &free_mb, &util_pct);
    brix_srv_update_load(ctx->host, ctx->port, free_mb, util_pct);
    ctx->free_mb  = free_mb;
    ctx->util_pct = util_pct;
}

/*
 * cms_srv_frame_pong — PONG: heartbeat reply to our ping; log only.
 */
static void
cms_srv_frame_pong(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                   "brix: CMS server: pong from %s", ctx->host);
}

/*
 * cms_srv_frame_ping — symmetric liveness (do_Ping): a node (or peer) probing
 * us gets a header-only kYR_pong.  No auth/state needed — pure liveness.
 */
static void
cms_srv_frame_ping(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                   "brix: CMS server: ping from %s -> pong", ctx->host);
    if (brix_cms_srv_send_pong(ctx) != NGX_OK) {
        cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
    }
}

/*
 * cms_srv_frame_disc — graceful disconnect (do_Disc as manager): echo a
 * kYR_disc back, then close — which unregisters the node from the registry.
 */
static void
cms_srv_frame_disc(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    ngx_log_error(NGX_LOG_NOTICE, ctx->c->log, 0,
                  "brix: CMS server: %s requested disconnect", ctx->host);
    (void) brix_cms_srv_send_disc(ctx);
    cms_srv_fail_close(ctx, BRIX_SESS_END_CLIENT);
}

/*
 * cms_srv_frame_update — state-refresh request (do_Update): resend our state
 * as a kYR_status frame so the peer keeps us active and eligible.
 */
static void
cms_srv_frame_update(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                   "brix: CMS server: update from %s -> status", ctx->host);
    if (brix_cms_srv_send_status(ctx, CMS_ST_RESUME | CMS_ST_NOSTAGE)
        != NGX_OK)
    {
        cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
    }
}

/*
 * cms_srv_frame_statfs — space query for a path (do_StatFS): answer kYR_data
 * with aggregate cluster space for the servers that hold the path.  We report
 * a single tier (staging == writable) since we model one storage class.
 */
static void
cms_srv_frame_statfs(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    brix_cms_rrdata_t         d;
    brix_cms_statfs_fields_t  space;
    u_char                      out[64];
    uint32_t                    free_mb = 0, util = 0, num;
    int                         olen;

    if (!ctx->logged_in
        || brix_cms_rrdata_parse(CMS_RR_STATFS, payload, payload_len, &d)
           != 0
        || d.path == NULL)
    {
        return;                          /* malformed / pre-auth: ignore */
    }

    num = (uint32_t) brix_srv_count_matching((const char *) d.path);
    brix_srv_aggregate_space(&free_mb, &util);
    space.w_num  = num;  space.w_free = free_mb;  space.w_util = util;
    space.s_num  = num;  space.s_free = free_mb;  space.s_util = util;
    olen = brix_cms_statfs_encode(&space, out, sizeof(out));
    if (olen > 0) {
        (void) brix_cms_srv_send_data(ctx, streamid, out, (size_t) olen);
    }
}

/*
 * cms_srv_frame_gone — a data server signals that it no longer holds a
 * specific path.  Remove that path token from its registry entry without
 * touching the rest of the registration (the server still holds other paths).
 */
static void
cms_srv_frame_gone(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    char    path[BRIX_SRV_MAX_PATHS];
    size_t  copy;

    if (!ctx->logged_in || payload_len == 0) {
        return;
    }

    copy = payload_len < sizeof(path) - 1
           ? payload_len : sizeof(path) - 1;
    ngx_memcpy(path, payload, copy);
    path[copy] = '\0';
    brix_srv_unregister_path(ctx->host, ctx->port, path);
    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                   "brix: CMS server: kYR_gone path=%s from %s:%d",
                   path, ctx->host, (int) ctx->port);
}

/*
 * cms_srv_frame_cns — §6 Composite Cluster Name Space: a data server reports a
 * namespace mutation.  Apply it into the manager inventory (collect mode only).
 */
static void
cms_srv_frame_cns(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    uint8_t   op;
    uint64_t  size, mtime;
    char      path[BRIX_CNS_PATH_MAX + 1];
    uint32_t  server_id;
    const u_char *h = (const u_char *) ctx->host;
    size_t    i;

    if (!ctx->logged_in || !brix_cns_collecting()) {
        return;
    }

    if (brix_cns_event_decode(payload, payload_len, &op, &size, &mtime,
                                path, sizeof(path)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, ctx->c->log, 0,
                      "brix: CMS server: malformed CNS event from %s",
                      ctx->host);
        return;
    }
    server_id = (uint32_t) ctx->port;        /* host hash + port = origin id */
    for (i = 0; h[i] != '\0'; i++) {
        server_id = server_id * 33 + h[i];
    }
    (void) brix_cns_apply(op, path, size, mtime, server_id);
    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                   "brix: CNS event op=%ud path=%s from %s",
                   (unsigned) op, path, ctx->host);
}

/*
 * cms_srv_frame_unknown — default: consult the manager routing table so the
 * log distinguishes a valid manager opcode we have not wired yet (e.g.
 * usage/stats/statfs) from a truly unroutable code.  Either way we drop it —
 * matching cmsd's tolerance of frames it does not act on.
 */
static void
cms_srv_frame_unknown(brix_cms_srv_ctx_t *ctx, u_char code)
{
    const brix_cms_route_t *r =
        brix_cms_route_lookup(XRDCMS_ROLE_MANAGER, code);
    if (r != NULL) {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                       "brix: CMS server: unhandled opcode '%s' from %s",
                       r->name, ctx->host);
    } else {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                       "brix: CMS server: unknown rrCode=%ui from %s",
                       (ngx_uint_t) code, ctx->host);
    }
}

/* Opcode → handler route table.  AVAIL and SPACE share a payload shape and a
 * handler; the NULL sentinel terminates the scan (unmatched codes fall through
 * to cms_srv_frame_unknown). */
static const struct {
    u_char            code;
    cms_srv_frame_pt  handler;
} cms_srv_frame_routes[] = {
    { CMS_RR_LOGIN,  cms_srv_frame_login  },
    { CMS_RR_XAUTH,  cms_srv_frame_xauth  },
    { CMS_RR_LOAD,   cms_srv_frame_load   },
    { CMS_RR_AVAIL,  cms_srv_frame_avail  },
    { CMS_RR_SPACE,  cms_srv_frame_avail  },
    { CMS_RR_PONG,   cms_srv_frame_pong   },
    { CMS_RR_PING,   cms_srv_frame_ping   },
    { CMS_RR_DISC,   cms_srv_frame_disc   },
    { CMS_RR_UPDATE, cms_srv_frame_update },
    { CMS_RR_STATFS, cms_srv_frame_statfs },
    { CMS_RR_GONE,   cms_srv_frame_gone   },
    { CMS_RR_CNS,    cms_srv_frame_cns    },
    { 0,             NULL                 },
};

/*
 * cms_srv_process_frame — route one complete frame by opcode through the
 * table above.  A handler that tears the connection down leaves ctx->c NULL;
 * the read loop checks that after every dispatch.
 */
void
cms_srv_process_frame(brix_cms_srv_ctx_t *ctx, u_char code, uint32_t streamid,
    const u_char *payload, size_t payload_len)
{
    ngx_uint_t  i;

    for (i = 0; cms_srv_frame_routes[i].handler != NULL; i++) {
        if (cms_srv_frame_routes[i].code == code) {
            cms_srv_frame_routes[i].handler(ctx, streamid,
                                            payload, payload_len);
            return;
        }
    }

    cms_srv_frame_unknown(ctx, code);
}
