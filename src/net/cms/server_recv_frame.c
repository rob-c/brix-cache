/*
 * cms/server_recv_frame.c — CMS server-side opcode handlers + dispatch table.
 *
 * WHAT: The per-opcode frame handlers for an accepted CMS data-server
 * connection (LOGIN, kYR_xauth, LOAD, AVAIL/SPACE, PONG, PING, DISC, UPDATE,
 * STATFS, USAGE, STATS, STATUS, GONE, CNS, and the unknown-opcode fallback), the
 * login-completion
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
#include "net/manager/loc_cache.h"         /* W3: dynamic file-location cache */
#include "recv_internal.h"                 /* W3: pending-locate client wake */
#include "cns.h"                          /* §6 CNS inventory + event codec */
#include "fanout.h"                       /* W8: fold forwarded-op kYR_error */

/* Ping timer */

/*
 * cms_srv_blfile_tick — enforce the operator blacklist file (Phase-89 W6′).
 *
 * Piggybacked on the per-connection ping cadence (and called with force=1
 * right after a registration) instead of a dedicated timer: the file only
 * matters while data servers are registered, and registered servers are
 * exactly the ones with a live ping timer.  The poll self-rate-limits its
 * stat() to 1/s, so many nodes sharing one srv block stay cheap.  The
 * blacklist duration is 3x the ping interval — always longer than the gap to
 * the next re-assert, so a file-listed server stays down (over undrain and
 * over the register-time blacklist clear) until the line is removed.
 */
static void
cms_srv_blfile_tick(brix_cms_srv_ctx_t *ctx, ngx_uint_t force,
    ngx_log_t *log)
{
    brix_cms_blfile_poll(&ctx->conf->blfile, &ctx->conf->blacklist_file,
                           ctx->interval_ms * 3, force, log);
}

static void
brix_cms_srv_ping_timer(ngx_event_t *ev)
{
    brix_cms_srv_ctx_t  *ctx = ev->data;

    cms_srv_blfile_tick(ctx, 0, ev->log);

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
void
cms_srv_complete_login(brix_cms_srv_ctx_t *ctx)
{
    brix_srv_register(ctx->host, ctx->port, ctx->paths,
                         ctx->free_mb, ctx->util_pct);
    if (ctx->vnid[0] != '\0') {
        brix_srv_set_vnid(ctx->host, ctx->port, ctx->vnid);
    }
    ctx->logged_in = 1;
    cms_srv_log_registration(ctx);

    /* W3: join this worker's fan-out set — locate misses can now probe this
     * node with kYR_state.  Removed again in brix_cms_srv_close. */
    brix_cms_srv_node_add(ctx);

    /* W6′: brix_srv_register just cleared any prior blacklist — re-assert
     * the file immediately so a listed node is never selectable, not even
     * for one poll period. */
    if (ctx->c != NULL) {
        cms_srv_blfile_tick(ctx, 1, ctx->c->log);
    }

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
    { CMS_RR_USAGE,  cms_srv_frame_usage  },
    { CMS_RR_STATS,  cms_srv_frame_stats  },
    { CMS_RR_STATUS, cms_srv_frame_status },
    { CMS_RR_GONE,   cms_srv_frame_gone   },
    { CMS_RR_HAVE,   cms_srv_frame_have   },
    { CMS_RSP_ERROR, cms_srv_frame_error  },   /* W8 fan-out reply fold */
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
