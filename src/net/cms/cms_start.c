/*
 * cms_start.c — CMS client worker-init: node-role derivation and context start.
 *
 * WHAT: The once-per-worker entry the module calls from config/process.c —
 *       derive this node's cmsd role from (manager_capable, has_upstream),
 *       allocate the CMS context, resolve the cold-start settle profile from
 *       manager locality, and schedule the first connect.
 *
 * WHY:  Split out of connect.c (coding-standards §1, 600-line cap): the steady-
 *       state connect/reconnect/heartbeat event machine and the one-shot
 *       worker-init bring-up are separate concerns with separate lifetimes.
 *       connect.c owns the event handlers; this owns the boot decision.
 */

#include "cms_internal.h"
#include "perf_pgm.h"      /* §2.11: external load feed */
#include "altds.h"         /* §2.12: foreign-DS liveness monitor */
#include "state_relay.h"   /* Phase-61 W7: flush parked kYR_state relays */
#include "action_log.h"                          /* cmsd-action NOTICE lines */
#include "protocols/root/connection/netopt.h"   /* Phase 50: TCP dead-peer opts (WS5) */
#include "core/compat/log_diag.h"
#include "core/compat/lifecycle_timing.h"   /* monotonic clock for settle timing */
#include "observability/sesslog/sesslog_ngx.h"

#include <ngx_event_connect.h>
#include <netinet/in.h>


/* cms_addr_is_loopback — classify the resolved manager address as on-host
 * (127.0.0.0/8 or ::1).  A loopback manager is reached with no network latency, so
 * it gets the most aggressive cold-start settle profile. */
static ngx_uint_t
cms_addr_is_loopback(struct sockaddr *sa)
{
    if (sa == NULL) {
        return 0;
    }

    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) sa;
        return (ntohl(sin->sin_addr.s_addr) & 0xFF000000u) == 0x7F000000u;
    }

#if (NGX_HAVE_INET6)
    if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
        return IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) ? 1 : 0;
    }
#endif

    return 0;
}

/* cms_ctx_create — allocate and arm ONE manager link's heartbeat context:
 * seed the reconnect backoff from cms_interval (capped at
 * NGX_BRIX_CMS_BACKOFF_INITIAL), resolve the cold-start settle profile from
 * THIS manager's locality, seed the disjoint streamid lane (seed = manager
 * index, stride = manager count), and schedule the first connect. */
static ngx_brix_cms_ctx_t *
cms_ctx_create(ngx_cycle_t *cycle, ngx_stream_brix_srv_conf_t *conf,
    brix_cms_manager_ent_t *ent, ngx_uint_t index, ngx_uint_t nmgrs)
{
    ngx_brix_cms_ctx_t  *ctx;

    ctx = ngx_pcalloc(cycle->pool, sizeof(ngx_brix_cms_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->cycle = cycle;
    ctx->conf = conf;
    ctx->mgr_addr = ent->addr;
    ctx->mgr_name = ent->raw;
    ctx->backoff = ngx_min((ngx_msec_t) conf->cms.interval * 1000,
                           (ngx_msec_t) NGX_BRIX_CMS_BACKOFF_INITIAL);
    ctx->in_need = NGX_BRIX_CMS_HDR_LEN;
    ctx->start_ns = brix_phase_now_ns();
    ctx->streamid_seed = (uint32_t) index;
    ctx->streamid_stride = (uint32_t) nmgrs;
    ctx->next_streamid = ctx->streamid_seed;

    /*
     * Resolve the cold-start settle profile once.  A loopback manager (same host)
     * is reached with no network latency, so it gets the most aggressive defaults;
     * an explicit directive overrides the locality default.  The fast-retry interval
     * is floored so a misconfigured "0" can never become a busy connect-storm.
     */
    ctx->is_loopback = cms_addr_is_loopback(ent->addr->sockaddr);

    ctx->fast_retry = (conf->cms.connect_retry != NGX_CONF_UNSET_MSEC)
                      ? conf->cms.connect_retry
                      : (ctx->is_loopback ? NGX_BRIX_CMS_FASTRETRY_LOOPBACK
                                          : NGX_BRIX_CMS_FASTRETRY_REMOTE);
    if (ctx->fast_retry < NGX_BRIX_CMS_FASTRETRY_FLOOR) {
        ctx->fast_retry = NGX_BRIX_CMS_FASTRETRY_FLOOR;
    }
    ctx->fast_window = ctx->is_loopback ? NGX_BRIX_CMS_FASTWIN_LOOPBACK
                                        : NGX_BRIX_CMS_FASTWIN_REMOTE;

    ctx->timer.handler = ngx_brix_cms_timer;
    ctx->timer.data = ctx;
    ctx->timer.log = cycle->log;
    /*
     * The heartbeat re-arms itself every cms_interval (connect.c:194,298).  Mark
     * it cancelable so a draining worker (ngx_exiting after `nginx -s reload`)
     * exits as soon as its connections close, instead of being held alive to the
     * shutdown timeout by the next pending heartbeat.  The cluster keepalive is
     * best-effort; dropping a final tick at teardown is harmless (the reconnect
     * path is already ngx_exiting-guarded).  Matches the io_uring panic timer.
     */
    ctx->timer.cancelable = 1;

    {
        /* First-connect delay: directive override, else the locality default
         * (0 for loopback — connect immediately; the fast-retry handles a miss). */
        ngx_msec_t init_delay = (conf->cms.initial_delay != NGX_CONF_UNSET_MSEC)
            ? conf->cms.initial_delay
            : (ctx->is_loopback ? NGX_BRIX_CMS_INITDELAY_LOOPBACK
                                : NGX_BRIX_CMS_INITDELAY_REMOTE);
        ngx_brix_cms_schedule(ctx, init_delay);
    }

    return ctx;
}

/* ngx_brix_cms_start — worker-init entry point (from config/process.c): start
 * one independent heartbeat link PER configured manager (concurrent logins into
 * every redundant manager, stock ManList parity).  Each worker that runs the
 * client keeps its own connections. */

void
ngx_brix_cms_start(ngx_cycle_t *cycle, ngx_stream_brix_srv_conf_t *conf)
{
    ngx_uint_t               i, nmgrs;
    brix_cms_manager_ent_t  *ents;

    if (conf->cms.managers == NULL || conf->cms.nctxs != 0) {
        return;
    }

    nmgrs = conf->cms.managers->nelts;
    ents = conf->cms.managers->elts;

    conf->cms.ctxs = ngx_pcalloc(cycle->pool,
                                 nmgrs * sizeof(ngx_brix_cms_ctx_t *));
    if (conf->cms.ctxs == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "brix: CMS heartbeat allocation failed");
        return;
    }

    for (i = 0; i < nmgrs; i++) {
        conf->cms.ctxs[i] = cms_ctx_create(cycle, conf, &ents[i], i, nmgrs);
        if (conf->cms.ctxs[i] == NULL) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "brix: CMS heartbeat allocation failed");
            conf->cms.ctxs = NULL;
            conf->cms.nctxs = 0;
            return;
        }
    }

    conf->cms.nctxs = nmgrs;
    conf->cms.rr = 0;

    /* §2.11: external machine-load feed (no-op unless brix_cms_perf_pgm). */
    brix_cms_perf_start(cycle, conf);

    /* §2.12: foreign-data-server liveness monitor (no-op unless
     * brix_cms_altds ... monitor). */
    brix_cms_altds_start(cycle, conf);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "brix: CMS heartbeat starting for manager %V (%ui manager(s))",
                  &conf->cms.manager, nmgrs);
}

/* ngx_brix_cms_pick_ctx — rotate locate/query traffic across the logged-in
 * manager links; see the declaration in cms_internal.h for the contract. */

ngx_brix_cms_ctx_t *
ngx_brix_cms_pick_ctx(ngx_stream_brix_srv_conf_t *conf)
{
    ngx_uint_t           i, start;
    ngx_brix_cms_ctx_t  *ctx;

    if (conf->cms.nctxs == 0) {
        return NULL;
    }

    start = conf->cms.rr++;

    for (i = 0; i < conf->cms.nctxs; i++) {
        ctx = conf->cms.ctxs[(start + i) % conf->cms.nctxs];
        if (ctx->connection != NULL && ctx->logged_in) {
            return ctx;
        }
    }

    return conf->cms.ctxs[start % conf->cms.nctxs];
}

/*
 * CMS auto-role derivation.
 *
 * The role a node plays in the cmsd cluster is derived — not hand-configured —
 * from two facts already present on the merged server conf:
 *
 *   manager_capable  = manager_mode  (set by `brix_manager_mode on`, or
 *                      auto-derived from `brix_cms_server on`; see
 *                      server_module.c: a block that accepts downstream nodes
 *                      IS a manager).
 *   has_upstream     = a `brix_cms_manager host:port` resolved into cms.addr,
 *                      i.e. this node registers UP to a parent manager.
 *
 *   manager_capable & !has_upstream -> MANAGER      (top of the tree)
 *   manager_capable &  has_upstream -> SUB-MANAGER  (accepts downstream AND
 *                                                    registers up + aggregates)
 *  !manager_capable &  has_upstream -> CLIENT       (leaf data server / relay)
 *  !manager_capable & !has_upstream -> NONE         (not a cmsd node)
 */
/*
 * The DERIVED node role, computed here from (manager_capable, has_upstream).
 * Deliberately its own vocabulary — distinct from the operator-declared config
 * role (BRIX_CMS_ROLE_* in conf_structs.h) and the wire-routing role
 * (XRDCMS_ROLE_* / brix_cms_role_t in router.h). Keep this prefix separate so
 * the three role namespaces never collide in a shared translation unit.
 */
typedef enum {
    BRIX_CMS_NODEROLE_NONE = 0,
    BRIX_CMS_NODEROLE_CLIENT,
    BRIX_CMS_NODEROLE_MANAGER,
    BRIX_CMS_NODEROLE_SUBMANAGER
} brix_cms_noderole_t;

static brix_cms_noderole_t
brix_cms_noderole_derive(ngx_flag_t manager_capable, ngx_flag_t has_upstream)
{
    if (manager_capable) {
        return has_upstream ? BRIX_CMS_NODEROLE_SUBMANAGER
                            : BRIX_CMS_NODEROLE_MANAGER;
    }
    return has_upstream ? BRIX_CMS_NODEROLE_CLIENT : BRIX_CMS_NODEROLE_NONE;
}

static const char *
brix_cms_noderole_name(brix_cms_noderole_t role)
{
    switch (role) {
    case BRIX_CMS_NODEROLE_MANAGER:    return "manager";
    case BRIX_CMS_NODEROLE_SUBMANAGER: return "sub-manager";
    case BRIX_CMS_NODEROLE_CLIENT:     return "client";
    default:                       return "none";
    }
}

/*
 * brix_cms_role_worker_init — per-worker CMS bring-up + role proof for ONE
 * server block.  Called for every stream server (process.c), including a
 * dedicated cms-only manager/sub-manager block whose main-module data path is
 * disabled (common.enable off) — that block still owns a cmsd role and, when it
 * has an upstream, an outbound client to start.
 *
 * Two jobs:
 *   1. PROOF-IN-LOGS: emit exactly one NOTICE naming this node's derived role
 *      (manager / sub-manager / client) and how it was derived.  Worker 0 only,
 *      because every worker shares this config and N identical lines help no one.
 *   2. SINGLE UPSTREAM CONNECTION: start the outbound CMS client on WORKER 0
 *      ONLY.  A stock cmsd admits one connection per node identity (SID =
 *      host:listen_port, identical across workers), so N per-worker connections
 *      collide as "already logged in" and get 30s-blacklisted.  Gating the
 *      client to a single worker makes brix register cleanly with a STOCK
 *      upstream cmsd and removes the self-collision entirely.  (Tradeoff: the
 *      §7.1 pending-locate bridge, which needs the client on the worker holding
 *      the suspended session, is unavailable in this single-connection mode —
 *      aggregation, which is what a sub-manager needs, works over one link.)
 */
void
brix_cms_role_worker_init(ngx_cycle_t *cycle, ngx_stream_brix_srv_conf_t *xcf)
{
    brix_cms_noderole_t  role;
    ngx_flag_t           has_upstream;
    ngx_flag_t           manager_capable;

    has_upstream = (xcf->cms.addr != NULL);
    manager_capable = (xcf->manager_mode == 1);
    role = brix_cms_noderole_derive(manager_capable, has_upstream);

    if (role == BRIX_CMS_NODEROLE_NONE) {
        return;
    }

    if (ngx_worker == 0) {
        if (has_upstream) {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "brix: cmsd role: this node is a %s "
                          "(listen :%d, upstream_manager=%V (+%ui more), "
                          "accepts_downstream=%s, aggregates_up=%s)",
                          brix_cms_noderole_name(role), (int) xcf->listen_port,
                          &xcf->cms.manager,
                          xcf->cms.managers->nelts - 1,
                          manager_capable ? "yes" : "no",
                          role == BRIX_CMS_NODEROLE_SUBMANAGER ? "yes" : "no");
        } else {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "brix: cmsd role: this node is a %s "
                          "(listen :%d, upstream_manager=none, "
                          "accepts_downstream=%s, aggregates_up=no)",
                          brix_cms_noderole_name(role), (int) xcf->listen_port,
                          manager_capable ? "yes" : "no");
        }
    }

    /* Single outbound connection: worker 0 only (see the note above). */
    if (has_upstream && ngx_worker == 0) {
        ngx_brix_cms_start(cycle, xcf);
    }
}
