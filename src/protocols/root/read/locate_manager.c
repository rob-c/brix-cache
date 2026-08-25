/*
 * locate_manager.c — kXR_locate manager-mode discovery chain (2026-08-09
 * file-size split of locate.c; behaviour-identical).
 *
 * WHAT: The manager/redirector legs a locate walks in manager_mode — the
 * SUPCount floor hold (§2.2), kXR_refresh cache flush (§2.7), multi-source
 * locate (§89 W5), the collapse-redir cache, the W3 dynamic-location fan-out
 * with stage-aware selection (§2.5), the live-registry select, and the async
 * CMS-parent locate.  Plus the two suspend helpers (cms_parent / dynamic) the
 * chain uses.
 *
 * WHY: locate.c crossed the 600-line ceiling when the parity-wave selection
 * policy landed; the manager chain is the natural, self-contained concern to
 * lift out.  locate.c keeps the orchestrator, path resolution, static-map and
 * data-server legs, and the local-location formatter.
 *
 * HOW: locate_try_manager is the one cross-file entry point (declared in
 * locate_internal.h); the two suspend helpers stay file-local.  Shared
 * per-request state travels in locate_ctx_t.
 */

#include "core/ngx_brix_module.h"
#include "protocols/root/path/op_path.h"
#include "net/manager/registry.h"
#include "net/manager/redir_cache.h"
#include "net/manager/pending.h"
#include "net/manager/loc_cache.h"     /* W3 dynamic location + negative cache */
#include "net/cms/cms_internal.h"
#include "net/cms/server.h"            /* W3: node fan-out set + kYR_state */
#include "locate.h"
#include "locate_internal.h"

/*
 * locate_try_cms_parent — suspend the stream and ask the CMS parent to locate.
 *
 * WHAT: On a registry miss under a configured CMS parent, registers a pending
 *       entry, arms the locate-timeout timer, moves the stream to
 *       XRD_ST_WAITING_CMS, and sends a kYR_locate upstream.
 * WHY:  CMS-backed discovery is asynchronous — the reply arrives on a later event
 *       and resumes the suspended stream, so this leg returns NGX_AGAIN.
 * HOW:  Returns 1 with *out_rc = NGX_AGAIN when the suspend succeeded; returns 0
 *       (unwinding pending/timer/state on send failure) so the caller falls
 *       through to the static map / notFound path, exactly as the original.
 */
static int
locate_try_cms_parent(locate_ctx_t *lc, ngx_int_t *out_rc)
{
    if (brix_cms_locate_park(lc->ctx, lc->c, lc->conf, lc->reqpath)
        != NGX_OK)
    {
        return 0;
    }
    *out_rc = NGX_AGAIN;
    return 1;
}

/* The shared implementation behind locate_try_cms_parent — also the CMS leg
 * of the stat and query-checksum manager paths (locate.h has the contract). */
ngx_int_t
brix_cms_locate_park(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *path)
{
    ngx_brix_cms_ctx_t *cms;
    uint32_t            streamid;

    if (conf->cms.nctxs == 0) {
        return NGX_DECLINED;
    }
    cms = ngx_brix_cms_pick_ctx(conf);
    if (cms == NULL) {
        return NGX_DECLINED;
    }

    streamid = ngx_brix_cms_next_streamid(cms);
    if (brix_pending_insert(streamid, ngx_pid, c->fd, c->number,
                              ctx->recv.cur_streamid,
                              conf->cms.locate_timeout) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    ctx->cms_wait_streamid = streamid;
    ctx->state = XRD_ST_WAITING_CMS;
    ngx_add_timer(c->read, conf->cms.locate_timeout);
    if (ngx_brix_cms_send_locate(cms, streamid, path) == NGX_OK) {
        return NGX_OK;
    }

    ngx_del_timer(c->read);
    ctx->state = XRD_ST_REQ_HEADER;
    brix_pending_remove(streamid, ngx_pid);
    return NGX_DECLINED;
}

/*
 * locate_try_loc_cache — answer a locate straight from the location cache.
 *
 * WHAT: returns 1 with *out_rc set when the cache already knows the answer
 *       (positive hit, or a negative that resolves to a stage target or a
 *       NotFound); returns 0 when the caller must fan out.
 *
 * WHY:  §2.6 — a live negative entry proves a recent fan-out found no holder,
 *       so answering now beats re-parking the client through another full
 *       window.  §2.5 — on a stage-aware cluster "no holder" means "needs a
 *       recall", so the roomiest stage-capable node wins over a NotFound.
 *
 * HOW:  1. look the path up once; a HIT redirects at the cached endpoint.
 *       2. a NEG tries stage selection first, then answers kXR_NotFound.
 *       3. anything else (miss) leaves the caller to probe the cluster.
 */
static int
locate_try_loc_cache(locate_ctx_t *lc, ngx_int_t *out_rc)
{
    brix_ctx_t                  *ctx = lc->ctx;
    ngx_connection_t            *c = lc->c;
    char                         redir_host[256];
    uint16_t                     redir_port;
    int                          loc;

    loc = brix_loc_cache_lookup2(lc->reqpath, redir_host,
                                   sizeof(redir_host), &redir_port);
    if (loc == BRIX_LOC_HIT) {
        brix_log_access(ctx, c, "LOCATE", lc->reqpath, "loc-cache",
                          1, 0, NULL, 0);
        BRIX_OP_OK(ctx, BRIX_OP_LOCATE);
        *out_rc = brix_send_redirect(ctx, c, redir_host, redir_port);
        return 1;
    }

    if (loc != BRIX_LOC_NEG) {
        return 0;
    }

    if (lc->conf->cms.stage_select
        && brix_srv_select_stage(lc->reqpath, redir_host,
                                   sizeof(redir_host), &redir_port))
    {
        brix_log_access(ctx, c, "LOCATE", lc->reqpath,
                          "stage-select", 1, 0, NULL, 0);
        BRIX_OP_OK(ctx, BRIX_OP_LOCATE);
        *out_rc = brix_send_redirect(ctx, c, redir_host, redir_port);
        return 1;
    }

    brix_log_access(ctx, c, "LOCATE", lc->reqpath, "-",
                      0, kXR_NotFound, "no holder (cached)", 0);
    BRIX_OP_ERR(ctx, BRIX_OP_LOCATE);
    *out_rc = brix_send_error(ctx, c, kXR_NotFound, "file not found");
    return 1;
}


/*
 * locate_fanout_state — probe the logged-in nodes that could hold the path.
 *
 * WHAT: sends kYR_state carrying `streamid` to at most cms_state_fanout
 *       eligible nodes; returns how many probes actually went out.
 *
 * WHY:  the fan-out is capped and filtered so one locate cannot storm the
 *       whole cluster, and a blacklisted or path-mismatched node is never
 *       asked — a reply from one would name a server the client must not use.
 *
 * HOW:  walk the node table until the cap is reached, skipping nodes that are
 *       not logged in, do not export a covering prefix, or are blacklisted.
 */
static ngx_uint_t
locate_fanout_state(locate_ctx_t *lc, uint32_t streamid)
{
    brix_cms_srv_ctx_t  *node;
    ngx_uint_t           i, sent = 0;

    for (i = 0; i < brix_cms_srv_node_count()
                && sent < lc->conf->caps.cms_state_fanout; i++)
    {
        node = brix_cms_srv_node_at(i);
        if (node == NULL || !node->logged_in
            || !brix_srv_paths_cover(node->paths, lc->reqpath)
            || brix_srv_is_blacklisted(node->host, node->port))
        {
            continue;
        }
        if (brix_cms_srv_send_state(node, streamid, lc->reqpath) == NGX_OK) {
            sent++;
        }
    }

    return sent;
}


/*
 * locate_try_dynamic — Phase-89 W3: file-granular location via the loc cache
 * and, on a miss, an on-demand kYR_state fan-out to this worker's nodes.
 *
 * WHAT: With brix_cms_locate_window > 0, first consults the SHM loc cache
 *       (path → node that answered kYR_have recently); on a hit, redirects.
 *       On a miss, sends kYR_state to up to cms_state_fanout logged-in node
 *       connections whose export prefixes cover the path, parks the client
 *       (pending table + XRD_ST_WAITING_CMS) for the window, and lets the
 *       first kYR_have win (cms_srv_frame_have wakes the client).
 * WHY:  Prefix registration cannot know which node HOLDS a file — every node
 *       exporting "/" matches every path.  This is stock cmsd's on-demand
 *       existence query, scoped per-worker (cross-worker fan-out is the PR-8
 *       aggregation plane).
 * HOW:  Returns 1 with the terminal result in *out_rc (redirect, or NGX_AGAIN
 *       after a successful park); returns 0 — unwinding the pending entry —
 *       when the flag is off or no node could be probed, so the caller falls
 *       through to registry prefix selection exactly as before.  Window
 *       expiry reuses the shared XRD_ST_WAITING_CMS timeout (kXR_wait 5).
 */
static int
locate_try_dynamic(locate_ctx_t *lc, ngx_int_t *out_rc)
{
    brix_ctx_t                  *ctx = lc->ctx;
    ngx_connection_t            *c = lc->c;
    ngx_stream_brix_srv_conf_t  *conf = lc->conf;
    uint32_t                     streamid;
    ngx_uint_t                   sent;

    if (conf->caps.cms_locate_window == 0) {
        return 0;
    }

    /* §2.8: a shared-filesystem cluster (cms.dfs) holds every file on every
     * node — the per-file existence probe is pure overhead.  Fall straight
     * through to load-based prefix selection. */
    if (conf->cms.dfs) {
        return 0;
    }

    /* §2.7: a kXR_refresh locate must observe the cluster, not the cache. */
    if (!lc->refresh && locate_try_loc_cache(lc, out_rc)) {
        return 1;
    }

    /* Park BEFORE probing (mirrors locate_try_cms_parent): the pending entry
     * must exist when the first kYR_have echoes our streamid back. */
    streamid = brix_cms_srv_next_streamid();
    if (brix_pending_insert(streamid, ngx_pid, c->fd, c->number,
                              ctx->recv.cur_streamid,
                              conf->caps.cms_locate_window) != NGX_OK)
    {
        return 0;
    }

    /* §2.6: remember what this fan-out asked, so a window that expires with
     * no kYR_have can record a negative location entry. */
    brix_pending_set_path(streamid, ngx_pid, lc->reqpath);

    sent = locate_fanout_state(lc, streamid);
    if (sent == 0) {
        brix_pending_remove(streamid, ngx_pid);
        return 0;    /* no probe-able node in this worker — fall through */
    }

    ctx->cms_wait_streamid = streamid;
    ctx->state = XRD_ST_WAITING_CMS;
    ngx_add_timer(c->read, conf->caps.cms_locate_window);
    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: W3 locate: kYR_state fan-out to %ui nodes for %s",
                   sent, lc->reqpath);
    *out_rc = NGX_AGAIN;
    return 1;
}

/*
 * locate_try_floor_hold — §2.2 (cms.delay servers).
 *
 * WHAT: returns 1 with a kXR_wait reply while fewer data servers than the
 *       configured floor are registered.
 * WHY:  redirecting the whole grid onto a half-formed cluster's first node
 *       melts that node; holding costs one round trip and protects it.
 * HOW:  ask the registry whether it is below the floor, then wait delay_hold.
 */
static int
locate_try_floor_hold(locate_ctx_t *lc, ngx_int_t *out_rc)
{
    if (!brix_srv_below_floor()) {
        return 0;
    }

    brix_log_access(lc->ctx, lc->c, "LOCATE", lc->reqpath, "floor-hold",
                      1, 0, NULL, 0);
    BRIX_OP_OK(lc->ctx, BRIX_OP_LOCATE);
    *out_rc = brix_send_wait(lc->ctx, lc->c,
                               (unsigned) lc->conf->cms.delay_hold);
    return 1;
}


/*
 * locate_try_multi — Phase-89 W5 multi-source locate.
 *
 * WHAT: returns 1 having answered with the FULL live server set
 *       ("S<r|w>host:port" entries, kXR_ok) so the client picks by locality
 *       (lateral redirect) instead of following a single kXR_redirect.
 * WHY:  placed before the single-entry collapse cache, which cannot represent
 *       a set.  Only live (non-blacklisted, host-validated at registration)
 *       entries can appear; an empty set falls through to the single-select /
 *       CMS legs.
 * HOW:  render the set into a bounded buffer; a zero-length render is a miss.
 */
static int
locate_try_multi(locate_ctx_t *lc, ngx_int_t *out_rc)
{
    char  list_buf[2048];
    int   list_len;

    if (!lc->conf->cms.locate_multi) {
        return 0;
    }

    list_len = brix_srv_locate_all(lc->reqpath, 0, list_buf, sizeof(list_buf));
    if (list_len <= 0) {
        return 0;
    }

    brix_log_access(lc->ctx, lc->c, "LOCATE", lc->reqpath, "registry-multi",
                      1, 0, NULL, 0);
    BRIX_OP_OK(lc->ctx, BRIX_OP_LOCATE);
    *out_rc = brix_send_ok(lc->ctx, lc->c, list_buf,
                             (uint32_t) (list_len + 1));
    return 1;
}


/*
 * locate_try_redir_cache — collapse-redir fast path.
 *
 * WHAT: returns 1 having redirected to the single recently-resolved server.
 * WHY:  cheapest leg in the chain, so it runs before any registry scan.
 *       Skipped on kXR_refresh (§2.7 — the cache was flushed for this request
 *       and must not be re-read, or the flush would be pointless).
 * HOW:  one bounded cache lookup, then a redirect at the cached endpoint.
 */
static int
locate_try_redir_cache(locate_ctx_t *lc, ngx_int_t *out_rc)
{
    char      redir_host[256];
    uint16_t  redir_port;

    if (lc->refresh || !lc->conf->caps.collapse_redir
        || !brix_redir_cache_lookup(lc->reqpath, redir_host,
                                      sizeof(redir_host), &redir_port))
    {
        return 0;
    }

    brix_log_access(lc->ctx, lc->c, "LOCATE", lc->reqpath, "redir-cache",
                      1, 0, NULL, 0);
    BRIX_OP_OK(lc->ctx, BRIX_OP_LOCATE);
    *out_rc = brix_send_redirect(lc->ctx, lc->c, redir_host, redir_port);
    return 1;
}


/*
 * locate_try_stage_select — §2.5 stage-aware selection.
 *
 * WHAT: returns 1 having redirected to the roomiest stage-capable node.
 * WHY:  the holder plane (loc cache / kYR_have) came up empty, so a read of
 *       this file needs a RECALL — and the recall is a write, so room matters
 *       more than utilisation.  Only when some node advertised staging, and
 *       never on a shared filesystem where every node already holds the file.
 * HOW:  gate on the two config knobs, then ask the registry for a stage node.
 */
static int
locate_try_stage_select(locate_ctx_t *lc, ngx_int_t *out_rc)
{
    char      redir_host[256];
    uint16_t  redir_port;

    if (!lc->conf->cms.stage_select || lc->conf->cms.dfs
        || !brix_srv_select_stage(lc->reqpath, redir_host,
                                    sizeof(redir_host), &redir_port))
    {
        return 0;
    }

    brix_log_access(lc->ctx, lc->c, "LOCATE", lc->reqpath, "stage-select",
                      1, 0, NULL, 0);
    BRIX_OP_OK(lc->ctx, BRIX_OP_LOCATE);
    *out_rc = brix_send_redirect(lc->ctx, lc->c, redir_host, redir_port);
    return 1;
}


/*
 * locate_try_registry — best available server for this path.
 *
 * WHAT: returns 1 having redirected to the registry's pick, seeding the
 *       collapse cache on the way out.
 * WHY:  the cache is seeded here and only here, so every entry in it came from
 *       a real selection rather than from a leg that bypassed load scoring.
 * HOW:  select, insert into the collapse cache when enabled, redirect.
 */
static int
locate_try_registry(locate_ctx_t *lc, ngx_int_t *out_rc)
{
    char      redir_host[256];
    uint16_t  redir_port;

    if (!brix_srv_select(lc->reqpath, 0, redir_host,
                           sizeof(redir_host), &redir_port))
    {
        return 0;
    }

    if (lc->conf->caps.collapse_redir) {
        brix_redir_cache_insert(lc->reqpath, redir_host, redir_port,
                                  lc->conf->caps.collapse_redir_ttl);
    }
    brix_log_access(lc->ctx, lc->c, "LOCATE", lc->reqpath, "registry",
                      1, 0, NULL, 0);
    BRIX_OP_OK(lc->ctx, BRIX_OP_LOCATE);
    *out_rc = brix_send_redirect(lc->ctx, lc->c, redir_host, redir_port);
    return 1;
}


/*
 * locate_try_parent_leg — registry miss: ask the CMS parent via kYR_locate.
 *
 * WHAT: returns 1 when the stream suspended awaiting the parent's answer.
 * WHY:  gives the leg table the same shape as every other entry — the
 *       "is there a parent at all" test belongs with the leg, not in the
 *       driver.
 * HOW:  skip when no CMS context is configured, else delegate.
 */
static int
locate_try_parent_leg(locate_ctx_t *lc, ngx_int_t *out_rc)
{
    if (lc->conf->cms.nctxs == 0) {
        return 0;
    }

    return locate_try_cms_parent(lc, out_rc);
}


/*
 * The manager discovery chain, in the order it must run: cheapest cache first,
 * the async CMS round-trip last (coding-standards §8.6 — a new leg is a row,
 * not another branch).  Each leg returns 1 when it produced a terminal result.
 */
static int (*const locate_manager_legs[])(locate_ctx_t *, ngx_int_t *) = {
    locate_try_floor_hold,
    locate_try_multi,
    locate_try_redir_cache,
    locate_try_dynamic,
    locate_try_stage_select,
    locate_try_registry,
    locate_try_parent_leg,
};


/*
 * locate_try_manager — resolve a path via the manager-mode discovery chain.
 *
 * WHAT: In manager_mode (non-wildcard), runs locate_manager_legs in order:
 *       floor hold, multi-source locate, the collapse-redir cache, the W3
 *       dynamic-location leg (loc cache / kYR_state fan-out, only when
 *       brix_cms_locate_window > 0), stage selection, the live server registry
 *       (seeding the cache on hit), then the async CMS parent leg.
 * WHY:  Manager nodes hold no data; they redirect clients to the best serving
 *       endpoint. Ordering the cheap cache before the registry before the async
 *       CMS round-trip minimises latency.
 * HOW:  Returns 1 when a leg produced a terminal result (redirect reply stored
 *       through *out_rc, or NGX_AGAIN from the CMS suspend); returns 0 to fall
 *       through to the static-map path.
 */
int
locate_try_manager(locate_ctx_t *lc, ngx_int_t *out_rc)
{
    size_t  n;

    if (!lc->conf->manager_mode || lc->is_wildcard) {
        return 0;
    }

    /* §2.7: kXR_refresh flushes both location caches up front so the fall-
     * through legs (and the NEXT non-refresh request) re-resolve. */
    if (lc->refresh) {
        brix_loc_cache_invalidate(lc->reqpath);
        brix_redir_cache_invalidate(lc->reqpath);
    }

    for (n = 0; n < sizeof(locate_manager_legs)
                    / sizeof(locate_manager_legs[0]); n++) {
        if (locate_manager_legs[n](lc, out_rc)) {
            return 1;
        }
    }

    /* Fall through to static-map / notFound if suspend fails or no CMS. */
    return 0;
}

