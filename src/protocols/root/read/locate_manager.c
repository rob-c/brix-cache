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
    brix_ctx_t                  *ctx = lc->ctx;
    ngx_connection_t            *c = lc->c;
    ngx_stream_brix_srv_conf_t  *conf = lc->conf;
    ngx_brix_cms_ctx_t          *cms = ngx_brix_cms_pick_ctx(conf);
    uint32_t                     streamid;

    if (cms == NULL) {
        return 0;
    }

    streamid = ngx_brix_cms_next_streamid(cms);
    if (brix_pending_insert(streamid, ngx_pid, c->fd, c->number,
                              ctx->recv.cur_streamid,
                              conf->cms.locate_timeout) != NGX_OK)
    {
        return 0;
    }

    ctx->cms_wait_streamid = streamid;
    ctx->state = XRD_ST_WAITING_CMS;
    ngx_add_timer(c->read, conf->cms.locate_timeout);
    if (ngx_brix_cms_send_locate(cms, streamid, lc->reqpath) == NGX_OK)
    {
        *out_rc = NGX_AGAIN;
        return 1;
    }

    ngx_del_timer(c->read);
    ctx->state = XRD_ST_REQ_HEADER;
    brix_pending_remove(streamid, ngx_pid);
    return 0;
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
    char                         redir_host[256];
    uint16_t                     redir_port;
    uint32_t                     streamid;
    ngx_uint_t                   i, sent;
    brix_cms_srv_ctx_t          *node;

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
    if (!lc->refresh) {
        int loc = brix_loc_cache_lookup2(lc->reqpath, redir_host,
                                           sizeof(redir_host), &redir_port);
        if (loc == BRIX_LOC_HIT) {
            brix_log_access(ctx, c, "LOCATE", lc->reqpath, "loc-cache",
                              1, 0, NULL, 0);
            BRIX_OP_OK(ctx, BRIX_OP_LOCATE);
            *out_rc = brix_send_redirect(ctx, c, redir_host, redir_port);
            return 1;
        }
        /* §2.6: a live negative entry proves a recent fan-out found no
         * holder — answer immediately instead of re-parking the client
         * through another full window.  §2.5: on a stage-aware cluster
         * "no holder" means "needs a recall", so the roomiest stage-capable
         * node wins over a NotFound. */
        if (loc == BRIX_LOC_NEG) {
            if (conf->cms.stage_select
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
            *out_rc = brix_send_error(ctx, c, kXR_NotFound,
                                        "file not found");
            return 1;
        }
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

    sent = 0;
    for (i = 0; i < brix_cms_srv_node_count()
                && sent < conf->caps.cms_state_fanout; i++)
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
 * locate_try_manager — resolve a path via the manager-mode discovery chain.
 *
 * WHAT: In manager_mode (non-wildcard), tries in order: the collapse-redir cache,
 *       the W3 dynamic-location leg (loc cache / kYR_state fan-out, only when
 *       brix_cms_locate_window > 0), the live server registry (seeding the
 *       cache on hit), then the async CMS parent leg.
 * WHY:  Manager nodes hold no data; they redirect clients to the best serving
 *       endpoint. Ordering the cheap cache before the registry before the async
 *       CMS round-trip minimises latency.
 * HOW:  Returns 1 when a leg produced a terminal result (redirect reply stored
 *       through *out_rc, or NGX_AGAIN from the CMS suspend); returns 0 to fall
 *       through to the static-map path. Behaviour is byte-identical to inline.
 */
int
locate_try_manager(locate_ctx_t *lc, ngx_int_t *out_rc)
{
    brix_ctx_t                  *ctx = lc->ctx;
    ngx_connection_t            *c = lc->c;
    ngx_stream_brix_srv_conf_t  *conf = lc->conf;
    char                         redir_host[256];
    uint16_t                     redir_port;
    char                         list_buf[2048];
    int                          list_len;

    if (!conf->manager_mode || lc->is_wildcard) {
        return 0;
    }

    /* §2.2 (cms.delay servers): while fewer data servers than the configured
     * floor are registered, hold every select with kXR_wait — redirecting the
     * whole grid onto a half-formed cluster's first node melts that node. */
    if (brix_srv_below_floor()) {
        brix_log_access(ctx, c, "LOCATE", lc->reqpath, "floor-hold",
                          1, 0, NULL, 0);
        BRIX_OP_OK(ctx, BRIX_OP_LOCATE);
        *out_rc = brix_send_wait(ctx, c, (unsigned) conf->cms.delay_hold);
        return 1;
    }

    /* §2.7: kXR_refresh flushes both location caches up front so the fall-
     * through legs (and the NEXT non-refresh request) re-resolve. */
    if (lc->refresh) {
        brix_loc_cache_invalidate(lc->reqpath);
        brix_redir_cache_invalidate(lc->reqpath);
    }

    /* Phase-89 W5: multi-source locate — answer with the FULL live server set
     * ("S<r|w>host:port" entries, kXR_ok) so the client picks by locality
     * (lateral redirect) instead of following a single kXR_redirect.  Placed
     * before the single-entry collapse cache, which cannot represent a set.
     * Only live (non-blacklisted, host-validated at registration) entries can
     * appear; an empty set falls through to the single-select / CMS legs. */
    if (conf->cms.locate_multi) {
        list_len = brix_srv_locate_all(lc->reqpath, 0, list_buf,
                                         sizeof(list_buf));
        if (list_len > 0) {
            brix_log_access(ctx, c, "LOCATE", lc->reqpath, "registry-multi",
                              1, 0, NULL, 0);
            BRIX_OP_OK(ctx, BRIX_OP_LOCATE);
            *out_rc = brix_send_ok(ctx, c, list_buf,
                                     (uint32_t) (list_len + 1));
            return 1;
        }
    }

    /* Collapse-redir cache: fast path — single recently-resolved server.
     * Skipped on kXR_refresh (§2.7 — flushed above, must not be re-read). */
    if (!lc->refresh && conf->caps.collapse_redir
        && brix_redir_cache_lookup(lc->reqpath, redir_host,
                                     sizeof(redir_host), &redir_port))
    {
        brix_log_access(ctx, c, "LOCATE", lc->reqpath, "redir-cache",
                          1, 0, NULL, 0);
        BRIX_OP_OK(ctx, BRIX_OP_LOCATE);
        *out_rc = brix_send_redirect(ctx, c, redir_host, redir_port);
        return 1;
    }

    /* W3 dynamic location: loc-cache hit or kYR_state fan-out + park.
     * Off (brix_cms_locate_window 0, the default) => zero behavior change. */
    if (locate_try_dynamic(lc, out_rc)) {
        return 1;
    }

    /* §2.5: stage-aware selection — the holder plane (loc cache / kYR_have)
     * came up empty, so a read of this file needs a RECALL: route to the
     * roomiest stage-capable node (the recall is a write) instead of the
     * least-utilised one.  Only when some node advertised staging. */
    if (conf->cms.stage_select && !conf->cms.dfs
        && brix_srv_select_stage(lc->reqpath, redir_host,
                                   sizeof(redir_host), &redir_port))
    {
        brix_log_access(ctx, c, "LOCATE", lc->reqpath, "stage-select",
                          1, 0, NULL, 0);
        BRIX_OP_OK(ctx, BRIX_OP_LOCATE);
        *out_rc = brix_send_redirect(ctx, c, redir_host, redir_port);
        return 1;
    }

    /* Registry: redirect to the best available server for this path. */
    if (brix_srv_select(lc->reqpath, 0, redir_host,
                          sizeof(redir_host), &redir_port))
    {
        if (conf->caps.collapse_redir) {
            brix_redir_cache_insert(lc->reqpath, redir_host, redir_port,
                                      conf->caps.collapse_redir_ttl);
        }
        brix_log_access(ctx, c, "LOCATE", lc->reqpath, "registry",
                          1, 0, NULL, 0);
        BRIX_OP_OK(ctx, BRIX_OP_LOCATE);
        *out_rc = brix_send_redirect(ctx, c, redir_host, redir_port);
        return 1;
    }

    /* Registry miss — ask the CMS parent via kYR_locate. */
    if (conf->cms.nctxs > 0 && locate_try_cms_parent(lc, out_rc)) {
        return 1;
    }

    /* Fall through to static-map / notFound if suspend fails or no CMS. */
    return 0;
}

