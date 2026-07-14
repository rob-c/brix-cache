/*
 * http_mirror.c — Phase 24 HTTP/WebDAV traffic mirror (see http_mirror.h).
 *
 * WHAT: Replays qualifying read requests to one or more shadow HTTP(S) backends
 * fire-and-forget, compares the shadow status to the primary, and counts
 * divergence — without ever delaying or exposing the shadow path to the client.
 *
 * HOW: A PRECONTENT-phase handler on the MAIN request fires one background
 * subrequest per shadow target (re-using the same location so the mirror config
 * is in scope).  Each subrequest is tagged is_mirror in its WebDAV request ctx;
 * the WebDAV access/content handlers skip those, and a CONTENT-phase handler
 * registered ahead of the WebDAV handler takes the subrequest over and proxies
 * it to the shadow with credentials stripped (unless an explicit mirror token is
 * configured).  The shadow response is parsed with the same upstream-callback
 * pattern as src/webdav/proxy_response.c but writes into a scratch status field
 * in the request ctx; finalize compares status classes and updates metrics.  A
 * LOG-phase handler stamps the primary's final status for that comparison.
 *
 * Split (phase-79 file-size cap) into three focused files:
 *   http_mirror.c         — this file: method classifiers + phase-handler /
 *                           subrequest orchestration (precontent/log handlers)
 *   http_mirror_request.c — shadow HTTP request/response build + the nginx
 *                           upstream callbacks it wires
 *   http_mirror_config.c  — merge-time upstream setup + directive setters
 * Cross-file symbols (the body-method predicate and the five upstream callbacks)
 * plus the shared MIR_HTTP_INC macro live in http_mirror_internal.h.
 */
#include "http_mirror.h"
#include "http_mirror_internal.h"
#include "core/http/http_body.h"
#include "core/http/http_headers.h"


/* method filter */
static ngx_uint_t
brix_http_mirror_method_bit(ngx_http_request_t *r)
{
    switch (r->method) {
    case NGX_HTTP_GET:      return BRIX_MIRROR_M_GET;
    case NGX_HTTP_HEAD:     return BRIX_MIRROR_M_HEAD;
    case NGX_HTTP_PROPFIND: return BRIX_MIRROR_M_PROPFIND;
    case NGX_HTTP_OPTIONS:  return BRIX_MIRROR_M_OPTIONS;
    /* Write methods (Phase 24 write mirroring; gated by brix_mirror_writes). */
    case NGX_HTTP_PUT:      return BRIX_MIRROR_M_PUT;
    case NGX_HTTP_DELETE:   return BRIX_MIRROR_M_DELETE;
    case NGX_HTTP_MKCOL:    return BRIX_MIRROR_M_MKCOL;
    case NGX_HTTP_MOVE:     return BRIX_MIRROR_M_MOVE;
    case NGX_HTTP_COPY:     return BRIX_MIRROR_M_COPY;
    default:                return 0;
    }
}

/* Methods that carry a request body the shadow must receive (PUT).  Non-static:
 * also used by the request builder in http_mirror_request.c (see
 * http_mirror_internal.h). */
ngx_int_t
brix_http_mirror_method_has_body(ngx_uint_t method)
{
    return method == NGX_HTTP_PUT;
}


/* mirror subrequest execution (CONTENT phase) */
static ngx_int_t
brix_http_mirror_proxy(ngx_http_request_t *r,
    ngx_http_brix_webdav_req_ctx_t *ctx)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    ngx_http_upstream_t               *u;
    brix_mirror_target_t            *t;
    struct sockaddr                   *sa;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    if (conf->mirror.targets == NULL
        || ctx->mirror_target_idx >= conf->mirror.targets->nelts)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    t = (brix_mirror_target_t *) conf->mirror.targets->elts
      + ctx->mirror_target_idx;

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    u = r->upstream;

    u->conf      = &conf->mirror_upstream_conf;
    u->buffering = 0;

    u->create_request   = mirror_create_request;
    u->reinit_request   = mirror_reinit_request;
    u->process_header   = mirror_process_status_line;
    u->abort_request    = mirror_abort_request;
    u->finalize_request = mirror_finalize_request;

    sa = ngx_palloc(r->pool, t->socklen);
    u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (sa == NULL || u->resolved == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(sa, &t->sockaddr, t->socklen);
    u->resolved->sockaddr = sa;
    u->resolved->socklen  = t->socklen;
    u->resolved->naddrs   = 1;
    u->resolved->host     = t->host;
    u->resolved->port     = t->port;

#if (NGX_HTTP_SSL)
    if (t->ssl) {
        u->ssl = 1;
    }
#endif

    /* Drive the shadow connection.  This is a background subrequest, so its
     * count (taken by ngx_http_subrequest) keeps the request alive until the
     * upstream finalizes; ngx_http_upstream_init runs the connect→send→read. */
    ngx_http_upstream_init(r);
    return NGX_DONE;
}

/* Fire one background subrequest per shadow target.  ctx (main) is already set
 * and ctx->mirror_fired marked by the caller.  Each subrequest is tagged
 * is_mirror so the precontent handler takes it over and proxies it. */
static void
mirror_fire_subrequests(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_uint_t  i;

    for (i = 0; i < conf->mirror.targets->nelts; i++) {
        ngx_http_brix_webdav_req_ctx_t *sctx;
        ngx_http_request_t               *sr;

        sctx = ngx_pcalloc(r->pool, sizeof(*sctx));
        if (sctx == NULL) { continue; }
        sctx->is_mirror         = 1;
        sctx->mirror_target_idx = i;

        if (ngx_http_subrequest(r, &r->uri, &r->args, &sr, NULL,
                                NGX_HTTP_SUBREQUEST_BACKGROUND) != NGX_OK)
        {
            continue;
        }
        ngx_http_set_ctx(sr, sctx, ngx_http_brix_webdav_module);
        sr->method      = r->method;
        sr->method_name = r->method_name;
        sr->header_only = 1;   /* discard shadow response body */
    }
}

/*
 * Request-body completion handler for body-bearing mirrored methods (PUT).
 * Modelled on stock ngx_http_mirror_module: read the body first (in PRECONTENT),
 * then fire the shadow subrequests (which clone the now-available body) and resume
 * the main request's phase processing so its own content handler runs normally.
 */
static void
mirror_put_body_handler(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    /* Keep the buffered body alive: the shadow subrequest sends a cloned chain
     * over the same memory/temp-file while the primary PUT handler also reads it. */
    r->preserve_body = 1;
    mirror_fire_subrequests(r, conf);

    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);
}

/* PRECONTENT handler * Two jobs: on the MAIN request, fire one background subrequest per shadow
 * target; on a mirror SUBREQUEST, take it over and proxy it to the shadow.
 * Doing the takeover here (before the content phase) avoids any dependence on
 * content-phase handler ordering. */

/*
 * WHAT: true if the request carries an X-Xrootd-Mirror loop-guard header.
 * WHY: a shadow pointed back at this server would otherwise mirror the replay
 * again; mirror_create_request stamps this header, so its presence means "do not
 * re-mirror".
 * HOW: linear scan of the parsed request headers, case-insensitive key compare;
 * pure query, no side effects.
 */
static int
mirror_request_is_replay(ngx_http_request_t *r)
{
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *hdr  = part->elts;
    ngx_uint_t       k;

    for (k = 0; /* void */; k++) {
        if (k >= part->nelts) {
            if (part->next == NULL) { break; }
            part = part->next;
            hdr  = part->elts;
            k    = 0;
        }
        if (hdr[k].key.len == sizeof("X-Xrootd-Mirror") - 1
            && ngx_strncasecmp(hdr[k].key.data,
                   (u_char *) "X-Xrootd-Mirror",
                   sizeof("X-Xrootd-Mirror") - 1) == 0)
        {
            return 1;
        }
    }
    return 0;
}

/*
 * WHAT: decide whether the MAIN request qualifies to be mirrored this pass.
 * WHY: consolidates every eligibility gate (enabled, already-fired, method mask,
 * write-guard, loop-guard replay, sampling) so the handler is pure dispatch and
 * each gate is reviewable in one place.
 * HOW: returns 1 (fire) or 0 (decline).  ctx may be NULL (never fired).  The
 * sampling gate has the side effect of counting a dropped request — kept here to
 * preserve the original ordering and metric behaviour exactly.
 */
static int
mirror_precontent_eligible(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_req_ctx_t *ctx)
{
    ngx_uint_t  mbit;

    if (!conf->mirror.enabled || conf->mirror.targets == NULL) {
        return 0;
    }
    if (ctx != NULL && ctx->mirror_fired) {
        return 0;   /* idempotent: fire once per request */
    }

    mbit = brix_http_mirror_method_bit(r);
    if ((mbit & conf->mirror.method_mask) == 0) {
        return 0;
    }
    /* Write methods only mirror when brix_mirror_writes is on — a second,
     * independent guard beyond the method mask.  The shadow must be an isolated
     * namespace (replaying writes onto the primary's store would corrupt it). */
    if ((mbit & BRIX_MIRROR_M_WRITE_ALL) && !conf->mirror.mirror_writes) {
        return 0;
    }
    /* Loop guard: never mirror a request that is itself a mirror replay (set by
     * mirror_create_request) — protects against a shadow pointed at this server. */
    if (mirror_request_is_replay(r)) {
        return 0;
    }
    if (!brix_mirror_should_sample(conf->mirror.sample_pct)) {
        MIR_HTTP_INC(mirror_http_dropped_total);
        return 0;
    }
    return 1;
}

ngx_int_t
brix_http_mirror_precontent_handler(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    ngx_http_brix_webdav_req_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    if (r != r->main) {
        if (ctx != NULL && ctx->is_mirror) {
            return brix_http_mirror_proxy(r, ctx);   /* take over the shadow req */
        }
        return NGX_DECLINED;   /* some other subrequest — ignore */
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    if (!mirror_precontent_eligible(r, conf, ctx)) {
        return NGX_DECLINED;
    }

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) { return NGX_DECLINED; }
        ngx_http_set_ctx(r, ctx, ngx_http_brix_webdav_module);
    }
    ctx->mirror_fired = 1;

    /* Body-bearing methods (PUT): read the request body first so the shadow
     * subrequest can forward a clone of it, then fire from the body handler and
     * resume phase processing.  NGX_DONE suspends the main request until the body
     * is buffered — it is not exposed to the client and the client is not delayed
     * beyond its own normal body read. */
    if (brix_http_mirror_method_has_body(r->method)) {
        ngx_int_t rc;

        r->preserve_body = 1;
        rc = ngx_http_read_client_request_body(r, mirror_put_body_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        return NGX_DONE;
    }

    /* Bodyless methods (GET/HEAD/PROPFIND/OPTIONS/DELETE/MKCOL/MOVE/COPY): fire
     * immediately and let the content handler proceed. */
    mirror_fire_subrequests(r, conf);
    return NGX_DECLINED;   /* main request continues to its content handler */
}


/* LOG handler (stamp the primary status for divergence) */
ngx_int_t
brix_http_mirror_log_handler(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *ctx;

    if (r != r->main) {
        return NGX_OK;
    }
    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (ctx != NULL && ctx->mirror_fired) {
        ctx->primary_status = r->headers_out.status;
    }
    return NGX_OK;
}
