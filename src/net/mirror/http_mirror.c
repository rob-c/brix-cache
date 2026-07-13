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
 */
#include "http_mirror.h"
#include "core/http/http_body.h"
#include "core/http/http_headers.h"

/* Mirror counters live in the shared root metrics struct (low cardinality, no
 * per-target labels per metrics INVARIANT 8). */
#define MIR_HTTP_INC(field)                                                  \
    do {                                                                     \
        ngx_brix_metrics_t *_m = brix_metrics_shared();                  \
        if (_m != NULL) { (void) ngx_atomic_fetch_add(&_m->field, 1); }      \
    } while (0)


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

/* Methods that carry a request body the shadow must receive (PUT). */
static ngx_int_t
brix_http_mirror_method_has_body(ngx_uint_t method)
{
    return method == NGX_HTTP_PUT;
}

/*
 * Rewrite a WebDAV Destination header URL so its host points at the shadow.
 * "https://public.example.org/dav/foo" + url_base "http://shadow:8443"
 *   => "http://shadow:8443/dav/foo".  Mirrors webdav_proxy_rewrite_destination()
 * (which is static to the proxy module); a relative/odd value is passed through.
 */
static ngx_str_t
brix_http_mirror_rewrite_dest(ngx_pool_t *pool, ngx_str_t *dest,
    ngx_str_t *url_base)
{
    ngx_str_t  result = *dest;
    u_char    *p, *end, *path_start;
    size_t     path_len;

    if (dest->len < 7
        || (ngx_strncasecmp(dest->data, (u_char *) "http://", 7) != 0
            && ngx_strncasecmp(dest->data, (u_char *) "https://", 8) != 0))
    {
        return result;   /* not absolute — forward unchanged */
    }
    p = ngx_strlchr(dest->data, dest->data + dest->len, '/');
    if (p == NULL) { return result; }
    p++;                                        /* skip first '/' of "://" */
    p = ngx_strlchr(p, dest->data + dest->len, '/');
    if (p == NULL) { return *url_base; }        /* scheme://host only */

    path_start = p;
    end        = dest->data + dest->len;
    path_len   = (size_t) (end - path_start);

    result.len  = url_base->len + path_len;
    result.data = ngx_pnalloc(pool, result.len);
    if (result.data == NULL) { return *dest; }
    p = ngx_copy(result.data, url_base->data, url_base->len);
    (void) ngx_copy(p, path_start, path_len);
    return result;
}

/*
 * Clone a request-body buf chain into r->pool with INDEPENDENT buf structs so the
 * shadow send (which advances buf->pos / file_pos) never disturbs the primary's
 * own consumption of the same body.  The underlying memory / file handle is shared
 * read-only; only the small ngx_buf_t bookkeeping is duplicated.
 */
static ngx_chain_t *
brix_http_mirror_clone_body(ngx_http_request_t *r,
    ngx_http_request_t *parent, off_t *len_out)
{
    ngx_chain_t *in, *head = NULL, **tail = &head;
    off_t        total = 0;

    *len_out = 0;
    if (parent->request_body == NULL || parent->request_body->bufs == NULL) {
        return NULL;
    }
    for (in = parent->request_body->bufs; in != NULL; in = in->next) {
        ngx_buf_t   *b;
        ngx_chain_t *cl;

        if (ngx_buf_size(in->buf) == 0) { continue; }
        cl = ngx_alloc_chain_link(r->pool);
        b  = ngx_palloc(r->pool, sizeof(ngx_buf_t));
        if (cl == NULL || b == NULL) { *len_out = -1; return NULL; }
        *b = *in->buf;          /* independent pos/last/file_pos/file_last */
        b->last_buf = b->last_in_chain = 0;
        cl->buf  = b;
        cl->next = NULL;
        *tail = cl;
        tail  = &cl->next;
        total += ngx_buf_size(in->buf);
    }
    *len_out = total;
    return head;
}


/* upstream callbacks (shadow request/response) */

/*
 * Derived per-subrequest inputs for building the shadow request line + headers.
 *
 * WHAT: A file-local plan struct that captures everything the header writer needs
 * — target host, auth policy, rewritten Destination, forwarded Depth/Overwrite,
 * and the cloned PUT body + its Content-Length rendering.
 * WHY: keeps mirror_create_request a short orchestrator and lets the length pass
 * and the write pass share exactly the same inputs (no drift between the two).
 * HOW: filled once by mirror_build_subrequest(), then consumed read-only by
 * mirror_headers_len() and mirror_copy_headers(); the body chain is attached by
 * mirror_set_body().  All fields zero-initialised at declaration.
 */
typedef struct {
    brix_mirror_target_t *t;             /* selected shadow target */
    ngx_str_t             host;          /* Host: header value */
    int                   inject_token;  /* send "Authorization: Bearer <tok>" */
    ngx_uint_t            has_body;      /* method carries a body (PUT) */
    ngx_table_elt_t      *depth_h;       /* forwarded Depth (MOVE/COPY) */
    ngx_table_elt_t      *over_h;        /* forwarded Overwrite (MOVE/COPY) */
    ngx_str_t             dest;          /* rewritten Destination (MOVE/COPY) */
    ngx_chain_t          *body;          /* cloned PUT body chain */
    u_char                clbuf[NGX_OFF_T_LEN]; /* rendered Content-Length */
    size_t                cl_digits;     /* digits written into clbuf */
} mirror_req_plan_t;

/*
 * WHAT: resolve the shadow target and gather every header input into *plan.
 * WHY: isolates the "figure out what to send" decisions (target lookup, auth
 * policy, Destination rewrite, Depth/Overwrite forwarding, PUT body clone) from
 * the byte-emitting passes, so the two passes cannot disagree.
 * HOW: returns NGX_OK on success, NGX_ERROR if the target is out of range or a
 * PUT body clone allocation failed (never send a truncated PUT).  *plan is
 * zero-initialised by the caller.
 */
static ngx_int_t
mirror_build_subrequest(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_req_ctx_t *ctx, mirror_req_plan_t *plan)
{
    ngx_uint_t  method;
    off_t       body_len = 0;

    if (ctx == NULL || conf->mirror.targets == NULL
        || ctx->mirror_target_idx >= conf->mirror.targets->nelts)
    {
        return NGX_ERROR;
    }
    plan->t    = (brix_mirror_target_t *) conf->mirror.targets->elts
               + ctx->mirror_target_idx;
    plan->host = plan->t->host;
    method     = r->method;
    plan->has_body = brix_http_mirror_method_has_body(method);

    /* Auth policy on the shadow request:
     *   token configured  => inject "Authorization: Bearer <token>"
     *   strip_auth on      => send no Authorization at all (default)
     *   strip_auth off     => forward the client's Authorization header. */
    plan->inject_token = (conf->mirror.token.len > 0);

    /* MOVE/COPY: rewrite the client's Destination to point at the shadow, and
     * forward Depth/Overwrite verbatim so the shadow performs the same op. */
    if (method == NGX_HTTP_MOVE || method == NGX_HTTP_COPY) {
        ngx_table_elt_t *dest_h = brix_http_find_header(r,
            "Destination", sizeof("Destination") - 1);
        if (dest_h != NULL) {
            plan->dest = brix_http_mirror_rewrite_dest(r->pool, &dest_h->value,
                             &plan->t->url_base);
        }
        plan->depth_h = brix_http_find_header(r, "Depth",
                            sizeof("Depth") - 1);
        plan->over_h  = brix_http_find_header(r, "Overwrite",
                            sizeof("Overwrite") - 1);
    }

    /* PUT: forward the (preserved) request body cloned from the parent request. */
    if (plan->has_body && r->parent != NULL) {
        plan->body = brix_http_mirror_clone_body(r, r->parent, &body_len);
        if (body_len < 0) {
            return NGX_ERROR;   /* clone alloc failed — don't send a truncated PUT */
        }
        plan->cl_digits =
            (size_t) (ngx_sprintf(plan->clbuf, "%O", body_len) - plan->clbuf);
    }
    return NGX_OK;
}

/*
 * WHAT: compute the exact byte length of the request line + header block.
 * WHY: mirror_copy_headers() writes into a fixed-size temp buf; this pure sizing
 * pass must mirror it field-for-field or the write would overrun/underrun.
 * HOW: sums the request line and every conditionally-present header from *plan;
 * no side effects.
 */
static size_t
mirror_headers_len(ngx_http_request_t *r, ngx_http_brix_webdav_loc_conf_t *conf,
    const mirror_req_plan_t *plan)
{
    /* "METHOD uri[?args] HTTP/1.1\r\nHost: <host>\r\nConnection: close\r\n" */
    size_t  len = r->method_name.len + 1
        + r->uri.len
        + (r->args.len ? 1 + r->args.len : 0)
        + sizeof(" HTTP/1.1" CRLF) - 1
        + sizeof("Host: ") - 1 + plan->host.len + sizeof(CRLF) - 1
        + sizeof("Connection: close" CRLF) - 1
        + sizeof("X-Xrootd-Mirror: 1" CRLF) - 1
        + sizeof(CRLF) - 1;

    if (plan->inject_token) {
        len += sizeof("Authorization: Bearer ") - 1
             + conf->mirror.token.len + sizeof(CRLF) - 1;
    } else if (!conf->mirror.strip_auth
               && r->headers_in.authorization != NULL) {
        len += sizeof("Authorization: ") - 1
             + r->headers_in.authorization->value.len + sizeof(CRLF) - 1;
    }
    if (plan->dest.len) {
        len += sizeof("Destination: ") - 1 + plan->dest.len + sizeof(CRLF) - 1;
    }
    if (plan->depth_h != NULL) {
        len += sizeof("Depth: ") - 1 + plan->depth_h->value.len
             + sizeof(CRLF) - 1;
    }
    if (plan->over_h != NULL) {
        len += sizeof("Overwrite: ") - 1 + plan->over_h->value.len
             + sizeof(CRLF) - 1;
    }
    if (plan->has_body) {
        len += sizeof("Content-Length: ") - 1 + plan->cl_digits
             + sizeof(CRLF) - 1;
    }
    return len;
}

/*
 * WHAT: write the request line + header block into buffer b per *plan.
 * WHY: the byte-emitting half of the two-pass build; keeps the exact wire order
 * (method line, Host, Connection, loop-guard, auth, Destination/Depth/Overwrite,
 * Content-Length, blank line) in one place — frozen for AF-shadow behaviour.
 * HOW: appends with ngx_copy from b->last; advances b->last to the end.  Emits
 * only the headers *plan marked present, matching mirror_headers_len() exactly.
 */
static void
mirror_copy_headers(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const mirror_req_plan_t *plan,
    ngx_buf_t *b)
{
    u_char  *p = b->last;

    p = ngx_copy(p, r->method_name.data, r->method_name.len);
    *p++ = ' ';
    p = ngx_copy(p, r->uri.data, r->uri.len);
    if (r->args.len) {
        *p++ = '?';
        p = ngx_copy(p, r->args.data, r->args.len);
    }
    p = ngx_copy(p, " HTTP/1.1" CRLF, sizeof(" HTTP/1.1" CRLF) - 1);

    p = ngx_copy(p, "Host: ", sizeof("Host: ") - 1);
    p = ngx_copy(p, plan->host.data, plan->host.len);
    p = ngx_copy(p, CRLF, sizeof(CRLF) - 1);

    p = ngx_copy(p, "Connection: close" CRLF,
                 sizeof("Connection: close" CRLF) - 1);

    /* Loop guard: a shadow that happens to be this same server will see this
     * marker and decline to mirror again (brix_http_mirror_precontent_handler). */
    p = ngx_copy(p, "X-Xrootd-Mirror: 1" CRLF,
                 sizeof("X-Xrootd-Mirror: 1" CRLF) - 1);

    if (plan->inject_token) {
        p = ngx_copy(p, "Authorization: Bearer ",
                     sizeof("Authorization: Bearer ") - 1);
        p = ngx_copy(p, conf->mirror.token.data, conf->mirror.token.len);
        p = ngx_copy(p, CRLF, sizeof(CRLF) - 1);
    } else if (!conf->mirror.strip_auth
               && r->headers_in.authorization != NULL) {
        p = ngx_copy(p, "Authorization: ", sizeof("Authorization: ") - 1);
        p = ngx_copy(p, r->headers_in.authorization->value.data,
                     r->headers_in.authorization->value.len);
        p = ngx_copy(p, CRLF, sizeof(CRLF) - 1);
    }
    if (plan->dest.len) {
        p = ngx_copy(p, "Destination: ", sizeof("Destination: ") - 1);
        p = ngx_copy(p, plan->dest.data, plan->dest.len);
        p = ngx_copy(p, CRLF, sizeof(CRLF) - 1);
    }
    if (plan->depth_h != NULL) {
        p = ngx_copy(p, "Depth: ", sizeof("Depth: ") - 1);
        p = ngx_copy(p, plan->depth_h->value.data, plan->depth_h->value.len);
        p = ngx_copy(p, CRLF, sizeof(CRLF) - 1);
    }
    if (plan->over_h != NULL) {
        p = ngx_copy(p, "Overwrite: ", sizeof("Overwrite: ") - 1);
        p = ngx_copy(p, plan->over_h->value.data, plan->over_h->value.len);
        p = ngx_copy(p, CRLF, sizeof(CRLF) - 1);
    }
    if (plan->has_body) {
        p = ngx_copy(p, "Content-Length: ", sizeof("Content-Length: ") - 1);
        p = ngx_copy(p, plan->clbuf, plan->cl_digits);
        p = ngx_copy(p, CRLF, sizeof(CRLF) - 1);
    }

    p = ngx_copy(p, CRLF, sizeof(CRLF) - 1);
    b->last = p;
}

/*
 * WHAT: chain the header buffer and (for PUT) the cloned body into request_bufs.
 * WHY: assembles the final send chain — header block first, cloned PUT body next
 * — and hands it to the upstream, keeping that wiring out of the orchestrator.
 * HOW: allocates one chain link for b, points its next at the cloned body chain
 * (NULL for bodyless methods), and stores it in r->upstream->request_bufs.
 * Returns NGX_OK, or NGX_ERROR on chain-link allocation failure.
 */
static ngx_int_t
mirror_set_body(ngx_http_request_t *r, const mirror_req_plan_t *plan,
    ngx_buf_t *b)
{
    ngx_chain_t  *cl = ngx_alloc_chain_link(r->pool);

    if (cl == NULL) {
        return NGX_ERROR;
    }
    cl->buf  = b;
    cl->next = plan->body;    /* PUT body (cloned) follows the header block */
    r->upstream->request_bufs = cl;
    return NGX_OK;
}

/*
 * WHAT: nginx upstream create_request callback — build the shadow HTTP request.
 * WHY: orchestrates the frozen two-pass build (measure, then write) plus body
 * attachment as a short linear sequence; the logic lives in the named helpers.
 * HOW: gather inputs into a plan, size + allocate the header buf, write it, then
 * chain the body; any step failure returns NGX_ERROR.
 */
static ngx_int_t
mirror_create_request(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    ngx_http_brix_webdav_req_ctx_t  *ctx;
    mirror_req_plan_t                  plan;
    ngx_buf_t                         *b;
    size_t                             len;

    ngx_memzero(&plan, sizeof(plan));

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    ctx  = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    if (mirror_build_subrequest(r, conf, ctx, &plan) != NGX_OK) {
        return NGX_ERROR;
    }

    len = mirror_headers_len(r, conf, &plan);
    b   = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    mirror_copy_headers(r, conf, &plan, b);

    return mirror_set_body(r, &plan, b);
}

static ngx_int_t
mirror_reinit_request(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (ctx == NULL) { return NGX_ERROR; }
    ngx_memzero(&ctx->mirror_status, sizeof(ngx_http_status_t));
    return NGX_OK;
}

static ngx_int_t mirror_process_header(ngx_http_request_t *r);

static ngx_int_t
mirror_process_status_line(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *ctx;
    ngx_http_upstream_t              *u;
    ngx_int_t                         rc;

    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (ctx == NULL) { return NGX_ERROR; }
    u  = r->upstream;

    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->mirror_status);
    if (rc == NGX_AGAIN) { return NGX_AGAIN; }
    if (rc == NGX_ERROR) { return NGX_HTTP_UPSTREAM_INVALID_HEADER; }

    if (u->state && u->state->status == 0) {
        u->state->status = ctx->mirror_status.code;
    }
    u->headers_in.status_n = ctx->mirror_status.code;

    u->process_header = mirror_process_header;
    return mirror_process_header(r);
}

static ngx_int_t
mirror_process_header(ngx_http_request_t *r)
{
    ngx_http_upstream_t  *u = r->upstream;

    for ( ;; ) {
        ngx_int_t rc = ngx_http_parse_header_line(r, &u->buffer, 1);

        if (rc == NGX_OK) {
            continue;   /* shadow headers are parsed but discarded */
        }
        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            return NGX_OK;
        }
        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

static void
mirror_abort_request(ngx_http_request_t *r)
{
    (void) r;
}

static void
mirror_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    ngx_http_request_t                *parent = r->parent;
    ngx_uint_t                         shadow_status;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    shadow_status = (r->upstream != NULL) ? r->upstream->headers_in.status_n : 0;

    if (shadow_status != 0) {
        MIR_HTTP_INC(mirror_http_total);
    } else {
        MIR_HTTP_INC(mirror_http_errors_total);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "xrootd mirror: shadow request failed (rc=%i) uri=%V",
                       rc, &r->uri);
    }

    if (parent != NULL && shadow_status != 0) {
        ngx_http_brix_webdav_req_ctx_t *pctx =
            ngx_http_get_module_ctx(parent, ngx_http_brix_webdav_module);

        if (pctx != NULL && pctx->primary_status != 0
            && brix_mirror_status_class(shadow_status)
               != brix_mirror_status_class(pctx->primary_status))
        {
            MIR_HTTP_INC(mirror_http_divergence_total);
            if (conf->mirror.log_diverge) {
                ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                    "xrootd mirror divergence: primary=%ui shadow=%ui uri=%V",
                    pctx->primary_status, shadow_status, &parent->uri);
            }
        }
    }
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


/* merge-time upstream-conf setup */
ngx_int_t
brix_http_mirror_setup(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_loc_conf_t *prev)
{
    static ngx_str_t  mirror_hide_headers[] = { ngx_null_string };
    ngx_hash_init_t   hh;

    if (conf->mirror_upstream_conf.connect_timeout == 0) {
        conf->mirror_upstream_conf.connect_timeout =
            conf->mirror.timeout_ms ? conf->mirror.timeout_ms
                                    : BRIX_MIRROR_DEFAULT_TIMEOUT_MS;
    }
    if (conf->mirror_upstream_conf.send_timeout == 0) {
        conf->mirror_upstream_conf.send_timeout =
            conf->mirror.timeout_ms ? conf->mirror.timeout_ms
                                    : BRIX_MIRROR_DEFAULT_TIMEOUT_MS;
    }
    if (conf->mirror_upstream_conf.read_timeout == 0) {
        conf->mirror_upstream_conf.read_timeout =
            conf->mirror.timeout_ms ? conf->mirror.timeout_ms
                                    : BRIX_MIRROR_DEFAULT_TIMEOUT_MS;
    }
    if (conf->mirror_upstream_conf.buffer_size == 0) {
        conf->mirror_upstream_conf.buffer_size = (size_t) ngx_pagesize;
    }
    conf->mirror_upstream_conf.buffering            = 0;
    conf->mirror_upstream_conf.bufs.num             = 4;
    conf->mirror_upstream_conf.bufs.size            = (size_t) ngx_pagesize;
    conf->mirror_upstream_conf.busy_buffers_size    = 2 * ngx_pagesize;
    conf->mirror_upstream_conf.max_temp_file_size   = 0;
    conf->mirror_upstream_conf.temp_file_write_size = 0;

#if (NGX_HTTP_SSL)
    if (conf->mirror_ssl_ctx == NULL) {
        ngx_ssl_t *s = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
        if (s == NULL) { return NGX_ERROR; }
        s->log = cf->log;
        if (ngx_ssl_create(s,
                NGX_SSL_TLSv1 | NGX_SSL_TLSv1_1 | NGX_SSL_TLSv1_2
                    | NGX_SSL_TLSv1_3, NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
        conf->mirror_ssl_ctx = s;
    }
    conf->mirror_upstream_conf.ssl        = conf->mirror_ssl_ctx;
    conf->mirror_upstream_conf.ssl_verify = 0;   /* shadow is internal; no CA */
#endif

    hh.max_size    = 512;
    hh.bucket_size = ngx_align(64, ngx_cacheline_size);
    hh.name        = "brix_mirror_hide_headers_hash";
    hh.pool        = cf->pool;
    hh.temp_pool   = NULL;
    if (ngx_http_upstream_hide_headers_hash(cf, &conf->mirror_upstream_conf,
            &prev->mirror_upstream_conf, mirror_hide_headers, &hh) != NGX_OK)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}


/* directive setters */
char *
brix_http_mirror_set_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_webdav_loc_conf_t *wlcf = conf;
    ngx_str_t                         *value = cf->args->elts;
    ngx_str_t                          url = value[1];
    brix_mirror_target_t            *t;
    ngx_url_t                          u;
    size_t                             scheme_len;
    ngx_uint_t                         ssl;
    in_port_t                          default_port;
    u_char                            *p;

    (void) cmd;

    if (ngx_strncasecmp(url.data, (u_char *) "https://", 8) == 0) {
        ssl = 1; scheme_len = 8; default_port = 443;
    } else if (ngx_strncasecmp(url.data, (u_char *) "http://", 7) == 0) {
        ssl = 0; scheme_len = 7; default_port = 80;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_mirror_url: \"%V\" must start with http:// or https://",
            &url);
        return NGX_CONF_ERROR;
    }

    if (wlcf->mirror.targets == NULL) {
        wlcf->mirror.targets = ngx_array_create(cf->pool,
            BRIX_MIRROR_MAX_TARGETS, sizeof(brix_mirror_target_t));
        if (wlcf->mirror.targets == NULL) { return NGX_CONF_ERROR; }
    }
    if (wlcf->mirror.targets->nelts >= BRIX_MIRROR_MAX_TARGETS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_mirror_url: at most %d targets supported",
            BRIX_MIRROR_MAX_TARGETS);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url.data     = url.data + scheme_len;
    u.url.len      = url.len  - scheme_len;
    u.uri_part     = 1;
    u.default_port = default_port;
    if (ngx_parse_url(cf->pool, &u) != NGX_OK || u.naddrs == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_mirror_url: cannot resolve \"%V\"%s%s", &url,
            u.err ? ": " : "", u.err ? u.err : "");
        return NGX_CONF_ERROR;
    }

    t = ngx_array_push(wlcf->mirror.targets);
    if (t == NULL) { return NGX_CONF_ERROR; }
    ngx_memzero(t, sizeof(*t));
    t->url  = url;
    t->ssl  = ssl;
    t->port = u.port;

    /* Host: header value — "host" or "host:port" if non-default. */
    if (u.port == default_port) {
        t->host = u.host;
    } else {
        p = ngx_pnalloc(cf->pool, u.host.len + 1 + sizeof("65535") - 1);
        if (p == NULL) { return NGX_CONF_ERROR; }
        t->host.data = p;
        t->host.len  = ngx_sprintf(p, "%V:%d", &u.host, (int) u.port) - p;
    }

    /* url_base — "scheme://host[:port]" for logging. */
    {
        size_t base = scheme_len + t->host.len;
        p = ngx_pnalloc(cf->pool, base);
        if (p == NULL) { return NGX_CONF_ERROR; }
        ngx_memcpy(p, url.data, scheme_len);
        ngx_memcpy(p + scheme_len, t->host.data, t->host.len);
        t->url_base.data = p;
        t->url_base.len  = base;
    }

    if (u.addrs[0].socklen > sizeof(t->sockaddr)) { return NGX_CONF_ERROR; }
    ngx_memcpy(&t->sockaddr, u.addrs[0].sockaddr, u.addrs[0].socklen);
    t->socklen = u.addrs[0].socklen;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: WebDAV mirror target %V (ssl=%d)", &t->url_base, (int) ssl);
    return NGX_CONF_OK;
}

char *
brix_http_mirror_set_methods(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_webdav_loc_conf_t *wlcf = conf;
    ngx_str_t                         *value = cf->args->elts;
    ngx_uint_t                         i, mask = 0;

    (void) cmd;

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_str_t *v = &value[i];
        if      (ngx_strcasecmp(v->data, (u_char *) "GET")      == 0) mask |= BRIX_MIRROR_M_GET;
        else if (ngx_strcasecmp(v->data, (u_char *) "HEAD")     == 0) mask |= BRIX_MIRROR_M_HEAD;
        else if (ngx_strcasecmp(v->data, (u_char *) "PROPFIND") == 0) mask |= BRIX_MIRROR_M_PROPFIND;
        else if (ngx_strcasecmp(v->data, (u_char *) "OPTIONS")  == 0) mask |= BRIX_MIRROR_M_OPTIONS;
        /* Write methods (require brix_mirror_writes on; isolated shadow). */
        else if (ngx_strcasecmp(v->data, (u_char *) "PUT")      == 0) mask |= BRIX_MIRROR_M_PUT;
        else if (ngx_strcasecmp(v->data, (u_char *) "DELETE")   == 0) mask |= BRIX_MIRROR_M_DELETE;
        else if (ngx_strcasecmp(v->data, (u_char *) "MKCOL")    == 0) mask |= BRIX_MIRROR_M_MKCOL;
        else if (ngx_strcasecmp(v->data, (u_char *) "MOVE")     == 0) mask |= BRIX_MIRROR_M_MOVE;
        else if (ngx_strcasecmp(v->data, (u_char *) "COPY")     == 0) mask |= BRIX_MIRROR_M_COPY;
        else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_mirror_methods: unsupported method \"%V\" (one of"
                " GET HEAD PROPFIND OPTIONS PUT DELETE MKCOL MOVE COPY;"
                " write methods also need brix_mirror_writes on)", v);
            return NGX_CONF_ERROR;
        }
    }
    wlcf->mirror.method_mask = mask;
    return NGX_CONF_OK;
}
