/*
 * http_mirror_request.c — shadow HTTP(S) request/response construction for the
 * Phase 24 HTTP/WebDAV traffic mirror (see http_mirror.h, http_mirror_internal.h).
 *
 * WHAT: Owns the nginx upstream callbacks that turn a mirror subrequest into a
 * wire request to a shadow target and parse (then discard) the shadow response:
 * the Destination rewrite + PUT-body clone helpers, the two-pass header build
 * (measure then write) driven by a file-local plan struct, and the
 * create/reinit/process/abort/finalize callback set.
 * WHY: split out of http_mirror.c (phase-79 file-size cap) so the "build the
 * shadow request" concern is one focused file; the subrequest driver in
 * http_mirror.c wires the five callbacks declared in http_mirror_internal.h.
 * HOW: brix_http_mirror_proxy() (http_mirror.c) assigns mirror_create_request /
 * mirror_reinit_request / mirror_process_status_line / mirror_abort_request /
 * mirror_finalize_request onto r->upstream; nginx invokes them across the
 * connect→send→read→finalize lifecycle of each background shadow subrequest.
 */
#include "http_mirror.h"
#include "http_mirror_internal.h"
#include "core/http/http_body.h"
#include "core/http/http_headers.h"

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
ngx_int_t
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

ngx_int_t
mirror_reinit_request(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (ctx == NULL) { return NGX_ERROR; }
    ngx_memzero(&ctx->mirror_status, sizeof(ngx_http_status_t));
    return NGX_OK;
}

static ngx_int_t mirror_process_header(ngx_http_request_t *r);

ngx_int_t
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

void
mirror_abort_request(ngx_http_request_t *r)
{
    (void) r;
}

void
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
