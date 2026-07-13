#include "proxy_internal.h"

/*
 * proxy_request.c - WebDAV upstream request relay and Destination header rewriting.
 *
 * WHAT: Rewrites client HTTP requests for forwarding to upstream backend — transforms Destination headers from public URLs to internal upstream paths, strips hop-by-hop headers, applies auth policy (anonymous/forward/token), and constructs complete HTTP/1.1 request line with all necessary headers for nginx upstream API relay.
 *
 * WHY: Proxy mode requires transforming client requests so they target the internal backend instead of the public perimeter server. Destination header rewriting converts "https://public.example.com/dav/foo" → "http://internal:1094/dav/foo" enabling COPY/MOVE operations to reach correct backend path. Hop-by-hop headers (Connection/Host/K
 *
 * If the Destination value doesn't look like an absolute URL with a host
 * component, it is forwarded unchanged.
 */
static ngx_str_t
webdav_proxy_rewrite_destination(ngx_pool_t *pool,
    ngx_str_t *dest, ngx_str_t *upstream_url_base)
{
    ngx_str_t  result;
    u_char    *p, *end, *path_start;
    size_t     path_len;

    result = *dest;   /* default: pass through unchanged */

    /* dest must start with "http://" or "https://" */
    if (dest->len < 7) {
        return result;
    }
    if (ngx_strncasecmp(dest->data, (u_char *) "http://", 7) != 0
        && ngx_strncasecmp(dest->data, (u_char *) "https://", 8) != 0)
    {
        return result;
    }

    /* Skip past the "://" */
    p = ngx_strlchr(dest->data, dest->data + dest->len, '/');
    if (p == NULL) return result;
    p++;  /* skip first '/' */
    p = ngx_strlchr(p, dest->data + dest->len, '/');
    if (p == NULL) {
        /* dest is just scheme://host; forward as upstream_url_base */
        result = *upstream_url_base;
        return result;
    }

    /* p now points to the first '/' of the path */
    path_start = p;
    end        = dest->data + dest->len;
    path_len   = end - path_start;

    result.len  = upstream_url_base->len + path_len;
    result.data = ngx_pnalloc(pool, result.len + 1);
    if (result.data == NULL) {
        result = *dest;
        return result;
    }
    p = ngx_copy(result.data, upstream_url_base->data, upstream_url_base->len);
    p = ngx_copy(p, path_start, path_len);
    *p = '\0';
    return result;
}

/*
 * wpr_ctx_t - resolved per-request relay parameters.
 *
 * WHAT: Bundles the fields shared across the create-request phases — the location
 * config (auth policy + token), and the selected backend's Host / URL base — so
 * the sizing and fill helpers take one explicit input instead of reaching for the
 * request context repeatedly.
 *
 * WHY: The size-computation and buffer-fill passes MUST agree byte-for-byte on
 * which backend host/url_base they use; carrying both in one struct guarantees
 * the two passes see identical values and keeps data flow explicit (§8).
 *
 * HOW: Populated once by wpr_build_url() from conf + the per-request proxy ctx,
 * then passed by const-ish value pointer to every helper. No mutation after build.
 */
typedef struct {
    ngx_http_brix_webdav_loc_conf_t  *conf;
    ngx_str_t                         host;      /* Host: header value */
    ngx_str_t                         url_base;  /* scheme://host[:port] */
} wpr_ctx_t;

/*
 * wpr_is_hop_by_hop - decide whether a client header is dropped before forwarding.
 *
 * WHAT: Returns 1 when the named header must NOT be copied verbatim into the
 * upstream request — the hop-by-hop set (Connection/Host/Keep-Alive/
 * Transfer-Encoding), plus Authorization (re-emitted per auth policy) and, when
 * `drop_content_length` is set, Content-Length (re-emitted from the body length).
 *
 * WHY: The size pass and the fill pass share this exact skip decision; expressing
 * it once as data prevents the two passes from diverging (a divergence would
 * mis-size the buffer). Content-Length is only skipped in the fill pass because
 * the size pass never charged the client's own Content-Length header.
 *
 * HOW: Case-insensitive compare against a static-const name table; the
 * Content-Length row is gated on the caller's `drop_content_length` flag.
 */
static int
wpr_is_hop_by_hop(ngx_str_t *key, int drop_content_length)
{
    static const char *const drop_names[] = {
        "Connection", "Host", "Keep-Alive", "Transfer-Encoding",
        "Authorization", NULL
    };
    const char *const *n;

    for (n = drop_names; *n != NULL; n++) {
        if (ngx_strcasecmp(key->data, (u_char *) *n) == 0) {
            return 1;
        }
    }
    if (drop_content_length
        && ngx_strcasecmp(key->data, (u_char *) "Content-Length") == 0)
    {
        return 1;
    }
    return 0;
}

/*
 * wpr_build_url - resolve the effective upstream host and URL base for this request.
 *
 * WHAT: Fills the wpr_ctx_t with the location config plus the Host / URL base to
 * target — the round-robin-selected backend's values when one was chosen for this
 * request, otherwise the legacy single-backend conf fields.
 *
 * WHY: Proxy mode may fan a location out to several backends; the request must be
 * addressed to whichever backend the picker selected. Resolving this once, up
 * front, is what lets the Destination rewrite and the Host header agree.
 *
 * HOW: Reads conf via the loc-conf accessor and the per-request proxy ctx via the
 * module ctx accessor; prefers pctx->selected_backend when present, else conf.
 */
static void
wpr_build_url(ngx_http_request_t *r, wpr_ctx_t *wc)
{
    webdav_proxy_ctx_t *pctx;

    wc->conf     = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    wc->host     = wc->conf->upstream_host;
    wc->url_base = wc->conf->upstream_url_base;

    pctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (pctx != NULL && pctx->selected_backend != NULL) {
        wc->host     = pctx->selected_backend->host;
        wc->url_base = pctx->selected_backend->url_base;
    }
}

/*
 * wpr_size_auth - byte budget for the Authorization line under the auth policy.
 *
 * WHAT: Returns the number of bytes the emitted Authorization header will consume
 * for this request: ANONYMOUS = 0 (stripped), TOKEN = a static "Bearer <token>",
 * FORWARD = the client's own Authorization value passed through.
 *
 * WHY: Phase-1 sizing must reserve exactly what phase-2 (wpr_emit_auth) writes;
 * the client's Authorization is skipped by the header loop, so FORWARD adds it
 * back here.
 *
 * HOW: Branches on conf->upstream_auth; pure arithmetic, no side effects.
 */
static size_t
wpr_size_auth(ngx_http_request_t *r, const wpr_ctx_t *wc)
{
    if (wc->conf->upstream_auth == WEBDAV_PROXY_AUTH_TOKEN) {
        return sizeof("Authorization: Bearer \r\n") - 1
             + wc->conf->upstream_auth_token.len;
    }
    if (wc->conf->upstream_auth == WEBDAV_PROXY_AUTH_FORWARD
        && r->headers_in.authorization != NULL)
    {
        return sizeof("Authorization: \r\n") - 1
             + r->headers_in.authorization->value.len;
    }
    return 0;   /* ANONYMOUS, or FORWARD with no client Authorization */
}

/*
 * wpr_size_request - total byte budget for the upstream request header block.
 *
 * WHAT: Computes the exact size of the request line + Host + Connection + blank
 * line + all forwarded client headers (Destination charged at the rewritten,
 * longer URL-base width) + the Authorization line + Content-Length (if a body).
 *
 * WHY: nginx's upstream API needs the whole header block in one pre-sized buffer;
 * an under-count would truncate/overflow. Mirrors wpr_fill_request exactly.
 *
 * HOW: Constant contributions first, then one pass over r->headers_in.headers
 * skipping the hop-by-hop set (wpr_is_hop_by_hop, Content-Length kept here — the
 * client's own is never forwarded but we don't charge it) and specially sizing
 * Destination; then wpr_size_auth and the optional Content-Length.
 */
static size_t
wpr_size_request(ngx_http_request_t *r, const wpr_ctx_t *wc)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;
    ngx_uint_t        i;
    size_t            len;

    /* Request line: "METHOD /uri?args HTTP/1.1\r\n" */
    len = r->method_name.len + 1
        + r->uri.len
        + (r->args.len ? 1 + r->args.len : 0)
        + sizeof(" HTTP/1.1\r\n") - 1;

    /* Host: header */
    len += sizeof("Host: \r\n") - 1 + wc->host.len;

    /* Connection: close */
    len += sizeof("Connection: close\r\n") - 1;

    /* blank line */
    len += sizeof("\r\n") - 1;

    /* Forwarded client headers (we'll skip some below) */
    part   = &r->headers_in.headers.part;
    header = part->elts;
    for (i = 0; /* */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next; header = part->elts; i = 0;
        }
        if (header[i].hash == 0) continue;

        if (wpr_is_hop_by_hop(&header[i].key, 0)) continue;

        /* Destination header is rewritten; account for longer URL base */
        if (ngx_strcasecmp(header[i].key.data,
                           (u_char *) "Destination") == 0) {
            len += sizeof("Destination: \r\n") - 1
                 + wc->url_base.len + header[i].value.len;
            continue;
        }

        len += header[i].key.len + sizeof(": \r\n") - 1 + header[i].value.len;
    }

    len += wpr_size_auth(r, wc);

    /* Content-Length if there is a body */
    if (r->headers_in.content_length_n > 0) {
        len += sizeof("Content-Length: \r\n") - 1 + NGX_OFF_T_LEN;
    }

    return len;
}

/*
 * wpr_emit_auth - write the Authorization line for the request's auth policy.
 *
 * WHAT: Appends the Authorization header at `p` per policy — TOKEN emits the
 * configured static "Bearer <token>", FORWARD copies the client's Authorization
 * value, ANONYMOUS emits nothing — and returns the advanced write cursor.
 *
 * WHY: Byte-for-byte counterpart to wpr_size_auth; keeps the credential-delegation
 * policy in one place so sizing and emission cannot drift.
 *
 * HOW: Branch on conf->upstream_auth using ngx_cpymem/ngx_copy; the header loop
 * never forwards Authorization, so this is the sole emitter.
 */
static u_char *
wpr_emit_auth(ngx_http_request_t *r, const wpr_ctx_t *wc, u_char *p)
{
    if (wc->conf->upstream_auth == WEBDAV_PROXY_AUTH_TOKEN) {
        p = ngx_cpymem(p, "Authorization: Bearer ",
                       sizeof("Authorization: Bearer ") - 1);
        p = ngx_copy(p, wc->conf->upstream_auth_token.data,
                     wc->conf->upstream_auth_token.len);
        *p++ = '\r'; *p++ = '\n';
    } else if (wc->conf->upstream_auth == WEBDAV_PROXY_AUTH_FORWARD
               && r->headers_in.authorization != NULL)
    {
        p = ngx_cpymem(p, "Authorization: ",
                       sizeof("Authorization: ") - 1);
        p = ngx_copy(p, r->headers_in.authorization->value.data,
                     r->headers_in.authorization->value.len);
        *p++ = '\r'; *p++ = '\n';
    }
    return p;
}

/*
 * wpr_emit_client_headers - copy the forwarded client headers into the buffer.
 *
 * WHAT: Iterates r->headers_in.headers, skips the hop-by-hop set plus
 * Content-Length and Authorization, rewrites Destination to the upstream URL
 * base, copies every other header verbatim, and returns the advanced cursor.
 *
 * WHY: Second half of the header block; must forward exactly the header set that
 * wpr_size_request charged for (Destination at the rewritten width).
 *
 * HOW: Same skip predicate as sizing but with drop_content_length=1 (the fill
 * pass drops Content-Length because wpr_emit_content_length already wrote the
 * body-derived one); Destination goes through webdav_proxy_rewrite_destination.
 */
static u_char *
wpr_emit_client_headers(ngx_http_request_t *r, const wpr_ctx_t *wc, u_char *p)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;
    ngx_uint_t        i;
    ngx_str_t         url_base = wc->url_base;

    part   = &r->headers_in.headers.part;
    header = part->elts;
    for (i = 0; /* */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next; header = part->elts; i = 0;
        }
        if (header[i].hash == 0) continue;

        if (wpr_is_hop_by_hop(&header[i].key, 1)) continue;

        if (ngx_strcasecmp(header[i].key.data,
                           (u_char *) "Destination") == 0) {
            /* Rewrite Destination to point at the upstream URL base */
            ngx_str_t rewritten = webdav_proxy_rewrite_destination(
                r->pool, &header[i].value, &url_base);
            p = ngx_copy(p, header[i].key.data, header[i].key.len);
            *p++ = ':'; *p++ = ' ';
            p = ngx_copy(p, rewritten.data, rewritten.len);
            *p++ = '\r'; *p++ = '\n';
            continue;
        }

        p = ngx_copy(p, header[i].key.data, header[i].key.len);
        *p++ = ':'; *p++ = ' ';
        p = ngx_copy(p, header[i].value.data, header[i].value.len);
        *p++ = '\r'; *p++ = '\n';
    }

    return p;
}

/*
 * wpr_fill_request - write the full request header block into the pre-sized buffer.
 *
 * WHAT: Fills `b` with the request line (METHOD /uri?args HTTP/1.1), Host,
 * Connection: close, Content-Length (if a body), the Authorization line per
 * policy, all forwarded client headers, and the terminating blank line; sets
 * b->last to the write cursor.
 *
 * WHY: The fill counterpart to wpr_size_request — same field order, same skip set,
 * so the buffer is filled to exactly its computed length (byte-frozen wire form).
 *
 * HOW: Advances a single cursor `p` through fixed lines, then delegates the auth
 * line to wpr_emit_auth and the variable header block to wpr_emit_client_headers.
 */
static void
wpr_fill_request(ngx_http_request_t *r, const wpr_ctx_t *wc, ngx_buf_t *b)
{
    u_char  *p = b->pos;

    /* Request line */
    p = ngx_copy(p, r->method_name.data, r->method_name.len);
    *p++ = ' ';
    p = ngx_copy(p, r->uri.data, r->uri.len);
    if (r->args.len) {
        *p++ = '?';
        p = ngx_copy(p, r->args.data, r->args.len);
    }
    p = ngx_cpymem(p, " HTTP/1.1\r\n", sizeof(" HTTP/1.1\r\n") - 1);

    /* Host */
    p = ngx_cpymem(p, "Host: ", sizeof("Host: ") - 1);
    p = ngx_copy(p, wc->host.data, wc->host.len);
    *p++ = '\r'; *p++ = '\n';

    /* Connection: close */
    p = ngx_cpymem(p, "Connection: close\r\n",
                   sizeof("Connection: close\r\n") - 1);

    /* Content-Length */
    if (r->headers_in.content_length_n > 0) {
        p = ngx_sprintf(p, "Content-Length: %O\r\n",
                        r->headers_in.content_length_n);
    }

    /* Forward auth */
    p = wpr_emit_auth(r, wc, p);

    /* Remaining client headers */
    p = wpr_emit_client_headers(r, wc, p);

    /* End of headers */
    *p++ = '\r'; *p++ = '\n';
    b->last = p;
}

/*
 * wpr_attach_body - hand the filled header buffer (and any body) to the upstream.
 *
 * WHAT: Wraps `b` in a chain link, publishes it as u->request_bufs, and appends
 * the buffered request body bufs when present. Returns NGX_OK or NGX_ERROR on a
 * chain-link allocation failure.
 *
 * WHY: nginx's upstream API sends u->request_bufs as the request; the body must
 * follow the header block in the same chain.
 *
 * HOW: ngx_alloc_chain_link from r->pool, link the header buf, then splice
 * r->request_body->bufs onto cl->next if a body was buffered.
 */
static ngx_int_t
wpr_attach_body(ngx_http_request_t *r, ngx_buf_t *b)
{
    ngx_chain_t          *cl;
    ngx_http_upstream_t  *u = r->upstream;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) return NGX_ERROR;
    cl->buf  = b;
    cl->next = NULL;

    u->request_bufs = cl;

    /* Append buffered request body */
    if (r->request_body != NULL && r->request_body->bufs != NULL) {
        cl->next = r->request_body->bufs;
    }

    return NGX_OK;
}

/*
 * webdav_proxy_create_request - u->create_request hook: build the upstream request.
 *
 * WHAT: Constructs the complete HTTP/1.1 request (line + headers + any buffered
 * body) into u->request_bufs, targeting the selected backend, stripping hop-by-hop
 * headers, rewriting Destination, and applying the auth policy. Returns NGX_OK or
 * NGX_ERROR on allocation failure.
 *
 * WHY: nginx's upstream API requires the whole request in one buffer before it
 * connects to the backend; proxy mode must retarget the client request at the
 * internal backend rather than the public perimeter server.
 *
 * HOW: Resolve the backend (wpr_build_url); size the header block (wpr_size_request);
 * allocate a temp buf; fill it (wpr_fill_request); attach it and any body
 * (wpr_attach_body). Each step is a pure/edge helper with explicit inputs.
 */
ngx_int_t
webdav_proxy_create_request(ngx_http_request_t *r)
{
    wpr_ctx_t   wc = {0};
    ngx_buf_t  *b;
    size_t      len;

    wpr_build_url(r, &wc);

    len = wpr_size_request(r, &wc);

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) return NGX_ERROR;

    wpr_fill_request(r, &wc, b);

    return wpr_attach_body(r, b);
}
