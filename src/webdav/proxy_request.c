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

 * WHAT: Constructs a complete HTTP/1.1 request for forwarding to upstream backend — computes total header block size, allocates buffer, fills request line (METHOD /uri?args HTTP/1.1), Host header, Connection: close, Content-Length, Authorization header per auth policy (anonymous strips, forward passes unchanged, token replaces with static Bearer), Destination header rewritten from public URL to internal upstream path, and all remaining client headers excluding hop-by-hop headers (Connection/Host/Keep-Alive/Transfer-Encoding). Appends buffered request body if present. Returns NGX_OK on success or NGX_ERROR on allocation failure.

 * WHY: nginx upstream API requires the complete request line+headers in a single buffer before sending to backend. Proxy mode must transform client requests so they target internal backend instead of public perimeter server — Destination rewriting converts https://public.example.com/dav/foo → http://internal:1094/dav/foo enabling COPY/MOVE operations. Three auth policies determine Authorization header handling: anonymous strips it (internal trust), forward passes unchanged (transparent relay), token replaces with static Bearer (credential delegation). Hop-by-hop headers are excluded because they have per-connection semantics that don't apply to the backend connection.

 * HOW: Two-phase algorithm. Phase 1 — size computation: iterate all client headers accumulating bytes for request line, Host header, Connection: close, blank line, each forwarded header (Destination rewritten so account for longer URL base), Authorization per policy, Content-Length if body present. Phase 2 — buffer fill: allocate temp buf via ngx_create_temp_buf(r->pool,len); copy request line; copy Host from conf->upstream_host; copy Connection: close; copy Content-Length via ngx_sprintf; copy Authorization per auth policy; iterate remaining headers skipping hop-by-hop, rewriting Destination via webdav_proxy_rewrite_destination(), copying all other headers verbatim; terminate with blank line; allocate chain link and set u->request_bufs; append request body bufs if present. */

ngx_int_t
webdav_proxy_create_request(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_http_upstream_t               *u;
    ngx_buf_t                         *b;
    ngx_chain_t                       *cl;
    ngx_list_part_t                   *part;
    ngx_table_elt_t                   *header;
    ngx_uint_t                         i;
    size_t                             len;
    u_char                            *p;
    int                                skip_auth;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    u    = r->upstream;

    /* Use the round-robin-selected backend's Host / URL base (falls back to
     * the legacy single-backend conf fields if no backend was selected). */
    ngx_str_t  host     = conf->upstream_host;
    ngx_str_t  url_base = conf->upstream_url_base;
    {
        webdav_proxy_ctx_t *pctx =
            ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
        if (pctx != NULL && pctx->selected_backend != NULL) {
            host     = pctx->selected_backend->host;
            url_base = pctx->selected_backend->url_base;
        }
    }

    /* compute header block size */
    /* Request line: "METHOD /uri?args HTTP/1.1\r\n" */
    len = r->method_name.len + 1
        + r->uri.len
        + (r->args.len ? 1 + r->args.len : 0)
        + sizeof(" HTTP/1.1\r\n") - 1;

    /* Host: header */
    len += sizeof("Host: \r\n") - 1 + host.len;

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

        /* Hop-by-hop headers are never forwarded */
        if (ngx_strcasecmp(header[i].key.data,
                           (u_char *) "Connection") == 0) continue;
        if (ngx_strcasecmp(header[i].key.data,
                           (u_char *) "Host") == 0) continue;
        if (ngx_strcasecmp(header[i].key.data,
                           (u_char *) "Keep-Alive") == 0) continue;
        if (ngx_strcasecmp(header[i].key.data,
                           (u_char *) "Transfer-Encoding") == 0) continue;
        if (ngx_strcasecmp(header[i].key.data,
                           (u_char *) "Authorization") == 0) {
            /* handled separately per auth policy */
            continue;
        }
        /* Destination header is rewritten; account for longer URL base */
        if (ngx_strcasecmp(header[i].key.data,
                           (u_char *) "Destination") == 0) {
            len += sizeof("Destination: \r\n") - 1
                 + url_base.len + header[i].value.len;
            continue;
        }

        len += header[i].key.len + sizeof(": \r\n") - 1 + header[i].value.len;
    }

    /* Authorization depending on policy */
    skip_auth = 0;
    if (conf->upstream_auth == WEBDAV_PROXY_AUTH_ANONYMOUS) {
        skip_auth = 1;  /* add nothing */
    } else if (conf->upstream_auth == WEBDAV_PROXY_AUTH_TOKEN) {
        len += sizeof("Authorization: Bearer \r\n") - 1
             + conf->upstream_auth_token.len;
        skip_auth = 1;  /* replace; don't forward original */
    }
    /* FORWARD: original Authorization header was counted in the loop above,
     * but we skipped it; add it back now */
    if (conf->upstream_auth == WEBDAV_PROXY_AUTH_FORWARD
        && r->headers_in.authorization != NULL)
    {
        len += sizeof("Authorization: \r\n") - 1
             + r->headers_in.authorization->value.len;
    }

    /* Content-Length if there is a body */
    if (r->headers_in.content_length_n > 0) {
        len += sizeof("Content-Length: \r\n") - 1 + NGX_OFF_T_LEN;
    }

    /* allocate and fill the header buffer */
    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) return NGX_ERROR;

    p = b->pos;

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
    p = ngx_copy(p, host.data, host.len);
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
    if (conf->upstream_auth == WEBDAV_PROXY_AUTH_TOKEN) {
        p = ngx_cpymem(p, "Authorization: Bearer ",
                       sizeof("Authorization: Bearer ") - 1);
        p = ngx_copy(p, conf->upstream_auth_token.data,
                     conf->upstream_auth_token.len);
        *p++ = '\r'; *p++ = '\n';
    } else if (conf->upstream_auth == WEBDAV_PROXY_AUTH_FORWARD
               && r->headers_in.authorization != NULL)
    {
        p = ngx_cpymem(p, "Authorization: ",
                       sizeof("Authorization: ") - 1);
        p = ngx_copy(p, r->headers_in.authorization->value.data,
                     r->headers_in.authorization->value.len);
        *p++ = '\r'; *p++ = '\n';
    }

    /* Remaining client headers */
    part   = &r->headers_in.headers.part;
    header = part->elts;
    for (i = 0; /* */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next; header = part->elts; i = 0;
        }
        if (header[i].hash == 0) continue;
        if (ngx_strcasecmp(header[i].key.data,
                           (u_char *) "Connection") == 0) continue;
        if (ngx_strcasecmp(header[i].key.data,
                           (u_char *) "Host") == 0) continue;
        if (ngx_strcasecmp(header[i].key.data,
                           (u_char *) "Keep-Alive") == 0) continue;
        if (ngx_strcasecmp(header[i].key.data,
                           (u_char *) "Transfer-Encoding") == 0) continue;
        if (ngx_strcasecmp(header[i].key.data,
                           (u_char *) "Content-Length") == 0) continue;
        if (ngx_strcasecmp(header[i].key.data,
                           (u_char *) "Authorization") == 0) continue;

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

    /* End of headers */
    *p++ = '\r'; *p++ = '\n';
    b->last = p;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) return NGX_ERROR;
    cl->buf  = b;
    cl->next = NULL;

    u->request_bufs = cl;

    /* Append buffered request body */
    if (r->request_body != NULL && r->request_body->bufs != NULL) {
        cl->next = r->request_body->bufs;
    }

    (void) skip_auth;  /* suppress unused-variable warning */
    return NGX_OK;
}
