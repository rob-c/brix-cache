/*
 * proxy.c — WebDAV upstream HTTP(S) proxy.
 *
 * After the auth gate, when xrootd_webdav_proxy is on, this module forwards
 * the request verbatim to a backend HTTP/HTTPS server (e.g., a plain xrootd
 * with davs:// disabled), using nginx's native upstream API.
 *
 * Auth policies:
 *   anonymous — strip Authorization before forwarding (internal trust)
 *   forward   — pass the client's Authorization header unchanged
 *   token     — replace Authorization with a static Bearer token
 *
 * The Destination header (used by COPY/MOVE) is rewritten from the client's
 * public URL base to the configured upstream URL base.
 */

#include "webdav.h"

/* ---- per-request state --------------------------------------------------- */

typedef struct {
    ngx_http_status_t  status;
} webdav_proxy_ctx_t;

/* ---- helpers ------------------------------------------------------------- */

/*
 * Rewrite a Destination header value: strip the scheme+host of the incoming
 * request and replace with the upstream URL base.
 *
 * E.g.:  "https://public.example.com/dav/foo"  →  "http://internal:1094/dav/foo"
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
        /* dest is just scheme://host — forward as upstream_url_base */
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

/* ---- upstream callbacks -------------------------------------------------- */

static ngx_int_t
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

    /* ---- compute header block size ---- */

    /* Request line: "METHOD /uri?args HTTP/1.1\r\n" */
    len = r->method_name.len + 1
        + r->uri.len
        + (r->args.len ? 1 + r->args.len : 0)
        + sizeof(" HTTP/1.1\r\n") - 1;

    /* Host: header */
    len += sizeof("Host: \r\n") - 1 + conf->upstream_host.len;

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
        /* Destination header is rewritten — account for longer URL base */
        if (ngx_strcasecmp(header[i].key.data,
                           (u_char *) "Destination") == 0) {
            len += sizeof("Destination: \r\n") - 1
                 + conf->upstream_url_base.len + header[i].value.len;
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
     * but we skipped it — add it back now */
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

    /* ---- allocate and fill the header buffer ---- */

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
    p = ngx_copy(p, conf->upstream_host.data, conf->upstream_host.len);
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
                r->pool, &header[i].value, &conf->upstream_url_base);
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

static ngx_int_t webdav_proxy_process_header(ngx_http_request_t *r);

static ngx_int_t
webdav_proxy_reinit_request(ngx_http_request_t *r)
{
    webdav_proxy_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    if (ctx == NULL) return NGX_ERROR;

    ngx_memzero(&ctx->status, sizeof(ngx_http_status_t));

    r->upstream->process_header = webdav_proxy_process_header;
    return NGX_OK;
}

static ngx_int_t
webdav_proxy_process_status_line(ngx_http_request_t *r)
{
    ngx_int_t              rc;
    ngx_http_upstream_t   *u;
    webdav_proxy_ctx_t    *ctx;
    size_t                 len;

    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    if (ctx == NULL) return NGX_ERROR;

    u  = r->upstream;
    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);

    if (rc == NGX_AGAIN) return NGX_AGAIN;

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "xrootd_webdav_proxy: upstream sent no valid HTTP/1.x header");
        /* Treat as 502 */
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    if (u->state && u->state->status == 0) {
        u->state->status = ctx->status.code;
    }

    u->headers_in.status_n = ctx->status.code;

    len = ctx->status.end - ctx->status.start;
    u->headers_in.status_line.len  = len;
    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) return NGX_ERROR;
    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xrootd_webdav_proxy: upstream status %ui \"%V\"",
                   u->headers_in.status_n, &u->headers_in.status_line);

    u->process_header = webdav_proxy_process_header;
    return webdav_proxy_process_header(r);
}

static ngx_int_t
webdav_proxy_process_header(ngx_http_request_t *r)
{
    ngx_int_t                        rc;
    ngx_table_elt_t                 *h;
    ngx_http_upstream_t             *u;
    ngx_http_upstream_header_t      *hh;
    ngx_http_upstream_main_conf_t   *umcf;

    u    = r->upstream;
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    for (;;) {
        rc = ngx_http_parse_header_line(r, &u->buffer, 1);

        if (rc == NGX_OK) {
            h = ngx_list_push(&u->headers_in.headers);
            if (h == NULL) return NGX_ERROR;

            h->hash      = r->header_hash;
            h->key.len   = r->header_name_end - r->header_name_start;
            h->key.data  = r->header_name_start;
            h->key.data[h->key.len] = '\0';
            h->value.len  = r->header_end - r->header_start;
            h->value.data = r->header_start;
            h->value.data[h->value.len] = '\0';

            h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
            if (h->lowcase_key == NULL) return NGX_ERROR;
            ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);
            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xrootd_webdav_proxy upstream header: \"%V: %V\"",
                           &h->key, &h->value);
            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xrootd_webdav_proxy: upstream headers done");
            return NGX_OK;
        }

        if (rc == NGX_AGAIN) return NGX_AGAIN;

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "xrootd_webdav_proxy: upstream sent invalid header line");
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

static void
webdav_proxy_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xrootd_webdav_proxy: abort request");
}

static void
webdav_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xrootd_webdav_proxy: finalize request rc=%i", rc);
}

/* ---- parse upstream URL at configuration time ---------------------------- */

ngx_int_t
webdav_proxy_parse_upstream_url(ngx_conf_t *cf,
    ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    ngx_url_t          u;
    ngx_str_t          url;
    u_char            *p;
    in_port_t          default_port;
    size_t             scheme_len;

    url = conf->upstream_url;

    if (url.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd_webdav_proxy: missing upstream URL");
        return NGX_ERROR;
    }

    if (ngx_strncasecmp(url.data, (u_char *) "https://", 8) == 0) {
        conf->upstream_ssl = 1;
        scheme_len         = 8;
        default_port       = 443;
    } else if (ngx_strncasecmp(url.data, (u_char *) "http://", 7) == 0) {
        conf->upstream_ssl = 0;
        scheme_len         = 7;
        default_port       = 80;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd_webdav_proxy: upstream URL must start with"
                           " http:// or https://");
        return NGX_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url.data = url.data + scheme_len;
    u.url.len  = url.len  - scheme_len;
    u.uri_part     = 1;
    u.default_port = default_port;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd_webdav_proxy: \"%V\" in upstream URL "
                               "\"%V\"", &u.err, &url);
        }
        return NGX_ERROR;
    }

    if (u.naddrs == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd_webdav_proxy: upstream URL \"%V\" resolved"
                           " to zero addresses", &url);
        return NGX_ERROR;
    }

    /* upstream_host: "host" or "host:port" for the Host: header */
    if (u.port == default_port) {
        conf->upstream_host = u.host;
    } else {
        p = ngx_pnalloc(cf->pool, u.host.len + 1 + NGX_INT_T_LEN + 1);
        if (p == NULL) return NGX_ERROR;
        conf->upstream_host.data = p;
        conf->upstream_host.len  = ngx_sprintf(p, "%V:%d",
                                               &u.host, (int) u.port) - p;
    }

    /* upstream_url_base: "scheme://host" or "scheme://host:port" */
    {
        size_t base_len = scheme_len + conf->upstream_host.len;
        p = ngx_pnalloc(cf->pool, base_len + 1);
        if (p == NULL) return NGX_ERROR;
        ngx_memcpy(p, conf->upstream_url.data, scheme_len);
        ngx_memcpy(p + scheme_len,
                   conf->upstream_host.data, conf->upstream_host.len);
        p[base_len] = '\0';
        conf->upstream_url_base.data = p;
        conf->upstream_url_base.len  = base_len;
    }

    /* Store the resolved address */
    conf->upstream_resolved = ngx_pcalloc(cf->pool,
                                          sizeof(ngx_http_upstream_resolved_t));
    if (conf->upstream_resolved == NULL) return NGX_ERROR;

    conf->upstream_resolved->sockaddr = u.addrs[0].sockaddr;
    conf->upstream_resolved->socklen  = u.addrs[0].socklen;
    conf->upstream_resolved->naddrs   = 1;
    conf->upstream_resolved->host     = u.host;
    conf->upstream_resolved->port     = u.port;

    /* Set sensible upstream_conf defaults (connect/send/read timeouts, buffer) */
    if (conf->upstream_conf.connect_timeout == 0) {
        conf->upstream_conf.connect_timeout = 60000;   /* 60 s */
    }
    if (conf->upstream_conf.send_timeout == 0) {
        conf->upstream_conf.send_timeout = 60000;
    }
    if (conf->upstream_conf.read_timeout == 0) {
        conf->upstream_conf.read_timeout = 60000;
    }
    if (conf->upstream_conf.buffer_size == 0) {
        conf->upstream_conf.buffer_size = (size_t) ngx_pagesize;
    }

    conf->upstream_conf.buffering       = 0;   /* pass-through, no temp files */
    conf->upstream_conf.bufs.num        = 8;
    conf->upstream_conf.bufs.size       = (size_t) ngx_pagesize;
    conf->upstream_conf.busy_buffers_size       = 2 * ngx_pagesize;
    conf->upstream_conf.max_temp_file_size      = 0;
    conf->upstream_conf.temp_file_write_size    = 0;
    /* hide_headers_hash left zeroed → nothing hidden */

#if (NGX_HTTP_SSL)
    if (conf->upstream_ssl) {
        ngx_ssl_t *ssl;

        ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
        if (ssl == NULL) return NGX_ERROR;
        ssl->log = cf->log;

        if (ngx_ssl_create(ssl,
                NGX_SSL_TLSv1 | NGX_SSL_TLSv1_1 | NGX_SSL_TLSv1_2
                    | NGX_SSL_TLSv1_3,
                NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }

        conf->upstream_ssl_ctx        = ssl;
        conf->upstream_conf.ssl       = ssl;
        conf->upstream_conf.ssl_verify = 0;  /* internal backend; no CA needed */
    }
#endif

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "xrootd_webdav_proxy: upstream \"%V\" → %V (ssl=%d)",
                  &url, &conf->upstream_url_base, (int) conf->upstream_ssl);

    return NGX_OK;
}

/* ---- entry point --------------------------------------------------------- */

ngx_int_t
webdav_proxy_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_http_upstream_t               *u;
    webdav_proxy_ctx_t                *ctx;
    ngx_int_t                          rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    u = r->upstream;

    ctx = ngx_pcalloc(r->pool, sizeof(webdav_proxy_ctx_t));
    if (ctx == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_http_set_ctx(r, ctx, ngx_http_xrootd_webdav_module);

    u->conf      = &conf->upstream_conf;
    u->buffering = conf->upstream_conf.buffering;

    u->create_request   = webdav_proxy_create_request;
    u->reinit_request   = webdav_proxy_reinit_request;
    u->process_header   = webdav_proxy_process_status_line;
    u->abort_request    = webdav_proxy_abort_request;
    u->finalize_request = webdav_proxy_finalize_request;

    /* Copy pre-resolved upstream address into the per-request resolved struct */
    u->resolved = ngx_palloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    *u->resolved = *conf->upstream_resolved;

#if (NGX_HTTP_SSL)
    if (conf->upstream_ssl) {
        r->upstream->ssl = 1;
    }
#endif

    r->request_body_no_buffering = 0;
    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    return NGX_DONE;
}
