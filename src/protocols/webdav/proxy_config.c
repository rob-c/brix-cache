/*
 * proxy_config.c - WebDAV upstream URL parsing and proxy backend resolution.
 *
 * Phase 21 Step D extends the original single-upstream parser into a
 * multi-backend builder: every URL in conf->upstream_urls (or the legacy
 * single conf->upstream_url) is resolved at configuration time, and each
 * resolved address becomes one xrootd_webdav_backend_t carrying its own Host:
 * header value, request-line URL base, and TLS flag.  proxy.c round-robins
 * across the resulting backend array with passive health tracking; the legacy
 * conf->upstream_{host,url_base,resolved,ssl} fields are aliased to backend[0]
 * so any older reader still sees a valid single backend.
 */

#include "proxy_internal.h"
#include "core/compat/host_format.h"  /* xrootd_format_host[_port] — IPv6 bracketing */
#include "core/compat/log_diag.h"

/*
 * Resolve one upstream URL and append one backend per resolved address.
 * All addresses of a single URL share that URL's host/url_base/ssl.
 */
static ngx_int_t
webdav_proxy_add_url(ngx_conf_t *cf, ngx_http_xrootd_webdav_loc_conf_t *conf,
    ngx_str_t *url)
{
    ngx_url_t                u;
    u_char                  *p;
    in_port_t                default_port;
    size_t                   scheme_len;
    ngx_flag_t               ssl;
    ngx_str_t                host;
    ngx_str_t                url_base;
    ngx_uint_t               a;
    xrootd_webdav_backend_t *be;

    if (url->len == 0) {
        XROOTD_DIAG_CONF(NGX_LOG_EMERG, cf, 0,
            "xrootd_webdav_proxy: no upstream URL given",
            "the directive was used without a backend URL argument",
            "supply the backend, e.g. xrootd_webdav_proxy https://backend:1094;");
        return NGX_ERROR;
    }

    if (ngx_strncasecmp(url->data, (u_char *) "https://", 8) == 0) {
        ssl = 1; scheme_len = 8; default_port = 443;
    } else if (ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        ssl = 0; scheme_len = 7; default_port = 80;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_webdav_proxy: upstream URL \"%V\" must start with"
            " http:// or https://", url);
        return NGX_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url.data     = url->data + scheme_len;
    u.url.len      = url->len  - scheme_len;
    u.uri_part     = 1;
    u.default_port = default_port;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_webdav_proxy: \"%V\" in upstream URL \"%V\"",
                &u.err, url);
        }
        return NGX_ERROR;
    }
    if (u.naddrs == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_webdav_proxy: upstream URL \"%V\" resolved to zero"
            " addresses", url);
        return NGX_ERROR;
    }

    /* Host: header value — "host" or "host:port", with IPv6 literals bracketed.
     * ngx_parse_url strips the brackets off "[::1]", so u.host arrives bare and
     * must be re-bracketed ("[::1]") before it is re-emitted in a Host header. */
    {
        char   hostz[256], fmt[288];
        size_t hn, fn;

        hn = ngx_min(u.host.len, sizeof(hostz) - 1);
        ngx_memcpy(hostz, u.host.data, hn);
        hostz[hn] = '\0';

        if (u.port == default_port) {
            fn = xrootd_format_host(hostz, fmt, sizeof(fmt));
        } else {
            fn = xrootd_format_host_port(hostz, (uint16_t) u.port,
                                         fmt, sizeof(fmt));
        }

        p = ngx_pnalloc(cf->pool, fn + 1);
        if (p == NULL) return NGX_ERROR;
        ngx_memcpy(p, fmt, fn);
        p[fn] = '\0';
        host.data = p;
        host.len  = fn;
    }

    /* Request-line base — "scheme://host[:port]". */
    {
        size_t base_len = scheme_len + host.len;
        p = ngx_pnalloc(cf->pool, base_len + 1);
        if (p == NULL) return NGX_ERROR;
        ngx_memcpy(p, url->data, scheme_len);
        ngx_memcpy(p + scheme_len, host.data, host.len);
        p[base_len] = '\0';
        url_base.data = p;
        url_base.len  = base_len;
    }

#if (NGX_HTTP_SSL)
    if (ssl && conf->upstream_ssl_ctx == NULL) {
        ngx_ssl_t *s = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
        if (s == NULL) return NGX_ERROR;
        s->log = cf->log;
        if (ngx_ssl_create(s,
                NGX_SSL_TLSv1 | NGX_SSL_TLSv1_1 | NGX_SSL_TLSv1_2
                    | NGX_SSL_TLSv1_3, NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
        conf->upstream_ssl_ctx = s;        /* shared across https backends */
    }
#endif

    for (a = 0; a < u.naddrs; a++) {
        be = ngx_array_push(conf->upstream_backends);
        if (be == NULL) return NGX_ERROR;
        ngx_memzero(be, sizeof(*be));

        be->resolved.sockaddr = u.addrs[a].sockaddr;
        be->resolved.socklen  = u.addrs[a].socklen;
        be->resolved.naddrs   = 1;
        be->resolved.host     = u.host;
        be->resolved.port     = u.port;
        be->host              = host;
        be->url_base          = url_base;
        be->ssl               = ssl;
#if (NGX_HTTP_SSL)
        be->ssl_ctx           = ssl ? conf->upstream_ssl_ctx : NULL;
#endif
    }

    return NGX_OK;
}

ngx_int_t
webdav_proxy_build_backends(ngx_conf_t *cf,
    ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    xrootd_webdav_backend_t *be0;

    conf->upstream_backends = ngx_array_create(cf->pool, 4,
                                               sizeof(xrootd_webdav_backend_t));
    if (conf->upstream_backends == NULL) {
        return NGX_ERROR;
    }

    if (conf->upstream_urls != NULL && conf->upstream_urls->nelts > 0) {
        ngx_str_t  *urls = conf->upstream_urls->elts;
        ngx_uint_t  i;
        for (i = 0; i < conf->upstream_urls->nelts; i++) {
            if (webdav_proxy_add_url(cf, conf, &urls[i]) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    } else if (conf->upstream_url.len > 0) {
        if (webdav_proxy_add_url(cf, conf, &conf->upstream_url) != NGX_OK) {
            return NGX_ERROR;
        }
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd_webdav_proxy: missing upstream URL");
        return NGX_ERROR;
    }

    if (conf->upstream_backends->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd_webdav_proxy: no usable backends");
        return NGX_ERROR;
    }

    /* upstream_conf defaults (shared by all backends). */
    if (conf->upstream_conf.connect_timeout == 0) {
        conf->upstream_conf.connect_timeout = 60000;
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
    conf->upstream_conf.buffering            = 0;
    conf->upstream_conf.bufs.num             = 8;
    conf->upstream_conf.bufs.size            = (size_t) ngx_pagesize;
    conf->upstream_conf.busy_buffers_size    = 2 * ngx_pagesize;
    conf->upstream_conf.max_temp_file_size   = 0;
    conf->upstream_conf.temp_file_write_size = 0;
#if (NGX_HTTP_SSL)
    if (conf->upstream_ssl_ctx != NULL) {
        conf->upstream_conf.ssl        = conf->upstream_ssl_ctx;
        conf->upstream_conf.ssl_verify = 0;   /* internal backend; no CA */
    }
#endif

    /* Legacy aliases point at the first backend. */
    be0 = (xrootd_webdav_backend_t *) conf->upstream_backends->elts;
    conf->upstream_host     = be0->host;
    conf->upstream_url_base = be0->url_base;
    conf->upstream_ssl      = be0->ssl;
    conf->upstream_resolved = &be0->resolved;

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "xrootd_webdav_proxy: %ui backend(s); primary %V (ssl=%d)",
                  conf->upstream_backends->nelts,
                  &conf->upstream_url_base, (int) conf->upstream_ssl);

    return NGX_OK;
}

/* Backward-compatible single-entry parser — delegates to the builder. */
ngx_int_t
webdav_proxy_parse_upstream_url(ngx_conf_t *cf,
    ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    return webdav_proxy_build_backends(cf, conf);
}

/*
 * Phase 23 — configure proxy mode for the dynamic SHM pool.  Unlike
 * build_backends, no static URL is parsed here: the pool lives in shared
 * memory and is populated at runtime via the admin REST API (it may
 * legitimately start empty).  We still must (1) create the SHM zone, (2)
 * establish upstream_conf defaults shared by every backend, (3) create a TLS
 * context up front because runtime-added backends may be https, and (4) build
 * the hide-headers hash so nginx's upstream header processing has a non-empty
 * hash to probe (an empty hash divides by zero on the first response).
 */
ngx_int_t
webdav_proxy_pool_setup(ngx_conf_t *cf,
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    ngx_http_xrootd_webdav_loc_conf_t *prev)
{
    static ngx_str_t  webdav_proxy_hide_headers[] = { ngx_null_string };
    ngx_hash_init_t   hh;

    if (xrootd_proxy_pool_configure(cf) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd_webdav_proxy_dynamic: shared zone setup"
                           " failed");
        return NGX_ERROR;
    }

    /* upstream_conf defaults (shared by all backends). */
    if (conf->upstream_conf.connect_timeout == 0) {
        conf->upstream_conf.connect_timeout = 60000;
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
    conf->upstream_conf.buffering            = 0;
    conf->upstream_conf.bufs.num             = 8;
    conf->upstream_conf.bufs.size            = (size_t) ngx_pagesize;
    conf->upstream_conf.busy_buffers_size    = 2 * ngx_pagesize;
    conf->upstream_conf.max_temp_file_size   = 0;
    conf->upstream_conf.temp_file_write_size = 0;

#if (NGX_HTTP_SSL)
    /* Runtime-added backends may be https — create the shared TLS context now. */
    if (conf->upstream_ssl_ctx == NULL) {
        ngx_ssl_t *s = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
        if (s == NULL) return NGX_ERROR;
        s->log = cf->log;
        if (ngx_ssl_create(s,
                NGX_SSL_TLSv1 | NGX_SSL_TLSv1_1 | NGX_SSL_TLSv1_2
                    | NGX_SSL_TLSv1_3, NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
        conf->upstream_ssl_ctx = s;
    }
    conf->upstream_conf.ssl        = conf->upstream_ssl_ctx;
    conf->upstream_conf.ssl_verify = 0;   /* internal backend; no CA */
#endif

    hh.max_size    = 512;
    hh.bucket_size = ngx_align(64, ngx_cacheline_size);
    hh.name        = "webdav_proxy_hide_headers_hash";
    hh.pool        = cf->pool;
    hh.temp_pool   = NULL;
    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream_conf,
            &prev->upstream_conf, webdav_proxy_hide_headers, &hh) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "xrootd_webdav_proxy_dynamic: SHM pool configured"
                  " (backends added at runtime via admin API)");
    return NGX_OK;
}
