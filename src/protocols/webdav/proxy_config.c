/*
 * proxy_config.c - WebDAV upstream URL parsing and proxy backend resolution.
 *
 * Phase 21 Step D extends the original single-upstream parser into a
 * multi-backend builder: every URL in conf->upstream_urls (or the legacy
 * single conf->upstream_url) is resolved at configuration time, and each
 * resolved address becomes one brix_webdav_backend_t carrying its own Host:
 * header value, request-line URL base, and TLS flag.  proxy.c round-robins
 * across the resulting backend array with passive health tracking; the legacy
 * conf->upstream_{host,url_base,resolved,ssl} fields are aliased to backend[0]
 * so any older reader still sees a valid single backend.
 */

#include "proxy_internal.h"
#include "core/compat/host_format.h"  /* brix_format_host[_port] — IPv6 bracketing */
#include "core/compat/log_diag.h"

/* ---- Split "http://"/"https://" scheme off an upstream URL ----
 *
 * WHAT: Inspects url's scheme prefix and sets *ssl (1 for https, 0 for http),
 * *scheme_len (8 or 7), and *default_port (443 or 80).  Returns NGX_OK on a
 * recognised scheme, or NGX_ERROR (after logging) for an empty URL or an
 * unrecognised scheme.
 *
 * WHY: Isolates the scheme-classification branch ladder so the resolver's
 * control flow stays flat and the accepted-scheme table lives in one place.
 *
 * HOW:
 *   1. Reject a zero-length URL with the "no upstream URL given" diagnostic.
 *   2. Case-insensitively match "https://" → ssl=1, len=8, port=443.
 *   3. Otherwise match "http://" → ssl=0, len=7, port=80.
 *   4. Otherwise log the "must start with http:// or https://" error and fail.
 */
static ngx_int_t
webdav_proxy_split_scheme(ngx_conf_t *cf, ngx_str_t *url, ngx_flag_t *ssl,
    size_t *scheme_len, in_port_t *default_port)
{
    if (url->len == 0) {
        BRIX_DIAG_CONF(NGX_LOG_EMERG, cf, 0,
            "brix_webdav_proxy: no upstream URL given",
            "the directive was used without a backend URL argument",
            "supply the backend, e.g. brix_webdav_proxy https://backend:1094;");
        return NGX_ERROR;
    }

    if (ngx_strncasecmp(url->data, (u_char *) "https://", 8) == 0) {
        *ssl = 1; *scheme_len = 8; *default_port = 443;
        return NGX_OK;
    }
    if (ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        *ssl = 0; *scheme_len = 7; *default_port = 80;
        return NGX_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "brix_webdav_proxy: upstream URL \"%V\" must start with"
        " http:// or https://", url);
    return NGX_ERROR;
}

/* ---- Parse the authority of an upstream URL into an ngx_url_t ----
 *
 * WHAT: Runs ngx_parse_url over the post-scheme portion of url with the given
 * default_port and fills *u.  Returns NGX_OK when at least one address is
 * resolved, otherwise NGX_ERROR (after logging the parse error or the
 * zero-address condition).
 *
 * WHY: Keeps the ngx_parse_url invocation plus its two failure diagnostics
 * together, out of the main resolver body.
 *
 * HOW:
 *   1. Zero *u and point it at url->data+scheme_len for uri_part parsing.
 *   2. On ngx_parse_url failure, emit u->err (if any) and fail.
 *   3. On zero resolved addresses, emit the "zero addresses" error and fail.
 */
static ngx_int_t
webdav_proxy_parse_authority(ngx_conf_t *cf, ngx_str_t *url, size_t scheme_len,
    in_port_t default_port, ngx_url_t *u)
{
    ngx_memzero(u, sizeof(ngx_url_t));
    u->url.data     = url->data + scheme_len;
    u->url.len      = url->len  - scheme_len;
    u->uri_part     = 1;
    u->default_port = default_port;

    if (ngx_parse_url(cf->pool, u) != NGX_OK) {
        if (u->err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_webdav_proxy: \"%V\" in upstream URL \"%V\"",
                &u->err, url);
        }
        return NGX_ERROR;
    }
    if (u->naddrs == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_webdav_proxy: upstream URL \"%V\" resolved to zero"
            " addresses", url);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* ---- Build the pool-owned Host: header value for a resolved upstream ----
 *
 * WHAT: Formats "host" or "host:port" (IPv6 literals re-bracketed) into a
 * fresh cf->pool allocation and stores it in *host.  Returns NGX_OK, or
 * NGX_ERROR on allocation failure.
 *
 * WHY: ngx_parse_url strips the brackets off "[::1]", so u->host arrives bare
 * and must be re-bracketed before it is re-emitted in a Host header; the port
 * is elided when it equals the scheme default.
 *
 * HOW:
 *   1. NUL-terminate a bounded copy of u->host into a stack buffer.
 *   2. Format host-only when u->port == default_port, else host:port.
 *   3. Copy the formatted bytes into a cf->pool allocation and record .len.
 */
static ngx_int_t
webdav_proxy_build_host(ngx_conf_t *cf, ngx_url_t *u, in_port_t default_port,
    ngx_str_t *host)
{
    char    hostz[256], fmt[288];
    size_t  hn, fn;
    u_char *p;

    hn = ngx_min(u->host.len, sizeof(hostz) - 1);
    ngx_memcpy(hostz, u->host.data, hn);
    hostz[hn] = '\0';

    if (u->port == default_port) {
        fn = brix_format_host(hostz, fmt, sizeof(fmt));
    } else {
        fn = brix_format_host_port(hostz, (uint16_t) u->port,
                                     fmt, sizeof(fmt));
    }

    p = ngx_pnalloc(cf->pool, fn + 1);
    if (p == NULL) return NGX_ERROR;
    ngx_memcpy(p, fmt, fn);
    p[fn] = '\0';
    host->data = p;
    host->len  = fn;
    return NGX_OK;
}

/* ---- Build the pool-owned request-line base "scheme://host[:port]" ----
 *
 * WHAT: Concatenates url's scheme prefix with the already-formatted host into
 * a fresh cf->pool allocation and stores it in *url_base.  Returns NGX_OK, or
 * NGX_ERROR on allocation failure.
 *
 * WHY: Backends emit absolute request-line URLs; the scheme+authority base is
 * computed once here and reused for every address of this URL.
 *
 * HOW:
 *   1. Allocate scheme_len + host->len + 1 bytes from cf->pool.
 *   2. Copy the scheme prefix, then the formatted host, then NUL-terminate.
 */
static ngx_int_t
webdav_proxy_build_url_base(ngx_conf_t *cf, ngx_str_t *url, size_t scheme_len,
    ngx_str_t *host, ngx_str_t *url_base)
{
    u_char *p;
    size_t  base_len = scheme_len + host->len;

    p = ngx_pnalloc(cf->pool, base_len + 1);
    if (p == NULL) return NGX_ERROR;
    ngx_memcpy(p, url->data, scheme_len);
    ngx_memcpy(p + scheme_len, host->data, host->len);
    p[base_len] = '\0';
    url_base->data = p;
    url_base->len  = base_len;
    return NGX_OK;
}

/* ---- Lazily create the TLS context shared by all https backends ----
 *
 * WHAT: When ssl is set and conf has no upstream_ssl_ctx yet, creates one
 * cf->pool ngx_ssl_t covering TLSv1 through TLSv1.3 and stores it on conf.
 * Returns
 * NGX_OK (including the no-op non-ssl / already-present cases), or NGX_ERROR
 * on allocation or ngx_ssl_create failure.
 *
 * WHY: One shared client TLS context serves every https backend; creating it
 * once keeps the resolver flat and avoids per-backend contexts.  On builds
 * without NGX_HTTP_SSL this is a no-op.
 *
 * HOW:
 *   1. Do nothing unless ssl is set and no context exists yet.
 *   2. Allocate and initialise an ngx_ssl_t, then publish it on conf.
 */
static ngx_int_t
webdav_proxy_ensure_ssl_ctx(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_flag_t ssl)
{
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
#else
    (void) cf; (void) conf; (void) ssl;
#endif
    return NGX_OK;
}

/* ---- Append one backend per resolved address of a single URL ----
 *
 * WHAT: Pushes u->naddrs entries onto conf->upstream_backends, each carrying
 * one resolved address plus the shared host/url_base/ssl (and ssl_ctx).
 * Returns NGX_OK, or NGX_ERROR if ngx_array_push fails.
 *
 * WHY: All addresses of a single URL share that URL's host/url_base/ssl; this
 * loop materialises one round-robin-able backend per address.
 *
 * HOW:
 *   1. For each address, push and zero a backend slot.
 *   2. Copy the address into a single-address resolved view.
 *   3. Alias the shared host/url_base/ssl (and, when built with TLS, ssl_ctx).
 */
static ngx_int_t
webdav_proxy_push_backends(ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_url_t *u, ngx_str_t *host, ngx_str_t *url_base, ngx_flag_t ssl)
{
    ngx_uint_t              a;
    brix_webdav_backend_t  *be;

    for (a = 0; a < u->naddrs; a++) {
        be = ngx_array_push(conf->upstream_backends);
        if (be == NULL) return NGX_ERROR;
        ngx_memzero(be, sizeof(*be));

        be->resolved.sockaddr = u->addrs[a].sockaddr;
        be->resolved.socklen  = u->addrs[a].socklen;
        be->resolved.naddrs   = 1;
        be->resolved.host     = u->host;
        be->resolved.port     = u->port;
        be->host              = *host;
        be->url_base          = *url_base;
        be->ssl               = ssl;
#if (NGX_HTTP_SSL)
        be->ssl_ctx           = ssl ? conf->upstream_ssl_ctx : NULL;
#endif
    }

    return NGX_OK;
}

/* ---- Resolve one upstream URL and append its backends ----
 *
 * WHAT: Parses url (scheme + authority), formats its Host header and
 * request-line base, ensures the shared https TLS context exists, and appends
 * one brix_webdav_backend_t per resolved address.  Returns NGX_OK, or
 * NGX_ERROR (after logging) on any parse or allocation failure.
 *
 * WHY: All addresses of a single URL share that URL's host/url_base/ssl; this
 * orchestrator runs the resolution steps in order, keeping each concern in its
 * own testable helper.
 *
 * HOW:
 *   1. Split the http/https scheme.
 *   2. Parse the authority into an ngx_url_t (>=1 address).
 *   3. Build the Host header value and the request-line base.
 *   4. Ensure the shared TLS context for https backends.
 *   5. Push one backend per resolved address.
 */
static ngx_int_t
webdav_proxy_add_url(ngx_conf_t *cf, ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_str_t *url)
{
    ngx_url_t   u;
    in_port_t   default_port = 0;
    size_t      scheme_len = 0;
    ngx_flag_t  ssl = 0;
    ngx_str_t   host;
    ngx_str_t   url_base;

    if (webdav_proxy_split_scheme(cf, url, &ssl, &scheme_len,
            &default_port) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (webdav_proxy_parse_authority(cf, url, scheme_len, default_port, &u)
            != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (webdav_proxy_build_host(cf, &u, default_port, &host) != NGX_OK) {
        return NGX_ERROR;
    }

    if (webdav_proxy_build_url_base(cf, url, scheme_len, &host, &url_base)
            != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (webdav_proxy_ensure_ssl_ctx(cf, conf, ssl) != NGX_OK) {
        return NGX_ERROR;
    }

    return webdav_proxy_push_backends(conf, &u, &host, &url_base, ssl);
}

ngx_int_t
webdav_proxy_build_backends(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    brix_webdav_backend_t *be0;

    conf->upstream_backends = ngx_array_create(cf->pool, 4,
                                               sizeof(brix_webdav_backend_t));
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
                           "brix_webdav_proxy: missing upstream URL");
        return NGX_ERROR;
    }

    if (conf->upstream_backends->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_webdav_proxy: no usable backends");
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
    be0 = (brix_webdav_backend_t *) conf->upstream_backends->elts;
    conf->upstream_host     = be0->host;
    conf->upstream_url_base = be0->url_base;
    conf->upstream_ssl      = be0->ssl;
    conf->upstream_resolved = &be0->resolved;

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "brix_webdav_proxy: %ui backend(s); primary %V (ssl=%d)",
                  conf->upstream_backends->nelts,
                  &conf->upstream_url_base, (int) conf->upstream_ssl);

    return NGX_OK;
}

/* Backward-compatible single-entry parser — delegates to the builder. */
ngx_int_t
webdav_proxy_parse_upstream_url(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf)
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
    ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_loc_conf_t *prev)
{
    static ngx_str_t  webdav_proxy_hide_headers[] = { ngx_null_string };
    ngx_hash_init_t   hh;

    if (brix_proxy_pool_configure(cf) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_webdav_proxy_dynamic: shared zone setup"
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
                  "brix_webdav_proxy_dynamic: SHM pool configured"
                  " (backends added at runtime via admin API)");
    return NGX_OK;
}
