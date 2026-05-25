/*
 * proxy_config.c - WebDAV upstream URL parsing and proxy configuration defaults.
 *
 * WHAT: Parse and validate upstream HTTP/HTTPS URL for WebDAV Perimeter Proxy mode — resolves DNS, determines SSL flag, allocates resolved address structure, sets sensible timeout/buffering defaults, creates upstream SSL context when backend requires HTTPS. Called during postconfiguration phase to prepare nginx upstream infrastructure before proxy handler can relay operations.
 *
 * WHY: Proxy mode requires pre-resolving the backend URL at configuration time (not per-request) to avoid DNS lookup latency on every WebDAV operation. This function validates that upstream_url directive contains valid http:// or https:// scheme, parses host+port via nginx ngx_parse_url() helper, allocates conf->upstream_resolved structure with resolved sockaddr for proxy handler's u->resolved copy (per proxy.c). Default timeouts of 60 seconds prevent hung connections in production deployments. SSL context creation under NGX_HTTP_SSL macro enables backend HTTPS connection without requiring CA certificate verification (conf->upstream_conf.ssl_verify=0 — internal trust model per README.md Mode 3: "forward to HTTP/HTTPS backend").
 *
 * HOW: First validates url.len > 0 or logs NGX_LOG_EMERG error. Second, determines scheme via ngx_strncasecmp() comparison: https:// (8 bytes, ssl=1, port=443) vs http:// (7 bytes, ssl=0, port=80). Third, constructs ngx_url_t with url.data offset by scheme_len, uri_part=1 for URI extraction, default_port for implicit port handling. Fourth calls ngx_parse_url(cf->pool, &u) parsing host+port from URL remainder — logs error if u.err present or naddrs==0 (DNS resolution failed). Fifth constructs upstream_host: uses plain u.host when port matches default, otherwise allocates "host:port" string via ngx_sprintf for Host: header generation. Sixth builds upstream_url_base ("scheme://host") by concatenating scheme + host for request URL construction. Seventh allocates upstream_resolved structure via ngx_pcalloc storing first resolved address sockaddr/socklen/host/port for proxy handler's u->resolved copy (per proxy.c). Eighth sets sensible timeout defaults: connect/send/read=60000ms, buffer_size=ngx_pagesize, buffering=0 (pass-through no temp files), bufs.num=8+bufs.size=ngx_pagesize. Ninth under NGX_HTTP_SSL macro creates upstream_ssl_ctx via ngx_ssl_create() with TLSv1+v1_1+v1_2+v1_3 protocol flags, sets ssl_verify=0 for internal backend trust model without CA verification requirement. Finally logs NOTICE message showing URL->base mapping and ssl status. Returns NGX_OK on success or NGX_ERROR with emerg-level error log on any failure.
 */

#include "proxy_internal.h"

/*
 * WHAT: Parse upstream HTTP/HTTPS URL — resolve DNS, configure SSL flag, set timeout defaults for proxy mode deployment.
 *
 * WHY: Proxy mode requires pre-resolving backend URL at configuration time (not per-request) to avoid DNS lookup latency on every WebDAV operation. This function validates http:// or https:// scheme, parses host+port via nginx ngx_parse_url() helper, allocates conf->upstream_resolved structure with resolved sockaddr for proxy handler's u->resolved copy (per proxy.c). Default timeouts of 60 seconds prevent hung connections in production deployments. SSL context creation under NGX_HTTP_SSL macro enables backend HTTPS connection without requiring CA certificate verification (ssl_verify=0 — internal trust model per README.md Mode 3: "forward to HTTP/HTTPS backend").
 *
 * HOW: First validates url.len > 0 or logs NGX_LOG_EMERG error. Second determines scheme via ngx_strncasecmp() comparison: https:// (8 bytes, ssl=1, port=443) vs http:// (7 bytes, ssl=0, port=80). Third constructs ngx_url_t with url.data offset by scheme_len, uri_part=1 for URI extraction, default_port for implicit port handling. Fourth calls ngx_parse_url(cf->pool, &u) parsing host+port from URL remainder — logs error if u.err present or naddrs==0 (DNS resolution failed). Fifth constructs upstream_host: uses plain u.host when port matches default, otherwise allocates "host:port" string via ngx_sprintf for Host: header generation. Sixth builds upstream_url_base ("scheme://host") by concatenating scheme + host for request URL construction. Seventh allocates upstream_resolved structure via ngx_pcalloc storing first resolved address sockaddr/socklen/host/port for proxy handler's u->resolved copy (per proxy.c). Eighth sets sensible timeout defaults: connect/send/read=60000ms, buffer_size=ngx_pagesize, buffering=0 (pass-through no temp files), bufs.num=8+bufs.size=ngx_pagesize. Ninth under NGX_HTTP_SSL macro creates upstream_ssl_ctx via ngx_ssl_create() with TLSv1+v1_1+v1_2+v1_3 protocol flags, sets ssl_verify=0 for internal backend trust model without CA verification requirement. Finally logs NOTICE message showing URL->base mapping and ssl status. Returns NGX_OK on success or NGX_ERROR with emerg-level error log on any failure.
 */
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
    /* hide_headers_hash left zeroed -> nothing hidden */

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
                  "xrootd_webdav_proxy: upstream \"%V\" -> %V (ssl=%d)",
                  &url, &conf->upstream_url_base, (int) conf->upstream_ssl);

    return NGX_OK;
}
