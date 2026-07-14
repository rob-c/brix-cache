/*
 * http_mirror_config.c — config-time wiring for the Phase 24 HTTP/WebDAV traffic
 * mirror (see http_mirror.h).
 *
 * WHAT: Owns the merge-time upstream-conf builder (timeouts, buffers, TLS ctx,
 * hide-headers hash) and the two directive setters `brix_mirror_url` (append a
 * resolved shadow target) and `brix_mirror_methods` (parse the method mask).
 * WHY: split out of http_mirror.c (phase-79 file-size cap) so all config-plane
 * code — which runs only at nginx configuration time and shares nothing with the
 * request-time path — lives in one focused file.
 * HOW: brix_http_mirror_setup() is called from the WebDAV loc-conf merge; the two
 * setters are registered in the WebDAV directive table (src/webdav/module.c) and
 * populate conf->mirror.  All three are declared in http_mirror.h.
 */
#include "http_mirror.h"


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
