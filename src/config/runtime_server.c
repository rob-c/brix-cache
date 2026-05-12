#include "config.h"

ngx_int_t
xrootd_config_prepare_server(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf)
{
    if (!xcf->manager_mode
        && xrootd_validate_path(cf, "xrootd_root", &xcf->root,
                                XROOTD_PATH_DIRECTORY,
                                xcf->allow_write ? (R_OK | W_OK | X_OK)
                                                 : (R_OK | X_OK))
               != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (xcf->cache) {
        if (xcf->allow_write) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_cache is read-only and requires "
                "xrootd_allow_write off");
            return NGX_ERROR;
        }

        if (xcf->cache_root.len == 0 || xcf->cache_origin_host.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_cache on requires xrootd_cache_root and "
                "xrootd_cache_origin");
            return NGX_ERROR;
        }

        if (xrootd_validate_path(cf, "xrootd_cache_root",
                                 &xcf->cache_root,
                                 XROOTD_PATH_DIRECTORY,
                                 R_OK | W_OK | X_OK)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (xcf->cache_lock_timeout <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_cache_lock_timeout must be greater than zero");
            return NGX_ERROR;
        }

        if (xcf->cache_eviction_threshold == 0
            || xcf->cache_eviction_threshold >= 1000000)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_cache_eviction_threshold must be greater than 0 "
                "and less than 1.0");
            return NGX_ERROR;
        }

#if !(NGX_THREADS)
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cache requires nginx built with --with-threads");
        return NGX_ERROR;
#endif

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "xrootd: cache enabled root=%V origin=%V tls=%s "
            "lock_timeout=%ds eviction_threshold=0.%06ui",
            &xcf->cache_root, &xcf->cache_origin,
            xcf->cache_origin_tls ? "on" : "off",
            (int) xcf->cache_lock_timeout,
            xcf->cache_eviction_threshold);
    }

    /*
     * Access log handling mirrors nginx conventions: empty means disabled by
     * default, the literal string "off" suppresses logging explicitly, and
     * any other value is treated as the path to append to.
     */
    if (xcf->access_log.len > 0
        && ngx_strcmp(xcf->access_log.data, (u_char *) "off") != 0)
    {
        xcf->access_log_fd = ngx_open_file(xcf->access_log.data,
            NGX_FILE_WRONLY,
            NGX_FILE_CREATE_OR_OPEN | NGX_FILE_APPEND,
            NGX_FILE_DEFAULT_ACCESS);

        if (xcf->access_log_fd == NGX_INVALID_FILE) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                "xrootd: cannot open access log \"%s\"",
                xcf->access_log.data);
            return NGX_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "xrootd: access log \"%s\" opened",
            xcf->access_log.data);
    }

    if (xcf->proxy_enable
        && xcf->proxy_audit_log.len > 0
        && ngx_strcmp(xcf->proxy_audit_log.data, (u_char *) "off") != 0)
    {
        xcf->proxy_audit_log_fd = ngx_open_file(xcf->proxy_audit_log.data,
            NGX_FILE_WRONLY,
            NGX_FILE_CREATE_OR_OPEN | NGX_FILE_APPEND,
            NGX_FILE_DEFAULT_ACCESS);

        if (xcf->proxy_audit_log_fd == NGX_INVALID_FILE) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                "xrootd: cannot open proxy audit log \"%s\"",
                xcf->proxy_audit_log.data);
            return NGX_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "xrootd: proxy audit log \"%s\" opened",
            xcf->proxy_audit_log.data);
    }

#if (NGX_SSL)
    if (xcf->proxy_enable && xcf->proxy_upstream_tls) {
        xcf->proxy_tls_ctx = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
        if (xcf->proxy_tls_ctx == NULL) {
            return NGX_ERROR;
        }
        xcf->proxy_tls_ctx->log = cf->log;
        if (ngx_ssl_create(xcf->proxy_tls_ctx,
                           NGX_SSL_TLSv1_2 | NGX_SSL_TLSv1_3,
                           NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }

        /* Peer certificate verification (optional; enabled by directive). */
        if (xcf->proxy_upstream_tls_ca.len > 0) {
            if (ngx_ssl_trusted_certificate(cf, xcf->proxy_tls_ctx,
                                             &xcf->proxy_upstream_tls_ca,
                                             5 /* chain depth */)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
            /* ngx_ssl_trusted_certificate sets SSL_VERIFY_PEER internally */
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "xrootd: proxy upstream TLS CA loaded from \"%V\"",
                &xcf->proxy_upstream_tls_ca);
        }
    }
#endif

    return NGX_OK;
}
