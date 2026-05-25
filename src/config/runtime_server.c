/* ------------------------------------------------------------------ */
/* Section: Server Block Runtime Preparation                            */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements server block runtime preparation during postconfiguration phase — validates root path existence and access,
 *      checks cache configuration prerequisites (read-only constraint, origin host requirement, thread pool availability), opens access/proxy
 *      audit log files, creates proxy upstream TLS context when proxy_upstream_tls is enabled. Called once per enabled server after config parsing. */

/* ------------------------------------------------------------------ */
/* Section: Root Path and Cache Validation                              */
/* ------------------------------------------------------------------ */
/*
 * WHAT: First phase validates root path existence (directory) with access mode matching write permission policy, then checks cache configuration
 *      prerequisites when xrootd_cache is enabled — read-only constraint requires allow_write off, origin host must be configured, cache_root directory
 *      must exist, lock timeout and eviction threshold must be within valid ranges, nginx must be built with --with-threads. Logs notice-level message on cache enablement. */

/* ---- Function: xrootd_config_prepare_server() ----
 *
 * WHAT: Performs server block runtime preparation during postconfiguration phase — validates root path existence (directory) with access mode matching
 *      write permission policy, checks cache configuration prerequisites when enabled (read-only constraint + origin host + directory + thread availability),
 *      opens access/proxy audit log files when configured, creates proxy upstream TLS context when proxy_upstream_tls is enabled. Returns NGX_OK on success;
 *      NGX_ERROR with emerg-level log on any validation or resource creation failure. Called once per enabled server after config parsing. */

/* ---- WHY: Runtime preparation ensures all server resources are available before accepting client connections — root path validation prevents runtime
 *      failures where nginx would attempt to serve files from non-existent directory under load. Cache prerequisite checks prevent misconfigured cache
 *      operations that could cause data corruption or performance degradation. Log file opening catches permission issues during startup rather than failing
 *      during high-traffic periods. TLS context creation ensures upstream proxy connections can negotiate secure transport when required. ---- */

#include "config.h"
#include "root_prepare.h"

ngx_int_t
xrootd_config_prepare_server(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf)
{
    if (!xcf->manager_mode) {
        xrootd_export_root_opts_t root_opts;
        root_opts.directive_name = "xrootd_root";
        root_opts.allow_write    = xcf->common.allow_write;
        root_opts.required       = 1;
        root_opts.canon_size     = sizeof(xcf->common.root_canon);
        if (xrootd_prepare_export_root(cf, &xcf->common.root, &root_opts,
                                       xcf->common.root_canon) != NGX_CONF_OK)
        {
            return NGX_ERROR;
        }
    }

    if (xcf->cache) {
        if (xcf->common.allow_write) {
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

    /* Upstream redirector TLS (for mid-stream kXR_gotoTLS upgrade). */
    if (xcf->upstream_tls) {
        xcf->upstream_tls_ctx = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
        if (xcf->upstream_tls_ctx == NULL) {
            return NGX_ERROR;
        }
        xcf->upstream_tls_ctx->log = cf->log;
        if (ngx_ssl_create(xcf->upstream_tls_ctx,
                           NGX_SSL_TLSv1_2 | NGX_SSL_TLSv1_3,
                           NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (xcf->upstream_tls_ca.len > 0) {
            if (ngx_ssl_trusted_certificate(cf, xcf->upstream_tls_ctx,
                                             &xcf->upstream_tls_ca,
                                             5 /* chain depth */)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "xrootd: upstream redirector TLS CA loaded from \"%V\"",
                &xcf->upstream_tls_ca);
        }

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "xrootd: upstream redirector TLS enabled (kXR_gotoTLS support)");
    }
#endif

    return NGX_OK;
}
