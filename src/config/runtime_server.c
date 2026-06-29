/*
 * runtime_server.c — per-server-block runtime preparation at postconfiguration.
 */

#include "config.h"
#include "root_prepare.h"
#include "../compat/staged_file.h"
#include "../fs/vfs_backend_registry.h"   /* per-export backend registration */

/* Prepare one server block at postconfiguration: validate the configured root
 * is an existing, accessible directory (access mode matching the write policy)
 * and check the cache configuration, before the block accepts connections.
 * Returns NGX_OK, or NGX_ERROR (emerg-logged) on any invalid resource. */
ngx_int_t
xrootd_config_prepare_server(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf)
{
    if (!xcf->manager_mode && !xcf->supervisor
        && xcf->manager_map == NULL && !xcf->proxy_enable) {
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

        /* Register the export's selected storage backend for VFS resolution at
         * request time. A "root://host:port" / "roots://host:port" value makes the
         * export's PRIMARY storage a REMOTE XRootD server (read + write through the
         * sd_xroot driver); a driver name (e.g. "pblock") selects a local backend;
         * the default POSIX backend is a no-op. */
        {
            ngx_str_t *sb = &xcf->common.storage_backend;
            u_char    *addr = NULL;
            size_t     addrn = 0;
            int        is_roots = 0;

            if (sb->len > sizeof("roots://") - 1
                && ngx_strncmp(sb->data, "roots://", sizeof("roots://") - 1) == 0)
            {
                addr = sb->data + sizeof("roots://") - 1;
                addrn = sb->len - (sizeof("roots://") - 1);
                is_roots = 1;
            } else if (sb->len > sizeof("root://") - 1
                && ngx_strncmp(sb->data, "root://", sizeof("root://") - 1) == 0)
            {
                addr = sb->data + sizeof("root://") - 1;
                addrn = sb->len - (sizeof("root://") - 1);
            }

            if (addr != NULL) {
                /* Split "host:port" on the last colon (a bracketed [v6]:port host
                 * keeps the colon after the ']'). */
                u_char *colon = NULL;
                size_t  i, hostn;
                ngx_int_t portnum;
                u_char *hcopy;

                for (i = addrn; i > 0; i--) {
                    if (addr[i - 1] == ':') { colon = addr + i - 1; break; }
                }
                if (colon == NULL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "xrootd_storage_backend: remote origin needs host:port");
                    return NGX_ERROR;
                }
                hostn   = (size_t) (colon - addr);
                portnum = ngx_atoi(colon + 1,
                                   (size_t) (addr + addrn - (colon + 1)));
                if (hostn == 0 || portnum == NGX_ERROR
                    || portnum <= 0 || portnum > 65535)
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "xrootd_storage_backend: invalid remote origin host:port");
                    return NGX_ERROR;
                }

                hcopy = ngx_pnalloc(cf->pool, hostn);
                if (hcopy == NULL) {
                    return NGX_ERROR;
                }
                ngx_memcpy(hcopy, addr, hostn);
                xcf->cache_origin_host.data = hcopy;
                xcf->cache_origin_host.len  = hostn;
                xcf->cache_origin_port      = (uint16_t) portnum;
                xcf->cache_origin_tls       = is_roots ? 1 : 0;

                xrootd_vfs_backend_config_xroot(xcf->common.root_canon, xcf);
            } else {
                xrootd_vfs_backend_config(xcf->common.root_canon, sb,
                                          xcf->common.pblock_block_size);
            }
        }

        /* Optional fast-cache upload staging device.  Canonicalize once here; an
         * unset/empty value leaves upload_stage_dir_canon empty (stage adjacent
         * to the destination).  A configured-but-bad path fails config loudly. */
        if (xcf->upload_stage_dir.len > 0) {
            xrootd_export_root_opts_t stage_opts;
            stage_opts.directive_name = "xrootd_stage_dir";
            stage_opts.allow_write    = 1;
            stage_opts.required       = 0;
            stage_opts.canon_size     = sizeof(xcf->upload_stage_dir_canon);
            if (xrootd_prepare_export_root(cf, &xcf->upload_stage_dir,
                    &stage_opts, xcf->upload_stage_dir_canon) != NGX_CONF_OK)
            {
                return NGX_ERROR;
            }
            /* Track for the stage-out reaper (finishes interrupted cache->storage
             * commits across restarts). */
            xrootd_stage_dir_register(xcf->upload_stage_dir_canon);
        }
    }

    if (xcf->cache) {
        /* The read-through cache is read-only UNLESS write-through is enabled,
         * in which case write handles are accepted and mirrored to the origin
         * at kXR_sync/kXR_close (see src/cache/writethrough_flush.c). */
        if (xcf->common.allow_write && !xcf->wt_enable) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_cache is read-only and requires "
                "xrootd_allow_write off (or enable xrootd_write_through)");
            return NGX_ERROR;
        }

        /* A driver-backed read cache keeps its bytes in the storage backend, so
         * its POSIX .meta/.cinfo sidecars cannot live under cache_root — require a
         * distinct xrootd_cache_state_root. Then register the backend keyed on the
         * cache root for VFS resolution (no-op for the default POSIX backend). */
        if (xcf->cache_storage_backend.len > 0) {
            if (xcf->cache_state_root.len == 0
                || (xcf->cache_state_root.len == xcf->cache_root.len
                    && ngx_strncmp(xcf->cache_state_root.data,
                                   xcf->cache_root.data,
                                   xcf->cache_root.len) == 0))
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_cache_storage_backend requires a distinct POSIX "
                    "xrootd_cache_state_root (sidecars cannot live in a "
                    "driver-backed cache_root)");
                return NGX_ERROR;
            }
            xrootd_vfs_backend_config((const char *) xcf->cache_root.data,
                                      &xcf->cache_storage_backend,
                                      xcf->cache_storage_block_size);
        }

        /* Write-back staging cache backend (its own root). Same sidecar rule. */
        if (xcf->cache_wt_stage_backend.len > 0) {
            if (xcf->cache_wt_stage_root.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_cache_wt_stage_backend requires "
                    "xrootd_cache_wt_stage_root");
                return NGX_ERROR;
            }
            if (xcf->cache_state_root.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_cache_wt_stage_backend requires a POSIX "
                    "xrootd_cache_state_root for its sidecars");
                return NGX_ERROR;
            }
            xrootd_vfs_backend_config((const char *) xcf->cache_wt_stage_root.data,
                                      &xcf->cache_wt_stage_backend,
                                      xcf->cache_wt_stage_block_size);
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

        /* Watermark reaper ordering: 0 < low < high < 1.0. Defaults already
         * satisfy this; an explicit pair that inverts it is a config error. */
        if (xcf->cache_high_watermark == 0
            || xcf->cache_high_watermark >= 1000000
            || xcf->cache_low_watermark == 0
            || xcf->cache_low_watermark >= xcf->cache_high_watermark)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_cache_low_watermark must be greater than 0 and less "
                "than xrootd_cache_high_watermark (which must be < 1.0)");
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

    /* Write-back-staging backpressure validation. Independent of the read cache —
     * write-through staging exists whenever xrootd_write_through is on, so this
     * runs at the server level. When a HIGH watermark is set it needs a staging
     * root to measure, and the pair must satisfy 0 < low < high < 1.0. */
    if (xcf->cache_wt_stage_high_watermark > 0) {
        if (xcf->cache_wt_stage_root.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_wt_stage_high_watermark requires "
                "xrootd_cache_wt_stage_root");
            return NGX_ERROR;
        }
        if (xcf->cache_wt_stage_high_watermark >= 1000000
            || xcf->cache_wt_stage_low_watermark == 0
            || xcf->cache_wt_stage_low_watermark
                   >= xcf->cache_wt_stage_high_watermark)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_wt_stage_low_watermark must be greater than 0 and "
                "less than xrootd_wt_stage_high_watermark (which must be < 1.0)");
            return NGX_ERROR;
        }
    }

    /*
     * Access log handling mirrors nginx conventions: empty means disabled by
     * default, the literal string "off" suppresses logging explicitly, and
     * any other value is treated as the path to append to.
     */
    if (xcf->access_log.len > 0
        && ngx_strcmp(xcf->access_log.data, (u_char *) "off") != 0)
    {
        /*
         * Register the log with nginx (cycle->open_files) rather than opening a
         * raw fd here.  The master opens it during ngx_init_cycle, reopens it on
         * USR1 (dup2 onto the same fd number), and closes it cleanly when the
         * cycle is torn down — so log rotation and `nginx -s reload` no longer
         * leak fds or keep writing to a rotated inode.  Each worker captures
         * file->fd into access_log_fd in init_process (the fd is not yet open at
         * this config-time point).
         */
        xcf->access_log_file = ngx_conf_open_file(cf->cycle, &xcf->access_log);
        if (xcf->access_log_file == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd: cannot register access log \"%V\"",
                &xcf->access_log);
            return NGX_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "xrootd: access log \"%V\" registered",
            &xcf->access_log);
    }

    if (xcf->proxy_enable
        && xcf->proxy_audit_log.len > 0
        && ngx_strcmp(xcf->proxy_audit_log.data, (u_char *) "off") != 0)
    {
        /* nginx-managed handle; see the access-log note above. */
        xcf->proxy_audit_log_file = ngx_conf_open_file(cf->cycle,
                                                       &xcf->proxy_audit_log);
        if (xcf->proxy_audit_log_file == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd: cannot register proxy audit log \"%V\"",
                &xcf->proxy_audit_log);
            return NGX_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "xrootd: proxy audit log \"%V\" registered",
            &xcf->proxy_audit_log);
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
