/*
 * runtime_server.c — per-server-block runtime preparation at postconfiguration.
 */

#include "config.h"
#include "root_prepare.h"
#include "credential_block.h"             /* §14 brix_credential lookup/bearer */
#include "core/compat/staged_file.h"
#include "core/compat/tmp_path.h"          /* SP4 orphan direct-write temp reaper */
#include "fs/vfs/vfs_backend_registry.h"   /* per-export backend registration */
#include "fs/path/path.h"                 /* brix_mkdir_recursive (pblock:// init) */
#include "fs/tier/tier.h"              /* phase-64 tier parse + cache/stage register */
#include "fs/cache/cache_internal.h"   /* brix_cache_state_root (effective sidecar tree) */
#include "core/config/export_guard.h"  /* brix_assert_dir_outside_export (hard guard) */

/*
 * Storage-backend root rewriting + phase-64 composable cache/stage tier
 * registration (brix_conf_set_store_slot, brix_storage_backend_posix_root,
 * brix_storage_backend_is_remote, brix_tier_register_stores) live in the sibling
 * runtime_server_backend.c; their prototypes are in shared_conf.h (via config.h).
 */

static int
brix_server_has_runtime_export(const ngx_stream_brix_srv_conf_t *xcf)
{
    return !xcf->manager_mode && !xcf->caps.supervisor
           && xcf->manager_map == NULL && !xcf->proxy.enable;
}

static int
brix_server_storage_backend_is_remote(const ngx_str_t *sb)
{
    return (sb->len > sizeof("root://") - 1
            && ngx_strncmp(sb->data, "root://", sizeof("root://") - 1) == 0)
           || (sb->len > sizeof("roots://") - 1
               && ngx_strncmp(sb->data, "roots://", sizeof("roots://") - 1) == 0)
           || (sb->len > sizeof("http://") - 1
               && ngx_strncmp(sb->data, "http://", sizeof("http://") - 1) == 0)
           || (sb->len > sizeof("https://") - 1
               && ngx_strncmp(sb->data, "https://", sizeof("https://") - 1) == 0);
}

static const char *
brix_server_cred_str_or_null(const ngx_str_t *s)
{
    return (s->len > 0) ? (const char *) s->data : NULL;
}

static void
brix_server_fill_x509_credential(const brix_credential_t *cred,
    brix_vfs_backend_cred_t *bcred)
{
    if (cred->x509_proxy.len > 0) {
        bcred->x509_proxy = (const char *) cred->x509_proxy.data;
        return;
    }
    if (cred->x509_cert.len > 0) {
        bcred->x509_proxy = (const char *) cred->x509_cert.data;
    }
    if (cred->x509_key.len > 0) {
        bcred->x509_key = (const char *) cred->x509_key.data;
    }
}

static ngx_int_t
brix_server_set_storage_credential(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    char                     cred_z[256];
    char                     bearer[4096];
    const brix_credential_t *cred;
    brix_vfs_backend_cred_t  bcred;

    if (xcf->common.storage_credential.len == 0) {
        return NGX_OK;
    }
    ngx_cpystrn((u_char *) cred_z, xcf->common.storage_credential.data,
                ngx_min(xcf->common.storage_credential.len + 1,
                        sizeof(cred_z)));
    cred = brix_credential_lookup(cred_z);
    if (cred == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_credential: no brix_credential \"%V\"",
            &xcf->common.storage_credential);
        return NGX_ERROR;
    }
    if (brix_credential_bearer(cred, bearer, sizeof(bearer), cf->log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_memzero(&bcred, sizeof(bcred));
    bcred.bearer = (bearer[0] != '\0') ? bearer : NULL;
    brix_server_fill_x509_credential(cred, &bcred);
    bcred.ca_dir = brix_server_cred_str_or_null(&cred->ca_dir);
    bcred.s3_access_key = brix_server_cred_str_or_null(&cred->s3_access_key);
    bcred.s3_secret_key = brix_server_cred_str_or_null(&cred->s3_secret_key);
    bcred.s3_region = brix_server_cred_str_or_null(&cred->s3_region);
    bcred.sss_keytab = brix_server_cred_str_or_null(&cred->sss_keytab);
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: backend credential \"%V\" for \"%s\": gsi=%s key=%s bearer=%s",
        &xcf->common.storage_credential, xcf->common.root_canon,
        bcred.x509_proxy ? bcred.x509_proxy : "(none)",
        bcred.x509_key ? bcred.x509_key : "(in-proxy/none)",
        bcred.bearer ? "set" : "(none)");
    brix_vfs_backend_set_credential(xcf->common.root_canon, &bcred);
    return NGX_OK;
}

static ngx_int_t
brix_server_set_wt_credential(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    char                     cred_z[256];
    char                     bearer[4096];
    const brix_credential_t *cred;

    if (xcf->wt.credential.len == 0) {
        return NGX_OK;
    }
    ngx_cpystrn((u_char *) cred_z, xcf->wt.credential.data,
                ngx_min(xcf->wt.credential.len + 1, sizeof(cred_z)));
    cred = brix_credential_lookup(cred_z);
    if (cred == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_wt_credential: no brix_credential \"%V\"",
            &xcf->wt.credential);
        return NGX_ERROR;
    }
    if (brix_credential_bearer(cred, bearer, sizeof(bearer), cf->log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (bearer[0] != '\0') {
        size_t  bl = ngx_strlen(bearer);
        u_char *bp = ngx_pnalloc(cf->pool, bl + 1);

        if (bp == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(bp, bearer, bl + 1);
        xcf->cache_origin_bearer.data = bp;
        xcf->cache_origin_bearer.len  = bl;
    }
    if (cred->x509_proxy.len > 0) {
        xcf->cache_origin_x509_proxy = cred->x509_proxy;
    } else if (cred->x509_cert.len > 0) {
        xcf->cache_origin_x509_proxy = cred->x509_cert;
        xcf->cache_origin_x509_key   = cred->x509_key;
    }
    if (cred->ca_dir.len > 0) {
        xcf->cache_origin_ca_dir = cred->ca_dir;
    }
    return NGX_OK;
}

static ngx_int_t
brix_server_setup_export(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    brix_export_root_opts_t root_opts;

    if (!brix_server_has_runtime_export(xcf)) {
        return NGX_OK;
    }
    brix_storage_backend_posix_root(&xcf->common);
    root_opts.directive_name = "brix_export";
    root_opts.allow_write    = xcf->common.allow_write
                             && !brix_storage_backend_is_remote(&xcf->common);
    root_opts.required       = 1;
    root_opts.canon_size     = sizeof(xcf->common.root_canon);
    if (brix_prepare_export_root(cf, &xcf->common.root, &root_opts,
                                   xcf->common.root_canon) != NGX_CONF_OK)
    {
        return NGX_ERROR;
    }
    brix_tmp_reap_register(xcf->common.root_canon);
    if (brix_vfs_backend_config_str(cf, xcf->common.root_canon,
            &xcf->common.storage_backend, xcf->common.pblock_block_size,
            (int) xcf->cache_origin_family) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (brix_server_set_storage_credential(cf, xcf) != NGX_OK
        || brix_server_set_wt_credential(cf, xcf) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (xcf->upload_stage_dir.len > 0) {
        brix_export_root_opts_t stage_opts;
        stage_opts.directive_name = "brix_stage_dir";
        stage_opts.allow_write    = 1;
        stage_opts.required       = 0;
        stage_opts.canon_size     = sizeof(xcf->upload_stage_dir_canon);
        if (brix_prepare_export_root(cf, &xcf->upload_stage_dir,
                &stage_opts, xcf->upload_stage_dir_canon) != NGX_CONF_OK)
        {
            return NGX_ERROR;
        }
        brix_stage_dir_register(xcf->upload_stage_dir_canon);
    }
    if (brix_tier_register_stores(cf, &xcf->common) != NGX_OK) {
        return NGX_ERROR;
    }
    if (brix_assert_dir_outside_export(cf, "cache state/sidecar tree",
            xcf->common.root_canon, brix_cache_state_root(xcf)) != NGX_OK
        || brix_assert_dir_outside_export(cf, "brix_stage_dir",
            xcf->common.root_canon, xcf->upload_stage_dir_canon) != NGX_OK)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
brix_server_validate_cache_stage_backend(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->cache_wt_stage_backend.len == 0) {
        return NGX_OK;
    }
    if (xcf->cache_wt_stage_root.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_wt_stage_backend requires brix_cache_wt_stage_root");
        return NGX_ERROR;
    }
    if (xcf->cache_state_root.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_wt_stage_backend requires a POSIX "
            "brix_cache_state_root for its sidecars");
        return NGX_ERROR;
    }
    brix_vfs_backend_config((const char *) xcf->cache_wt_stage_root.data,
                              &xcf->cache_wt_stage_backend,
                              xcf->cache_wt_stage_block_size);
    return NGX_OK;
}

static ngx_int_t
brix_server_validate_cache_watermarks(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->cache_eviction_threshold == 0
        || xcf->cache_eviction_threshold >= 1000000)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_eviction_threshold must be greater than 0 "
            "and less than 1.0");
        return NGX_ERROR;
    }
    if (xcf->reaper.high_watermark == 0
        || xcf->reaper.high_watermark >= 1000000
        || xcf->reaper.low_watermark == 0
        || xcf->reaper.low_watermark >= xcf->reaper.high_watermark)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_low_watermark must be greater than 0 and less "
            "than brix_cache_high_watermark (which must be < 1.0)");
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
brix_server_validate_cache(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    if (!xcf->cache) {
        return NGX_OK;
    }
    if (xcf->common.allow_write && !xcf->wt.enable) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache is read-only and requires "
            "brix_allow_write off (or enable brix_write_through)");
        return NGX_ERROR;
    }
    if (brix_server_validate_cache_stage_backend(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }
    if (xcf->cache_root.len == 0
        || !brix_server_storage_backend_is_remote(&xcf->common.storage_backend))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache on requires brix_cache_export and a remote "
            "brix_storage_backend (root://host:port); the retired "
            "brix_cache_origin model is the tier grammar now "
            "(brix_storage_backend + brix_cache_store)");
        return NGX_ERROR;
    }
    if (brix_validate_path(cf, "brix_cache_export", &xcf->cache_root,
                             BRIX_PATH_DIRECTORY, R_OK | W_OK | X_OK)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (xcf->cache_lock_timeout <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_lock_timeout must be greater than zero");
        return NGX_ERROR;
    }
    if (brix_server_validate_cache_watermarks(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: cache enabled root=%V origin=%V tls=%s "
        "lock_timeout=%ds eviction_threshold=0.%06ui",
        &xcf->cache_root, &xcf->cache_origin,
        xcf->cache_origin_tls ? "on" : "off",
        (int) xcf->cache_lock_timeout,
        xcf->cache_eviction_threshold);
    return NGX_OK;
}

static ngx_int_t
brix_server_validate_wt_stage(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->cache_wt_stage_high_watermark == 0) {
        return NGX_OK;
    }
    if (xcf->cache_wt_stage_root.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_wt_stage_high_watermark requires brix_cache_wt_stage_root");
        return NGX_ERROR;
    }
    if (xcf->cache_wt_stage_high_watermark >= 1000000
        || xcf->cache_wt_stage_low_watermark == 0
        || xcf->cache_wt_stage_low_watermark
               >= xcf->cache_wt_stage_high_watermark)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_wt_stage_low_watermark must be greater than 0 and "
            "less than brix_wt_stage_high_watermark (which must be < 1.0)");
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
brix_server_setup_logging(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->access_log.len > 0
        && ngx_strcmp(xcf->access_log.data, (u_char *) "off") != 0)
    {
        xcf->access_log_file = ngx_conf_open_file(cf->cycle, &xcf->access_log);
        if (xcf->access_log_file == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix: cannot register access log \"%V\"", &xcf->access_log);
            return NGX_ERROR;
        }
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix: access log \"%V\" registered", &xcf->access_log);
    }
    if (xcf->proxy.enable && xcf->proxy.audit_log.len > 0
        && ngx_strcmp(xcf->proxy.audit_log.data, (u_char *) "off") != 0)
    {
        xcf->proxy.audit_log_file = ngx_conf_open_file(cf->cycle,
                                                       &xcf->proxy.audit_log);
        if (xcf->proxy.audit_log_file == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix: cannot register proxy audit log \"%V\"",
                &xcf->proxy.audit_log);
            return NGX_ERROR;
        }
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix: proxy audit log \"%V\" registered", &xcf->proxy.audit_log);
    }
    return NGX_OK;
}

static ngx_int_t
brix_server_setup_tls(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
#if (NGX_SSL)
    if (xcf->proxy.enable && xcf->proxy.upstream_tls) {
        xcf->proxy.tls_ctx = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
        if (xcf->proxy.tls_ctx == NULL) {
            return NGX_ERROR;
        }
        xcf->proxy.tls_ctx->log = cf->log;
        if (ngx_ssl_create(xcf->proxy.tls_ctx,
                           NGX_SSL_TLSv1_2 | NGX_SSL_TLSv1_3,
                           NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
        if (xcf->proxy.upstream_tls_ca.len > 0) {
            if (ngx_ssl_trusted_certificate(cf, xcf->proxy.tls_ctx,
                                             &xcf->proxy.upstream_tls_ca,
                                             5) != NGX_OK)
            {
                return NGX_ERROR;
            }
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "brix: proxy upstream TLS CA loaded from \"%V\"",
                &xcf->proxy.upstream_tls_ca);
        }
    }
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
                                             5) != NGX_OK)
            {
                return NGX_ERROR;
            }
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "brix: upstream redirector TLS CA loaded from \"%V\"",
                &xcf->upstream_tls_ca);
        }
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix: upstream redirector TLS enabled (kXR_gotoTLS support)");
    }
#else
    (void) cf;
    (void) xcf;
#endif
    return NGX_OK;
}

/* Prepare one server block at postconfiguration: validate the configured root
 * is an existing, accessible directory (access mode matching the write policy)
 * and check the cache configuration, before the block accepts connections.
 * Returns NGX_OK, or NGX_ERROR (emerg-logged) on any invalid resource. */
ngx_int_t
brix_config_prepare_server(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    /* Hard read-only switch: force allow_write off before any allow_write-dependent
     * setup, so every write gate rejects (root:// require_write, write-open, ...). */
    brix_shared_apply_read_only(&xcf->common, cf->log);

    /* Phase-4b: a GSI tap proxy must capture the client's delegated proxy to
     * present it upstream — auto-enable delegation receipt if the admin didn't. */
    if (xcf->proxy.enable && xcf->proxy.auth == BRIX_PROXY_AUTH_GSI
        && !xcf->tpc_delegate)
    {
        xcf->tpc_delegate = 1;
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix_tap_proxy_auth gsi: enabling GSI proxy delegation capture");
    }

    if (brix_server_setup_export(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }
    if (brix_server_validate_cache(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }
    if (brix_server_validate_wt_stage(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }
    if (brix_server_setup_logging(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }
    if (brix_server_setup_tls(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
