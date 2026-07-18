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

/*
 * brix_server_guard_remote_authz — config-time guardrail for an origin-scheme
 * backend whose export setup will never run (P80.5, finding 1.5).
 *
 * WHAT: Rejects at config time the combination of an origin-scheme
 *       brix_storage_backend (s3/http/xroot/...), configured authorization
 *       rules (brix_authdb / brix_require_vo / brix_inherit_parent_group),
 *       and a server mode that skips brix_server_setup_export — the exact
 *       gate below (brix_server_has_runtime_export).
 *
 * WHY: When the export setup is skipped, root_canon stays "/" and the path
 *      join produces "//<wire-path>" while every authdb/VO rule was
 *      canonicalized to "/<path>" at load — nothing ever matches and every
 *      op dies "3010 authdb denied" with zero hint at the cause. The lab
 *      burned hours on this silent everything-denied server; make it a loud
 *      config error instead.
 *
 * HOW: Pure predicate over already-merged conf fields; emits one EMERG
 *      naming the "//path vs /path" mechanics and which engine breaks on
 *      which side (xrdacc authorizes the LOGICAL wire path; native authdb /
 *      VO ACLs authorize the RESOLVED backing path).
 */
static ngx_int_t
brix_server_guard_remote_authz(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    int  has_rules;

    if (brix_server_has_runtime_export(xcf)
        || !brix_storage_backend_is_remote(&xcf->common))
    {
        return NGX_OK;
    }

    has_rules = xcf->authdb.len > 0
                || (xcf->vo_rules != NULL && xcf->vo_rules->nelts > 0)
                || (xcf->group_rules != NULL && xcf->group_rules->nelts > 0);
    if (!has_rules) {
        return NGX_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "brix_storage_backend \"%V\" with authorization rules "
        "(brix_authdb/brix_require_vo/brix_inherit_parent_group) requires a "
        "runtime export: this server mode (manager/supervisor/proxy) skips "
        "brix_export setup, so the authz gate would check \"//<path>\" "
        "(root_canon \"/\" + wire path) against rules canonicalized to "
        "\"/<path>\" — nothing matches and EVERY request is denied 3010. "
        "xrdacc rules break on the logical wire path; native authdb/VO ACL "
        "rules break on the resolved backing path. Set brix_export to a real "
        "local directory (it aligns both sides), or drop the authz rules "
        "from this server block",
        &xcf->common.storage_backend);
    return NGX_ERROR;
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
    if (brix_credential_to_backend_cred(cred, bearer, sizeof(bearer),
                                          &bcred, cf->log) != NGX_OK)
    {
        return NGX_ERROR;
    }
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
    /* Bridge the (now fully merged) read-cache admission config from the stream
     * srv conf into the shared preamble, so the protocol-agnostic tier
     * registration below can enforce it on the composable sd_cache read-fill
     * path — parity with write-through and the legacy cache_origin admit. */
    xcf->common.cache_deny_prefixes  = xcf->cache_deny_prefixes;
    xcf->common.cache_allow_prefixes = xcf->cache_allow_prefixes;
    xcf->common.cache_include_re     = xcf->include_regex.set
                                     ? &xcf->include_regex.re : NULL;
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

#if (NGX_SSL)
/*
 * brix_tls_ctx_enable_verify — turn on real peer authentication for an outbound
 * client SSL_CTX.
 *
 * WHAT: Sets SSL_VERIFY_PEER (so a bad or untrusted chain fails the handshake)
 *       and, when `host` is non-empty, pins the expected certificate hostname on
 *       the context's verify parameters (so a valid cert for the WRONG host is
 *       also rejected).
 * WHY:  Loading a trust store without SSL_VERIFY_PEER is inert — OpenSSL clients
 *       default to SSL_VERIFY_NONE, so an on-path attacker presenting any
 *       CA-valid (or self-signed) cert completes the handshake and the proxy /
 *       redirector re-sends kXR_login over the attacker's channel. Chain-only
 *       verification still accepts any CA-valid cert for a different host, so the
 *       name check is folded in via the CTX verify param (mirrors the cache
 *       origin path in fs/cache/origin_connection.c). Applied on the shared CTX
 *       so every connection it spawns inherits verification; a failure then
 *       aborts at the existing `!handshaked` check in the handshake callbacks.
 * HOW:  SSL_CTX_set_verify + X509_VERIFY_PARAM_set1_host on SSL_CTX_get0_param.
 */
static ngx_int_t
brix_tls_ctx_enable_verify(ngx_conf_t *cf, SSL_CTX *ctx, const ngx_str_t *host)
{
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (host != NULL && host->len > 0 && host->data != NULL) {
        X509_VERIFY_PARAM *param = SSL_CTX_get0_param(ctx);
        char               hbuf[256];
        size_t             hl = host->len < sizeof(hbuf) - 1
                                ? host->len : sizeof(hbuf) - 1;

        ngx_memcpy(hbuf, host->data, hl);
        hbuf[hl] = '\0';
        X509_VERIFY_PARAM_set_hostflags(param,
            X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (X509_VERIFY_PARAM_set1_host(param, hbuf, 0) != 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix: failed to pin upstream TLS verify host \"%V\"", host);
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}
#endif

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
            if (xcf->proxy.upstream_ssl_verify) {
                if (brix_tls_ctx_enable_verify(cf, xcf->proxy.tls_ctx->ctx,
                        (xcf->proxy.upstream_tls_name.len > 0)
                            ? &xcf->proxy.upstream_tls_name : &xcf->proxy.host)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
                ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                    "brix: proxy upstream TLS CA loaded from \"%V\" — peer "
                    "verification (chain + host) enabled",
                    &xcf->proxy.upstream_tls_ca);
            } else {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                    "brix: proxy upstream TLS CA loaded from \"%V\" but "
                    "brix_tap_proxy_upstream_tls_verify is off — the peer is "
                    "UNVERIFIED and the hop is MITM-able",
                    &xcf->proxy.upstream_tls_ca);
            }
        } else if (xcf->proxy.upstream_ssl_verify) {
            /* A-1: fail closed — an unauthenticated TLS upstream re-sends the
             * client's kXR_login over an attacker-controllable channel. */
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix: brix_tap_proxy_upstream_tls is on but no "
                "brix_tap_proxy_upstream_tls_ca is set — refusing an "
                "unauthenticated, MITM-able TLS upstream (set the CA, or "
                "brix_tap_proxy_upstream_tls_verify off to opt out)");
            return NGX_ERROR;
        } else {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "brix: brix_tap_proxy_upstream_tls is on with verification "
                "explicitly off and no CA — the upstream TLS peer is UNVERIFIED "
                "and the hop is MITM-able");
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
            if (xcf->upstream_ssl_verify) {
                if (brix_tls_ctx_enable_verify(cf, xcf->upstream_tls_ctx->ctx,
                        (xcf->upstream_tls_name.len > 0)
                            ? &xcf->upstream_tls_name : &xcf->upstream_host)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
                ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                    "brix: upstream redirector TLS CA loaded from \"%V\" — peer "
                    "verification (chain + host) enabled",
                    &xcf->upstream_tls_ca);
            } else {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                    "brix: upstream redirector TLS CA loaded from \"%V\" but "
                    "brix_upstream_tls_verify is off — the peer is UNVERIFIED "
                    "and the hop is MITM-able",
                    &xcf->upstream_tls_ca);
            }
        } else if (xcf->upstream_ssl_verify) {
            /* A-1: fail closed — see the proxy-leg rationale above. */
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix: brix_upstream_tls (redirector) is on but no "
                "brix_upstream_tls_ca is set — refusing an unauthenticated, "
                "MITM-able TLS upstream (set the CA, or brix_upstream_tls_verify "
                "off to opt out)");
            return NGX_ERROR;
        } else {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "brix: brix_upstream_tls (redirector) is on with verification "
                "explicitly off and no CA — the upstream TLS peer is UNVERIFIED "
                "and the hop is MITM-able");
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

    if (brix_server_guard_remote_authz(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
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
