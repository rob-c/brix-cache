/*
 * runtime_server_tls.c — outbound-TLS context setup for a prepared server block
 * (mechanical file-size split off runtime_server.c). Builds the proxy-leg and
 * redirector-leg client SSL_CTXs with fail-closed peer verification. The single
 * entry point brix_server_setup_tls() is invoked by the top-level
 * brix_config_prepare_server() orchestrator (runtime_server.c) and is declared
 * in runtime_server_backend_internal.h; its verify helper stays file-local.
 */

#include "config.h"
#include "runtime_server_backend_internal.h"

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

#if (NGX_SSL)
/*
 * WHAT: Build and configure the proxy leg's outbound TLS context.
 * WHY:  Proxy and redirector TLS are independent configuration lifecycles.
 * HOW:  Create the context, load its CA, enforce requested verification, log.
 */
static ngx_int_t
brix_server_setup_proxy_tls(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    if (!xcf->proxy.enable || !xcf->proxy.upstream_tls)
        return NGX_OK;
    xcf->proxy.tls_ctx = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (xcf->proxy.tls_ctx == NULL)
        return NGX_ERROR;
    xcf->proxy.tls_ctx->log = cf->log;
    if (ngx_ssl_create(xcf->proxy.tls_ctx,
                       NGX_SSL_TLSv1_2 | NGX_SSL_TLSv1_3, NULL) != NGX_OK)
        return NGX_ERROR;
    if (xcf->proxy.upstream_tls_ca.len > 0) {
        if (ngx_ssl_trusted_certificate(cf, xcf->proxy.tls_ctx,
                                        &xcf->proxy.upstream_tls_ca, 5)
            != NGX_OK)
            return NGX_ERROR;
        if (xcf->proxy.upstream_ssl_verify) {
            const ngx_str_t *host = xcf->proxy.upstream_tls_name.len > 0
                                  ? &xcf->proxy.upstream_tls_name
                                  : &xcf->proxy.host;

            if (brix_tls_ctx_enable_verify(cf, xcf->proxy.tls_ctx->ctx, host)
                != NGX_OK)
                return NGX_ERROR;
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "brix: proxy upstream TLS CA loaded from \"%V\" — peer "
                "verification (chain + host) enabled", &xcf->proxy.upstream_tls_ca);
        } else {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "brix: proxy upstream TLS CA loaded from \"%V\" but "
                "verification is off — the peer is UNVERIFIED",
                &xcf->proxy.upstream_tls_ca);
        }
        return NGX_OK;
    }
    if (xcf->proxy.upstream_ssl_verify) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix: proxy upstream TLS verification requires an upstream CA");
        return NGX_ERROR;
    }
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "brix: proxy upstream TLS is explicitly UNVERIFIED");
    return NGX_OK;
}

/*
 * WHAT: Build and configure the redirector leg's outbound TLS context.
 * WHY:  Redirector trust policy must fail independently from proxy setup.
 * HOW:  Create the context, load its CA, enforce requested verification, log.
 */
static ngx_int_t
brix_server_setup_redirect_tls(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    if (!xcf->upstream_tls)
        return NGX_OK;
    xcf->upstream_tls_ctx = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (xcf->upstream_tls_ctx == NULL)
        return NGX_ERROR;
    xcf->upstream_tls_ctx->log = cf->log;
    if (ngx_ssl_create(xcf->upstream_tls_ctx,
                       NGX_SSL_TLSv1_2 | NGX_SSL_TLSv1_3, NULL) != NGX_OK)
        return NGX_ERROR;
    if (xcf->upstream_tls_ca.len > 0) {
        if (ngx_ssl_trusted_certificate(cf, xcf->upstream_tls_ctx,
                                        &xcf->upstream_tls_ca, 5) != NGX_OK)
            return NGX_ERROR;
        if (xcf->upstream_ssl_verify) {
            const ngx_str_t *host = xcf->upstream_tls_name.len > 0
                                  ? &xcf->upstream_tls_name : &xcf->upstream_host;

            if (brix_tls_ctx_enable_verify(cf, xcf->upstream_tls_ctx->ctx, host)
                != NGX_OK)
                return NGX_ERROR;
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "brix: redirector TLS CA loaded from \"%V\" — peer "
                "verification (chain + host) enabled", &xcf->upstream_tls_ca);
        } else {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "brix: redirector TLS CA loaded from \"%V\" but verification "
                "is off — the peer is UNVERIFIED", &xcf->upstream_tls_ca);
        }
    } else if (xcf->upstream_ssl_verify) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix: redirector TLS verification requires an upstream CA");
        return NGX_ERROR;
    } else {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix: redirector TLS is explicitly UNVERIFIED");
    }
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: upstream redirector TLS enabled (kXR_gotoTLS support)");
    return NGX_OK;
}
#endif

ngx_int_t
brix_server_setup_tls(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
#if (NGX_SSL)
    if (brix_server_setup_proxy_tls(cf, xcf) != NGX_OK)
        return NGX_ERROR;
    return brix_server_setup_redirect_tls(cf, xcf);
#else
    (void) cf;
    (void) xcf;
    return NGX_OK;
#endif
}
