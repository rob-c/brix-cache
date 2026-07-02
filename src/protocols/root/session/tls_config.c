#include "core/config/config.h"
#include "auth/crypto/ocsp.h"

/*
 * WHAT: This file configures the SSL context for in-protocol TLS upgrade. When
 *       xrootd_tls is enabled, clients can request kXR_wantTLS after login and
 *       the server upgrades the raw TCP connection to TLS using the configured
 *       certificate/key pair. This allows "roots://" style communication without
 *       requiring a separate TLS listener port.
 *
 * WHY: In-protocol TLS provides flexibility — operators can serve both raw TCP
 *      (root://) and TLS-upgraded (roots://) connections from the same server block.
 *      Clients that need strict TLS enforcement can request upgrade after login
 *      rather than connecting to a dedicated ports:// listener.
 *
 * HOW: Single function called during postconfiguration phase: checks tls flag,
 *      validates certificate/key pair exists, creates ngx_ssl_t context with
 *      TLSv1.2+TLSv1.3 enabled, loads the server certificate and private key,
 *      returns NGX_OK or NGX_ERROR with emerg-level log if prerequisites missing. */

/*
 *
 * WHAT: Configures an SSL context for in-protocol TLS upgrade (kXR_ableTLS). Called during nginx
 *       postconfiguration when the tls directive is enabled. Creates and populates an ngx_ssl_t object
 *      with TLSv1.2/TLSv1.3 support, loads server certificate and private key from configured PEM files.
 *
 * WHY: Enables clients to request kXR_wantTLS after login and upgrade their raw TCP connection to TLS,
 *      providing "roots://"-style communication without requiring a separate dedicated listener port.
 *      Supports mixed deployments where some clients need strict TLS while others connect via plain root://.
 *
 * HOW: Four-step validation → tls flag check (skip if off) → cert/key existence validation (emerg error if missing) →
 *      ngx_ssl_t allocation + TLSv1.2+TLSv1.3 initialization → certificate and key loading from PEM files → NGX_OK/NGX_ERROR. */

/*
 *
 * WHAT: OpenSSL callback invoked for each TLS ClientHello that includes the status_request extension. If a cached staple exists in srv_conf->ocsp_staple_data, it is attached to the ServerHello via SSL_set_tlsext_status_ocsp_resp(). The buffer is allocated with OPENSSL_malloc and freed by OpenSSL on SSL_free.
 *
 * WHY: OCSP stapling allows clients to verify certificate revocation status without making a separate network request to the CA's OCSP responder, reducing TLS handshake latency and improving privacy (the server reveals revocation status instead of the client).
 *
 * HOW: Check ocsp_staple_data/len → if present, OPENSSL_malloc copy → SSL_set_tlsext_status_ocsp_resp(ssl, copy, len) → return SSL_TLSEXT_ERR_OK; if absent or allocation fails, return SSL_TLSEXT_ERR_NOACK. */
static int
xrootd_ocsp_stapling_cb(SSL *ssl, void *arg)
{
    ngx_stream_xrootd_srv_conf_t *xcf = arg;

    if (xcf->ocsp_staple_data == NULL || xcf->ocsp_staple_len == 0) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    /* OpenSSL takes ownership and frees this buffer via OPENSSL_free(). */
    unsigned char *copy = OPENSSL_malloc(xcf->ocsp_staple_len);
    if (copy == NULL) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    ngx_memcpy(copy, xcf->ocsp_staple_data, xcf->ocsp_staple_len);
    SSL_set_tlsext_status_ocsp_resp(ssl, copy, (int)xcf->ocsp_staple_len);
    return SSL_TLSEXT_ERR_OK;
}

ngx_int_t
xrootd_configure_tls(ngx_conf_t *cf, ngx_stream_xrootd_srv_conf_t *xcf)
{
    if (!xcf->tls) {
        return NGX_OK;
    }

    if (xcf->certificate.len == 0 || xcf->certificate_key.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_tls requires xrootd_certificate and "
            "xrootd_certificate_key");
        return NGX_ERROR;
    }

    xcf->tls_ctx = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (xcf->tls_ctx == NULL) {
        return NGX_ERROR;
    }
    xcf->tls_ctx->log = cf->log;

    if (ngx_ssl_create(xcf->tls_ctx,
                       NGX_SSL_TLSv1_2 | NGX_SSL_TLSv1_3,
                       NULL) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_ssl_certificate(cf, xcf->tls_ctx,
                            &xcf->certificate,
                            &xcf->certificate_key,
                            NULL) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /*
     * Phase 29 kTLS: enable kernel-TLS so the in-protocol/GSI TLS data stream can
     * use sendfile(2) — the kernel encrypts the records in-place, letting TLS
     * reads take the zero-copy sendfile fast path (and its Phase-2 pipelining) in
     * src/read/read.c instead of the userspace-encrypt memory path.  Runtime-safe:
     * OpenSSL only uses kTLS when the negotiated cipher AND the running kernel
     * support the offload, otherwise it transparently falls back to userspace TLS;
     * the read path independently re-checks BIO_get_ktls_send() per connection
     * before choosing the file-backed chain.
     */
#ifdef SSL_OP_ENABLE_KTLS
    if (xcf->tls_ktls) {
        SSL_CTX_set_options(xcf->tls_ctx->ctx, SSL_OP_ENABLE_KTLS);
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "xrootd: kernel-TLS (kTLS) send offload enabled for TLS context "
            "(xrootd_ktls on) - only beneficial with HW TLS-offload NICs");
    }
#endif

    /* Register OCSP stapling callback if stapling is configured */
    if (xcf->ocsp_stapling) {
        SSL_CTX_set_tlsext_status_cb(xcf->tls_ctx->ctx, xrootd_ocsp_stapling_cb);
        SSL_CTX_set_tlsext_status_arg(xcf->tls_ctx->ctx, xcf);
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "xrootd: OCSP stapling enabled for TLS context");
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: kXR_ableTLS enabled - cert=%s",
        xcf->certificate.data);

    return NGX_OK;
}
