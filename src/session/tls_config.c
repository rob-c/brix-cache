#include "../config/config.h"

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

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: kXR_ableTLS enabled - cert=%s",
        xcf->certificate.data);

    return NGX_OK;
}
