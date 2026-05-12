#include "../config/config.h"

ngx_int_t
xrootd_configure_token_auth(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf)
{
    if (xcf->auth != XROOTD_AUTH_TOKEN && xcf->auth != XROOTD_AUTH_BOTH) {
        return NGX_OK;
    }

    if (xcf->token_jwks.len == 0 || xcf->token_issuer.len == 0
        || xcf->token_audience.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_auth token/both requires "
            "xrootd_token_jwks, "
            "xrootd_token_issuer and xrootd_token_audience");
        return NGX_ERROR;
    }

    if (xrootd_validate_path(cf, "xrootd_token_jwks",
                             &xcf->token_jwks,
                             XROOTD_PATH_REGULAR_FILE, R_OK)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    xcf->jwks_key_count = xrootd_jwks_load(
        cf->log, (const char *) xcf->token_jwks.data,
        xcf->jwks_keys, XROOTD_MAX_JWKS_KEYS);

    if (xcf->jwks_key_count < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd: failed to load JWKS from \"%s\"",
            xcf->token_jwks.data);
        return NGX_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: token auth configured - jwks=%s issuer=%s "
        "audience=%s keys=%d",
        xcf->token_jwks.data, xcf->token_issuer.data,
        xcf->token_audience.data, xcf->jwks_key_count);

    return NGX_OK;
}
