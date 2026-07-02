#include "config/config.h"
#include "issuer_registry.h"
#include <sys/stat.h>

/*
 *
 * WHAT: Validates that required token auth configuration fields are present when auth mode is XROOTD_AUTH_TOKEN or XROOTD_AUTH_BOTH. Checks for non-empty token_jwks (JWKS key file path), token_issuer, and token_audience. Validates JWKS file exists as a regular file with read permissions via xrootd_validate_path(). Loads all public keys from the JWKS file into jwks_keys array using xrootd_jwks_load() — returns NGX_OK only when at least one key loaded successfully. Logs configuration summary with key count on success, or emerg-level errors on any validation failure.
 *
 * WHY: Token authentication requires three prerequisites: a valid JWKS file containing public keys for JWT verification, an issuer string to validate token claims against, and an audience string to restrict which tokens are accepted. Missing any of these would cause runtime auth failures for all clients — nginx -t must catch this at configuration validation time rather than allowing the server to start with broken auth. The JWKS key count serves as a sanity check: loading zero keys indicates file corruption or invalid format, not just absence. Thread safety: config setup runs once during nginx startup on main process thread; no concurrent access after initialization. */

ngx_int_t
xrootd_configure_token_auth(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf)
{
    if (xcf->auth != XROOTD_AUTH_TOKEN && xcf->auth != XROOTD_AUTH_BOTH) {
        return NGX_OK;
    }

    /* Multi-issuer registry (phase-59 W1): when xrootd_token_config is set it
     * supersedes the single-issuer token_jwks/_issuer/_audience directives. */
    if (xcf->token_config.len > 0) {
        xrootd_token_registry_t *reg = NULL;

        if (xcf->token_issuer.len || xcf->token_audience.len
            || xcf->token_jwks.len)
        {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "xrootd_token_config supersedes xrootd_token_issuer/"
                "_audience/_jwks (single-issuer directives ignored)");
        }
        if (xrootd_token_registry_build(cf,
                (const char *) xcf->token_config.data,
                XROOTD_AUTHZ_CAPABILITY, &reg) != NGX_OK)
        {
            return NGX_ERROR;
        }
        xcf->token_registry = reg;
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

    if (xcf->jwks_key_count > 0
        && xrootd_jwks_register_cleanup(cf->pool, xcf->jwks_keys,
                                        &xcf->jwks_key_count) != NGX_OK)
    {
        return NGX_ERROR;
    }

    {
        /* Record mtime so the refresh timer can detect changes */
        struct stat  st;
        if (stat((const char *) xcf->token_jwks.data, &st) == 0) {
            xcf->jwks_mtime = st.st_mtime;
        }
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: token auth configured - jwks=%s issuer=%s "
        "audience=%s keys=%d",
        xcf->token_jwks.data, xcf->token_issuer.data,
        xcf->token_audience.data, xcf->jwks_key_count);

    return NGX_OK;
/*
 * HOW: 1) Early-exit if auth mode is not token/both (anonymous/GSI pass).
 *       2) Check all three required ngx_str_t fields are non-empty — log emerg and return NGX_ERROR if any missing.
 *       3) Validate JWKS file path via xrootd_validate_path() (must be regular file, readable). Early-exit on failure.
 *       4) Load public keys from JWKS into jwks_keys array; check return count ≥ 0 for success.
 *       5) Capture file mtime via stat() so refresh timer can detect changes. Ignored if stat fails (mtime stays unset).
 *       6) Log configuration summary with key count at notice level.
 */
}
