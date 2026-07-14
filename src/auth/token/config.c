#include "core/config/config.h"
#include "issuer_registry.h"
#include <sys/stat.h>

/* ---- Build the multi-issuer token registry from brix_token_config ----
 *
 * WHAT: Constructs a brix_token_registry_t from the brix_token_config file and
 *       stores it on xcf->token_registry. Warns (non-fatally) when the legacy
 *       single-issuer directives are also set, since the registry supersedes
 *       them. Returns NGX_OK on success, NGX_ERROR if registry construction
 *       fails.
 *
 * WHY: The multi-issuer registry (phase-59 W1) is the modern replacement for the
 *      single brix_token_jwks/_issuer/_audience directives. When both are
 *      present the registry wins; the operator is warned so they understand the
 *      single-issuer settings are being ignored rather than merged.
 *
 * HOW: 1) If any single-issuer directive is non-empty, emit a WARN that the
 *         registry supersedes them.
 *      2) Call brix_token_registry_build() with the config path and the
 *         capability authz mode; return NGX_ERROR on failure.
 *      3) Publish the built registry on xcf and return NGX_OK.
 */
static ngx_int_t
brix_token_configure_registry(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    brix_token_registry_t *reg = NULL;

    /* Multi-issuer registry (phase-59 W1): when brix_token_config is set it
     * supersedes the single-issuer token_jwks/_issuer/_audience directives. */
    if (xcf->token_issuer.len || xcf->token_audience.len
        || xcf->token_jwks.len)
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix_token_config supersedes brix_token_issuer/"
            "_audience/_jwks (single-issuer directives ignored)");
    }
    if (brix_token_registry_build(cf,
            (const char *) xcf->token_config.data,
            BRIX_AUTHZ_CAPABILITY, &reg) != NGX_OK)
    {
        return NGX_ERROR;
    }
    xcf->token_registry = reg;
    return NGX_OK;
}

/* ---- Require the three single-issuer token directives ----
 *
 * WHAT: Verifies that brix_token_jwks, brix_token_issuer and brix_token_audience
 *       are all non-empty. Returns NGX_OK when all three are present, otherwise
 *       logs an emerg-level error and returns NGX_ERROR.
 *
 * WHY: Single-issuer token authentication cannot function without a JWKS key
 *      file, an issuer to validate token claims against, and an audience to
 *      restrict which tokens are accepted. Catching the omission at
 *      configuration-validation time (nginx -t) prevents starting a server with
 *      auth that would reject every client at runtime.
 *
 * HOW: 1) If any of the three ngx_str_t fields has zero length, log an emerg
 *         error naming all three directives and return NGX_ERROR.
 *      2) Otherwise return NGX_OK.
 */
static ngx_int_t
brix_token_require_single_issuer_fields(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->token_jwks.len == 0 || xcf->token_issuer.len == 0
        || xcf->token_audience.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_auth token/both requires "
            "brix_token_jwks, "
            "brix_token_issuer and brix_token_audience");
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- Validate, load and register the JWKS keys ----
 *
 * WHAT: Validates the brix_token_jwks path (regular file, readable), loads its
 *       public keys into xcf->jwks_keys, registers a pool cleanup for the loaded
 *       keys, and records the file mtime for the refresh timer. Returns NGX_OK on
 *       success, NGX_ERROR on any validation, load, or cleanup-registration
 *       failure.
 *
 * WHY: JWT verification needs the issuer's public keys resident in memory. A
 *      loaded key count below zero indicates file corruption or invalid format
 *      (distinct from mere absence), which must fail configuration rather than
 *      allow a server with unusable keys. The mtime lets the refresh timer detect
 *      later changes to the JWKS file.
 *
 * HOW: 1) Validate the JWKS path via brix_validate_path() (regular file, R_OK);
 *         return NGX_ERROR on failure.
 *      2) Load keys via brix_jwks_load(); a negative count is a load failure —
 *         log emerg and return NGX_ERROR.
 *      3) If any keys loaded, register a pool cleanup for them; return NGX_ERROR
 *         if that fails.
 *      4) stat() the file and record st_mtime; a stat failure is ignored so the
 *         mtime simply stays unset.
 *      5) Return NGX_OK.
 */
static ngx_int_t
brix_token_load_and_register_jwks(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    struct stat  st;

    if (brix_validate_path(cf, "brix_token_jwks",
                             &xcf->token_jwks,
                             BRIX_PATH_REGULAR_FILE, R_OK)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    xcf->jwks_key_count = brix_jwks_load(
        cf->log, (const char *) xcf->token_jwks.data,
        xcf->jwks_keys, BRIX_MAX_JWKS_KEYS);

    if (xcf->jwks_key_count < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix: failed to load JWKS from \"%s\"",
            xcf->token_jwks.data);
        return NGX_ERROR;
    }

    if (xcf->jwks_key_count > 0
        && brix_jwks_register_cleanup(cf->pool, xcf->jwks_keys,
                                        &xcf->jwks_key_count) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Record mtime so the refresh timer can detect changes */
    if (stat((const char *) xcf->token_jwks.data, &st) == 0) {
        xcf->jwks_mtime = st.st_mtime;
    }

    return NGX_OK;
}

/* ---- Log the single-issuer token auth configuration summary ----
 *
 * WHAT: Emits a NOTICE-level line summarising the configured JWKS path, issuer,
 *       audience, and loaded key count. Returns nothing.
 *
 * WHY: A single confirmation line at startup gives operators a sanity check that
 *      token auth is wired up with the expected inputs and a plausible key count,
 *      without having to enable debug logging.
 *
 * HOW: 1) Format jwks, issuer, audience, and jwks_key_count into one NOTICE line.
 */
static void
brix_token_log_summary(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: token auth configured - jwks=%s issuer=%s "
        "audience=%s keys=%d",
        xcf->token_jwks.data, xcf->token_issuer.data,
        xcf->token_audience.data, xcf->jwks_key_count);
}

/* ---- Validate and materialise token/JWT auth configuration ----
 *
 * WHAT: Validates token auth configuration when auth mode is BRIX_AUTH_TOKEN or
 *       BRIX_AUTH_BOTH. Dispatches to the multi-issuer registry when
 *       brix_token_config is set; otherwise requires the single-issuer
 *       directives, loads the JWKS keys, and logs a summary. Returns NGX_OK when
 *       auth is not token-based or is fully configured, NGX_ERROR on any
 *       validation failure.
 *
 * WHY: Missing or invalid token auth prerequisites would cause runtime auth
 *      failures for all clients — nginx -t must catch this at configuration
 *      validation time rather than allowing the server to start with broken
 *      auth. Config setup runs once during nginx startup on the main process
 *      thread; there is no concurrent access after initialization.
 *
 * HOW: 1) Early-exit NGX_OK if auth mode is not token/both.
 *      2) If brix_token_config is set, delegate entirely to the multi-issuer
 *         registry builder and return its result.
 *      3) Require the three single-issuer directives; return NGX_ERROR if any is
 *         missing.
 *      4) Validate, load, and register the JWKS keys (and capture mtime); return
 *         NGX_ERROR on failure.
 *      5) Log the configuration summary and return NGX_OK.
 */
ngx_int_t
brix_configure_token_auth(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->auth != BRIX_AUTH_TOKEN && xcf->auth != BRIX_AUTH_BOTH) {
        return NGX_OK;
    }

    /* Multi-issuer registry (phase-59 W1) supersedes single-issuer directives. */
    if (xcf->token_config.len > 0) {
        return brix_token_configure_registry(cf, xcf);
    }

    if (brix_token_require_single_issuer_fields(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (brix_token_load_and_register_jwks(cf, xcf) != NGX_OK) {
        return NGX_ERROR;
    }

    brix_token_log_summary(cf, xcf);

    return NGX_OK;
}
