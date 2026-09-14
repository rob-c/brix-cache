/* oci_delegate_identity.c — downstream delegation identity and uniform refusal.
 * WHAT: Decode Basic credentials and enforce the transport requirement.
 * WHY: Identity extraction precedes the asynchronous proof gate in oci_delegate.c.
 * HOW: Validate into request-pool storage; retain only a hash in shared proof keys.
 */
#include "oci.h"
#include "oci_module_internal.h"
#include <string.h>

/* ---- the downstream identity (event loop) -------------------------------- */

/*
 * oci_deleg_challenge_hdr — emit WWW-Authenticate: Basic challenge header.
 *
 * WHAT: Adds WWW-Authenticate: Basic realm="<realm>" response header to request.
 *   Allocates from request pool. Returns NGX_OK on success, NGX_ERROR on allocation
 *   failure.
 *
 * WHY: RFC 7235 requires servers to send WWW-Authenticate when rejecting with 401.
 *   Basic auth is used because clients already speak it (docker/podman login), and
 *   we're delegating the client's own registry credential, not issuing bearer tokens.
 *
 * HOW: Allocates header from ngx_list, formats realm string into pool memory,
 *   sets hash=1 for header lookup optimization.
 */
static ngx_int_t
oci_deleg_challenge_hdr(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    u_char          *v;
    size_t           n;

    if (h == NULL) {
        return NGX_ERROR;
    }
    n = sizeof("Basic realm=\"\"") + lcf->delegate_realm.len;
    v = ngx_pnalloc(r->pool, n);
    if (v == NULL) {
        return NGX_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "WWW-Authenticate");
    h->value.data = v;
    h->value.len  = (size_t) (ngx_snprintf(v, n, "Basic realm=\"%V\"",
                                           &lcf->delegate_realm) - v);

    return NGX_OK;
}

/*
 * brix_oci_delegate_refuse — uniform 401 refusal for all delegation failures.
 *
 * WHAT: Sends HTTP 401 Unauthorized with WWW-Authenticate: Basic challenge and
 *   OCI DENIED error envelope. Returns NGX_HTTP_UNAUTHORIZED. Used for all
 *   delegation failures: bad credential, no credential, repository not found,
 *   scope denied.
 *
 * WHY: Security through uniformity — any difference between "bad password",
 *   "no such repo", and "not authorized" creates an enumeration oracle that
 *   leaks information about private namespaces. RFC 7235 requires WWW-Authenticate
 *   on 401. OCI spec requires DENIED envelope for errors.
 *
 * HOW: Sets status=401, adds WWW-Authenticate header via oci_deleg_challenge_hdr(),
 *   builds OCI error JSON with DENIED code and generic message, marks request
 *   as completed.
 */
ngx_int_t
brix_oci_delegate_refuse(ngx_http_request_t *r, ngx_http_brix_oci_loc_conf_t *lcf,
    ngx_http_brix_oci_ctx_t *ctx)
{
    ctx->disp = BRIX_OCI_OUT_REFUSED;
    brix_oci_guard_emit(r, GUARD_R_AUTHFAIL, GUARD_OP_READ,
                        NGX_HTTP_UNAUTHORIZED);
    if (oci_deleg_challenge_hdr(r, lcf) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return brix_oci_error(r, NGX_HTTP_UNAUTHORIZED, BRIX_OCI_ERR_DENIED,
                          NULL);
}

/*
 * oci_deleg_decode — decode Basic auth header and extract credential hash.
 *
 * WHAT: Decodes Base64 Basic authorization header into "user:pass" format,
 *   validates format (must contain colon, non-empty username), computes SHA256
 *   hash of credential for SHM keying. Stores hash in ctx->deleg_cred, plaintext
 *   in ctx->deleg_basic (request pool), username in ctx->deleg_user. Returns
 *   NGX_DECLINED on success (identity established), error code on failure.
 *
 * WHY: Basic auth credentials arrive Base64-encoded and must be decoded before
 *   use. The SHA256 hash is the only form that persists (as SHM key) — plaintext
 *   is used only for the upstream proof exchange then discarded. Validation prevents
 *   malformed credentials from reaching the upstream.
 *
 * HOW: Allocates decode buffer from request pool, decodes Base64, validates
 *   length and NUL-absence, finds colon separator, computes SHA256, extracts
 *   username for logging. Refuses with brix_oci_delegate_refuse() on any validation failure.
 */
static ngx_int_t
oci_deleg_decode(ngx_http_request_t *r, ngx_http_brix_oci_loc_conf_t *lcf,
    ngx_http_brix_oci_ctx_t *ctx, ngx_str_t *b64)
{
    ngx_str_t          dst;
    u_char            *colon;
    char              *user;

    dst.data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(b64->len) + 1);
    if (dst.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (ngx_decode_base64(&dst, b64) != NGX_OK
        || dst.len == 0 || dst.len >= BRIX_OCI_BASIC_MAX
        || memchr(dst.data, '\0', dst.len) != NULL)
    {
        return brix_oci_delegate_refuse(r, lcf, ctx);
    }
    dst.data[dst.len] = '\0';

    colon = (u_char *) strchr((char *) dst.data, ':');
    if (colon == NULL || colon == dst.data) {
        return brix_oci_delegate_refuse(r, lcf, ctx);
    }

    if (brix_oci_sha256_key(dst.data, dst.len, ctx->deleg_cred) != 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ctx->deleg_basic = (const char *) dst.data;

    /* The username half, for the dashboard/log identity. Never the pair. */
    user = ngx_pnalloc(r->pool, (size_t) (colon - dst.data) + 1);
    if (user == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(user, dst.data, (size_t) (colon - dst.data));
    user[colon - dst.data] = '\0';
    ctx->deleg_user = user;

    return NGX_DECLINED;
}

/*
 * brix_oci_delegate_ident — extract downstream client identity from authorization header.
 *
 * WHAT: Main entry point for delegation identity extraction. Checks for Basic auth
 *   header, validates TLS requirement (unless deleg_insecure configured), decodes
 *   credential via oci_deleg_decode(). Returns NGX_DECLINED if delegation is off or
 *   anonymous access, NGX_HTTP_UNAUTHORIZED on credential errors, NGX_HTTP_BAD_REQUEST
 *   on TLS violation.
 *
 * WHY: Delegation mode requires every request to carry the client's own registry
 *   credential. This function is the gatekeeper that extracts and validates that
 *   credential before the authorization proof phase. TLS enforcement prevents
 *   credential interception on cleartext connections.
 *
 * HOW: Checks lcf->delegate flag, retrieves Authorization header, validates TLS
 *   (unless insecure mode), verifies Basic scheme prefix, delegates decoding to
 *   oci_deleg_decode(). Refuses non-Basic schemes (Bearer, Negotiate) to avoid
 *   guessing at credential formats.
 */
ngx_int_t
brix_oci_delegate_ident(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx)
{
    ngx_table_elt_t *auth = r->headers_in.authorization;
    ngx_str_t        b64;
    int              is_tls = 0;

    if (!lcf->delegate || auth == NULL) {
        return NGX_DECLINED;               /* off, or anonymous: cred = 0s */
    }

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL);
#endif
    /* A credential on a cleartext connection is already burned; the ONE
     * thing still in our power is to refuse to act on it — before decoding,
     * so the secret never even enters this process's data flow. */
    if (!is_tls && !lcf->deleg_insecure) {
        ctx->disp = BRIX_OCI_OUT_REFUSED;
        brix_oci_guard_emit(r, GUARD_R_AUTHFAIL, GUARD_OP_READ,
                            NGX_HTTP_BAD_REQUEST);
        return brix_oci_error(r, NGX_HTTP_BAD_REQUEST, BRIX_OCI_ERR_DENIED,
                              "credentials require TLS on this mirror");
    }

    if (auth->value.len < sizeof("Basic ") - 1
        || ngx_strncasecmp(auth->value.data, (u_char *) "Basic ",
                           sizeof("Basic ") - 1) != 0)
    {
        /* Bearer, Negotiate, junk: not a credential this surface can
         * delegate, and guessing is how a secret goes somewhere wrong. */
        return brix_oci_delegate_refuse(r, lcf, ctx);
    }
    b64.data = auth->value.data + sizeof("Basic ") - 1;
    b64.len  = auth->value.len - (sizeof("Basic ") - 1);

    return oci_deleg_decode(r, lcf, ctx, &b64);
}
