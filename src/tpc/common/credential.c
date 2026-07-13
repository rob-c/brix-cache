#include "credential.h"

/*
 * credential.c — parse and validate TPC delegated credentials.
 *
 * WHAT: Implements the brix_tpc_credential.h interface: sniff a raw
 *       credential string into a typed brix_tpc_credential_t
 *       (brix_tpc_credential_parse), reject empty/expired credentials
 *       (brix_tpc_credential_validate), and name a credential type for logs
 *       (brix_tpc_credential_type_name).
 *
 * WHY: The shared TPC core accepts a credential from either transport in a free
 *      form (a bearer token, optionally "Bearer "-prefixed, or a GSI proxy PEM)
 *      and must classify it without baking transport-specific assumptions into
 *      the core. Centralising the sniffing here keeps the format heuristics and
 *      the expiry check in one auditable place.
 *
 * HOW: parse() trims surrounding whitespace/CRLF, treats empty or "none" as
 *      BRIX_TPC_CREDENTIAL_NONE, then routes on the caller hint or on the
 *      "Bearer " / "-----BEGIN" markers, stripping the "Bearer " prefix for
 *      tokens. The static brix_tpc_copy_credential_str() duplicates the value
 *      into the pool (NUL-terminated) when a pool is supplied, or aliases the
 *      caller's bytes when pool is NULL. validate() enforces non-empty bodies
 *      per type and compares expires_at against ngx_time().
 */

#include <string.h>

static ngx_int_t
brix_tpc_copy_credential_str(ngx_str_t *dst, const u_char *data,
    size_t len, ngx_pool_t *pool)
{
    if (dst == NULL) {
        return NGX_ERROR;
    }

    dst->data = NULL;
    dst->len = 0;

    if (data == NULL || len == 0) {
        return NGX_OK;
    }

    if (pool == NULL) {
        dst->data = (u_char *) data;
        dst->len = len;
        return NGX_OK;
    }

    dst->data = ngx_pnalloc(pool, len + 1);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst->data, data, len);
    dst->data[len] = '\0';
    dst->len = len;

    return NGX_OK;
}

static ngx_flag_t
brix_tpc_str_equals(const u_char *data, size_t len, const char *literal)
{
    size_t literal_len;

    if (data == NULL || literal == NULL) {
        return 0;
    }

    literal_len = ngx_strlen(literal);
    return len == literal_len
           && ngx_strncasecmp((u_char *) data, (u_char *) literal,
                              literal_len) == 0;
}

static ngx_flag_t
brix_tpc_starts_with(const u_char *data, size_t len, const char *prefix)
{
    size_t prefix_len;

    if (data == NULL || prefix == NULL) {
        return 0;
    }

    prefix_len = ngx_strlen(prefix);
    return len >= prefix_len
           && ngx_strncasecmp((u_char *) data, (u_char *) prefix,
                              prefix_len) == 0;
}

/* Map a credential type enum to a stable lowercase string for logs/metrics. */
const char *
brix_tpc_credential_type_name(brix_tpc_credential_type_t type)
{
    switch (type) {
    case BRIX_TPC_CREDENTIAL_NONE:
        return "none";
    case BRIX_TPC_CREDENTIAL_PROXY:
        return "proxy";
    case BRIX_TPC_CREDENTIAL_TOKEN:
        return "token";
    default:
        return "unknown";
    }
}

/*
 * WHAT: Trim leading/trailing ASCII whitespace and CRLF from [data,len),
 *       writing the trimmed view back through *data / *len.
 * WHY:  Callers pass free-form credential bytes that may carry surrounding
 *       spaces, tabs, or line endings from a header or file; sniffing must run
 *       on the bare value so the markers and length checks are exact.
 * HOW:  Advances the start past leading ' '/'\t' and shrinks the length past
 *       trailing ' '/'\t'/'\n'/'\r'. Pure pointer/length arithmetic, no copy.
 */
static void
brix_tpc_trim_credential(const u_char **data, size_t *len)
{
    const u_char *p = *data;
    size_t        n = *len;

    while (n > 0 && (*p == ' ' || *p == '\t')) {
        p++;
        n--;
    }
    while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t'
                     || p[n - 1] == '\n' || p[n - 1] == '\r')) {
        n--;
    }

    *data = p;
    *len = n;
}

/*
 * WHAT: Classify [data,len) as a bearer TOKEN when the hint requests a token or
 *       the value carries the "Bearer " marker, populating cred->bearer.
 * WHY:  The token branch owns the "Bearer " prefix strip and the token copy;
 *       isolating it keeps brix_tpc_credential_parse a flat router.
 * HOW:  Returns NGX_DECLINED when neither the hint nor the marker matches (the
 *       caller then tries the proxy branch). Otherwise strips a leading
 *       "Bearer ", sets cred->type, and copies the remaining bytes; returns
 *       NGX_OK, or NGX_ERROR on an allocation failure.
 */
static ngx_int_t
brix_tpc_parse_token(const u_char *data, size_t len,
    brix_tpc_credential_type_t hint, brix_tpc_credential_t *cred,
    ngx_pool_t *pool)
{
    if (hint != BRIX_TPC_CREDENTIAL_TOKEN
        && !brix_tpc_starts_with(data, len, "Bearer "))
    {
        return NGX_DECLINED;
    }

    if (brix_tpc_starts_with(data, len, "Bearer ")) {
        data += sizeof("Bearer ") - 1;
        len -= sizeof("Bearer ") - 1;
    }

    cred->type = BRIX_TPC_CREDENTIAL_TOKEN;
    if (brix_tpc_copy_credential_str(&cred->bearer, data, len, pool) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * WHAT: Classify [data,len) as a GSI PROXY when the hint requests a proxy or the
 *       value carries the "-----BEGIN" PEM marker, populating cred->proxy_pem.
 * WHY:  Mirrors brix_tpc_parse_token for the PEM branch so the router stays a
 *       flat sequence of early-return attempts with no nested branching.
 * HOW:  Returns NGX_DECLINED when neither the hint nor the marker matches.
 *       Otherwise sets cred->type and copies the PEM bytes; returns NGX_OK, or
 *       NGX_ERROR on an allocation failure.
 */
static ngx_int_t
brix_tpc_parse_proxy(const u_char *data, size_t len,
    brix_tpc_credential_type_t hint, brix_tpc_credential_t *cred,
    ngx_pool_t *pool)
{
    if (hint != BRIX_TPC_CREDENTIAL_PROXY
        && !brix_tpc_starts_with(data, len, "-----BEGIN"))
    {
        return NGX_DECLINED;
    }

    cred->type = BRIX_TPC_CREDENTIAL_PROXY;
    if (brix_tpc_copy_credential_str(&cred->proxy_pem, data, len, pool)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * Sniff raw_credential into a typed *cred. Honours an optional type hint and
 * the "Bearer "/"-----BEGIN" markers; trims surrounding whitespace and CRLF.
 * Empty or "none" yields BRIX_TPC_CREDENTIAL_NONE. When pool is non-NULL the
 * value is copied (NUL-terminated) into it, otherwise *cred aliases the input.
 * Returns NGX_OK, NGX_DECLINED for an unrecognised format, or NGX_ERROR on a
 * NULL cred / allocation failure.
 */
ngx_int_t
brix_tpc_credential_parse(const ngx_str_t *raw_credential,
    brix_tpc_credential_type_t hint, brix_tpc_credential_t *cred,
    ngx_pool_t *pool, ngx_log_t *log)
{
    const u_char *data = NULL;
    size_t        len = 0;
    ngx_int_t     rc;

    if (cred == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(cred, sizeof(*cred));
    cred->type = BRIX_TPC_CREDENTIAL_NONE;

    if (raw_credential == NULL || raw_credential->data == NULL
        || raw_credential->len == 0)
    {
        return NGX_OK;
    }

    data = raw_credential->data;
    len = raw_credential->len;
    brix_tpc_trim_credential(&data, &len);

    if (len == 0 || brix_tpc_str_equals(data, len, "none")) {
        cred->type = BRIX_TPC_CREDENTIAL_NONE;
        return NGX_OK;
    }

    rc = brix_tpc_parse_token(data, len, hint, cred, pool);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    rc = brix_tpc_parse_proxy(data, len, hint, cred, pool);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "brix_tpc: unsupported credential format");
    return NGX_DECLINED;
}

/*
 * Validate a parsed credential: PROXY/TOKEN must carry a non-empty body, and a
 * non-zero expires_at must be in the future relative to ngx_time(). NONE always
 * passes. Returns NGX_OK, NGX_DECLINED if empty/expired/invalid-type, or
 * NGX_ERROR on a NULL cred.
 */
ngx_int_t
brix_tpc_credential_validate(const brix_tpc_credential_t *cred,
    ngx_log_t *log)
{
    time_t now;

    if (cred == NULL) {
        return NGX_ERROR;
    }

    switch (cred->type) {
    case BRIX_TPC_CREDENTIAL_NONE:
        return NGX_OK;

    case BRIX_TPC_CREDENTIAL_PROXY:
        if (cred->proxy_pem.data == NULL || cred->proxy_pem.len == 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix_tpc: empty proxy credential");
            return NGX_DECLINED;
        }
        break;

    case BRIX_TPC_CREDENTIAL_TOKEN:
        if (cred->bearer.data == NULL || cred->bearer.len == 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix_tpc: empty bearer credential");
            return NGX_DECLINED;
        }
        break;

    default:
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_tpc: invalid credential type %d",
                      (int) cred->type);
        return NGX_DECLINED;
    }

    if (cred->expires_at != 0) {
        now = ngx_time();
        if (cred->expires_at <= now) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix_tpc: %s credential expired",
                          brix_tpc_credential_type_name(cred->type));
            return NGX_DECLINED;
        }
    }

    return NGX_OK;
}
