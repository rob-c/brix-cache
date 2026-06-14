#include "identity.h"

#include <string.h>

/*
 * identity.c — builder/accessors for the protocol-agnostic principal.
 *
 * WHAT: Implements xrootd_identity_t lifecycle (alloc) and the setters that
 *       populate it from the various wire-auth flavours — GSI DN, JWT/token
 *       claims, SSS user, S3 access key — plus const accessors
 *       (xrootd_identity_dn_cstr / _subject_cstr / _vo_csv_cstr), a token
 *       scope check (xrootd_identity_check_token_scope), and a one-line audit
 *       summary (xrootd_identity_describe).
 *
 * WHY:  Each protocol verifies credentials its own way, but policy, ACL, and
 *       audit code must reason about a single canonical principal shape.  This
 *       module is the only place that knows how to translate per-protocol
 *       credential fragments into that shape and to keep the structured arrays
 *       (vo_list, scopes, token_scopes) consistent with the flat compatibility
 *       views (vo_csv, scope_raw) that current hot paths still read.
 *
 * HOW:  Every string lands in the caller's ngx_pool_t via the internal
 *       xrootd_identity_set_cstr (NUL-terminated copy so the values can be
 *       passed to C string APIs).  CSV group lists are tokenised by
 *       xrootd_identity_split_csv and space-separated OAuth scopes by
 *       xrootd_identity_split_spaces into ngx_str_t arrays.  Any setter that
 *       records a credential ORs the matching XROOTD_AUTHN_* bit into
 *       auth_method and marks is_authenticated; token claims additionally
 *       cache the parsed scope table and derive has_read_scope /
 *       has_write_scope for fast policy decisions.
 */

/*
 * Append one ngx_str_t copy of [start, start+len) to *array, lazily creating
 * the array on first use.  Empty/NULL inputs are a successful no-op so callers
 * can feed raw tokeniser output without pre-filtering.
 */
static ngx_int_t
xrootd_identity_push_str(ngx_pool_t *pool, ngx_array_t **array,
    const char *start, size_t len)
{
    ngx_str_t *elt;

    if (pool == NULL || array == NULL || start == NULL || len == 0) {
        return NGX_OK;
    }

    if (*array == NULL) {
        *array = ngx_array_create(pool, 4, sizeof(ngx_str_t));
        if (*array == NULL) {
            return NGX_ERROR;
        }
    }

    elt = ngx_array_push(*array);
    if (elt == NULL) {
        return NGX_ERROR;
    }

    elt->data = ngx_pnalloc(pool, len + 1);
    if (elt->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(elt->data, start, len);
    elt->data[len] = '\0';
    elt->len = len;

    return NGX_OK;
}

/*
 * Split a comma-separated list (e.g. VO/group CSV) into individual ngx_str_t
 * elements, skipping empty fields and runs of commas.
 */
static ngx_int_t
xrootd_identity_split_csv(ngx_pool_t *pool, ngx_array_t **array,
    const char *csv)
{
    const char *p, *start;

    if (csv == NULL || csv[0] == '\0') {
        return NGX_OK;
    }

    p = csv;
    while (*p != '\0') {
        while (*p == ',') {
            p++;
        }
        start = p;
        while (*p != '\0' && *p != ',') {
            p++;
        }
        if ((size_t) (p - start) > 0
            && xrootd_identity_push_str(pool, array, start,
                                        (size_t) (p - start)) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * Split a space-separated list (the raw OAuth `scope` claim) into individual
 * ngx_str_t scope tokens, skipping empty fields and runs of spaces.
 */
static ngx_int_t
xrootd_identity_split_spaces(ngx_pool_t *pool, ngx_array_t **array,
    const char *spaces)
{
    const char *p, *start;

    if (spaces == NULL || spaces[0] == '\0') {
        return NGX_OK;
    }

    p = spaces;
    while (*p != '\0') {
        while (*p == ' ') {
            p++;
        }
        start = p;
        while (*p != '\0' && *p != ' ') {
            p++;
        }
        if ((size_t) (p - start) > 0
            && xrootd_identity_push_str(pool, array, start,
                                        (size_t) (p - start)) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * Map an auth_method bitmask to a single human-readable label for audit
 * output.  Methods are tested in priority order; the first set bit wins, so a
 * principal authenticated by several mechanisms reports its strongest one.
 */
static const char *
xrootd_identity_method_name(ngx_uint_t method)
{
    if (method & XROOTD_AUTHN_GSI) {
        return "GSI";
    }
    if (method & XROOTD_AUTHN_TOKEN) {
        return "TOKEN";
    }
    if (method & XROOTD_AUTHN_SSS) {
        return "SSS";
    }
    if (method & XROOTD_AUTHN_S3KEY) {
        return "S3KEY";
    }
    if (method & XROOTD_AUTHN_KRB5) {
        return "KRB5";
    }
    if (method & XROOTD_AUTHN_UNIX) {
        return "UNIX";
    }
    return "NONE";
}

/*
 * Allocate and zero-initialise a new identity on `pool`, seeding auth_method
 * to XROOTD_AUTHN_NONE (unauthenticated until a setter records a credential).
 */
xrootd_identity_t *
xrootd_identity_alloc(ngx_pool_t *pool)
{
    xrootd_identity_t *id;

    if (pool == NULL) {
        return NULL;
    }

    id = ngx_pcalloc(pool, sizeof(*id));
    if (id != NULL) {
        id->auth_method = XROOTD_AUTHN_NONE;
    }

    return id;
}

/*
 * Copy a C string into `dst` as a pool-allocated, NUL-terminated ngx_str_t.
 * A NULL or empty source clears `dst` to a null string and still succeeds.
 */
ngx_int_t
xrootd_identity_set_cstr(ngx_pool_t *pool, ngx_str_t *dst, const char *src)
{
    size_t len;

    if (pool == NULL || dst == NULL) {
        return NGX_ERROR;
    }

    if (src == NULL || src[0] == '\0') {
        ngx_str_null(dst);
        return NGX_OK;
    }

    len = strlen(src);
    dst->data = ngx_pnalloc(pool, len + 1);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst->data, src, len);
    dst->data[len] = '\0';
    dst->len = len;

    return NGX_OK;
}

/*
 * Record a distinguished name (GSI cert DN, SSS user, etc.), OR in the given
 * XROOTD_AUTHN_* method bit, and mark the principal authenticated.
 */
ngx_int_t
xrootd_identity_set_dn(xrootd_identity_t *id, ngx_pool_t *pool,
    const char *dn, ngx_uint_t auth_method)
{
    if (id == NULL) {
        return NGX_ERROR;
    }

    if (xrootd_identity_set_cstr(pool, &id->dn, dn) != NGX_OK) {
        return NGX_ERROR;
    }

    id->auth_method |= auth_method;
    id->is_authenticated = 1;
    return NGX_OK;
}

/*
 * Record a subject (JWT `sub` or S3 access key), OR in the given
 * XROOTD_AUTHN_* method bit, and mark the principal authenticated.
 */
ngx_int_t
xrootd_identity_set_subject(xrootd_identity_t *id, ngx_pool_t *pool,
    const char *subject, ngx_uint_t auth_method)
{
    if (id == NULL) {
        return NGX_ERROR;
    }

    if (xrootd_identity_set_cstr(pool, &id->subject, subject) != NGX_OK) {
        return NGX_ERROR;
    }

    id->auth_method |= auth_method;
    id->is_authenticated = 1;
    return NGX_OK;
}

/*
 * Store the VO/group membership both as the flat CSV compatibility view
 * (vo_csv) and as the structured vo_list array, keeping the two in sync.
 */
ngx_int_t
xrootd_identity_set_vos_csv(xrootd_identity_t *id, ngx_pool_t *pool,
    const char *vo_csv)
{
    if (id == NULL) {
        return NGX_ERROR;
    }

    if (xrootd_identity_set_cstr(pool, &id->vo_csv, vo_csv) != NGX_OK) {
        return NGX_ERROR;
    }

    return xrootd_identity_split_csv(pool, &id->vo_list, vo_csv);
}

/*
 * Populate the identity from a verified token's claims: sets subject (sub),
 * issuer (iss), raw scope string, and groups; mirrors `sub` into `dn` when
 * present; tokenises the raw scope into the scopes array; caches up to
 * XROOTD_MAX_TOKEN_SCOPES parsed scope entries; and derives has_read_scope /
 * has_write_scope from their read/write/create flags.  Marks the principal
 * token-authenticated.
 */
ngx_int_t
xrootd_identity_set_token_claims(xrootd_identity_t *id, ngx_pool_t *pool,
    const xrootd_token_claims_t *claims)
{
    int i;

    if (id == NULL || claims == NULL) {
        return NGX_ERROR;
    }

    if (xrootd_identity_set_subject(id, pool, claims->sub,
                                    XROOTD_AUTHN_TOKEN) != NGX_OK
        || xrootd_identity_set_cstr(pool, &id->issuer, claims->iss) != NGX_OK
        || xrootd_identity_set_cstr(pool, &id->scope_raw,
                                    claims->scope_raw) != NGX_OK
        || xrootd_identity_set_vos_csv(id, pool, claims->groups) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (claims->sub[0] != '\0'
        && xrootd_identity_set_cstr(pool, &id->dn, claims->sub) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (xrootd_identity_split_spaces(pool, &id->scopes,
                                     claims->scope_raw) != NGX_OK)
    {
        return NGX_ERROR;
    }

    id->token_scope_count = claims->scope_count;
    if (id->token_scope_count > XROOTD_MAX_TOKEN_SCOPES) {
        id->token_scope_count = XROOTD_MAX_TOKEN_SCOPES;
    }

    for (i = 0; i < id->token_scope_count; i++) {
        id->token_scopes[i] = claims->scopes[i];
        if (claims->scopes[i].read) {
            id->has_read_scope = 1;
        }
        if (claims->scopes[i].write || claims->scopes[i].create) {
            id->has_write_scope = 1;
        }
    }

    id->auth_method |= XROOTD_AUTHN_TOKEN;
    id->is_authenticated = 1;

    return NGX_OK;
}

/* Return the DN as a C string, or "" when the identity or field is unset. */
const char *
xrootd_identity_dn_cstr(const xrootd_identity_t *id)
{
    return (id != NULL && id->dn.data != NULL) ? (const char *) id->dn.data : "";
}

/* Return the subject as a C string, or "" when the identity or field is unset. */
const char *
xrootd_identity_subject_cstr(const xrootd_identity_t *id)
{
    return (id != NULL && id->subject.data != NULL)
           ? (const char *) id->subject.data : "";
}

/* Return the VO/group CSV as a C string, or "" when unset. */
const char *
xrootd_identity_vo_csv_cstr(const xrootd_identity_t *id)
{
    return (id != NULL && id->vo_csv.data != NULL)
           ? (const char *) id->vo_csv.data : "";
}

/*
 * Authorise `logical_path` against the cached token scopes.  Returns NGX_OK
 * (allow) immediately for non-token principals — scope checks apply only to
 * token auth; otherwise delegates to xrootd_token_check_write/read depending
 * on need_write and returns NGX_OK only when the scope grants access.
 */
ngx_int_t
xrootd_identity_check_token_scope(const xrootd_identity_t *id,
    const char *logical_path, int need_write)
{
    if (id == NULL || !(id->auth_method & XROOTD_AUTHN_TOKEN)) {
        return NGX_OK;
    }

    if (need_write) {
        return xrootd_token_check_write(id->token_scopes,
                                        id->token_scope_count,
                                        logical_path)
               ? NGX_OK : NGX_ERROR;
    }

    return xrootd_token_check_read(id->token_scopes,
                                   id->token_scope_count,
                                   logical_path)
           ? NGX_OK : NGX_ERROR;
}

/*
 * Build a pool-allocated "dn=... sub=... method=..." summary string suitable
 * for access/audit logs.  Returns a null ngx_str_t on allocation failure.
 */
ngx_str_t
xrootd_identity_describe(const xrootd_identity_t *id, ngx_pool_t *pool)
{
    ngx_str_t   out;
    const char *dn, *sub, *method;
    size_t      len;
    u_char     *last;

    ngx_str_null(&out);
    if (pool == NULL) {
        return out;
    }

    dn = xrootd_identity_dn_cstr(id);
    sub = xrootd_identity_subject_cstr(id);
    method = xrootd_identity_method_name(id != NULL ? id->auth_method
                                                    : XROOTD_AUTHN_NONE);

    len = strlen("dn= sub= method=") + strlen(dn) + strlen(sub)
          + strlen(method);

    out.data = ngx_pnalloc(pool, len + 1);
    if (out.data == NULL) {
        return out;
    }

    last = ngx_snprintf(out.data, len + 1, "dn=%s sub=%s method=%s",
                        dn, sub, method);
    out.len = (size_t) (last - out.data);
    return out;
}
