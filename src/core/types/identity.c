#include "identity.h"
#include "auth/token/issuer_registry.h"   /* phase-59 W1: per-path issuer gate */

#include <string.h>

/*
 * identity.c — builder/accessors for the protocol-agnostic principal.
 *
 * WHAT: Implements brix_identity_t lifecycle (alloc) and the setters that
 *       populate it from the various wire-auth flavours — GSI DN, JWT/token
 *       claims, SSS user, S3 access key — plus const accessors
 *       (brix_identity_dn_cstr / _subject_cstr / _vo_csv_cstr), a token
 *       scope check (brix_identity_check_token_scope), and a one-line audit
 *       summary (brix_identity_describe).
 *
 * WHY:  Each protocol verifies credentials its own way, but policy, ACL, and
 *       audit code must reason about a single canonical principal shape.  This
 *       module is the only place that knows how to translate per-protocol
 *       credential fragments into that shape and to keep the structured arrays
 *       (vo_list, scopes, token_scopes) consistent with the flat compatibility
 *       views (vo_csv, scope_raw) that current hot paths still read.
 *
 * HOW:  Every string lands in the caller's ngx_pool_t via the internal
 *       brix_identity_set_cstr (NUL-terminated copy so the values can be
 *       passed to C string APIs).  CSV group lists are tokenised by
 *       brix_identity_split_csv and space-separated OAuth scopes by
 *       brix_identity_split_spaces into ngx_str_t arrays.  Any setter that
 *       records a credential ORs the matching BRIX_AUTHN_* bit into
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
brix_identity_push_str(ngx_pool_t *pool, ngx_array_t **array,
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
brix_identity_split_csv(ngx_pool_t *pool, ngx_array_t **array,
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
            && brix_identity_push_str(pool, array, start,
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
brix_identity_split_spaces(ngx_pool_t *pool, ngx_array_t **array,
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
            && brix_identity_push_str(pool, array, start,
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
brix_identity_method_name(ngx_uint_t method)
{
    if (method & BRIX_AUTHN_GSI) {
        return "GSI";
    }
    if (method & BRIX_AUTHN_TOKEN) {
        return "TOKEN";
    }
    if (method & BRIX_AUTHN_SSS) {
        return "SSS";
    }
    if (method & BRIX_AUTHN_S3KEY) {
        return "S3KEY";
    }
    if (method & BRIX_AUTHN_KRB5) {
        return "KRB5";
    }
    if (method & BRIX_AUTHN_UNIX) {
        return "UNIX";
    }
    return "NONE";
}

/*
 * Allocate and zero-initialise a new identity on `pool`, seeding auth_method
 * to BRIX_AUTHN_NONE (unauthenticated until a setter records a credential).
 */
brix_identity_t *
brix_identity_alloc(ngx_pool_t *pool)
{
    brix_identity_t *id;

    if (pool == NULL) {
        return NULL;
    }

    id = ngx_pcalloc(pool, sizeof(*id));
    if (id != NULL) {
        id->auth_method = BRIX_AUTHN_NONE;
    }

    return id;
}

/*
 * Copy a C string into `dst` as a pool-allocated, NUL-terminated ngx_str_t.
 * A NULL or empty source clears `dst` to a null string and still succeeds.
 */
ngx_int_t
brix_identity_set_cstr(ngx_pool_t *pool, ngx_str_t *dst, const char *src)
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
 * BRIX_AUTHN_* method bit, and mark the principal authenticated.
 */
ngx_int_t
brix_identity_set_dn(brix_identity_t *id, ngx_pool_t *pool,
    const char *dn, ngx_uint_t auth_method)
{
    if (id == NULL) {
        return NGX_ERROR;
    }

    if (brix_identity_set_cstr(pool, &id->dn, dn) != NGX_OK) {
        return NGX_ERROR;
    }

    id->auth_method |= auth_method;
    id->is_authenticated = 1;
    return NGX_OK;
}

/*
 * Record a subject (JWT `sub` or S3 access key), OR in the given
 * BRIX_AUTHN_* method bit, and mark the principal authenticated.
 */
ngx_int_t
brix_identity_set_subject(brix_identity_t *id, ngx_pool_t *pool,
    const char *subject, ngx_uint_t auth_method)
{
    if (id == NULL) {
        return NGX_ERROR;
    }

    if (brix_identity_set_cstr(pool, &id->subject, subject) != NGX_OK) {
        return NGX_ERROR;
    }

    id->auth_method |= auth_method;
    id->is_authenticated = 1;
    return NGX_OK;
}

/*
 * brix_identity_derive_attrs — split each comma-separated VOMS FQAN / token
 * group into (vorg, role, group) and store them as three index-aligned CSVs for
 * the xrdacc engine.  An FQAN like "/cms/Role=production/Capability=NULL" yields
 * vorg="cms", role="production", group="/cms"; "Role=NULL" and a plain group
 * name ("cms") yield an empty role.  Each output is a prefix/substring of the
 * input, so an strlen(vo_csv)-sized buffer always suffices.
 */
static ngx_int_t
brix_identity_derive_attrs(brix_identity_t *id, ngx_pool_t *pool,
    const char *vo_csv)
{
    size_t   inlen = (vo_csv != NULL) ? ngx_strlen(vo_csv) : 0;
    u_char  *vb, *rb, *gb;
    size_t   vl = 0, rl = 0, gl = 0;
    const char *p, *toks;
    int      first = 1;

    ngx_str_null(&id->acc_vorg_csv);
    ngx_str_null(&id->acc_role_csv);
    ngx_str_null(&id->acc_group_csv);
    if (inlen == 0) {
        return NGX_OK;
    }

    vb = ngx_pnalloc(pool, inlen + 1);
    rb = ngx_pnalloc(pool, inlen + 1);
    gb = ngx_pnalloc(pool, inlen + 1);
    if (vb == NULL || rb == NULL || gb == NULL) {
        return NGX_ERROR;
    }

    p = toks = vo_csv;
    for (;;) {
        if (*p == ',' || *p == '\0') {
            const char *tok = toks;
            size_t      tl = (size_t) (p - toks);
            const char *role = NULL, *grp, *rp, *cp, *vstart, *vend;
            size_t      rlen = 0, glen, vlen;

            while (tl > 0 && (*tok == ' ' || *tok == '\t')) { tok++; tl--; }
            while (tl > 0 && (tok[tl - 1] == ' ' || tok[tl - 1] == '\t')) { tl--; }

            grp = tok;
            glen = tl;
            rp = memmem(tok, tl, "/Role=", 6);
            if (rp != NULL) {
                const char *rs = rp + 6, *re;
                glen = (size_t) (rp - tok);                /* group = before /Role= */
                re = memchr(rs, '/', (size_t) ((tok + tl) - rs));
                if (re == NULL) { re = tok + tl; }
                role = rs;
                rlen = (size_t) (re - rs);
                if (rlen == 4 && ngx_strncmp(role, "NULL", 4) == 0) { rlen = 0; }
            } else if ((cp = memmem(tok, tl, "/Capability=", 12)) != NULL) {
                glen = (size_t) (cp - tok);                /* strip trailing capability */
            }

            vstart = grp;
            vlen = glen;
            if (vlen > 0 && *vstart == '/') { vstart++; vlen--; }
            vend = memchr(vstart, '/', vlen);
            if (vend != NULL) { vlen = (size_t) (vend - vstart); }

            if (!first) { vb[vl++] = ','; rb[rl++] = ','; gb[gl++] = ','; }
            first = 0;
            if (vlen) { ngx_memcpy(vb + vl, vstart, vlen); vl += vlen; }
            if (rlen) { ngx_memcpy(rb + rl, role, rlen);   rl += rlen; }
            if (glen) { ngx_memcpy(gb + gl, grp, glen);    gl += glen; }

            if (*p == '\0') { break; }
            toks = p + 1;
        }
        p++;
    }
    vb[vl] = '\0'; rb[rl] = '\0'; gb[gl] = '\0';
    id->acc_vorg_csv.data  = vb; id->acc_vorg_csv.len  = vl;
    id->acc_role_csv.data  = rb; id->acc_role_csv.len  = rl;
    id->acc_group_csv.data = gb; id->acc_group_csv.len = gl;
    return NGX_OK;
}

/*
 * Store the VO/group membership both as the flat CSV compatibility view
 * (vo_csv) and as the structured vo_list array, keeping the two in sync; also
 * derive the xrdacc (vorg, role, group) attribute views.
 */
ngx_int_t
brix_identity_set_vos_csv(brix_identity_t *id, ngx_pool_t *pool,
    const char *vo_csv)
{
    if (id == NULL) {
        return NGX_ERROR;
    }

    if (brix_identity_set_cstr(pool, &id->vo_csv, vo_csv) != NGX_OK) {
        return NGX_ERROR;
    }
    if (brix_identity_derive_attrs(id, pool, vo_csv) != NGX_OK) {
        return NGX_ERROR;
    }

    return brix_identity_split_csv(pool, &id->vo_list, vo_csv);
}

/*
 * Populate the identity from a verified token's claims: sets subject (sub),
 * issuer (iss), raw scope string, and groups; mirrors `sub` into `dn` when
 * present; tokenises the raw scope into the scopes array; caches up to
 * BRIX_MAX_TOKEN_SCOPES parsed scope entries; and derives has_read_scope /
 * has_write_scope from their read/write/create flags.  Marks the principal
 * token-authenticated.
 */
ngx_int_t
brix_identity_set_token_claims(brix_identity_t *id, ngx_pool_t *pool,
    const brix_token_claims_t *claims)
{
    int i;

    if (id == NULL || claims == NULL) {
        return NGX_ERROR;
    }

    if (brix_identity_set_subject(id, pool, claims->sub,
                                    BRIX_AUTHN_TOKEN) != NGX_OK
        || brix_identity_set_cstr(pool, &id->issuer, claims->iss) != NGX_OK
        || brix_identity_set_cstr(pool, &id->scope_raw,
                                    claims->scope_raw) != NGX_OK
        || brix_identity_set_vos_csv(id, pool, claims->groups) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (claims->sub[0] != '\0'
        && brix_identity_set_cstr(pool, &id->dn, claims->sub) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (brix_identity_split_spaces(pool, &id->scopes,
                                     claims->scope_raw) != NGX_OK)
    {
        return NGX_ERROR;
    }

    id->token_scope_count = claims->scope_count;
    if (id->token_scope_count > BRIX_MAX_TOKEN_SCOPES) {
        id->token_scope_count = BRIX_MAX_TOKEN_SCOPES;
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

    id->auth_method |= BRIX_AUTHN_TOKEN;
    id->is_authenticated = 1;

    return NGX_OK;
}

/* Return the DN as a C string, or "" when the identity or field is unset. */
const char *
brix_identity_dn_cstr(const brix_identity_t *id)
{
    return (id != NULL && id->dn.data != NULL) ? (const char *) id->dn.data : "";
}

/* Return the subject as a C string, or "" when the identity or field is unset. */
const char *
brix_identity_subject_cstr(const brix_identity_t *id)
{
    return (id != NULL && id->subject.data != NULL)
           ? (const char *) id->subject.data : "";
}

/* Return the VO/group CSV as a C string, or "" when unset. */
const char *
brix_identity_vo_csv_cstr(const brix_identity_t *id)
{
    return (id != NULL && id->vo_csv.data != NULL)
           ? (const char *) id->vo_csv.data : "";
}

/* XrdAcc attribute views derived from the FQANs; "" when unset (never NULL). */
const char *
brix_identity_acc_vorg_cstr(const brix_identity_t *id)
{
    return (id != NULL && id->acc_vorg_csv.data != NULL)
           ? (const char *) id->acc_vorg_csv.data : "";
}

const char *
brix_identity_acc_role_cstr(const brix_identity_t *id)
{
    return (id != NULL && id->acc_role_csv.data != NULL)
           ? (const char *) id->acc_role_csv.data : "";
}

const char *
brix_identity_acc_group_cstr(const brix_identity_t *id)
{
    return (id != NULL && id->acc_group_csv.data != NULL)
           ? (const char *) id->acc_group_csv.data : "";
}

/*
 * Authorise `logical_path` against the cached token scopes.  Returns NGX_OK
 * (allow) immediately for non-token principals — scope checks apply only to
 * token auth; otherwise delegates to brix_token_check_write/read depending
 * on need_write and returns NGX_OK only when the scope grants access.
 */
ngx_int_t
brix_identity_check_token_scope(const brix_identity_t *id,
    const char *logical_path, int need_write)
{
    if (id == NULL || !(id->auth_method & BRIX_AUTHN_TOKEN)) {
        return NGX_OK;
    }

    /* phase-59 W1: when authed via a multi-issuer registry, enforce the
     * issuer's base_path/restricted_path gate + strategy ladder per path. */
    if (id->token_issuer != NULL) {
        brix_token_op_e op = need_write ? BRIX_TOKEN_OP_WRITE
                                          : BRIX_TOKEN_OP_READ;
        brix_token_claims_t c;
        ngx_memzero(&c, sizeof(c));
        c.scope_count = id->token_scope_count;
        ngx_memcpy(c.scopes, id->token_scopes,
                   sizeof(brix_token_scope_t) * id->token_scope_count);
        return brix_token_authz_strategy(
                   (const brix_token_issuer_t *) id->token_issuer,
                   &c, logical_path, op) ? NGX_OK : NGX_ERROR;
    }

    if (need_write) {
        return brix_token_check_write(id->token_scopes,
                                        id->token_scope_count,
                                        logical_path)
               ? NGX_OK : NGX_ERROR;
    }

    return brix_token_check_read(id->token_scopes,
                                   id->token_scope_count,
                                   logical_path)
           ? NGX_OK : NGX_ERROR;
}

/*
 * Build a pool-allocated "dn=... sub=... method=..." summary string suitable
 * for access/audit logs.  Returns a null ngx_str_t on allocation failure.
 */
ngx_str_t
brix_identity_describe(const brix_identity_t *id, ngx_pool_t *pool)
{
    ngx_str_t   out;
    const char *dn, *sub, *method;
    size_t      len;
    u_char     *last;

    ngx_str_null(&out);
    if (pool == NULL) {
        return out;
    }

    dn = brix_identity_dn_cstr(id);
    sub = brix_identity_subject_cstr(id);
    method = brix_identity_method_name(id != NULL ? id->auth_method
                                                    : BRIX_AUTHN_NONE);

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
