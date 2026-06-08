#include "identity.h"

#include <string.h>

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

const char *
xrootd_identity_dn_cstr(const xrootd_identity_t *id)
{
    return (id != NULL && id->dn.data != NULL) ? (const char *) id->dn.data : "";
}

const char *
xrootd_identity_subject_cstr(const xrootd_identity_t *id)
{
    return (id != NULL && id->subject.data != NULL)
           ? (const char *) id->subject.data : "";
}

const char *
xrootd_identity_vo_csv_cstr(const xrootd_identity_t *id)
{
    return (id != NULL && id->vo_csv.data != NULL)
           ? (const char *) id->vo_csv.data : "";
}

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
