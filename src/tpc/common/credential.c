#include "credential.h"

#include <string.h>

static ngx_int_t
xrootd_tpc_copy_credential_str(ngx_str_t *dst, const u_char *data,
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
xrootd_tpc_str_equals(const u_char *data, size_t len, const char *literal)
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
xrootd_tpc_starts_with(const u_char *data, size_t len, const char *prefix)
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

const char *
xrootd_tpc_credential_type_name(xrootd_tpc_credential_type_t type)
{
    switch (type) {
    case XROOTD_TPC_CREDENTIAL_NONE:
        return "none";
    case XROOTD_TPC_CREDENTIAL_PROXY:
        return "proxy";
    case XROOTD_TPC_CREDENTIAL_TOKEN:
        return "token";
    default:
        return "unknown";
    }
}

ngx_int_t
xrootd_tpc_credential_parse(const ngx_str_t *raw_credential,
    xrootd_tpc_credential_type_t hint, xrootd_tpc_credential_t *cred,
    ngx_pool_t *pool, ngx_log_t *log)
{
    const u_char *data;
    size_t        len;

    if (cred == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(cred, sizeof(*cred));
    cred->type = XROOTD_TPC_CREDENTIAL_NONE;

    if (raw_credential == NULL || raw_credential->data == NULL
        || raw_credential->len == 0)
    {
        return NGX_OK;
    }

    data = raw_credential->data;
    len = raw_credential->len;

    while (len > 0 && (*data == ' ' || *data == '\t')) {
        data++;
        len--;
    }
    while (len > 0 && (data[len - 1] == ' ' || data[len - 1] == '\t'
                       || data[len - 1] == '\n' || data[len - 1] == '\r')) {
        len--;
    }

    if (len == 0 || xrootd_tpc_str_equals(data, len, "none")) {
        cred->type = XROOTD_TPC_CREDENTIAL_NONE;
        return NGX_OK;
    }

    if (hint == XROOTD_TPC_CREDENTIAL_TOKEN
        || xrootd_tpc_starts_with(data, len, "Bearer "))
    {
        if (xrootd_tpc_starts_with(data, len, "Bearer ")) {
            data += sizeof("Bearer ") - 1;
            len -= sizeof("Bearer ") - 1;
        }

        cred->type = XROOTD_TPC_CREDENTIAL_TOKEN;
        if (xrootd_tpc_copy_credential_str(&cred->bearer, data, len, pool)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    if (hint == XROOTD_TPC_CREDENTIAL_PROXY
        || xrootd_tpc_starts_with(data, len, "-----BEGIN"))
    {
        cred->type = XROOTD_TPC_CREDENTIAL_PROXY;
        if (xrootd_tpc_copy_credential_str(&cred->proxy_pem, data, len, pool)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "xrootd_tpc: unsupported credential format");
    return NGX_DECLINED;
}

ngx_int_t
xrootd_tpc_credential_validate(const xrootd_tpc_credential_t *cred,
    ngx_log_t *log)
{
    time_t now;

    if (cred == NULL) {
        return NGX_ERROR;
    }

    switch (cred->type) {
    case XROOTD_TPC_CREDENTIAL_NONE:
        return NGX_OK;

    case XROOTD_TPC_CREDENTIAL_PROXY:
        if (cred->proxy_pem.data == NULL || cred->proxy_pem.len == 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_tpc: empty proxy credential");
            return NGX_DECLINED;
        }
        break;

    case XROOTD_TPC_CREDENTIAL_TOKEN:
        if (cred->bearer.data == NULL || cred->bearer.len == 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_tpc: empty bearer credential");
            return NGX_DECLINED;
        }
        break;

    default:
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_tpc: invalid credential type %d",
                      (int) cred->type);
        return NGX_DECLINED;
    }

    if (cred->expires_at != 0) {
        now = ngx_time();
        if (cred->expires_at <= now) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_tpc: %s credential expired",
                          xrootd_tpc_credential_type_name(cred->type));
            return NGX_DECLINED;
        }
    }

    return NGX_OK;
}
