#ifndef XROOTD_COMPAT_HTTP_HEADERS_H
#define XROOTD_COMPAT_HTTP_HEADERS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * Shared HTTP header helpers for request lookup, value comparison, bearer
 * extraction, and safe response-header insertion.
 */
ngx_table_elt_t *xrootd_http_find_header(ngx_http_request_t *r,
    const char *name, size_t name_len);
ngx_str_t xrootd_http_get_header(ngx_http_request_t *r, const char *name);
ngx_int_t xrootd_http_extract_bearer(const ngx_str_t *auth_header,
    ngx_str_t *token_out);
ngx_int_t xrootd_http_str_has_ctl(const u_char *data, size_t len);
ngx_int_t xrootd_http_header_value_equals(const ngx_str_t *value,
    const char *literal);
ngx_uint_t xrootd_http_effective_status(ngx_http_request_t *r,
    ngx_int_t rc);
ngx_int_t xrootd_http_set_header_str(ngx_http_request_t *r, const char *key,
    const ngx_str_t *value, ngx_flag_t copy_value, ngx_table_elt_t **out);
ngx_int_t xrootd_http_set_header(ngx_http_request_t *r, const char *key,
    const char *value, ngx_table_elt_t **out);
ngx_int_t xrootd_http_set_header_num(ngx_http_request_t *r,
    const char *key, long value);
ngx_int_t xrootd_http_request_header_add(ngx_http_request_t *r,
    const char *key, const char *value, ngx_table_elt_t **out);

#endif /* XROOTD_COMPAT_HTTP_HEADERS_H */
