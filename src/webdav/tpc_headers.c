/*
 * tpc_headers.c - HTTP-TPC COPY header parsing and validation helpers.
 */

#include "webdav.h"

#include <string.h>

ngx_table_elt_t *
webdav_tpc_find_header(ngx_http_request_t *r, const char *name,
                       size_t name_len)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *hdr;
    ngx_uint_t       i;

    part = &r->headers_in.headers.part;
    hdr = part->elts;

    for (;;) {
        for (i = 0; i < part->nelts; i++) {
            if (hdr[i].key.len == name_len
                && ngx_strncasecmp(hdr[i].key.data,
                                   (u_char *) name, name_len) == 0)
            {
                return &hdr[i];
            }
        }

        if (part->next == NULL) {
            break;
        }

        part = part->next;
        hdr = part->elts;
    }

    return NULL;
}

ngx_flag_t
webdav_tpc_str_has_ctl(const u_char *data, size_t len)
{
    size_t i;

    if (data == NULL) {
        return 1;
    }

    for (i = 0; i < len; i++) {
        if (data[i] < 0x20 || data[i] == 0x7f) {
            return 1;
        }
    }

    return 0;
}

ngx_int_t
webdav_tpc_header_value_equals(ngx_str_t *value, const char *literal)
{
    u_char *start;
    u_char *end;
    size_t  len;
    size_t  literal_len;

    if (value == NULL || literal == NULL) {
        return 0;
    }

    start = value->data;
    end = value->data + value->len;

    while (start < end && (*start == ' ' || *start == '\t')) {
        start++;
    }
    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
        end--;
    }

    len = (size_t) (end - start);
    literal_len = strlen(literal);

    return len == literal_len
           && ngx_strncasecmp(start, (u_char *) literal, literal_len) == 0;
}

char *
webdav_tpc_pstrndup0(ngx_pool_t *pool, const u_char *data, size_t len)
{
    char *out;

    out = ngx_pnalloc(pool, len + 1);
    if (out == NULL) {
        return NULL;
    }

    ngx_memcpy(out, data, len);
    out[len] = '\0';
    return out;
}

char *
webdav_strnstr(const char *s1, const char *s2, size_t len)
{
    size_t n = strlen(s2);
    const char *p;

    if (n == 0) {
        return (char *) s1;
    }

    for (p = s1; len >= n; p++, len--) {
        if (*p == *s2 && strncmp(p, s2, n) == 0) {
            return (char *) p;
        }
    }

    return NULL;
}

ngx_int_t
webdav_tpc_collect_transfer_headers(ngx_http_request_t *r, ngx_array_t **out)
{
    ngx_array_t     *headers;
    ngx_list_part_t *part;
    ngx_table_elt_t *hdr;
    ngx_uint_t       i;
    const size_t     prefix_len = sizeof("TransferHeader") - 1;

    headers = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));
    if (headers == NULL) {
        return NGX_ERROR;
    }

    part = &r->headers_in.headers.part;
    hdr = part->elts;

    for (;;) {
        for (i = 0; i < part->nelts; i++) {
            ngx_str_t *dst;
            size_t     name_len;
            size_t     value_len;
            size_t     total_len;
            u_char    *p;

            if (hdr[i].key.len <= prefix_len
                || ngx_strncasecmp(hdr[i].key.data,
                                   (u_char *) "TransferHeader",
                                   prefix_len) != 0)
            {
                continue;
            }

            if (headers->nelts >= WEBDAV_TPC_MAX_HEADERS) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "xrootd_webdav: too many TransferHeader* "
                              "headers in HTTP-TPC request");
                return NGX_HTTP_BAD_REQUEST;
            }

            name_len = hdr[i].key.len - prefix_len;
            value_len = hdr[i].value.len;

            if (webdav_tpc_str_has_ctl(hdr[i].key.data + prefix_len,
                                       name_len)
                || webdav_tpc_str_has_ctl(hdr[i].value.data, value_len))
            {
                return NGX_HTTP_BAD_REQUEST;
            }

            total_len = name_len + sizeof(": ") - 1 + value_len;
            dst = ngx_array_push(headers);
            if (dst == NULL) {
                return NGX_ERROR;
            }

            dst->data = ngx_pnalloc(r->pool, total_len + 1);
            if (dst->data == NULL) {
                return NGX_ERROR;
            }

            p = dst->data;
            p = ngx_cpymem(p, hdr[i].key.data + prefix_len, name_len);
            p = ngx_cpymem(p, ": ", sizeof(": ") - 1);
            p = ngx_cpymem(p, hdr[i].value.data, value_len);
            *p = '\0';
            dst->len = total_len;
        }

        if (part->next == NULL) {
            break;
        }

        part = part->next;
        hdr = part->elts;
    }

    *out = headers;
    return NGX_OK;
}
