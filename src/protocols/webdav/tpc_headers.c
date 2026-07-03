/*
 * tpc_headers.c - HTTP-TPC TransferHeader* request header collection.
 *
 * The simple header lookup, value comparison, and string helpers previously
 * defined here are now macro aliases to src/compat/http_headers.c in webdav.h.
 * Only webdav_tpc_collect_transfer_headers() remains here as it has real logic.
 */

#include "webdav.h"

/*
 * webdav_tpc_collect_transfer_headers — collect all TransferHeader* request
 * headers into an ngx_array_t of ngx_str_t values for the curl TPC transfer.
 *
 * Each matching header "TransferHeaderX-Foo: bar" contributes a string
 * "X-Foo: bar" to the output array.  Headers with control characters in
 * either name or value are rejected (400 Bad Request).
 */
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
                              "brix_webdav: too many TransferHeader* "
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
