#include "../ngx_xrootd_module.h"

#include "path_internal.h"

ngx_int_t
xrootd_normalize_policy_path(ngx_pool_t *pool, const ngx_str_t *src,
                             ngx_str_t *dst)
{
    u_char *out;
    size_t  i;
    size_t  written;

    if (pool == NULL || src == NULL || dst == NULL || src->len == 0) {
        return NGX_ERROR;
    }

    out = ngx_pnalloc(pool, src->len + 2);
    if (out == NULL) {
        return NGX_ERROR;
    }

    i = 0;
    written = 0;
    out[written++] = '/';

    while (i < src->len) {
        size_t start;
        size_t seg_len;

        while (i < src->len && src->data[i] == '/') {
            i++;
        }

        if (i == src->len) {
            break;
        }

        start = i;

        while (i < src->len && src->data[i] != '/') {
            i++;
        }

        seg_len = i - start;
        if (seg_len == 0) {
            continue;
        }

        if (xrootd_path_component_forbidden((const char *) src->data + start,
                                            seg_len))
        {
            return NGX_ERROR;
        }

        if (written > 1) {
            out[written++] = '/';
        }

        ngx_memcpy(out + written, src->data + start, seg_len);
        written += seg_len;
    }

    if (written == 0) {
        out[written++] = '/';
    }

    out[written] = '\0';
    dst->data = out;
    dst->len = written;

    return NGX_OK;
}
