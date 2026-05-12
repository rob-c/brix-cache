#include "../ngx_xrootd_module.h"

ngx_array_t *
xrootd_merge_arrays(ngx_conf_t *cf, ngx_array_t *parent, ngx_array_t *child,
                    size_t element_size)
{
    ngx_array_t *merged;
    char        *dst;
    size_t       total;

    total = 0;

    if (parent != NULL) {
        total += parent->nelts;
    }

    if (child != NULL) {
        total += child->nelts;
    }

    if (total == 0) {
        return NULL;
    }

    merged = ngx_array_create(cf->pool, (ngx_uint_t) total, element_size);
    if (merged == NULL) {
        return NULL;
    }

    if (parent != NULL && parent->nelts > 0) {
        dst = ngx_array_push_n(merged, parent->nelts);
        if (dst == NULL) {
            return NULL;
        }

        ngx_memcpy(dst, parent->elts, parent->nelts * element_size);
    }

    if (child != NULL && child->nelts > 0) {
        dst = ngx_array_push_n(merged, child->nelts);
        if (dst == NULL) {
            return NULL;
        }

        ngx_memcpy(dst, child->elts, child->nelts * element_size);
    }

    return merged;
}
