#include "core/ngx_xrootd_module.h"

#include "path_internal.h"
#include "core/compat/alloc_guard.h"

/*
 * WHAT: Normalize a policy path from wire format into canonical form — collapses multiple slashes,
 *      validates components against forbidden characters, and produces a clean '/'-prefixed string.
 * WHY: Policy paths (VO names, group identifiers, manager-map entries) come in as raw wire strings
 *      that may contain redundant slashes or invalid components. Canonical normalization ensures
 *      longest-prefix matching in find_rule.c works correctly and prevents policy bypass via path tricks.
 * HOW: Allocate src->len+2 bytes from nginx pool; prepend '/' prefix; skip consecutive '/' characters;
 *      validate each segment with xrootd_path_component_forbidden(); join segments with single '/';
 *      null-terminate and set dst->data/dst->len. Returns NGX_OK on success, NGX_ERROR on allocation
 *      failure or invalid component detection. INVARIANT: all policy paths must be canonical before matching.
 */

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

    XROOTD_PNALLOC_OR_RETURN(out, pool, src->len + 2, NGX_ERROR);

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
