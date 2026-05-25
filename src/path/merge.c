#include "../ngx_xrootd_module.h"

/* ---- Function: xrootd_merge_arrays() — concatenate two nginx arrays into one ----
 *
 * WHAT: Merges parent and child nginx arrays into a single combined array by concatenating elements in order (parent first, then child). Calculates total element count from both inputs, creates new array with ngx_array_create() using caller's pool allocation. Copies parent elements via ngx_memcpy() if parent exists and has elements, then copies child elements similarly. Returns NULL when either input is NULL or total element count is zero; returns NULL on any allocation failure during creation or copy operations. All memory allocated from cf->pool ensures proper cleanup during nginx request lifecycle.
 *
 * WHY: Config merging across nginx hierarchy (main→srv→loc) requires combining parent-level and child-level array entries — ACL rules, policy entries, and other list-based configurations must be inherited while preserving local overrides. This helper provides a reusable merge pattern that handles NULL inputs gracefully without requiring callers to implement the concatenation logic themselves. Consistency invariant: all config merge operations in path/acl.c, handshake/policy.c, etc. must use this same function to ensure uniform array merging behavior across the codebase. Thread safety: pure function with no shared state — operates only on provided arrays and local stack variables during config setup phase. */

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
