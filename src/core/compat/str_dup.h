/*
 * str_dup.h — duplicate a byte range into a NUL-terminated ngx_str_t.
 *
 * WHAT: collapse the recurring five-line idiom that copies `len` bytes into a
 *       pool buffer, NUL-terminates it, and records the length on an ngx_str_t:
 *
 *           dst->data = ngx_pnalloc(pool, len + 1);
 *           if (dst->data == NULL) { return err; }
 *           ngx_memcpy(dst->data, src, len);
 *           dst->data[len] = '\0';
 *           dst->len = len;
 *
 *       into a single call that returns a status.
 *
 * WHY: this exact shape recurs across directive parsers and runtime string
 *      capture (cache/upstream/tpc origin hosts, path prefixes, …).  Each hand-
 *      written copy must remember the `+ 1`, the terminator, and to set `.len` —
 *      a trio that is easy to get subtly wrong.  Centralising it removes the
 *      boilerplate and makes the NUL-termination guarantee uniform.  Unlike the
 *      alloc-only guards in alloc_guard.h, this captures the full copy + set.
 *
 * HOW: a pure inline helper with the allocation side effect at the edge.  The
 *      result buffer is always NUL-terminated (len + 1 bytes) so the data is
 *      safe to hand to C string APIs, while dst->len excludes the terminator.
 */
#ifndef BRIX_COMPAT_STR_DUP_H
#define BRIX_COMPAT_STR_DUP_H

#include <ngx_core.h>

/*
 * Copy `len` bytes from `src` into a freshly allocated, NUL-terminated buffer
 * from `pool`, recording it on `dst` (dst->len = len, excluding the terminator).
 *
 * Returns NGX_OK on success, NGX_ERROR on allocation failure (dst untouched on
 * failure).  A zero-length copy still allocates a 1-byte "" buffer so dst->data
 * is never NULL on success.  `src` may be NULL only when len == 0.
 */
static ngx_inline ngx_int_t
brix_pstrdupz(ngx_pool_t *pool, ngx_str_t *dst, const u_char *src, size_t len)
{
    u_char *buf = ngx_pnalloc(pool, len + 1);

    if (buf == NULL) {
        return NGX_ERROR;
    }

    if (len != 0) {
        ngx_memcpy(buf, src, len);
    }
    buf[len] = '\0';

    dst->data = buf;
    dst->len = len;
    return NGX_OK;
}

#endif /* BRIX_COMPAT_STR_DUP_H */
