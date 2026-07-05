/*
 * cstr.h — bounded ngx_str_t → NUL-terminated C-string conversion.
 *
 * WHAT: brix_cbuf_copy() copies len bytes into a caller buffer and
 *       NUL-terminates, refusing (returns NULL, buffer untouched) when the
 *       result would not fit; brix_str_cbuf() is the ngx_str_t wrapper;
 *       brix_pstrdup_z() pool-allocates len+1 bytes and NUL-terminates.
 *
 * WHY:  ~40 call sites hand-rolled the same bounds-check + ngx_memcpy +
 *       `buf[len] = '\0'` triple — each one an independently auditable
 *       off-by-one risk. One reviewed helper replaces per-site review.
 *
 * HOW:  The core is ngx-free (define BRIX_CSTR_NO_NGX to drop the ngx
 *       wrappers) so tests/cstr_unittest.c compiles standalone with plain
 *       gcc, the same pattern as core/compat/af_policy.h.
 */

#ifndef BRIX_COMPAT_CSTR_H
#define BRIX_COMPAT_CSTR_H

#include <stddef.h>
#include <string.h>

/* Copy len bytes into buf and NUL-terminate. Returns buf, or NULL (buffer
 * untouched) when len+1 would exceed bufsize or buf is NULL. */
static inline const char *
brix_cbuf_copy(char *buf, size_t bufsize, const void *data, size_t len)
{
    if (buf == NULL || bufsize == 0 || len >= bufsize) {
        return NULL;
    }
    if (len > 0) {
        memcpy(buf, data, len);
    }
    buf[len] = '\0';
    return buf;
}

#ifndef BRIX_CSTR_NO_NGX

/* ngx_str_t flavor of brix_cbuf_copy(). */
static inline const char *
brix_str_cbuf(char *buf, size_t bufsize, const ngx_str_t *s)
{
    return brix_cbuf_copy(buf, bufsize, s->data, s->len);
}

/* Pool-duplicate an ngx_str_t as a NUL-terminated C string (len+1 bytes).
 * Returns NULL on allocation failure. */
static inline char *
brix_pstrdup_z(ngx_pool_t *pool, const ngx_str_t *s)
{
    char  *p;

    p = ngx_pnalloc(pool, s->len + 1);
    if (p == NULL) {
        return NULL;
    }
    ngx_memcpy(p, s->data, s->len);
    p[s->len] = '\0';
    return p;
}

#endif /* !BRIX_CSTR_NO_NGX */

#endif /* BRIX_COMPAT_CSTR_H */
