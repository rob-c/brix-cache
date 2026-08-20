/*
 * url_internal.h — the one byte-copy the two halves of the URL grammar share.
 *
 * The grammar is split across two TUs on purpose: authority.c owns
 * "host[:port]", which the image-reference parser also needs, while url.c owns
 * the scheme and the path prefix, which only a base URL has. Both fill
 * fixed-size fields from a span, and both must REFUSE rather than truncate —
 * a half-copied host is a different host — so the rule lives here, once, as a
 * header-local inline rather than a symbol either file could diverge from.
 */
#ifndef BRIX_OCI_URL_INTERNAL_H
#define BRIX_OCI_URL_INTERNAL_H

#include <stddef.h>
#include <string.h>

/* Copy [s, s+n) into a fixed field, refusing rather than truncating. */
static inline int
oci_url_field(char *dst, size_t dstsz, const char *s, size_t n)
{
    if (n == 0 || n >= dstsz) {
        return -1;
    }
    memcpy(dst, s, n);
    dst[n] = '\0';
    return 0;
}

#endif /* BRIX_OCI_URL_INTERNAL_H */
