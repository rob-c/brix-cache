/*
 * cache_key.c — the cache key derivation (pure, libc-only).
 *
 * The cache key is the EXPORT-relative ("logical") form of the resolved path —
 * the leading-slash suffix after `root_canon`. The cache STORAGE driver is bound
 * to the cache root, so the key is keyed against the export namespace, not the
 * cache root (which is where the bytes physically live). Kept in its own
 * nginx-free translation unit so the standalone unit test links it with libc only.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

int
brix_cache_key_from(const char *cache_root_canon, const char *root_canon,
                      const char *resolved, char *dst, size_t dstsz)
{
    size_t rlen;

    (void) cache_root_canon;             /* not part of the key (see docblock) */
    if (root_canon == NULL || resolved == NULL || root_canon[0] == '\0') {
        return -1;
    }
    rlen = strlen(root_canon);
    if (strncmp(resolved, root_canon, rlen) != 0
        || (resolved[rlen] != '/' && resolved[rlen] != '\0'))
    {
        return -1;                       /* not under the export root */
    }
    if (resolved[rlen] == '\0') {        /* the export root itself */
        if (dstsz < 2) { return -1; }
        dst[0] = '/'; dst[1] = '\0';
        return 0;
    }
    if ((size_t) snprintf(dst, dstsz, "%s", resolved + rlen) >= dstsz) {
        return -1;
    }
    return 0;                            /* resolved[rlen]=='/' ⇒ leading slash kept */
}
