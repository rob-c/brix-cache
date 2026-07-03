/*
 * site_n2n.c — the tunable site name-translation. See the header. Pure libc.
 */

#include "site_n2n.h"

#include <stdio.h>
#include <string.h>

/* Reject any ".." path component (traversal). Returns 1 if present. */
static int
n2n_has_traversal(const char *p)
{
    const char *s = p;

    while (*s != '\0') {
        const char *start = s;
        size_t      len;

        while (*s != '\0' && *s != '/') {
            s++;
        }
        len = (size_t) (s - start);
        if (len == 2 && start[0] == '.' && start[1] == '.') {
            return 1;
        }
        if (*s == '/') {
            s++;
        }
    }
    return 0;
}

/* Copy src into dst[cap] (NUL-terminated); 0 / -1 (overflow). */
static int
n2n_copy(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);

    if (n + 1 > cap) {
        return -1;
    }
    memcpy(dst, src, n + 1);
    return 0;
}

int
brix_n2n_lfn2pfn(const brix_n2n_cfg_t *cfg, const char *lfn,
                   char *pfn, size_t cap)
{
    int r;

    if (cfg == NULL || lfn == NULL || pfn == NULL || cap == 0
        || n2n_has_traversal(lfn)) {
        return -1;
    }

    switch (cfg->scheme) {
    case BRIX_N2N_IDENTITY:
        return n2n_copy(pfn, cap, lfn);

    case BRIX_N2N_RAL:
        r = snprintf(pfn, cap, "%s:%s%s", cfg->pool, cfg->prefix, lfn);
        break;

    case BRIX_N2N_CEPHFS_PATH:
        r = snprintf(pfn, cap, "%s%s", cfg->prefix, lfn);
        break;

    default:
        return -1;
    }
    return (r < 0 || (size_t) r >= cap) ? -1 : 0;
}

int
brix_n2n_pfn2lfn(const brix_n2n_cfg_t *cfg, const char *pfn,
                   char *lfn, size_t cap)
{
    const char *p;
    size_t      plen;

    if (cfg == NULL || pfn == NULL || lfn == NULL || cap == 0) {
        return -1;
    }

    switch (cfg->scheme) {
    case BRIX_N2N_IDENTITY:
        return n2n_copy(lfn, cap, pfn);

    case BRIX_N2N_RAL:
        p = strchr(pfn, ':');
        if (p == NULL) {
            return -1;                 /* not a "<pool>:…" name */
        }
        p++;                           /* past the colon */
        plen = strlen(cfg->prefix);
        if (plen > 0) {
            if (strncmp(p, cfg->prefix, plen) != 0) {
                return -1;
            }
            p += plen;
        }
        return n2n_copy(lfn, cap, p);

    case BRIX_N2N_CEPHFS_PATH:
        p = pfn;
        plen = strlen(cfg->prefix);
        if (plen > 0) {
            if (strncmp(p, cfg->prefix, plen) != 0) {
                return -1;             /* not under the localroot */
            }
            p += plen;
        }
        return n2n_copy(lfn, cap, p);

    default:
        return -1;
    }
}

int
brix_n2n_extract_pool(const char *objname, char *pool, size_t cap,
                        const char **rest)
{
    const char *colon;
    size_t      n;

    if (objname == NULL || pool == NULL || cap == 0) {
        return -1;
    }
    colon = strchr(objname, ':');
    if (colon == NULL) {
        /* stock XrdCephOss::extractPool: no colon → whole string is the pool. */
        if (n2n_copy(pool, cap, objname) != 0) {
            return -1;
        }
        if (rest != NULL) {
            *rest = objname + strlen(objname);   /* "" */
        }
        return 0;
    }
    n = (size_t) (colon - objname);
    if (n + 1 > cap) {
        return -1;
    }
    memcpy(pool, objname, n);
    pool[n] = '\0';
    if (rest != NULL) {
        *rest = colon + 1;
    }
    return 0;
}
