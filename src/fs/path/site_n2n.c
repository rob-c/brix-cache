/*
 * site_n2n.c — the tunable site name-translation. See the header. Pure libc.
 */

#include "site_n2n.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* One path segment carved out of an LFN: a pointer into the source string and
 * its length (not NUL-terminated). */
typedef struct {
    const char *start;
    size_t      len;
} n2n_seg_t;

/* Advance *cursor to the next non-empty segment: skip the run of '/' separators,
 * then capture the next run of non-'/' bytes. 1 when a segment was found (cursor
 * advanced past it), 0 at end of string. This is the tokenizer that lets the
 * canonicalizer read as a flat loop over already-carved segments. */
static int
n2n_next_seg(const char **cursor, n2n_seg_t *seg)
{
    const char *p = *cursor;

    while (*p == '/') {
        p++;
    }
    if (*p == '\0') {
        *cursor = p;
        return 0;
    }
    seg->start = p;
    while (*p != '\0' && *p != '/') {
        p++;
    }
    seg->len = (size_t) (p - seg->start);
    *cursor  = p;
    return 1;
}

/* Append one ordinary segment as "/<seg>" to the canonical buffer at cursor `w`.
 * Returns the new cursor, or (size_t)-1 when it would not fit within `cap`. */
static size_t
n2n_append(char *out, size_t cap, size_t w, const n2n_seg_t *seg)
{
    if (w + 1 + seg->len + 1 > cap) {
        return (size_t) -1;
    }
    out[w++] = '/';
    memcpy(out + w, seg->start, seg->len);
    w += seg->len;
    out[w] = '\0';
    return w;
}

static int
n2n_seg_is_dot(const n2n_seg_t *seg)
{
    return seg->len == 1 && seg->start[0] == '.';
}

static int
n2n_seg_is_dotdot(const n2n_seg_t *seg)
{
    return seg->len == 2 && seg->start[0] == '.' && seg->start[1] == '.';
}

int
brix_n2n_canonicalize(const char *lfn, char *out, size_t cap)
{
    const char *cursor = lfn;
    n2n_seg_t   seg = {0};
    size_t      w = 0;

    if (lfn == NULL || out == NULL || cap < 2) {
        errno = EINVAL;
        return -1;
    }
    out[0] = '\0';

    while (n2n_next_seg(&cursor, &seg)) {
        if (n2n_seg_is_dot(&seg)) {
            continue;                  /* "." — no-op */
        }
        if (n2n_seg_is_dotdot(&seg)) {
            errno = EINVAL;            /* ".." — rejected, never resolved (C13) */
            return -1;
        }
        w = n2n_append(out, cap, w, &seg);
        if (w == (size_t) -1) {
            errno = ENAMETOOLONG;
            return -1;
        }
    }

    if (w == 0) {                      /* everything collapsed -> bare root */
        out[0] = '/';
        out[1] = '\0';
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
    char canon[1024];
    int  r;

    if (cfg == NULL || lfn == NULL || pfn == NULL || cap == 0) {
        errno = EINVAL;
        return -1;
    }
    /* Canonicalize before composing: folds "." and "//" so "/a/./b", "/a//b"
     * and "/a/b" yield one physical name, and rejects ".." traversal. errno is
     * set by the canonicalizer (EINVAL on "..", ENAMETOOLONG on overflow). */
    if (brix_n2n_canonicalize(lfn, canon, sizeof(canon)) != 0) {
        return -1;
    }

    switch (cfg->scheme) {
    case BRIX_N2N_IDENTITY:
        if (n2n_copy(pfn, cap, canon) != 0) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return 0;

    case BRIX_N2N_RAL:
        r = snprintf(pfn, cap, "%s:%s%s", cfg->pool, cfg->prefix, canon);
        break;

    case BRIX_N2N_CEPHFS_PATH:
        r = snprintf(pfn, cap, "%s%s", cfg->prefix, canon);
        break;

    default:
        errno = EINVAL;
        return -1;
    }
    if (r < 0 || (size_t) r >= cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
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
