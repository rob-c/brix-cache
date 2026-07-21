/*
 * sd_ceph_compat.c — pure libradosstriper layout helpers. See the header.
 */

#include "sd_ceph_compat.h"

#include <string.h>

#define SUFFIX     BRIX_CEPH_FIRST_STRIPE_SUFFIX
#define SUFFIX_LEN (sizeof(BRIX_CEPH_FIRST_STRIPE_SUFFIX) - 1)   /* 17 */

int
sd_ceph_first_stripe(const char *name, char *oid, size_t cap)
{
    size_t n;

    if (name == NULL || oid == NULL) {
        return -1;
    }
    n = strlen(name);
    if (n + SUFFIX_LEN + 1 > cap) {
        return -1;
    }
    memcpy(oid, name, n);
    memcpy(oid + n, SUFFIX, SUFFIX_LEN + 1);    /* incl. NUL */
    return 0;
}

int
sd_ceph_oid_is_first_stripe(const char *oid)
{
    size_t n;

    if (oid == NULL) {
        return 0;
    }
    n = strlen(oid);
    if (n < SUFFIX_LEN) {
        return 0;
    }
    return (memcmp(oid + n - SUFFIX_LEN, SUFFIX, SUFFIX_LEN) == 0) ? 1 : 0;
}

int
sd_ceph_oid_to_pfn(const char *oid, char *pfn, size_t cap)
{
    size_t n, base;

    if (oid == NULL || pfn == NULL || !sd_ceph_oid_is_first_stripe(oid)) {
        return -1;
    }
    n = strlen(oid);
    base = n - SUFFIX_LEN;
    if (base + 1 > cap) {
        return -1;
    }
    memcpy(pfn, oid, base);
    pfn[base] = '\0';
    return 0;
}

int
sd_ceph_oid_is_stripe_data(const char *oid)
{
    size_t n, i;

    if (oid == NULL) {
        return 0;
    }
    n = strlen(oid);
    /* must end in '.' + exactly 16 lowercase-hex digits to be ANY stripe object */
    if (n < SUFFIX_LEN || oid[n - SUFFIX_LEN] != '.') {
        return 0;
    }
    for (i = n - SUFFIX_LEN + 1; i < n; i++) {
        char c = oid[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return 0;                          /* not a 16-hex stripe suffix */
        }
    }
    /* a striper data stripe iff it is NOT the all-zero first stripe */
    return sd_ceph_oid_is_first_stripe(oid) ? 0 : 1;
}

int
sd_ceph_path_child(const char *dir, const char *path, char *name, size_t cap)
{
    size_t      dlen;
    const char *rest;
    const char *slash;
    size_t      n;

    if (dir == NULL || path == NULL || name == NULL
        || dir[0] != '/' || path[0] != '/')
    {
        return 0;
    }

    dlen = strlen(dir);
    if (dlen == 1) {
        rest = path + 1;                       /* listing the root */
    } else {
        if (strncmp(path, dir, dlen) != 0 || path[dlen] != '/') {
            return 0;                          /* outside dir (or a sibling
                                                * sharing dir as a name prefix) */
        }
        rest = path + dlen + 1;
    }
    if (*rest == '\0') {
        return 0;                              /* path IS dir — not a child */
    }

    slash = strchr(rest, '/');
    n = (slash != NULL) ? (size_t) (slash - rest) : strlen(rest);
    if (n == 0 || n + 1 > cap) {
        return 0;                              /* empty / unrepresentable name */
    }
    memcpy(name, rest, n);
    name[n] = '\0';
    return (slash != NULL) ? 2 : 1;
}
