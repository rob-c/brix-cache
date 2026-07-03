/*
 * sd_ceph_striper.c — libradosstriper data-plane wrappers. See the header.
 *
 * Gated on BRIX_HAVE_RADOSSTRIPER: without the Ceph striper library this file is
 * empty (a translation unit with no symbols), so a no-Ceph build is unchanged —
 * the same pattern `sd_ceph.c` uses for BRIX_HAVE_CEPH. The logic here is the
 * straight stock mapping; it requires a Ceph build (and a pool) to validate, which
 * `tests/run_rados_parity.sh` does when BRIX_TEST_RADOS_POOL is set.
 */

#include "sd_ceph_striper.h"

#if defined(BRIX_HAVE_RADOSSTRIPER)

#include <string.h>

int
sd_ceph_striper_create(rados_ioctx_t ioctx,
    const sd_ceph_striper_layout_t *layout, rados_striper_t *out)
{
    rados_striper_t s;
    int             rc;

    if (out == NULL) {
        return -EINVAL;
    }
    rc = rados_striper_create(ioctx, &s);
    if (rc < 0) {
        return rc;
    }
    if (layout != NULL) {
        /* Stamp the stock-compatible layout on objects this striper creates.
         * A zero field means "leave the library/site default". */
        if (layout->stripe_unit != 0) {
            (void) rados_striper_set_object_layout_stripe_unit(s,
                       layout->stripe_unit);
        }
        if (layout->stripe_count != 0) {
            (void) rados_striper_set_object_layout_stripe_count(s,
                       layout->stripe_count);
        }
        if (layout->object_size != 0) {
            (void) rados_striper_set_object_layout_object_size(s,
                       layout->object_size);
        }
    }
    *out = s;
    return 0;
}

void
sd_ceph_striper_destroy(rados_striper_t striper)
{
    rados_striper_destroy(striper);
}

ssize_t
sd_ceph_striper_read(rados_striper_t s, const char *soid, void *buf,
    size_t len, uint64_t off)
{
    int rc = rados_striper_read(s, soid, (char *) buf, len, off);
    return (rc < 0) ? (ssize_t) rc : (ssize_t) rc;   /* rc = bytes read, or -errno */
}

ssize_t
sd_ceph_striper_write(rados_striper_t s, const char *soid, const void *buf,
    size_t len, uint64_t off)
{
    int rc = rados_striper_write(s, soid, (const char *) buf, len, off);
    return (rc < 0) ? (ssize_t) rc : (ssize_t) len;  /* write returns 0 on success */
}

int
sd_ceph_striper_trunc(rados_striper_t s, const char *soid, uint64_t size)
{
    return rados_striper_trunc(s, soid, size);
}

int
sd_ceph_striper_remove(rados_striper_t s, const char *soid)
{
    return rados_striper_remove(s, soid);
}

int
sd_ceph_striper_stat(rados_striper_t s, const char *soid,
    uint64_t *size_out, time_t *mtime_out)
{
    uint64_t size = 0;
    time_t   mtime = 0;
    int      rc = rados_striper_stat(s, soid, &size, &mtime);

    if (rc < 0) {
        return rc;
    }
    if (size_out != NULL)  { *size_out = size; }
    if (mtime_out != NULL) { *mtime_out = mtime; }
    return 0;
}

ssize_t
sd_ceph_striper_getxattr(rados_striper_t s, const char *soid,
    const char *name, void *buf, size_t cap)
{
    return rados_striper_getxattr(s, soid, name, (char *) buf, cap);
}

int
sd_ceph_striper_setxattr(rados_striper_t s, const char *soid,
    const char *name, const void *buf, size_t len)
{
    return rados_striper_setxattr(s, soid, name, (const char *) buf, len);
}

int
sd_ceph_striper_rmxattr(rados_striper_t s, const char *soid, const char *name)
{
    return rados_striper_rmxattr(s, soid, name);
}

ssize_t
sd_ceph_striper_listxattr(rados_striper_t s, const char *soid,
    char *buf, size_t cap)
{
    rados_xattrs_iter_t iter;
    size_t              used = 0;
    int                 rc = rados_striper_getxattrs(s, soid, &iter);

    if (rc < 0) {
        return rc;
    }
    for (;;) {
        const char *name = NULL, *val = NULL;
        size_t      vlen = 0, nlen;

        rc = rados_striper_getxattrs_next(iter, &name, &val, &vlen);
        if (rc < 0) {
            rados_striper_getxattrs_end(iter);
            return rc;
        }
        if (name == NULL || name[0] == '\0') {
            break;                               /* end of iteration */
        }
        nlen = strlen(name) + 1;                 /* incl. NUL separator */
        if (used + nlen > cap) {
            rados_striper_getxattrs_end(iter);
            return -ERANGE;
        }
        memcpy(buf + used, name, nlen);
        used += nlen;
    }
    rados_striper_getxattrs_end(iter);
    return (ssize_t) used;
}

#endif /* BRIX_HAVE_RADOSSTRIPER */
