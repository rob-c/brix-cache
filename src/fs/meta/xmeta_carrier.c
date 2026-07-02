/*
 * fs/meta/xmeta_carrier.c — xattr-preferred / sidecar-fallback persistence
 * for the unified metadata record. See xmeta_carrier.h for the contract.
 */

#include "xmeta_carrier.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Compose the sidecar object key "<key>.cinfo" into out[cap]. 0 / -1. */
static int
xmeta_sidecar_key(const char *key, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s%s", key, XROOTD_XMETA_SIDECAR_SUFFIX);

    return (n > 0 && (size_t) n < cap) ? 0 : -1;
}

/* "the value cannot ride in an xattr here" — fall back, don't fail */
static int
xmeta_xattr_unfit(int err)
{
    return err == E2BIG || err == ERANGE || err == ENOSPC || err == ENOTSUP
#ifdef EOPNOTSUPP
           || err == EOPNOTSUPP
#endif
           ;
}

/* ---- sidecar carrier ------------------------------------------------------ */

static ngx_int_t
xmeta_sidecar_write(xrootd_sd_instance_t *store, const char *key,
    const uint8_t *buf, size_t len)
{
    char                ck[PATH_MAX];
    xrootd_sd_staged_t *st;
    int                 err = 0;

    if (store->driver->staged_open == NULL
        || store->driver->staged_write == NULL
        || store->driver->staged_commit == NULL)
    {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    if (xmeta_sidecar_key(key, ck, sizeof(ck)) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    st = store->driver->staged_open(store, ck, 0644, &err);
    if (st == NULL) {
        errno = err ? err : EIO;
        return NGX_ERROR;
    }
    if (store->driver->staged_write(st, buf, len, 0) != (ssize_t) len) {
        int e = errno;

        if (store->driver->staged_abort != NULL) {
            store->driver->staged_abort(st);
        }
        errno = e ? e : EIO;
        return NGX_ERROR;
    }
    if (store->driver->staged_commit(st, 0) != NGX_OK) {
        return NGX_ERROR;                          /* errno from the driver */
    }
    return NGX_OK;
}

/* Read the whole sidecar object into a malloc'd buffer. NGX_OK/DECLINED/ERROR. */
static ngx_int_t
xmeta_sidecar_read(xrootd_sd_instance_t *store, const char *key,
    uint8_t **out, size_t *out_len)
{
    char             ck[PATH_MAX];
    xrootd_sd_obj_t *obj;
    uint8_t         *buf = NULL;
    size_t           cap = 0, got = 0;
    int              err = 0;

    if (store->driver->open == NULL || store->driver->pread == NULL) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    if (xmeta_sidecar_key(key, ck, sizeof(ck)) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    obj = store->driver->open(store, ck, XROOTD_SD_O_READ, 0, &err);
    if (obj == NULL) {
        return (err == ENOENT) ? NGX_DECLINED : NGX_ERROR;
    }

    for ( ;; ) {
        ssize_t n;

        if (got == cap) {
            uint8_t *grown;

            cap = cap ? cap * 2 : 64 * 1024;
            grown = realloc(buf, cap);
            if (grown == NULL) {
                free(buf);
                store->driver->close(obj);
                if (obj->heap_shell) { free(obj); }
                errno = ENOMEM;
                return NGX_ERROR;
            }
            buf = grown;
        }
        n = store->driver->pread(obj, buf + got, cap - got, (off_t) got);
        if (n < 0) {
            int e = errno;

            free(buf);
            store->driver->close(obj);
            if (obj->heap_shell) { free(obj); }
            errno = e ? e : EIO;
            return NGX_ERROR;
        }
        if (n == 0) {
            break;
        }
        got += (size_t) n;
    }
    store->driver->close(obj);
    if (obj->heap_shell) { free(obj); }

    if (got == 0) {
        free(buf);
        return NGX_DECLINED;
    }
    *out = buf;
    *out_len = got;
    return NGX_OK;
}

/* ---- public API ------------------------------------------------------------ */

ngx_int_t
xrootd_xmeta_save(xrootd_sd_instance_t *store, const char *key,
    const xrootd_xmeta_t *m)
{
    uint8_t  *buf = NULL;
    size_t    len = 0;
    ngx_int_t rc;

    if (store == NULL || store->driver == NULL || key == NULL || m == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (xrootd_xmeta_encode(m, &buf, &len) != XROOTD_XMETA_OK) {
        return NGX_ERROR;
    }

    if (store->driver->setxattr != NULL && len <= XROOTD_XMETA_XATTR_MAX) {
        rc = store->driver->setxattr(store, key, XROOTD_XMETA_XATTR_NAME,
                                     buf, len, 0);
        if (rc == NGX_OK) {
            free(buf);
            return NGX_OK;
        }
        if (!xmeta_xattr_unfit(errno)) {
            int e = errno;

            free(buf);
            errno = e;
            return NGX_ERROR;
        }
        /* doesn't fit / not supported here: ride the sidecar instead */
    }

    rc = xmeta_sidecar_write(store, key, buf, len);
    free(buf);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }
    /* exactly one carrier: drop any (stale or just-outgrown) xattr copy */
    if (store->driver->removexattr != NULL) {
        (void) store->driver->removexattr(store, key,
                                          XROOTD_XMETA_XATTR_NAME);
    }
    return NGX_OK;
}

ngx_int_t
xrootd_xmeta_load(xrootd_sd_instance_t *store, const char *key,
    xrootd_xmeta_t *m)
{
    uint8_t  *buf;
    ssize_t   n;
    size_t    len = 0;
    ngx_int_t rc;
    int       drc;

    if (store == NULL || store->driver == NULL || key == NULL || m == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    /* xattr carrier first */
    if (store->driver->getxattr != NULL) {
        buf = malloc(XROOTD_XMETA_XATTR_MAX);
        if (buf == NULL) {
            errno = ENOMEM;
            return NGX_ERROR;
        }
        n = store->driver->getxattr(store, key, XROOTD_XMETA_XATTR_NAME,
                                    buf, XROOTD_XMETA_XATTR_MAX);
        if (n > 0) {
            drc = xrootd_xmeta_decode(buf, (size_t) n, m);
            free(buf);
            if (drc == XROOTD_XMETA_OK) {
                return NGX_OK;
            }
            return (drc == XROOTD_XMETA_FOREIGN) ? NGX_DECLINED : NGX_ERROR;
        }
        free(buf);
        if (n < 0 && errno != ENODATA && errno != ENOENT
#ifdef ENOATTR
            && errno != ENOATTR
#endif
            && !xmeta_xattr_unfit(errno))
        {
            return NGX_ERROR;
        }
        /* absent / unsupported: try the sidecar */
    }

    rc = xmeta_sidecar_read(store, key, &buf, &len);
    if (rc != NGX_OK) {
        return rc;
    }
    drc = xrootd_xmeta_decode(buf, len, m);
    free(buf);
    if (drc == XROOTD_XMETA_OK) {
        return NGX_OK;
    }
    return (drc == XROOTD_XMETA_FOREIGN) ? NGX_DECLINED : NGX_ERROR;
}

ngx_int_t
xrootd_xmeta_remove(xrootd_sd_instance_t *store, const char *key)
{
    char ck[PATH_MAX];

    if (store == NULL || store->driver == NULL || key == NULL) {
        return NGX_OK;
    }
    if (store->driver->removexattr != NULL) {
        (void) store->driver->removexattr(store, key,
                                          XROOTD_XMETA_XATTR_NAME);
    }
    if (store->driver->unlink != NULL
        && xmeta_sidecar_key(key, ck, sizeof(ck)) == 0)
    {
        (void) store->driver->unlink(store, ck, 0);   /* best-effort */
    }
    return NGX_OK;
}
