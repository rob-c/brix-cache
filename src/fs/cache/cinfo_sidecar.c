/*
 * cinfo_sidecar.c - cinfo as a co-located store object (SIDECAR mode). See header.
 *
 * The fixed cinfo header POD is the body of a "<key>.xrdcinfo" object; store is a
 * staged PUT, load is open + pread of the POD with a magic/version check (a foreign
 * or short or absent object reads as "absent"). Every writable store - posix,
 * pblock, xroot, s3, http - exposes the staged-write / open / pread / unlink slots
 * this uses, so the same record works on a store with no xattr surface.
 */
#include "cinfo_sidecar.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Compose the sidecar object key "<key>.xrdcinfo" into out[cap]. 0 / -1. */
static int
sidecar_key(const char *key, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s%s", key, XROOTD_CINFO_SIDECAR_SUFFIX);

    return (n > 0 && (size_t) n < cap) ? 0 : -1;
}

ngx_int_t
xrootd_cinfo_sidecar_store(xrootd_sd_instance_t *store, const char *key,
    const xrootd_cache_cinfo_t *hdr)
{
    char                ck[PATH_MAX];
    xrootd_sd_staged_t *st;
    int                 err = 0;

    if (store == NULL || store->driver == NULL
        || store->driver->staged_open == NULL
        || store->driver->staged_write == NULL
        || store->driver->staged_commit == NULL
        || key == NULL || hdr == NULL)
    {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    if (sidecar_key(key, ck, sizeof(ck)) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    st = store->driver->staged_open(store, ck, 0644, &err);
    if (st == NULL) {
        errno = err ? err : EIO;
        return NGX_ERROR;
    }
    if (store->driver->staged_write(st, hdr, sizeof(*hdr), 0)
        != (ssize_t) sizeof(*hdr))
    {
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

ngx_int_t
xrootd_cinfo_sidecar_load(xrootd_sd_instance_t *store, const char *key,
    xrootd_cache_cinfo_t *hdr)
{
    char                 ck[PATH_MAX];
    xrootd_cache_cinfo_t tmp;
    xrootd_sd_obj_t     *obj;
    ssize_t              got = 0;
    int                  err = 0;

    if (store == NULL || store->driver == NULL || store->driver->open == NULL
        || store->driver->pread == NULL || key == NULL || hdr == NULL)
    {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    if (sidecar_key(key, ck, sizeof(ck)) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    obj = store->driver->open(store, ck, XROOTD_SD_O_READ, 0, &err);
    if (obj == NULL) {
        /* Absent (the common cold-read case) reads as "nothing cached". */
        return (err == ENOENT) ? NGX_DECLINED : NGX_ERROR;
    }
    while ((size_t) got < sizeof(tmp)) {
        ssize_t n = store->driver->pread(obj, (char *) &tmp + got,
                                         sizeof(tmp) - (size_t) got, got);
        if (n < 0) {
            int e = errno;

            store->driver->close(obj);
            if (obj->heap_shell) { free(obj); }
            errno = e ? e : EIO;
            return NGX_ERROR;
        }
        if (n == 0) {
            break;                                 /* short object */
        }
        got += n;
    }
    store->driver->close(obj);
    if (obj->heap_shell) { free(obj); }

    if ((size_t) got < sizeof(tmp)
        || tmp.magic != XROOTD_CACHE_CINFO_MAGIC
        || tmp.version != XROOTD_CACHE_CINFO_VERSION)
    {
        return NGX_DECLINED;                        /* short / foreign / stale */
    }
    *hdr = tmp;
    return NGX_OK;
}

ngx_int_t
xrootd_cinfo_sidecar_remove(xrootd_sd_instance_t *store, const char *key)
{
    char ck[PATH_MAX];

    if (store == NULL || store->driver == NULL || key == NULL) {
        return NGX_OK;
    }
    if (store->driver->unlink != NULL && sidecar_key(key, ck, sizeof(ck)) == 0) {
        (void) store->driver->unlink(store, ck, 0);   /* best-effort */
    }
    return NGX_OK;
}
