/*
 * cinfo_xattr.c - cinfo as a store xattr (SP2, XATTR mode). See header.
 *
 * The fixed cinfo header POD is the xattr value verbatim; store/load are thin
 * wrappers over the SD instance's setxattr/getxattr slots on user.xrd.cinfo, with
 * a magic/version check on load so a foreign or truncated value reads as "absent".
 */
#include "cinfo_xattr.h"

#include <errno.h>
#include <string.h>

ngx_int_t
xrootd_cinfo_xattr_store(xrootd_sd_instance_t *store, const char *key,
    const xrootd_cache_cinfo_t *hdr)
{
    if (store == NULL || store->driver == NULL
        || store->driver->setxattr == NULL || key == NULL || hdr == NULL)
    {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    return store->driver->setxattr(store, key, XROOTD_CINFO_XATTR_NAME,
                                   hdr, sizeof(*hdr), 0);
}

ngx_int_t
xrootd_cinfo_xattr_load(xrootd_sd_instance_t *store, const char *key,
    xrootd_cache_cinfo_t *hdr)
{
    xrootd_cache_cinfo_t tmp;
    ssize_t              n;

    if (store == NULL || store->driver == NULL
        || store->driver->getxattr == NULL || key == NULL || hdr == NULL)
    {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    n = store->driver->getxattr(store, key, XROOTD_CINFO_XATTR_NAME,
                                &tmp, sizeof(tmp));
    if (n < 0) {
        /* ENOATTR/ENODATA/ENOENT = nothing recorded; anything else is a real error. */
        return (errno == ENODATA || errno == ENOENT
#ifdef ENOATTR
                || errno == ENOATTR
#endif
               ) ? NGX_DECLINED : NGX_ERROR;
    }
    if ((size_t) n < sizeof(tmp)
        || tmp.magic != XROOTD_CACHE_CINFO_MAGIC
        || tmp.version != XROOTD_CACHE_CINFO_VERSION)
    {
        return NGX_DECLINED;                    /* short / foreign / stale */
    }
    *hdr = tmp;
    return NGX_OK;
}

ngx_int_t
xrootd_cinfo_xattr_remove(xrootd_sd_instance_t *store, const char *key)
{
    if (store == NULL || store->driver == NULL || key == NULL) {
        return NGX_OK;
    }
    if (store->driver->removexattr != NULL) {
        (void) store->driver->removexattr(store, key, XROOTD_CINFO_XATTR_NAME);
    }
    return NGX_OK;                              /* best-effort */
}
