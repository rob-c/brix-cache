#ifndef XROOTD_CACHE_CINFO_XATTR_H
#define XROOTD_CACHE_CINFO_XATTR_H

/*
 * cinfo_xattr.h - cinfo as a store xattr (phase-64 SP2, section 6.3 XATTR mode).
 *
 * WHAT: Store and load the cinfo HEADER record as the reserved "user.xrd.cinfo"
 *       xattr on a cache object, through an SD instance's setxattr/getxattr slots.
 *       This is how a cache store that is NOT a local POSIX tree (a pblock catalog,
 *       a remote roots:// cache server, an s3 bucket, ...) keeps each object's
 *       cache state ON THE STORE ITSELF - so a node holds no durable cinfo state
 *       and a warm hit survives a restart of the cache node (G3).
 *
 * WHY:  Phase-64 P3/G3 require every tier to hold 100% of its bytes AND metadata.
 *       LOCAL mode writes a ".cinfo" sidecar file next to the object; that only
 *       works for a posix dir. Moving the SAME record into a store xattr is a
 *       transport change, not a format change (section 6.2): the on-disk cinfo
 *       header is already a fixed, self-contained POD.
 *
 * HOW:  The header POD (xrootd_cache_cinfo_t, ~300 bytes) is written verbatim as
 *       the xattr value via store->driver->setxattr(user.xrd.cinfo, ...) and read
 *       back via getxattr. The reserved user.xrd.* namespace is set BELOW the VFS
 *       seam (the VFS maps client attrs to user.U.*), so a client cannot forge it
 *       (section 17). The present bitmap is reconstructable from the COMPLETE flag
 *       for whole-file caching; a partial-object bitmap in the xattr is section
 *       6.5 / a later increment.
 */

#include <ngx_core.h>

#include "cinfo.h"             /* xrootd_cache_cinfo_t */
#include "fs/backend/sd.h"  /* xrootd_sd_instance_t */

/* The reserved xattr name (Appendix B). */
#define XROOTD_CINFO_XATTR_NAME "user.xrd.cinfo"

/* Write *hdr as the user.xrd.cinfo xattr on `key`'s object in `store`. Returns
 * NGX_OK, or NGX_ERROR (errno set; ENOTSUP when the store lacks setxattr). */
ngx_int_t xrootd_cinfo_xattr_store(xrootd_sd_instance_t *store, const char *key,
    const xrootd_cache_cinfo_t *hdr);

/* Load the cinfo header from the user.xrd.cinfo xattr on `key`'s object into
 * *hdr. Returns NGX_OK, NGX_DECLINED when the xattr is absent or short/invalid
 * (treat as "nothing cached"), or NGX_ERROR on a hard store error. */
ngx_int_t xrootd_cinfo_xattr_load(xrootd_sd_instance_t *store, const char *key,
    xrootd_cache_cinfo_t *hdr);

/* Remove the cinfo xattr from `key`'s object (best-effort; NGX_OK even if the
 * object or the xattr is already gone). */
ngx_int_t xrootd_cinfo_xattr_remove(xrootd_sd_instance_t *store, const char *key);

#endif /* XROOTD_CACHE_CINFO_XATTR_H */
