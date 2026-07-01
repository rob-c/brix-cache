#ifndef XROOTD_CACHE_CINFO_SIDECAR_H
#define XROOTD_CACHE_CINFO_SIDECAR_H

/*
 * cinfo_sidecar.h - cinfo as a co-located store OBJECT (section 6.3 SIDECAR mode).
 *
 * WHAT: Store and load the cinfo HEADER record as a small "<key>.xrdcinfo" object
 *       NEXT TO the cached object, through the store's own staged-write / open /
 *       pread / unlink slots.
 *
 * WHY:  XATTR mode (cinfo_xattr.c) keeps cache state on the store, but needs a store
 *       that advertises CAP_XATTR (a user.* attribute surface). An object store
 *       reached over plain PUT/GET - an S3 endpoint, an HTTP/WebDAV origin - has no
 *       xattr surface, so the record rides as a separate tiny object instead. Same
 *       self-contained POD, a different carrier (section 6.2): the cache stays
 *       driver-agnostic (G3/G5) for ANY writable store, not just xattr-capable ones.
 *
 * HOW:  The header POD (xrootd_cache_cinfo_t) is the object body, written via
 *       staged_open/_write/_commit and read back via open/pread, with a magic +
 *       version check on load (a foreign / short / absent object reads as "nothing
 *       cached"). Whole-file caching only (the present bitmap is the COMPLETE flag);
 *       a partial-object bitmap is a later increment, as for XATTR.
 */

#include <ngx_core.h>

#include "cinfo.h"             /* xrootd_cache_cinfo_t */
#include "../fs/backend/sd.h"  /* xrootd_sd_instance_t */

/* The sidecar object key suffix (Appendix B). */
#define XROOTD_CINFO_SIDECAR_SUFFIX ".xrdcinfo"

/* Write *hdr as the "<key>.xrdcinfo" object in `store` (a staged PUT). Returns
 * NGX_OK, or NGX_ERROR (errno set; ENOTSUP when the store has no staged-write). */
ngx_int_t xrootd_cinfo_sidecar_store(xrootd_sd_instance_t *store, const char *key,
    const xrootd_cache_cinfo_t *hdr);

/* Load the cinfo header from the "<key>.xrdcinfo" object into *hdr. Returns NGX_OK,
 * NGX_DECLINED when the sidecar is absent or short/invalid (treat as "nothing
 * cached"), or NGX_ERROR on a hard store error. */
ngx_int_t xrootd_cinfo_sidecar_load(xrootd_sd_instance_t *store, const char *key,
    xrootd_cache_cinfo_t *hdr);

/* Remove the "<key>.xrdcinfo" object (best-effort; NGX_OK even if already gone). */
ngx_int_t xrootd_cinfo_sidecar_remove(xrootd_sd_instance_t *store, const char *key);

#endif /* XROOTD_CACHE_CINFO_SIDECAR_H */
