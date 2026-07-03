#ifndef BRIX_FS_META_XMETA_CARRIER_H
#define BRIX_FS_META_XMETA_CARRIER_H

/*
 * fs/meta/xmeta_carrier.h — carriers for the unified metadata record (P1).
 *
 * WHAT: Persist/load an encoded xmeta record for a store object: preferred
 *       carrier is the reserved "user.xrd.cinfo" xattr (below the VFS seam,
 *       unforgeable by clients — the VFS maps client attrs to user.U.*);
 *       when the store has no xattr surface or the record exceeds the
 *       store's xattr value cap, the identical bytes ride as a co-located
 *       "<key>.cinfo" sidecar object — which, thanks to the stock-compatible
 *       prefix, IS a valid stock XrdPfc cinfo file.
 *
 * WHY:  Exactly one metadata record per file, wherever the store can keep it
 *       (spec 2026-07-02-xmeta-unified-metadata-design.md §Carriers).
 *
 * HOW:  Save encodes then TRIES the xattr; E2BIG/ERANGE/ENOSPC/ENOTSUP (or a
 *       missing slot) falls back to a staged sidecar write, then best-effort
 *       removes the xattr so the file never has two carriers. Load checks
 *       the xattr first, then the sidecar. (Try-then-fallback replaces the
 *       spec's startup cap probe: same behavior, no probe machinery, and it
 *       adapts per file rather than per store.)
 */

#include <ngx_core.h>

#include "xmeta.h"
#include "fs/backend/sd.h"

#define BRIX_XMETA_XATTR_NAME     "user.xrd.cinfo"
#define BRIX_XMETA_SIDECAR_SUFFIX ".cinfo"

/* Largest xattr value we ever attempt (linux VFS cap). */
#define BRIX_XMETA_XATTR_MAX      (64 * 1024)

/* Persist *m for `key` (xattr preferred, sidecar fallback). Returns NGX_OK,
 * or NGX_ERROR with errno (ENOTSUP when the store can carry neither). */
ngx_int_t brix_xmeta_save(brix_sd_instance_t *store, const char *key,
    const brix_xmeta_t *m);

/* Load the record for `key` into *m (caller must brix_xmeta_free on OK).
 * Returns NGX_OK, NGX_DECLINED when nothing (valid) is recorded, or
 * NGX_ERROR on a hard store error / torn record (errno set). */
ngx_int_t brix_xmeta_load(brix_sd_instance_t *store, const char *key,
    brix_xmeta_t *m);

/* Remove both carriers for `key` (best-effort; NGX_OK even when absent). */
ngx_int_t brix_xmeta_remove(brix_sd_instance_t *store, const char *key);

#endif /* BRIX_FS_META_XMETA_CARRIER_H */
