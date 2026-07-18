/*
 * vfs_wverify.c — VFS seam for self-computed write-verify (read-back compare).
 *
 * WHAT: brix_vfs_wverify_check() — given a write-side CRC accumulator and a
 *       FRESH read-only handle on the just-written object, re-read the object
 *       through its storage driver and confirm the persisted bytes match what
 *       was written.
 * WHY:  An object backend (pblock, rados) keeps no single kernel file whose
 *       bytes are the object, so "did the write actually land?" can only be
 *       answered by reading it back through the same driver. This is the reusable
 *       seam any protocol write path (GridFTP STOR, WebDAV/root/S3 PUT) can call
 *       after close to fail a silently-corrupted or short write.
 * HOW:  brix_wverify_expected() gives the whole-object CRC-32 and length the
 *       write should have produced (only when the writes covered [0, size) with
 *       no gap/overlap); the read handle's size must match, and a driver-routed
 *       brix_cksum_u32_obj(BRIX_CK_CRC32, …) over the reopened object must equal
 *       the expected CRC. Any divergence → NGX_ERROR (the caller unlinks + fails
 *       the transfer).
 */
#include "vfs_internal.h"
#include "core/compat/wverify.h"
#include "core/compat/checksum_core.h"

ngx_int_t
brix_vfs_wverify_check(brix_wverify_t *w, brix_vfs_file_t *rfh)
{
    brix_sd_obj_t obj;
    uint32_t      expect = 0, actual = 0;
    off_t         total = 0;

    if (w == NULL || rfh == NULL) {
        return NGX_ERROR;
    }

    /* What the write path should have persisted: a single [0, total) run. A gap,
     * an overlap, or a degraded accumulator all fail closed here. */
    if (brix_wverify_expected(w, &expect, &total) != 0) {
        return NGX_ERROR;
    }
    if (total != brix_vfs_file_size(rfh)) {
        return NGX_ERROR;                   /* persisted length disagrees */
    }

    /* Read the object back through the SAME driver and compare content. */
    brix_vfs_file_sd_obj(rfh, &obj);
    if (obj.driver == NULL
        || brix_cksum_u32_obj(BRIX_CK_CRC32, &obj, &actual) != 0)
    {
        return NGX_ERROR;
    }
    return (actual == expect) ? NGX_OK : NGX_ERROR;
}
