/*
 * sd_pblock_namespace_copy.c — server-side copy vtable slots for the pblock
 * storage driver.
 *
 * WHAT: Implements the server_copy metadata-plane slots of
 *       brix_sd_pblock_driver: sd_pblock_server_copy_as (owner-parameterised)
 *       and sd_pblock_server_copy (the plain 0/0 service slot). A copy either
 *       shares the source's blob copy-on-write (F10 refs) or physically
 *       duplicates every block under a fresh blob id, then publishes the
 *       destination catalog row owned by the copier.
 *
 * WHY:  Split out of sd_pblock_namespace.c (file-size guard burndown) to keep
 *       every pblock file under the one-concept size cap. The byte/metadata copy
 *       path is self-contained — its three static helpers (CoW share, block copy,
 *       physical copy) are used only by the two public slots here — so it lives
 *       apart from the namespace mutations (stat/unlink/mkdir/setattr/rename),
 *       directory iteration and xattr CRUD that stay in sd_pblock_namespace.c.
 *       The two public functions are non-static because the driver descriptor
 *       names them; declarations live in sd_pblock_internal.h.
 *
 * HOW:  Every operation reaches the namespace through the catalog API
 *       (sd_pblock_catalog.h) and touches block files only through the packed-block
 *       engine (pblock_store.h) — no raw byte syscalls here. ngx-free (libc +
 *       catalog + engine) so the module and standalone unit test compile it
 *       identically. Gated by BRIX_HAVE_SQLITE like the rest of the backend.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* UTIME_OMIT / UTIME_NOW (the module build sets it) */
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "sd_pblock_catalog.h"
#include "pblock_store.h"        /* packed-block storage engine (split out) */
#include "pblock_fault.h"        /* F7 crash points */
#include "pblock_ctl.h"          /* F17 audit log */
#include "pblock_csi.h"          /* F3 per-block CRC32c integrity */
#include "pblock_quota.h"
#include "pblock_nearline.h"     /* Phase-83 F4 nearline residency rows */
#include "pblock_anomaly.h"      /* Phase-83 F9 consistency anomalies */
#include "sd_pblock_internal.h"
#include "pblock_locks.h"        /* Phase-83 F15 mandatory lease enforcement */
#include "pblock_refs.h"         /* Phase-83 F10 refcounted blobs + dedup */
#include "pblock_snap.h"         /* Phase-83 F6 snapshots / fixture reset */
#include "pblock_hist.h"         /* Phase-83 F11 versioning + trash/undelete */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>

/* F10 CoW copy: dst shares src's blob — O(metadata), no bytes move; the first
 * write to either row breaks the share at open. The dst row is owned by
 * (uid, gid). Returns NGX_OK / NGX_ERROR. */
static ngx_int_t
pblock_copy_cow(pblock_state_t *st, const pblock_meta *smeta, const char *dst,
    uint32_t uid, uint32_t gid, off_t *bytes_out)
{
    pblock_meta dexist, dmeta;
    int         dhad = pblock_catalog_lookup(st->cat, dst, &dexist) == 0;

    if (pblock_refs_bump(st, smeta->blob_id, smeta->size,
                         smeta->block_size) != 0)
    {
        return NGX_ERROR;
    }
    memset(&dmeta, 0, sizeof(dmeta));
    memcpy(dmeta.blob_id, smeta->blob_id, sizeof(dmeta.blob_id));
    dmeta.is_dir     = 0;
    dmeta.size       = smeta->size;
    dmeta.block_size = smeta->block_size;
    dmeta.mtime      = dmeta.ctime = pblock_now();
    dmeta.mode       = smeta->mode;
    dmeta.uid        = uid;
    dmeta.gid        = gid;
    if (pblock_catalog_put(st->cat, dst, &dmeta) != 0) {
        int err = errno;

        pblock_refs_release(st, smeta->blob_id, smeta->size,
                            smeta->block_size);
        errno = err;
        return NGX_ERROR;
    }
    if (dhad && !dexist.is_dir) {    /* the replaced dst's blob loses a ref */
        pblock_refs_release(st, dexist.blob_id, dexist.size,
                            dexist.block_size);
    }
    if (st->lab != NULL) {                           /* F9 */
        if (dhad) {
            pblock_anomaly_updated(st, dst, dexist.size, dexist.mtime);
        } else {
            pblock_anomaly_created(st, dst);
        }
    }
    if (bytes_out != NULL) {
        *bytes_out = (off_t) smeta->size;
    }
    /* No csi flush: the shared blob's integrity rows already exist. */
    if (st->audit) {                                 /* F17 */
        char aux[32];

        snprintf(aux, sizeof(aux), "cow=1 w=%lld", (long long) smeta->size);
        pblock_audit_log(st->cat, "copy", dst, aux, uid, gid, 0, 0);
    }
    return NGX_OK;
}

/* Physically copy every block of `src_blob` to `dst_blob`. Returns 0, or -1
 * with errno set from the failing call (the caller unwinds the partial dst). */
static int
pblock_copy_blocks(pblock_state_t *st, const char *src_blob,
    const char *dst_blob, int64_t size, int64_t block_size)
{
    int64_t last = pblock_last_block(size, block_size);
    int64_t i;

    for (i = 0; i <= last; i++) {
        char sp[PATH_MAX], dp[PATH_MAX];

        if (pblock_block_path(st, src_blob, i, sp, sizeof(sp)) != 0
            || pblock_block_path(st, dst_blob, i, dp, sizeof(dp)) != 0
            || pblock_copy_one_block(sp, dp) < 0)
        {
            return -1;
        }
    }
    return 0;
}

/* Full byte copy: allocate a fresh blob, copy every block, then publish the dst
 * row owned by (uid, gid). Returns NGX_OK / NGX_ERROR (partial blob unwound). */
static ngx_int_t
pblock_copy_physical(pblock_state_t *st, const pblock_meta *smeta,
    const char *dst, uint32_t uid, uint32_t gid, off_t *bytes_out)
{
    pblock_meta dmeta, dexist;
    int         dhad = 0;

    memset(&dmeta, 0, sizeof(dmeta));
    if (pblock_gen_blob_id(dmeta.blob_id) != 0
        || pblock_ensure_obj_dir(st, dmeta.blob_id) != 0)
    {
        return NGX_ERROR;
    }

    if (pblock_copy_blocks(st, smeta->blob_id, dmeta.blob_id, smeta->size,
                           smeta->block_size) != 0)
    {
        int err = errno;

        pblock_remove_blocks(st, dmeta.blob_id, smeta->size,
                             smeta->block_size);
        errno = err;
        return NGX_ERROR;
    }

    dmeta.is_dir     = 0;
    dmeta.size       = smeta->size;
    dmeta.block_size = smeta->block_size;
    dmeta.mtime      = dmeta.ctime = pblock_now();
    dmeta.mode       = smeta->mode;
    dmeta.uid        = uid;
    dmeta.gid        = gid;

    /* F9: is this copy a create or an overwrite of dst? The pre-put row is what
     * a stale stat will serve. */
    if (st->lab != NULL) {
        dhad = pblock_catalog_lookup(st->cat, dst, &dexist) == 0;
    }
    if (pblock_catalog_put(st->cat, dst, &dmeta) != 0) {
        int err = errno;

        pblock_remove_blocks(st, dmeta.blob_id, smeta->size,
                             smeta->block_size);
        errno = err;
        return NGX_ERROR;
    }
    if (st->lab != NULL) {
        if (dhad) {
            pblock_anomaly_updated(st, dst, dexist.size, dexist.mtime);
        } else {
            pblock_anomaly_created(st, dst);
        }
    }
    if (bytes_out != NULL) {
        *bytes_out = (off_t) smeta->size;
    }
    if (st->csi) {                                       /* F3: tag the copy */
        (void) pblock_csi_flush(st, dmeta.blob_id, dmeta.size,
                                dmeta.block_size, 0, INT64_MAX);
    }
    if (st->audit) {                                     /* F17 */
        char aux[32];

        snprintf(aux, sizeof(aux), "w=%lld", (long long) smeta->size);
        pblock_audit_log(st->cat, "copy", dst, aux, uid, gid, 0, 0);
    }
    return NGX_OK;
}

/* sd_pblock_server_copy_as — server-side copy whose destination row is owned
 * by (uid, gid): the copier, not the source's owner (POSIX cp semantics). The
 * plain slot passes 0/0 (service); server_copy_cred passes the requester. */
ngx_int_t
sd_pblock_server_copy_as(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, uint32_t uid, uint32_t gid)
{
    pblock_state_t *st = inst->state;
    pblock_meta     smeta;
    int             rc;

    rc = pblock_catalog_lookup(st->cat, src, &smeta);
    if (rc < 0) {
        return NGX_ERROR;
    }
    if (rc == 1) {
        errno = ENOENT;
        return NGX_ERROR;
    }
    if (smeta.is_dir) {
        errno = EISDIR;
        return NGX_ERROR;
    }

    if (st->quota) {                                     /* F5 */
        pblock_meta dexist;
        int         drc = pblock_catalog_lookup(st->cat, dst, &dexist);

        if (pblock_quota_admit(st, uid,
                (int64_t) smeta.size - (drc == 0 ? dexist.size : 0),
                drc == 0 ? 0 : 1) != 0)
        {
            return NGX_ERROR;
        }
    }

    if (st->refs) {                                      /* F10: CoW copy */
        return pblock_copy_cow(st, &smeta, dst, uid, gid, bytes_out);
    }
    return pblock_copy_physical(st, &smeta, dst, uid, gid, bytes_out);
}

ngx_int_t
sd_pblock_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out)
{
    return sd_pblock_server_copy_as(inst, src, dst, bytes_out, 0, 0);
}

#endif /* BRIX_HAVE_SQLITE */
