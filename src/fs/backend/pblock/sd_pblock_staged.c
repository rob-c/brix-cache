/*
 * sd_pblock_staged.c — staged atomic-publish vtable slots for the pblock driver.
 *
 * WHAT: Implements the staged-write path of brix_sd_pblock_driver:
 *       staged_open/write/commit/abort. Body bytes are written to a fresh blob id
 *       (no visible catalog row yet); commit publishes them atomically by
 *       inserting the final row that points at that blob (the staged blocks simply
 *       become the object — no copy or rename), while abort removes them.
 *
 * WHY:  Split out of sd_pblock.c (phase-79) to keep every pblock file under the
 *       ~500-line, one-concept cap. Atomic publish is its own concern, distinct
 *       from the object lifecycle (sd_pblock.c), the hot byte path (sd_pblock_io.c)
 *       and the namespace ops (sd_pblock_namespace.c). The functions are
 *       non-static because the driver descriptor names them; commit reuses
 *       sd_pblock_drop_dst from the namespace file. Declarations live in
 *       sd_pblock_internal.h.
 *
 * HOW:  staged_open gates the parent collection up front (POSIX parity with the
 *       POSIX driver's O_EXCL temp) before any blob is allocated, then reserves a
 *       blob id + object dir. staged_write appends through the packed-block engine
 *       with no persistent block-0 fd (blk0_fd = -1). commit does the replace/
 *       insert against the catalog and consumes the handle on success. ngx-free;
 *       gated by BRIX_HAVE_SQLITE like the rest of the backend.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "sd_pblock_catalog.h"
#include "pblock_store.h"        /* packed-block storage engine (split out) */
#include "sd_pblock_internal.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>

/* Staged (atomic-publish) state (staged->state); local to this file. */
typedef struct {
    pblock_state_t *st;
    char            final_path[PATH_MAX];
    char            blob_id[PBLOCK_BLOB_ID_CAP];
    int64_t         block_size;
    int64_t         size;                 /* high-water mark of staged writes  */
    mode_t          mode;
    uint32_t        uid;                  /* owner recorded on the committed   */
    uint32_t        gid;                  /* row (0/0 = the service itself)    */
} pblock_staged_t;

/* ---- staged atomic publish ------------------------------------------------ */

/* sd_pblock_staged_open_as — staged open whose eventual committed row is owned
 * by (uid, gid). The plain slot passes 0/0 (service); staged_open_cred
 * (sd_pblock_cred.c) passes the requester's resolved catalog ids. */
brix_sd_staged_t *
sd_pblock_staged_open_as(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, uint32_t uid, uint32_t gid, int *err_out)
{
    pblock_state_t     *st = inst->state;
    brix_sd_staged_t *handle;
    pblock_staged_t    *ps;

    /* POSIX parity with the posix driver's staged temp (O_EXCL in the final
     * directory): a missing parent collection fails HERE — before any blob
     * is allocated or a single body byte is accepted — not at commit. */
    if (pblock_catalog_parent_ok(st->cat, final_path) != 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    handle = calloc(1, sizeof(*handle));
    ps     = calloc(1, sizeof(*ps));
    if (handle == NULL || ps == NULL) {
        free(handle);
        free(ps);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    if (pblock_gen_blob_id(ps->blob_id) != 0
        || pblock_ensure_obj_dir(st, ps->blob_id) != 0)
    {
        if (err_out != NULL) { *err_out = errno; }
        free(handle);
        free(ps);
        return NULL;
    }

    ps->st         = st;
    ps->block_size = st->block_size;
    ps->size       = 0;
    ps->mode       = mode;
    ps->uid        = uid;
    ps->gid        = gid;
    snprintf(ps->final_path, sizeof(ps->final_path), "%s", final_path);
    handle->inst  = inst;
    handle->state = ps;
    return handle;
}

brix_sd_staged_t *
sd_pblock_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    return sd_pblock_staged_open_as(inst, final_path, mode, 0, 0, err_out);
}

ssize_t
sd_pblock_staged_write(brix_sd_staged_t *st, const void *buf, size_t len,
    off_t off)
{
    pblock_staged_t *ps = st->state;
    ssize_t          n;

    n = pblock_write_blocks(ps->st, ps->blob_id, ps->block_size, -1, buf, len,
                            off);
    if (n > 0 && (int64_t) off + n > ps->size) {
        ps->size = (int64_t) off + n;
    }
    return n;
}

/* sd_pblock_staged_commit — publish the staged blocks atomically by inserting
 * the final catalog row pointing at the staged blob id (the blocks simply become
 * the final object — no copy or rename). On success the handle is consumed; on
 * failure it stays valid and the caller must staged_abort to release it. */
ngx_int_t
sd_pblock_staged_commit(brix_sd_staged_t *st, int noreplace)
{
    pblock_staged_t *ps = st->state;
    pblock_state_t  *pst = ps->st;
    pblock_meta      meta, dmeta;
    int              rc;

    rc = pblock_catalog_lookup(pst->cat, ps->final_path, &dmeta);
    if (rc < 0) {
        return NGX_ERROR;
    }
    if (rc == 0) {
        if (noreplace) {
            errno = EEXIST;
            return NGX_ERROR;
        }
        if (sd_pblock_drop_dst(pst, ps->final_path, &dmeta) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    memset(&meta, 0, sizeof(meta));
    meta.is_dir = 0;
    snprintf(meta.blob_id, sizeof(meta.blob_id), "%s", ps->blob_id);
    meta.size       = ps->size;
    meta.block_size = ps->block_size;
    meta.mtime      = meta.ctime = pblock_now();
    meta.mode       = S_IFREG | (ps->mode & 0777);
    meta.uid        = ps->uid;
    meta.gid        = ps->gid;

    if (pblock_catalog_put(pst->cat, ps->final_path, &meta) != 0) {
        return NGX_ERROR;
    }

    free(ps);
    free(st);
    return NGX_OK;
}

void
sd_pblock_staged_abort(brix_sd_staged_t *st)
{
    pblock_staged_t *ps = st->state;

    if (ps != NULL) {
        pblock_remove_blocks(ps->st, ps->blob_id, ps->size, ps->block_size);
        free(ps);
    }
    free(st);
}

#endif /* BRIX_HAVE_SQLITE */
