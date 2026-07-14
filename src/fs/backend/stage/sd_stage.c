/*
 * sd_stage.c - the generic write-stage decorator CORE (section 12.2). See header.
 *
 * The decorator forwards every read / namespace / xattr / dir op to the wrapped
 * `source` (open returns the source's own object, so read byte-I/O bypasses the
 * decorator) and interposes only the staged-write path. This file owns the
 * decorator core — the open dispatch, the read/namespace/xattr/dir forwarders,
 * the driver descriptor, and the instance lifecycle (create/destroy/predicates/
 * reflush). The two interposed WRITE paths (the write-back byte-I/O object and
 * the staged-upload path) live in sd_stage_write.c; the driver table below
 * dispatches to them and the shared seam is declared in sd_stage_internal.h.
 * A posix stage store is byte-equivalent to phase-63's local-temp promote.
 */
#include "sd_stage.h"
#include "sd_stage_internal.h"
#include "fs/xfer/stage_engine.h"   /* brix_stage_run_inline_cred (reflush FLUSH) */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define SD_STAGE_SRC(inst)  (((sd_stage_inst_state *) (inst)->state)->source)

/* ---- open dispatch -------------------------------------------------------- */

static brix_sd_obj_t *
sd_stage_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_stage_inst_state *is = inst->state;

    /* Write open → a write-back object on the stage store (pwrite buffers, fsync/close
     * flush to the backend). Read open → the source's own object, so read byte-I/O
     * bypasses the decorator entirely. */
    if (sd_flags & BRIX_SD_O_WRITE) {
        return sd_stage_open_writeback(inst, is, path, sd_flags, mode, NULL,
                                        err_out);
    }
    return is->source->driver->open(is->source, path, sd_flags, mode, err_out);
}

/* Credential-scoped open: records the caller's per-user identity in the
 * write-back state so the eventual flush authenticates as the original user.
 *
 * WHAT: Write opens route through sd_stage_open_writeback with the cred so the
 *       owner key/dir/deny are embedded in the durable wb state; read opens
 *       forward to the source via brix_sd_open_maybe_cred.
 *
 * WHY:  Without this slot the stage decorator drops a caller-supplied cred on
 *       the floor: write opens use the service account for the flush, and read
 *       opens use the service account for the source open on credential-aware
 *       backends.
 *
 * HOW:  Write → sd_stage_open_writeback(... cred); read →
 *       brix_sd_open_maybe_cred(source, ..., cred). */
static brix_sd_obj_t *
sd_stage_open_cred(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    sd_stage_inst_state *is = inst->state;

    if (sd_flags & BRIX_SD_O_WRITE) {
        return sd_stage_open_writeback(inst, is, path, sd_flags, mode, cred,
                                        err_out);
    }
    return brix_sd_open_maybe_cred(is->source, path, sd_flags, mode, cred,
                                    err_out);
}

/* ---- namespace / xattr / dir forwarders (delegate to the source) ---------- */

static ngx_int_t
sd_stage_stat(brix_sd_instance_t *inst, const char *path, brix_sd_stat_t *out)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    return s->driver->stat ? s->driver->stat(s, path, out) : NGX_ERROR;
}

static ngx_int_t
sd_stage_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    return s->driver->unlink ? s->driver->unlink(s, path, is_dir) : NGX_ERROR;
}

static ngx_int_t
sd_stage_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    return s->driver->mkdir ? s->driver->mkdir(s, path, mode) : NGX_ERROR;
}

static ngx_int_t
sd_stage_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    return s->driver->rename ? s->driver->rename(s, src, dst, noreplace)
                             : NGX_ERROR;
}

static ngx_int_t
sd_stage_server_copy(brix_sd_instance_t *inst, const char *src, const char *dst,
    off_t *bytes_out)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    return s->driver->server_copy ? s->driver->server_copy(s, src, dst, bytes_out)
                                  : NGX_ERROR;
}

static ngx_int_t
sd_stage_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    return s->driver->setattr ? s->driver->setattr(s, path, attr) : NGX_OK;
}

static brix_sd_dir_t *
sd_stage_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    if (s->driver->opendir == NULL) {
        if (err_out != NULL) { *err_out = ENOSYS; }
        return NULL;
    }
    return s->driver->opendir(s, path, err_out);    /* dir->inst = the source */
}

static ngx_int_t
sd_stage_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
{
    /* The dir handle carries its owning (source) instance; dispatch through it. */
    return d->inst->driver->readdir ? d->inst->driver->readdir(d, out) : NGX_ERROR;
}

static ngx_int_t
sd_stage_closedir(brix_sd_dir_t *d)
{
    return d->inst->driver->closedir ? d->inst->driver->closedir(d) : NGX_ERROR;
}

static ssize_t
sd_stage_getxattr(brix_sd_instance_t *inst, const char *path, const char *name,
    void *buf, size_t cap)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    if (s->driver->getxattr == NULL) { errno = ENOTSUP; return -1; }
    return s->driver->getxattr(s, path, name, buf, cap);
}

static ssize_t
sd_stage_listxattr(brix_sd_instance_t *inst, const char *path, void *buf,
    size_t cap)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    if (s->driver->listxattr == NULL) { errno = ENOTSUP; return -1; }
    return s->driver->listxattr(s, path, buf, cap);
}

static ngx_int_t
sd_stage_setxattr(brix_sd_instance_t *inst, const char *path, const char *name,
    const void *val, size_t len, int flags)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    if (s->driver->setxattr == NULL) { errno = ENOTSUP; return NGX_ERROR; }
    return s->driver->setxattr(s, path, name, val, len, flags);
}

static ngx_int_t
sd_stage_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    if (s->driver->removexattr == NULL) { errno = ENOTSUP; return NGX_ERROR; }
    return s->driver->removexattr(s, path, name);
}

/* ---- driver descriptor ---------------------------------------------------- */

/* The decorator advertises the writable-remote slot set; read byte-I/O is never
 * reached here (open returns source objects). The write-back and staged methods
 * live in sd_stage_write.c (declared in sd_stage_internal.h). */
const brix_sd_driver_t brix_sd_stage_driver = {
    .name        = "stage",
    .caps        = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_RANDOM_WRITE
                 | BRIX_SD_CAP_TRUNCATE | BRIX_SD_CAP_XATTR
                 | BRIX_SD_CAP_XATTR_WRITE
                 | BRIX_SD_CAP_HARD_RENAME | BRIX_SD_CAP_SERVER_COPY,
    .open        = sd_stage_open,
    .open_cred   = sd_stage_open_cred,
    /* write-back byte-I/O (only dispatched for objects opened for write — a read
     * open returns the source's own object with the source driver). */
    .pread       = sd_stage_wb_pread,
    .pwrite      = sd_stage_wb_pwrite,
    .ftruncate   = sd_stage_wb_ftruncate,
    .fstat       = sd_stage_wb_fstat,
    .fsync       = sd_stage_wb_fsync,
    .close       = sd_stage_wb_close,
    .stat        = sd_stage_stat,
    .unlink      = sd_stage_unlink,
    .mkdir       = sd_stage_mkdir,
    .rename      = sd_stage_rename,
    .server_copy = sd_stage_server_copy,
    .setattr     = sd_stage_setattr,
    .opendir     = sd_stage_opendir,
    .readdir     = sd_stage_readdir,
    .closedir    = sd_stage_closedir,
    .getxattr    = sd_stage_getxattr,
    .listxattr   = sd_stage_listxattr,
    .setxattr    = sd_stage_setxattr,
    .removexattr = sd_stage_removexattr,
    .staged_open      = sd_stage_staged_open,
    .staged_open_cred = sd_stage_staged_open_cred,
    .staged_write     = sd_stage_staged_write,
    .staged_commit    = sd_stage_staged_commit,
    .staged_abort     = sd_stage_staged_abort,
};

/* ---- instance lifecycle --------------------------------------------------- */

brix_sd_instance_t *
brix_sd_stage_create(brix_sd_instance_t *source, brix_sd_instance_t *store,
    const brix_stage_policy_t *policy, const char *root_canon, ngx_log_t *log)
{
    brix_sd_instance_t *inst;
    sd_stage_inst_state  *is;

    if (source == NULL || store == NULL) {
        errno = EINVAL;
        return NULL;
    }
    inst = calloc(1, sizeof(*inst));
    is   = calloc(1, sizeof(*is));
    if (inst == NULL || is == NULL) {
        free(inst);
        free(is);
        errno = ENOMEM;
        return NULL;
    }
    is->source = source;
    is->store  = store;
    is->log    = log;
    if (root_canon != NULL) {
        ngx_cpystrn((u_char *) is->root_canon, (u_char *) root_canon,
                    sizeof(is->root_canon));
    }
    if (policy != NULL) {
        is->policy = *policy;
    } else {
        ngx_memzero(&is->policy, sizeof(is->policy));
        is->policy.flush_mode = BRIX_WT_MODE_SYNC;
    }

    inst->driver = &brix_sd_stage_driver;
    inst->log    = log;
    inst->pool   = NULL;
    inst->state  = is;
    return inst;
}

void
brix_sd_stage_destroy(brix_sd_instance_t *inst)
{
    if (inst == NULL) {
        return;
    }
    free(inst->state);
    free(inst);
}

/* 1 iff `inst` is a stage decorator built by brix_sd_stage_create. */
int
brix_sd_stage_instance_is(const brix_sd_instance_t *inst)
{
    return (inst != NULL && inst->driver == &brix_sd_stage_driver) ? 1 : 0;
}

/* The stage SOURCE instance (the backend reads forward to it), or NULL for a
 * non-stage instance. The serve-locality predicate recurses into it (a stage
 * read is served from the source, not the stage buffer). */
brix_sd_instance_t *
brix_sd_stage_source_instance(const brix_sd_instance_t *inst)
{
    return brix_sd_stage_instance_is(inst) ? SD_STAGE_SRC(inst) : NULL;
}

/* The stage STORE instance (the buffer holding the durable staged object). */
brix_sd_instance_t *
brix_sd_stage_store_instance(const brix_sd_instance_t *inst)
{
    return brix_sd_stage_instance_is(inst)
         ? ((sd_stage_inst_state *) inst->state)->store : NULL;
}

/* SP4 restart-reconcile: re-flush the durable staged object `key` from the stage
 * store to the backend (the FLUSH a crash interrupted), dropping the stage copy on
 * success - exactly the sync staged_commit tail, run again.
 *
 * WHAT: Delegates to brix_stage_run_inline_cred so the owner identity (from the
 *       persisted brix_sreq_t.cred) is threaded into the flush and presented to the
 *       backend driver.  A NULL cred uses the service credential.
 *
 * WHY:  A restart-reconcile must authenticate as the original user — not the
 *       service account — for per-user quota / audit / ACL enforcement.
 *
 * HOW:  Same as the pre-cred path but calls _cred instead of _inline, passing the
 *       caller-supplied cred unchanged.  Returns NGX_OK / NGX_DECLINED (not a stage
 *       instance) / NGX_ERROR (errno set; the record is kept for retry). */
ngx_int_t
brix_sd_stage_reflush(brix_sd_instance_t *inst, const char *key,
    const brix_stage_cred_t *cred)
{
    sd_stage_inst_state *is;
    ngx_int_t            rc;

    if (!brix_sd_stage_instance_is(inst) || key == NULL) {
        return NGX_DECLINED;
    }
    is = inst->state;
    rc = brix_stage_run_inline_cred(BRIX_STAGE_FLUSH, is->store, key, is->source,
                                     key, cred);
    if (rc == NGX_OK && is->store->driver->unlink != NULL) {
        (void) is->store->driver->unlink(is->store, key, 0);   /* drop stage copy */
    }
    return rc;
}
