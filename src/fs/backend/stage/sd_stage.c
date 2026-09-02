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

/* sd_stage_store_mkparents — create `key`'s parent chain inside the stage STORE.
 *
 * WHAT: EEXIST-tolerant prefix walk calling the store driver's mkdir slot for
 *       every directory component before the key's last '/'.
 * WHY:  The stage store is a PRIVATE spool, not a client-visible namespace: a
 *       client mkdir (or the kXR_mkpath/kXR_async pre-create) builds the chain in
 *       the EXPORT, never in the spool, so the store's create-open of a nested key
 *       failed ENOENT — with a stage tier configured, a write to ANY subdirectory
 *       was impossible. The staged (whole-object) leg never hit this because the
 *       POSIX store's staged_open mkpaths its own parents; this is that same rule
 *       for the write-back leg.
 * HOW:  Copies the parent prefix and mkdirs each component in turn with mode 0700
 *       (service-owned spool), tolerating EEXIST. A flat key, or a store with no
 *       mkdir slot, is NGX_OK — the open then decides, exactly as before. */
static ngx_int_t
sd_stage_store_mkparents(sd_stage_inst_state *is, const char *key)
{
    char        acc[PATH_MAX];
    const char *last = strrchr(key, '/');
    size_t      plen, j;

    if (last == NULL || last == key || is->store->driver->mkdir == NULL) {
        return NGX_OK;
    }

    plen = (size_t) (last - key);
    if (plen >= sizeof(acc)) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    memcpy(acc, key, plen);
    acc[plen] = '\0';

    for (j = 1; j <= plen; j++) {
        char sep = acc[j];

        if (sep != '/' && sep != '\0') {
            continue;
        }
        acc[j] = '\0';
        if (is->store->driver->mkdir(is->store, acc, 0700) != NGX_OK
            && errno != EEXIST)
        {
            return NGX_ERROR;
        }
        acc[j] = sep;
    }
    return NGX_OK;
}

/* ---- open dispatch -------------------------------------------------------- */

/* The one write-open entry both open slots share: build the spool-side parent
 * chain for a creating open, then hand off to the write-back open. Only a CREATE
 * may materialise a new key, so a plain update open never mkdirs. */
static brix_sd_obj_t *
sd_stage_open_write(brix_sd_instance_t *inst, sd_stage_inst_state *is,
    const char *path, int sd_flags, mode_t mode, const brix_sd_cred_t *cred,
    int *err_out)
{
    if ((sd_flags & BRIX_SD_O_CREATE)
        && sd_stage_store_mkparents(is, path) != NGX_OK)
    {
        if (err_out != NULL) { *err_out = errno ? errno : EIO; }
        return NULL;
    }
    return sd_stage_open_writeback(inst, is, path, sd_flags, mode, cred,
                                    err_out);
}

static brix_sd_obj_t *
sd_stage_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_stage_inst_state *is = inst->state;

    /* Write open → a write-back object on the stage store (pwrite buffers, fsync/close
     * flush to the backend). Read open → the source's own object, so read byte-I/O
     * bypasses the decorator entirely. */
    if (sd_flags & BRIX_SD_O_WRITE) {
        return sd_stage_open_write(inst, is, path, sd_flags, mode, NULL,
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
 * HOW:  Write → sd_stage_open_write(... cred); read →
 *       brix_sd_open_maybe_cred(source, ..., cred). */
static brix_sd_obj_t *
sd_stage_open_cred(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    sd_stage_inst_state *is = inst->state;

    if (sd_flags & BRIX_SD_O_WRITE) {
        return sd_stage_open_write(inst, is, path, sd_flags, mode, cred,
                                    err_out);
    }
    return brix_sd_open_maybe_cred(is->source, path, sd_flags, mode, cred,
                                    err_out);
}

/* ---- namespace / xattr / dir forwarders (delegate to the source) ----------
 *
 * Each op appears twice: a plain slot and its credential-scoped twin, both
 * landing on brix_sd_<op>_maybe_cred against the SOURCE (cred=NULL for the
 * plain one, which is exactly the pre-existing behaviour). The twins are not
 * optional politeness: brix_sd_<op>_maybe_cred keys off the instance it is
 * CALLED on, so a decorator publishing `.mkdir` and no `.mkdir_cred` looks
 * from above like a driver with no per-user support, whatever the source can
 * actually do. That is why every VFS namespace site unwraps to the LEAF today
 * (brix_vfs_ns_leaf) — a bypass that also skips this decorator's own work, so
 * each bypassing site has to re-add the cache eviction by hand. See the same
 * block in sd_cache_forward.c. ENOTSUP is preserved where the pre-split code
 * reported it: for the xattr ops it means "no extended attributes here". */

static ngx_int_t
sd_stage_stat(brix_sd_instance_t *inst, const char *path, brix_sd_stat_t *out)
{
    return brix_sd_stat_maybe_cred(SD_STAGE_SRC(inst), path, out, NULL);
}

static ngx_int_t
sd_stage_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    return brix_sd_stat_maybe_cred(SD_STAGE_SRC(inst), path, out, cred);
}

static ngx_int_t
sd_stage_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    return brix_sd_unlink_maybe_cred(SD_STAGE_SRC(inst), path, is_dir, NULL);
}

static ngx_int_t
sd_stage_unlink_cred(brix_sd_instance_t *inst, const char *path, int is_dir,
    const brix_sd_cred_t *cred)
{
    return brix_sd_unlink_maybe_cred(SD_STAGE_SRC(inst), path, is_dir, cred);
}

static ngx_int_t
sd_stage_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    return brix_sd_mkdir_maybe_cred(SD_STAGE_SRC(inst), path, mode, NULL);
}

static ngx_int_t
sd_stage_mkdir_cred(brix_sd_instance_t *inst, const char *path, mode_t mode,
    const brix_sd_cred_t *cred)
{
    return brix_sd_mkdir_maybe_cred(SD_STAGE_SRC(inst), path, mode, cred);
}

static ngx_int_t
sd_stage_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    return brix_sd_rename_maybe_cred(SD_STAGE_SRC(inst), src, dst, noreplace,
                                     NULL);
}

static ngx_int_t
sd_stage_rename_cred(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace, const brix_sd_cred_t *cred)
{
    return brix_sd_rename_maybe_cred(SD_STAGE_SRC(inst), src, dst, noreplace,
                                     cred);
}

/* Phase-107 C3: the write-back store keeps no namespace of its own — the
 * publish the barrier protects happened in the SOURCE, so the flush belongs
 * there too. A source without the slot has nothing local to flush (NGX_OK,
 * mirroring the NULL-slot contract the VFS applies to a bare leaf). */
static ngx_int_t
sd_stage_sync_publish(brix_sd_instance_t *inst, const char *path)
{
    brix_sd_instance_t *src = SD_STAGE_SRC(inst);

    return (src->driver->sync_publish != NULL)
         ? src->driver->sync_publish(src, path) : NGX_OK;
}

static ngx_int_t
sd_stage_server_copy(brix_sd_instance_t *inst, const char *src, const char *dst,
    off_t *bytes_out)
{
    return brix_sd_server_copy_maybe_cred(SD_STAGE_SRC(inst), src, dst,
                                          bytes_out, NULL);
}

static ngx_int_t
sd_stage_server_copy_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, const brix_sd_cred_t *cred)
{
    return brix_sd_server_copy_maybe_cred(SD_STAGE_SRC(inst), src, dst,
                                          bytes_out, cred);
}

static ngx_int_t
sd_stage_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr)
{
    return brix_sd_setattr_maybe_cred(SD_STAGE_SRC(inst), path, attr, NULL);
}

static ngx_int_t
sd_stage_setattr_cred(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr, const brix_sd_cred_t *cred)
{
    return brix_sd_setattr_maybe_cred(SD_STAGE_SRC(inst), path, attr, cred);
}

/* The truncate-path and exchange relays live in sd_stage_write.c — this file
 * sits at the 600-line cap (phase-107 C6 displacement); protos in
 * sd_stage_internal.h. */

/* Phase-107 C4: the batch relays straight to the source (mirrors
 * sd_stage_unlink — the stage tier keeps no per-path state to drop here);
 * ENOTSUP without a source slot pair, so the VFS chunker keeps its per-key
 * walk instead of the decorator inventing a loop. */
static ngx_int_t
sd_stage_unlink_many(brix_sd_instance_t *inst, brix_sd_unlink_batch_t *b)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    if (s->driver->unlink_many == NULL && s->driver->unlink_many_cred == NULL) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    return brix_sd_unlink_many_maybe_cred(s, b, NULL);
}

static ngx_int_t
sd_stage_unlink_many_cred(brix_sd_instance_t *inst, brix_sd_unlink_batch_t *b,
    const brix_sd_cred_t *cred)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    if (s->driver->unlink_many == NULL && s->driver->unlink_many_cred == NULL) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    return brix_sd_unlink_many_maybe_cred(s, b, cred);
}

/* dir->inst is the SOURCE either way, so readdir/closedir need no cred twin. */
static brix_sd_dir_t *
sd_stage_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    return brix_sd_opendir_maybe_cred(SD_STAGE_SRC(inst), path, err_out, NULL);
}

static brix_sd_dir_t *
sd_stage_opendir_cred(brix_sd_instance_t *inst, const char *path, int *err_out,
    const brix_sd_cred_t *cred)
{
    return brix_sd_opendir_maybe_cred(SD_STAGE_SRC(inst), path, err_out, cred);
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

/* Both slot pairs absent → the source has no extended attributes at all, which
 * callers read off ENOTSUP rather than the forwarder's less specific ENOSYS. */
static ngx_int_t
sd_stage_src_no_xattr(const brix_sd_instance_t *s, int write_side)
{
    if (write_side) {
        return s->driver->setxattr == NULL && s->driver->setxattr_cred == NULL
            && s->driver->removexattr == NULL
            && s->driver->removexattr_cred == NULL;
    }
    return s->driver->getxattr == NULL && s->driver->getxattr_cred == NULL
        && s->driver->listxattr == NULL && s->driver->listxattr_cred == NULL;
}

static ssize_t
sd_stage_getxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    if (sd_stage_src_no_xattr(s, 0)) { errno = ENOTSUP; return -1; }
    return brix_sd_getxattr_maybe_cred(s, path, name, buf, cap, cred);
}

static ssize_t
sd_stage_getxattr(brix_sd_instance_t *inst, const char *path, const char *name,
    void *buf, size_t cap)
{
    return sd_stage_getxattr_cred(inst, path, name, buf, cap, NULL);
}

static ssize_t
sd_stage_listxattr_cred(brix_sd_instance_t *inst, const char *path, void *buf,
    size_t cap, const brix_sd_cred_t *cred)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    if (sd_stage_src_no_xattr(s, 0)) { errno = ENOTSUP; return -1; }
    return brix_sd_listxattr_maybe_cred(s, path, buf, cap, cred);
}

static ssize_t
sd_stage_listxattr(brix_sd_instance_t *inst, const char *path, void *buf,
    size_t cap)
{
    return sd_stage_listxattr_cred(inst, path, buf, cap, NULL);
}

static ngx_int_t
sd_stage_setxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags,
    const brix_sd_cred_t *cred)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    if (sd_stage_src_no_xattr(s, 1)) { errno = ENOTSUP; return NGX_ERROR; }
    return brix_sd_setxattr_maybe_cred(s, path, name, val, len, flags, cred);
}

static ngx_int_t
sd_stage_setxattr(brix_sd_instance_t *inst, const char *path, const char *name,
    const void *val, size_t len, int flags)
{
    return sd_stage_setxattr_cred(inst, path, name, val, len, flags, NULL);
}

static ngx_int_t
sd_stage_removexattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const brix_sd_cred_t *cred)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    if (sd_stage_src_no_xattr(s, 1)) { errno = ENOTSUP; return NGX_ERROR; }
    return brix_sd_removexattr_maybe_cred(s, path, name, cred);
}

static ngx_int_t
sd_stage_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    return sd_stage_removexattr_cred(inst, path, name, NULL);
}

/* Capacity belongs to the wrapped source (the stage store is a private spool),
 * so statvfs/Qspace/QFSinfo/SRR report the source's numbers, not the spool's. */
static ngx_int_t
sd_stage_space(brix_sd_instance_t *inst, brix_sd_space_t *out)
{
    brix_sd_instance_t *s = SD_STAGE_SRC(inst);
    if (s->driver->space == NULL) { errno = ENOTSUP; return NGX_ERROR; }
    return s->driver->space(s, out);
}

/* ---- driver descriptor ---------------------------------------------------- */

/* The decorator advertises the writable-remote slot set; read byte-I/O is never
 * reached here (open returns source objects). The write-back and staged methods
 * live in sd_stage_write.c (declared in sd_stage_internal.h). CAP_DIRS[_WRITE]
 * are advertised (as on the cache decorator) so the namespace-mutation gate in
 * vfs_{mkdir,rename,unlink} passes and defers the actual op to the wrapped leaf
 * (which enforces its real capability — ENOTSUP/EPERM if it lacks one). */
const brix_sd_driver_t brix_sd_stage_driver = {
    .name        = "stage",
    .caps        = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_RANDOM_WRITE
                 | BRIX_SD_CAP_TRUNCATE | BRIX_SD_CAP_XATTR
                 | BRIX_SD_CAP_XATTR_WRITE
                 | BRIX_SD_CAP_HARD_RENAME | BRIX_SD_CAP_SERVER_COPY
                 | BRIX_SD_CAP_DIRS | BRIX_SD_CAP_DIRS_WRITE,
    .open        = sd_stage_open,
    .open_cred   = sd_stage_open_cred,
    /* write-back byte-I/O (only dispatched for objects opened for write — a read
     * open returns the source's own object with the source driver). */
    .pread       = sd_stage_wb_pread,
    .pwrite      = sd_stage_wb_pwrite,
    .ftruncate   = sd_stage_wb_ftruncate,
    .reserve     = sd_stage_wb_reserve,   /* phase-107 C5 spool relay */
    .fstat       = sd_stage_wb_fstat,
    .fsync       = sd_stage_wb_fsync,
    .close       = sd_stage_wb_close,
    .stat        = sd_stage_stat,
    .unlink      = sd_stage_unlink,
    .unlink_many = sd_stage_unlink_many,
    .mkdir       = sd_stage_mkdir,
    .rename      = sd_stage_rename,
    .server_copy = sd_stage_server_copy,
    .setattr     = sd_stage_setattr,
    .space       = sd_stage_space,
    .truncate_path = sd_stage_truncate_path,
    .exchange      = sd_stage_exchange,      /* C6 relay: source or ENOTSUP */
    .evict         = sd_stage_evict,         /* C2: EBUSY when dirty, else relay */
    .sync_publish  = sd_stage_sync_publish,   /* phase-107 C3 relay */
    .opendir     = sd_stage_opendir,
    .readdir     = sd_stage_readdir,
    .closedir    = sd_stage_closedir,
    .getxattr    = sd_stage_getxattr,
    .listxattr   = sd_stage_listxattr,
    .setxattr    = sd_stage_setxattr,
    .removexattr = sd_stage_removexattr,
    /* Credential-scoped twins — a decorator that omits them erases the caller's
     * credential for every path op behind it (see the forwarder block above). */
    .stat_cred          = sd_stage_stat_cred,
    .unlink_cred        = sd_stage_unlink_cred,
    .unlink_many_cred   = sd_stage_unlink_many_cred,
    .mkdir_cred         = sd_stage_mkdir_cred,
    .rename_cred        = sd_stage_rename_cred,
    .server_copy_cred   = sd_stage_server_copy_cred,
    .setattr_cred       = sd_stage_setattr_cred,
    .truncate_path_cred = sd_stage_truncate_path_cred,
    .exchange_cred      = sd_stage_exchange_cred,
    .evict_cred         = sd_stage_evict_cred,
    .opendir_cred       = sd_stage_opendir_cred,
    .getxattr_cred      = sd_stage_getxattr_cred,
    .listxattr_cred     = sd_stage_listxattr_cred,
    .setxattr_cred      = sd_stage_setxattr_cred,
    .removexattr_cred   = sd_stage_removexattr_cred,
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
    inst->domain = BRIX_VFS_DOMAIN_EXPORT;   /* the decorator FRONTS the export;
                                              * only its store is DOMAIN_STAGE (C9) */
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
