/*
 * sd_stage.c - the generic write-stage decorator (section 12.2). See header.
 *
 * The decorator forwards every read / namespace / xattr / dir op to the wrapped
 * `source` (open returns the source's own object, so read byte-I/O bypasses the
 * decorator) and implements only the staged-write path: a staged upload lands on
 * the STAGE STORE (`store`) and is flushed to the source on commit through the one
 * staging engine (brix_stage_run_inline FLUSH). A posix stage store is
 * byte-equivalent to phase-63's local-temp promote.
 */
#include "sd_stage.h"
#include "fs/xfer/stage_engine.h"   /* brix_stage_run_inline (FLUSH) */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    brix_sd_instance_t  *source;     /* the backend (flush target)            */
    brix_sd_instance_t  *store;      /* the stage buffer (any driver)         */
    brix_stage_policy_t  policy;
    char                   root_canon[PATH_MAX]; /* export anchor for SP4 reconcile */
    ngx_log_t             *log;
} sd_stage_inst_state;

/* Staged-write object state: an upload lands on the stage store and is flushed
 * to the backend on commit.  `cred` records the owner identity so a deferred or
 * async flush can authenticate as the original user rather than the service account. */
typedef struct {
    sd_stage_inst_state  *is;          /* back-ref: source / store / policy     */
    char                  key[PATH_MAX];   /* export-relative final key         */
    brix_sd_staged_t   *inner;       /* the stage store's staged handle       */
    brix_stage_cred_t    cred;        /* per-user identity (zeroed = service)  */
} sd_stage_staged_state;

/* Write-BACK object state (Option A / §12.2): a random-access write open lands on
 * the STAGE STORE as a normal writable object; pwrite buffers there, and fsync/close
 * flush the whole object to the backend through the one staging engine. This lets
 * root:// kXR_write (direct pwrite at arbitrary offsets) use the SAME stage mechanism
 * as the staged (HTTP PUT) path, so writethrough_flush's bespoke loop is retired.
 * `cred` records the owner identity at open time so the flush can authenticate as
 * the original user even if the flush runs on a background thread or after a restart. */
typedef struct {
    sd_stage_inst_state  *is;              /* back-ref: source / store / policy   */
    char                  key[PATH_MAX];   /* export-relative object key          */
    brix_sd_obj_t       store_obj;       /* the writable stage-store object     */
    off_t                 high_water;      /* max offset+len written (flush size) */
    unsigned              dirty:1;         /* written since the last flush        */
    brix_stage_cred_t    cred;            /* per-user identity (zeroed = service) */
} sd_stage_wb_state;

#define SD_STAGE_SRC(inst)  (((sd_stage_inst_state *) (inst)->state)->source)

static const brix_sd_driver_t brix_sd_stage_driver;   /* fwd: write-back objs carry it */

/* ---- namespace / xattr / dir forwarders (delegate to the source) ---------- */

/* Open the write-BACK object on the stage store (a normal writable object).
 *
 * WHAT: Opens a writable object on the stage store and wires a sd_stage_wb_state
 *       that carries the owner identity for the eventual flush.
 *
 * WHY:  The returned obj carries the stage driver so its pwrite/pread/fsync/close
 *       dispatch to the write-back methods below; the stage-store object is held
 *       BY VALUE so the handle is self-contained.  Recording the caller's cred
 *       in wb->cred ensures sd_stage_wb_flush can authenticate to the backend
 *       as the original user rather than the service account.
 *
 * HOW:  Opens the stage STORE (always local) with a plain open — the store is
 *       service-owned.  Copies key/principal/cred_dir/fallback_deny from `cred`
 *       into wb->cred when cred is non-NULL and cred->key is non-empty;
 *       otherwise wb->cred stays zeroed (service-credential path). */
static brix_sd_obj_t *
sd_stage_open_writeback(brix_sd_instance_t *inst, sd_stage_inst_state *is,
    const char *path, int sd_flags, mode_t mode,
    const brix_sd_cred_t *cred, int *err_out)
{
    brix_sd_obj_t   *store_obj;
    brix_sd_obj_t   *obj;
    sd_stage_wb_state *wb;
    int                e = 0;

    if (is->store->driver->open == NULL || is->store->driver->pwrite == NULL) {
        if (err_out != NULL) { *err_out = ENOSYS; }
        return NULL;
    }
    /* The stage store is service-owned (local POSIX); always open it plain. */
    store_obj = is->store->driver->open(is->store, path, sd_flags, mode, &e);
    if (store_obj == NULL) {
        if (err_out != NULL) { *err_out = e; }
        return NULL;
    }

    obj = calloc(1, sizeof(*obj));
    wb  = calloc(1, sizeof(*wb));
    if (obj == NULL || wb == NULL) {
        if (store_obj->driver->close != NULL) { store_obj->driver->close(store_obj); }
        if (store_obj->heap_shell) { free(store_obj); }
        free(obj);
        free(wb);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    wb->is         = is;
    wb->high_water = 0;
    wb->dirty      = 0;
    ngx_cpystrn((u_char *) wb->key, (u_char *) path, sizeof(wb->key));
    wb->store_obj  = *store_obj;                 /* adopt by value */
    if (store_obj->heap_shell) { free(store_obj); }
    wb->store_obj.heap_shell = 0;

    /* Record the owner identity for the flush; zeroed cred = service account. */
    if (cred != NULL && cred->key != NULL && cred->key[0] != '\0') {
        ngx_cpystrn((u_char *) wb->cred.key, (u_char *) cred->key,
                    sizeof(wb->cred.key));
        ngx_cpystrn((u_char *) wb->cred.principal,
                    (u_char *) (cred->principal ? cred->principal : ""),
                    sizeof(wb->cred.principal));
        ngx_cpystrn((u_char *) wb->cred.dir,
                    (u_char *) (cred->cred_dir ? cred->cred_dir : ""),
                    sizeof(wb->cred.dir));
        wb->cred.deny = (uint8_t) cred->fallback_deny;
    }

    obj->driver     = &brix_sd_stage_driver;   /* → the write-back methods below */
    obj->inst       = inst;
    obj->fd         = wb->store_obj.fd;          /* expose the stage fd (posix sendfile) */
    obj->snap       = wb->store_obj.snap;
    obj->state      = wb;
    obj->heap_shell = 1;                         /* malloc'd shell; caller frees post-copy */
    return obj;
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

/* ---- write-back byte-I/O (only reached for objects opened for write above) ------ */

/* Flush the buffered stage object to the backend through the one staging engine.
 * Persists the stage buffer first (fsync), then FLUSHes store→source by key. On
 * success clears the dirty flag; on failure keeps the stage copy for retry. */
static ngx_int_t
sd_stage_wb_flush(sd_stage_wb_state *wb)
{
    sd_stage_inst_state *is = wb->is;
    ngx_int_t            rc;

    if (wb->store_obj.driver->fsync != NULL) {
        (void) wb->store_obj.driver->fsync(&wb->store_obj);
    }
    if (!wb->dirty) {
        return NGX_OK;
    }
    rc = brix_stage_run_inline_cred(BRIX_STAGE_FLUSH, is->store, wb->key,
                                     is->source, wb->key,
                                     (wb->cred.key[0] != '\0') ? &wb->cred : NULL);
    if (rc == NGX_OK) {
        wb->dirty = 0;
    }
    return rc;
}

static ssize_t
sd_stage_wb_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    sd_stage_wb_state *wb = obj->state;
    ssize_t            n  = wb->store_obj.driver->pwrite(&wb->store_obj, buf, len, off);

    if (n > 0) {
        wb->dirty = 1;
        if (off + (off_t) n > wb->high_water) {
            wb->high_water = off + (off_t) n;
        }
    }
    return n;
}

static ssize_t
sd_stage_wb_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_stage_wb_state *wb = obj->state;
    return wb->store_obj.driver->pread
         ? wb->store_obj.driver->pread(&wb->store_obj, buf, len, off) : -1;
}

static ngx_int_t
sd_stage_wb_ftruncate(brix_sd_obj_t *obj, off_t length)
{
    sd_stage_wb_state *wb = obj->state;
    ngx_int_t          rc;

    if (wb->store_obj.driver->ftruncate == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
    rc = wb->store_obj.driver->ftruncate(&wb->store_obj, length);
    if (rc == NGX_OK) {
        wb->dirty      = 1;
        wb->high_water = length;
    }
    return rc;
}

static ngx_int_t
sd_stage_wb_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    sd_stage_wb_state *wb = obj->state;
    return wb->store_obj.driver->fstat
         ? wb->store_obj.driver->fstat(&wb->store_obj, out) : NGX_ERROR;
}

static ngx_int_t
sd_stage_wb_fsync(brix_sd_obj_t *obj)
{
    return sd_stage_wb_flush(obj->state);
}

static ngx_int_t
sd_stage_wb_close(brix_sd_obj_t *obj)
{
    sd_stage_wb_state *wb = obj->state;
    ngx_int_t          rc = NGX_OK;

    if (wb->dirty) {
        rc = sd_stage_wb_flush(wb);          /* final flush if not already synced */
    }
    if (wb->store_obj.driver->close != NULL) {
        (void) wb->store_obj.driver->close(&wb->store_obj);
    }
    free(wb);
    return rc;
}

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

/* ---- the write-stage path (the only interposed path) ---------------------- */

/* Common staged_open body shared by sd_stage_staged_open and
 * sd_stage_staged_open_cred.
 *
 * WHAT: Opens a staged upload slot on the STORE (local — always plain) and
 *       records the optional per-user cred in ss->cred for the commit-time flush.
 *
 * WHY:  The store is service-owned so its staged_open is always plain; the
 *       credential is only needed at flush time (store→source) and must be
 *       captured now while the request context is still live.
 *
 * HOW:  Allocate ss + h, wire them, copy cred when key is non-empty. */
static brix_sd_staged_t *
sd_stage_staged_open_inner(brix_sd_instance_t *inst, sd_stage_inst_state *is,
    const char *final_path, mode_t mode,
    const brix_sd_cred_t *cred, int *err_out)
{
    sd_stage_staged_state *ss;
    brix_sd_staged_t    *h;
    brix_sd_staged_t    *inner;
    int                    err = 0;

    if (is->store->driver->staged_open == NULL) {
        if (err_out != NULL) { *err_out = ENOSYS; }
        return NULL;
    }
    inner = is->store->driver->staged_open(is->store, final_path, mode, &err);
    if (inner == NULL) {
        if (err_out != NULL) { *err_out = err ? err : EIO; }
        return NULL;
    }
    ss = calloc(1, sizeof(*ss));
    h  = calloc(1, sizeof(*h));
    if (ss == NULL || h == NULL) {
        if (is->store->driver->staged_abort != NULL) {
            is->store->driver->staged_abort(inner);
        }
        free(ss);
        free(h);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }
    ss->is    = is;
    ss->inner = inner;
    ngx_cpystrn((u_char *) ss->key, (u_char *) final_path, sizeof(ss->key));

    /* Record the owner identity for the flush; zeroed cred = service account. */
    if (cred != NULL && cred->key != NULL && cred->key[0] != '\0') {
        ngx_cpystrn((u_char *) ss->cred.key, (u_char *) cred->key,
                    sizeof(ss->cred.key));
        ngx_cpystrn((u_char *) ss->cred.principal,
                    (u_char *) (cred->principal ? cred->principal : ""),
                    sizeof(ss->cred.principal));
        ngx_cpystrn((u_char *) ss->cred.dir,
                    (u_char *) (cred->cred_dir ? cred->cred_dir : ""),
                    sizeof(ss->cred.dir));
        ss->cred.deny = (uint8_t) cred->fallback_deny;
    }

    h->inst  = inst;
    h->state = ss;
    return h;
}

static brix_sd_staged_t *
sd_stage_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    sd_stage_inst_state *is = inst->state;
    return sd_stage_staged_open_inner(inst, is, final_path, mode, NULL, err_out);
}

/* Credential-scoped staged_open: records the owner identity so the commit-time
 * flush can authenticate as the original user.
 *
 * WHAT: Delegates to sd_stage_staged_open_inner with the caller's cred.
 *
 * WHY:  Without this slot a caller using brix_sd_staged_open_maybe_cred against
 *       the stage decorator would lose the credential — the plain staged_open
 *       slot receives no cred parameter.
 *
 * HOW:  sd_stage_staged_open_inner copies key/principal/cred_dir/deny into
 *       ss->cred; sd_stage_staged_commit then passes &ss->cred to the flush. */
static brix_sd_staged_t *
sd_stage_staged_open_cred(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    sd_stage_inst_state *is = inst->state;
    return sd_stage_staged_open_inner(inst, is, final_path, mode, cred, err_out);
}

static ssize_t
sd_stage_staged_write(brix_sd_staged_t *st, const void *buf, size_t len,
    off_t off)
{
    sd_stage_staged_state *ss = st->state;
    brix_sd_staged_t    *inner = ss->inner;

    return inner->inst->driver->staged_write
         ? inner->inst->driver->staged_write(inner, buf, len, off) : -1;
}

/* Publish the buffered object on the stage store, then FLUSH it to the backend
 * through the one staging engine. On a successful flush the stage buffer copy is
 * dropped; on a failed flush it is KEPT (durability preserved for retry, section
 * 16). Consumes the handle. */
static ngx_int_t
sd_stage_staged_commit(brix_sd_staged_t *st, int noreplace)
{
    sd_stage_staged_state *ss = st->state;
    sd_stage_inst_state   *is = ss->is;
    brix_sd_instance_t  *store = is->store;
    brix_sd_instance_t  *source = is->source;
    ngx_int_t              rc;

    /* 1. publish the buffered object on the stage store. */
    if (store->driver->staged_commit(ss->inner, noreplace) != NGX_OK) {
        int e = errno;
        if (store->driver->staged_abort != NULL) {
            store->driver->staged_abort(ss->inner);
        }
        free(ss);
        free(st);
        errno = e ? e : EIO;
        return NGX_ERROR;
    }
    /* ss->inner is consumed by the commit above. */

    /* 2a. ASYNC write-back (SP4): the object is durable on the stage store now, so
     * the commit succeeds immediately; the scheduler flushes it to the backend and
     * drops the stage copy on completion. The export anchor rides on the durable
     * record so a restart-reconcile can rebuild both tiers and re-flush (§11.3).
     * The owner cred is embedded in the opts so the scheduler can authenticate as
     * the original user when it drains the queue (non-NULL only when a key was
     * recorded at staged_open time). */
    if (is->policy.flush_mode == BRIX_WT_MODE_ASYNC) {
        brix_stage_opts_t o;

        ngx_memzero(&o, sizeof(o));
        o.async       = 1;
        o.export_root = (is->root_canon[0] != '\0') ? is->root_canon : NULL;
        o.cred        = (ss->cred.key[0] != '\0') ? &ss->cred : NULL;
        /* phase74-fp: argument order verified against brix_stage_submit(kind,
         * src, src_key, dst, dst_key, opts) — a FLUSH moves bytes FROM the
         * stage `store` TO the backend instance (locally named `source`), so
         * store is the src and source the dst; the name swap is deliberate. */
        (void) brix_stage_submit(BRIX_STAGE_FLUSH, store, ss->key, source,  /* NOLINT(readability-suspicious-call-argument) */
                                   ss->key, &o);
        free(ss);
        free(st);
        return NGX_OK;
    }

    /* 2b. SYNC write-back: flush inline and reflect the result, threading the
     * owner cred so the backend driver uses the per-user proxy rather than the
     * service credential. */
    /* phase74-fp: same verified src/dst order as the async submit above —
     * FLUSH reads from the stage store and writes to the backend `source`. */
    rc = brix_stage_run_inline_cred(BRIX_STAGE_FLUSH, store, ss->key, source,  /* NOLINT(readability-suspicious-call-argument) */
                                     ss->key,
                                     (ss->cred.key[0] != '\0') ? &ss->cred : NULL);

    /* 3. on success drop the stage buffer copy; on failure keep it for retry. */
    if (rc == NGX_OK && store->driver->unlink != NULL) {
        (void) store->driver->unlink(store, ss->key, 0);
    }

    free(ss);
    free(st);
    return rc;
}

static void
sd_stage_staged_abort(brix_sd_staged_t *st)
{
    sd_stage_staged_state *ss = st->state;
    sd_stage_inst_state   *is = ss->is;

    if (is->store->driver->staged_abort != NULL) {
        is->store->driver->staged_abort(ss->inner);
    }
    free(ss);
    free(st);
}

/* The decorator advertises the writable-remote slot set; read byte-I/O is never
 * reached here (open returns source objects). */
static const brix_sd_driver_t brix_sd_stage_driver = {
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
