/*
 * sd_stage_write.c - the two interposed WRITE paths of the write-stage decorator
 * (section 12.2). Split from sd_stage.c (phase-79) to hold each half under the
 * file-size cap; see sd_stage.h for the decorator contract and sd_stage_internal.h
 * for the shared seam.
 *
 * WHAT: Implements the only paths the stage decorator interposes on:
 *         - the write-BACK object (Option A): a random-access write open lands on
 *           the stage store as a normal writable object; pwrite buffers there and
 *           fsync/close flush the whole object to the backend; and
 *         - the staged-upload path (HTTP PUT): a staged slot lands on the stage
 *           store and is FLUSHed to the backend on commit.
 *       Both flush through the one staging engine (brix_stage_run_inline_cred /
 *       brix_stage_submit FLUSH). A posix stage store is byte-equivalent to
 *       phase-63's local-temp promote.
 * WHY:  Keeping both write paths together isolates the ONLY interposed logic from
 *       the decorator core (forwarders + dispatch + driver table + lifecycle in
 *       sd_stage.c), so each file owns one concept and stays under 500 lines. The
 *       write-back path lets root:// kXR_write reuse the SAME stage mechanism as
 *       the staged (HTTP PUT) path.
 * HOW:  The open dispatch in sd_stage.c calls sd_stage_open_writeback here for
 *       write opens; the driver table in sd_stage.c routes byte-I/O and staged
 *       ops to the methods below. Each captured cred records the owner identity at
 *       open time so a deferred or async flush authenticates as the original user.
 */
#include "sd_stage.h"
#include "sd_stage_internal.h"
#include "fs/xfer/stage_engine.h"   /* brix_stage_run_inline / _submit (FLUSH) */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

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

/* Record the caller's per-user identity into a durable stage cred slot.
 *
 * WHAT: Copies key/principal/cred_dir/fallback_deny from an optional
 *       brix_sd_cred_t into `dst` (a brix_stage_cred_t embedded in the durable
 *       write-back or staged state). A NULL or empty-key cred leaves `dst`
 *       untouched (zeroed = service-credential path).
 *
 * WHY:  Both the write-back open and the staged open must capture the owner
 *       identity NOW, while the request context is live, so a deferred or async
 *       flush can authenticate to the backend as the original user rather than
 *       the service account. Sharing one copier keeps the two capture sites
 *       byte-identical and keeps each caller's branch count in check.
 *
 * HOW:  1. Return immediately unless cred is non-NULL with a non-empty key.
 *       2. ngx_cpystrn key; principal/dir default to "" when their source
 *          pointer is NULL. 3. Narrow fallback_deny into dst->deny. */
static void
sd_stage_record_cred(brix_stage_cred_t *dst, const brix_sd_cred_t *cred)
{
    if (cred == NULL || cred->key == NULL || cred->key[0] == '\0') {
        return;
    }
    ngx_cpystrn((u_char *) dst->key, (u_char *) cred->key, sizeof(dst->key));
    ngx_cpystrn((u_char *) dst->principal,
                (u_char *) (cred->principal ? cred->principal : ""),
                sizeof(dst->principal));
    ngx_cpystrn((u_char *) dst->dir,
                (u_char *) (cred->cred_dir ? cred->cred_dir : ""),
                sizeof(dst->dir));
    dst->deny = (uint8_t) cred->fallback_deny;
}

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
brix_sd_obj_t *
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
    sd_stage_record_cred(&wb->cred, cred);

    obj->driver     = &brix_sd_stage_driver;   /* → the write-back methods below */
    obj->inst       = inst;
    obj->fd         = wb->store_obj.fd;          /* expose the stage fd (posix sendfile) */
    obj->snap       = wb->store_obj.snap;
    obj->state      = wb;
    obj->heap_shell = 1;                         /* malloc'd shell; caller frees post-copy */
    return obj;
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

ssize_t
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

ssize_t
sd_stage_wb_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_stage_wb_state *wb = obj->state;
    return wb->store_obj.driver->pread
         ? wb->store_obj.driver->pread(&wb->store_obj, buf, len, off) : -1;
}

ngx_int_t
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

ngx_int_t
sd_stage_wb_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    sd_stage_wb_state *wb = obj->state;
    return wb->store_obj.driver->fstat
         ? wb->store_obj.driver->fstat(&wb->store_obj, out) : NGX_ERROR;
}

ngx_int_t
sd_stage_wb_fsync(brix_sd_obj_t *obj)
{
    return sd_stage_wb_flush(obj->state);
}

ngx_int_t
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

/* ---- the staged-upload path (the only interposed HTTP-PUT path) ------------ */

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
    sd_stage_record_cred(&ss->cred, cred);

    h->inst  = inst;
    h->state = ss;
    return h;
}

brix_sd_staged_t *
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
brix_sd_staged_t *
sd_stage_staged_open_cred(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    sd_stage_inst_state *is = inst->state;
    return sd_stage_staged_open_inner(inst, is, final_path, mode, cred, err_out);
}

ssize_t
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
ngx_int_t
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

void
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
