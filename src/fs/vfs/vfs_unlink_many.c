/*
 * vfs_unlink_many.c — VFS bulk delete (phase-107 C4): the per-level rmtree
 * chunker and the flat client-batch entry brix_vfs_delete_many().
 *
 * WHAT: Two callers of the storage drivers' unlink_many/_cred batch slots:
 *       brix_vfs_rmtree_dispatch() routes a recursive driver delete either to
 *       the classic per-key walk (vfs_unlink.c) or, when the LEAF advertises
 *       BRIX_SD_CAP_BULK_DELETE, to a windowed walk that accumulates up to
 *       BRIX_SD_BULK_DELETE_WINDOW file keys and flushes them in one driver
 *       round trip; brix_vfs_delete_many() serves the S3 DeleteObjects
 *       handler's flat, client-supplied key list under ONE policy check and
 *       ONE metric observation for the whole batch.
 *
 * WHY:  A DeleteObjects of 1,000 keys over a remote backend was 1,000 signed
 *       HTTPS round trips whose entire purpose was to avoid exactly that. The
 *       tree walk may only batch WITHIN one directory level — a prefix cannot
 *       be removed before its children, and every registered driver except
 *       mirage advertises CAP_DIRS, so the per-level rule IS the rule. The one
 *       place a flat window is legitimate is brix_vfs_delete_many(), where the
 *       client itself supplied a flat key list and no tree walk is involved.
 *
 * HOW:  The window pre-fills every per-key errno slot with ECANCELED before a
 *       flush so a key the driver never reached can never be reported as
 *       deleted; the batch contract (sd_batch_types.h) has the slot overwrite
 *       exactly the leading `done` entries it attempted. The chunker gates on
 *       the LEAF's caps and dispatches through brix_sd_unlink_many_maybe_cred
 *       on the LEAF (the R-wave truncate_path lesson: gate and dispatch on the
 *       same instance, or a cache-fronted export loses the slot). Each flush
 *       books one brix_metric_vfs_bulk_delete() observation carrying the key
 *       count in the VALUE, never in a label (INVARIANT #8).
 */
#include "vfs_internal.h"
#include "fs/backend/cache/sd_cache.h"   /* brix_sd_cache_evict: leaf dispatch bypasses the decorator's own evict */
#include "core/compat/fs_walk.h"         /* BRIX_FS_TREE_MAX_DEPTH (shared recursion cap) */
#include "observability/metrics/unified.h" /* brix_metric_vfs_bulk_delete */

#include <stdlib.h>

/* The rmtree accumulation window: up to BRIX_SD_BULK_DELETE_WINDOW owned
 * (strdup'd) file keys plus their per-key result vector, bound to the leaf
 * instance + resolved credential so a flush needs no extra arguments. Heap-
 * allocated by the dispatcher (~12 KiB of pointers/ints — too large for the
 * worker stack next to the recursion it feeds). */
typedef struct {
    brix_sd_instance_t   *leaf;
    const brix_sd_cred_t *cred;
    const char           *paths[BRIX_SD_BULK_DELETE_WINDOW];
    int                   errs[BRIX_SD_BULK_DELETE_WINDOW];
    size_t                n;
} brix_vfs_unlink_window_t;

/* Release the window's owned key copies and empty it. */
static void
brix_vfs_unlink_window_reset(brix_vfs_unlink_window_t *w)
{
    size_t i;

    for (i = 0; i < w->n; i++) {
        free((void *) w->paths[i]);
    }
    w->n = 0;
}

/* Flush the accumulated window as ONE unlink_many batch on the leaf.
 *
 * WHAT: Pre-fills every result slot with ECANCELED, runs the batch through
 *       brix_sd_unlink_many_maybe_cred, books the per-batch metric, and turns
 *       the per-key results back into rmtree semantics: any per-key failure
 *       fails the walk with that key's errno (the classic walk aborts on the
 *       first failed unlink; a batch must not weaken that).
 * WHY:  ECANCELED pre-fill is the "never report an untried key as deleted"
 *       clause of the batch contract made concrete — a transport failure at
 *       key k leaves errs[k..n) exactly as we set them here.
 * HOW:  One metric observation per flush, key count (successes) as the value,
 *       leaf driver as the label. The window is emptied on every exit so the
 *       caller can keep accumulating or abort without leaking key copies. */
static ngx_int_t
brix_vfs_unlink_window_flush(brix_vfs_unlink_window_t *w)
{
    brix_sd_unlink_batch_t b;
    size_t                   i, attempted, removed = 0;
    ngx_int_t                rc;
    int                      saved;

    if (w->n == 0) {
        return NGX_OK;
    }

    for (i = 0; i < w->n; i++) {
        w->errs[i] = ECANCELED;
    }
    b.paths = w->paths;
    b.n     = w->n;
    b.errs  = w->errs;
    b.done  = 0;

    errno = 0;
    rc = brix_sd_unlink_many_maybe_cred(w->leaf, &b, w->cred);
    saved = errno;

    attempted = (rc == NGX_OK) ? w->n : b.done;
    for (i = 0; i < attempted; i++) {
        if (w->errs[i] == 0) {
            removed++;
        }
    }
    brix_metric_vfs_bulk_delete(brix_sd_backend_name(w->leaf), removed);

    if (rc == NGX_OK) {
        for (i = 0; i < w->n; i++) {
            if (w->errs[i] != 0) {
                saved = w->errs[i];
                rc = NGX_ERROR;
                break;
            }
        }
    }

    brix_vfs_unlink_window_reset(w);
    if (rc != NGX_OK) {
        errno = saved != 0 ? saved : EIO;
    }
    return rc;
}

/* Add one file key to the window, flushing first when it is full. The copy is
 * owned by the window (the walk's stack path buffer is reused per level). */
static ngx_int_t
brix_vfs_unlink_window_add(brix_vfs_unlink_window_t *w, const char *logical)
{
    char *copy;

    if (w->n == BRIX_SD_BULK_DELETE_WINDOW
        && brix_vfs_unlink_window_flush(w) != NGX_OK)
    {
        return NGX_ERROR;
    }

    copy = strdup(logical);
    if (copy == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    w->paths[w->n++] = copy;
    return NGX_OK;
}

/* brix_vfs_rmtree_bulk — the windowed twin of brix_vfs_driver_rmtree.
 *
 * WHAT: Depth-first walk of `logical`: a file joins the window (deleted at the
 *       next flush); a directory recurses over its children, then FLUSHES the
 *       window, then removes itself. Same stat/opendir/readdir dispatch and
 *       ELOOP depth bound as the classic walk.
 * WHY:  The flush-before-rmdir is the whole correctness content of C4's trap:
 *       a directory's accumulated child files must be gone before the
 *       directory itself, or an S3-appearing success leaves a half-removed
 *       tree on a backend with real collections. Sibling files of an inner
 *       directory may flush early inside its recursion — files are deletable
 *       any time before their OWN parent's boundary, so early is safe.
 * HOW:  stat decides file/dir per child (d_type is a hint, never authority —
 *       sd_remote_dir.c says so in as many words), matching what the classic
 *       walk pays; the saving is unlink round trips, not stats. */
static ngx_int_t
brix_vfs_rmtree_bulk(brix_sd_instance_t *leaf, const brix_sd_driver_t *drv,
    const char *logical, const brix_sd_cred_t *cred, ngx_uint_t depth,
    brix_vfs_unlink_window_t *w)
{
    brix_sd_stat_t st;

    if (depth > BRIX_FS_TREE_MAX_DEPTH) {
        errno = ELOOP;
        return NGX_ERROR;
    }
    if (brix_sd_stat_maybe_cred(leaf, logical, &st, cred) != NGX_OK) {
        return NGX_ERROR;            /* ENOENT etc. — errno set by the driver */
    }

    if (!st.is_dir) {
        return brix_vfs_unlink_window_add(w, logical);
    }

    if (drv->opendir != NULL) {
        brix_sd_dir_t *dir;
        int              err = 0;

        dir = brix_sd_opendir_maybe_cred(leaf, logical, &err, cred);
        if (dir != NULL) {
            brix_sd_dirent_t de;
            ngx_int_t          drc;

            while ((drc = drv->readdir(dir, &de)) == NGX_OK) {
                char child[PATH_MAX];

                ngx_snprintf((u_char *) child, sizeof(child), "%s/%s%Z",
                             (logical[0] == '/' && logical[1] == '\0')
                                 ? "" : logical,
                             de.name);
                if (brix_vfs_rmtree_bulk(leaf, drv, child, cred, depth + 1, w)
                    != NGX_OK)
                {
                    drv->closedir(dir);
                    return NGX_ERROR;
                }
            }
            drv->closedir(dir);
            if (drc == NGX_ERROR) {
                return NGX_ERROR;
            }
        }
    }

    /* Directory boundary: every accumulated child file must be gone before the
     * directory itself is removed. */
    if (brix_vfs_unlink_window_flush(w) != NGX_OK) {
        return NGX_ERROR;
    }
    return brix_sd_unlink_maybe_cred(leaf, logical, 1, cred);
}

/* brix_vfs_rmtree_dispatch — route a recursive driver delete to the windowed
 * walk (leaf advertises CAP_BULK_DELETE + a real unlink_many) or the classic
 * per-key walk. The gate probes the LEAF, exactly where the dispatch lands. */
ngx_int_t
brix_vfs_rmtree_dispatch(brix_sd_instance_t *leaf,
    const brix_sd_driver_t *drv, const char *logical,
    const brix_sd_cred_t *cred)
{
    brix_vfs_unlink_window_t *w;
    ngx_int_t                   rc;
    int                         saved;

    if (brix_sd_supports(leaf, BRIX_SD_CAP_BULK_DELETE) != NGX_OK
        || leaf->driver->unlink_many == NULL)
    {
        return brix_vfs_driver_rmtree(leaf, drv, logical, cred, 0);
    }

    w = calloc(1, sizeof(*w));
    if (w == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    w->leaf = leaf;
    w->cred = cred;

    rc = brix_vfs_rmtree_bulk(leaf, drv, logical, cred, 0, w);
    if (rc == NGX_OK) {
        rc = brix_vfs_unlink_window_flush(w);   /* top-level file case */
    }
    saved = errno;
    brix_vfs_unlink_window_reset(w);
    free(w);
    errno = saved;
    return rc;
}

/* POSIX arm of brix_vfs_delete_many: one confined brix_ns_delete per key with
 * unlink semantics (the same opts brix_vfs_unlink uses), per-key errno into
 * errs. The batch itself cannot fail here — rc is per key. */
static ngx_int_t
brix_vfs_delete_many_via_namespace(brix_vfs_ctx_t *ctx,
    const char *const *paths, size_t n, int *errs, size_t *done)
{
    brix_ns_delete_opts_t opts;
    brix_ns_result_t      res;
    size_t                  i, removed = 0;

    ngx_memzero(&opts, sizeof(opts));

    for (i = 0; i < n; i++) {
        res = ctx->rootfd >= 0
                  ? brix_ns_delete_at(ctx->log, ctx->rootfd,
                                        ctx->root_canon, paths[i], &opts)
                  : brix_ns_delete(ctx->log, ctx->root_canon, paths[i],
                                     &opts);
        if (res.status == BRIX_NS_OK) {
            errs[i] = 0;
            removed++;
        } else {
            errs[i] = res.sys_errno != 0
                          ? res.sys_errno
                          : brix_vfs_ns_status_errno(res.status);
        }
        (*done)++;
    }

    brix_metric_vfs_bulk_delete("posix", removed);
    return NGX_OK;
}

/* The dispatch half of the driver arm: hand the whole logical key list to
 * the leaf's unlink_many slot when it has one (window-capped by the caller),
 * else run the per-key unlink loop. Per-key verdicts land in errs[]; *done
 * counts the keys actually attempted; NGX_OK = every key attempted. */
static ngx_int_t
delete_many_dispatch(brix_sd_instance_t *leaf, const char *const *logical,
    size_t n, int *errs, size_t *done, const brix_sd_cred_t *cred)
{
    size_t     i;
    ngx_int_t  rc;

    if (leaf->driver->unlink_many != NULL
        || leaf->driver->unlink_many_cred != NULL)
    {
        brix_sd_unlink_batch_t b;

        b.paths = logical;
        b.n     = n;
        b.errs  = errs;
        b.done  = 0;
        errno = 0;
        rc = brix_sd_unlink_many_maybe_cred(leaf, &b, cred);
        *done = (rc == NGX_OK) ? n : b.done;
        return rc;
    }

    for (i = 0; i < n; i++) {
        errno = 0;
        if (brix_sd_unlink_maybe_cred(leaf, logical[i], 0, cred) == NGX_OK) {
            errs[i] = 0;
        } else {
            errs[i] = errno != 0 ? errno : EIO;
        }
        (*done)++;
    }
    return NGX_OK;
}

/* Driver arm of brix_vfs_delete_many: resolve the credential ONCE for the
 * whole batch, hand the full flat key list to the leaf's unlink_many slot
 * (window-capped by the caller), or fall back to the per-key unlink loop when
 * the leaf has no batch slot. Evicts each successfully removed key from a
 * fronting cache decorator — the leaf dispatch skipped the decorator's own
 * unlink and with it its cstore evict (the N–P wave's stale-bytes class). */
static ngx_int_t
brix_vfs_delete_many_via_driver(brix_vfs_ctx_t *ctx,
    const char *const *paths, size_t n, int *errs, size_t *done)
{
    brix_sd_instance_t  *leaf = brix_vfs_ns_leaf(ctx->sd);
    brix_sd_ucred_t      store;
    brix_sd_cred_t       cred;
    const char          **logical;
    size_t                i, removed = 0;
    ngx_int_t             rc;
    int                   saved, use_cred = 0, cred_err = 0;

    /* Zero before the gate: an unzeroed cred hands a garbage inactive pointer
     * to the driver's cred slot (same rule as brix_vfs_delete_via_driver). */
    ngx_memzero(&cred, sizeof(cred));
    if (brix_vfs_cred_gate_active(ctx)) {
        if (brix_vfs_ns_cred(ctx, &store, &cred, &use_cred, &cred_err)
            != NGX_OK)
        {
            errno = cred_err ? cred_err : EACCES;
            return NGX_ERROR;
        }
    }

    logical = malloc(n * sizeof(*logical));
    if (logical == NULL) {
        brix_sd_ucred_wipe(&store);
        errno = ENOMEM;
        return NGX_ERROR;
    }
    for (i = 0; i < n; i++) {
        logical[i] = brix_vfs_export_relative_root(paths[i], ctx->root_canon);
    }

    rc = delete_many_dispatch(leaf, logical, n, errs, done,
                                use_cred ? &cred : NULL);
    saved = errno;
    brix_sd_ucred_wipe(&store);   /* secret consumed by the batch; erase */

    for (i = 0; i < *done; i++) {
        if (errs[i] == 0) {
            removed++;
            brix_metric_cache_evicted(brix_vfs_metrics_proto(ctx),
                                        brix_sd_cache_evict(ctx->sd,
                                                              logical[i]));
        }
    }
    brix_metric_vfs_bulk_delete(brix_sd_backend_name(leaf), removed);

    free(logical);
    errno = saved;
    return rc;
}

/* brix_vfs_delete_many — delete a flat, client-supplied batch of confined
 * paths under ONE policy check and ONE metric observation.
 *
 * WHAT: The S3 DeleteObjects batch entry: every element of `paths` is an
 *       already-confined absolute path under ctx->root_canon (the handler's
 *       per-key confinement ran first); errs[i] receives 0 or a positive errno
 *       per key (ENOENT stays ENOENT — the CALLER decides idempotency);
 *       *done counts the leading keys actually attempted.
 * WHY:  One brix_vfs_unlink per key meant one policy check, one metric line
 *       and — over a remote backend — one signed round trip per key. The batch
 *       runs the EROFS gate once BEFORE any key is examined (a read-only
 *       endpoint discloses nothing about which keys exist) and books one
 *       OP_DELETE observation carrying the key count.
 * HOW:  errs is pre-filled with ECANCELED so an untried key can never read as
 *       deleted; NGX_ERROR means the batch itself failed (policy, credential,
 *       or transport — errno says which), NGX_OK means every key was attempted
 *       and errs holds the per-key verdicts. n is capped at the batch window
 *       (the S3 handler's own 1,000-key cap is the same constant). */
ngx_int_t
brix_vfs_delete_many(brix_vfs_ctx_t *ctx, const char *const *paths, size_t n,
    int *errs, size_t *done)
{
    const char *anchor;
    uint64_t     start;
    ngx_int_t    rc;
    int          saved;
    size_t       i;

    *done = 0;
    for (i = 0; i < n; i++) {
        errs[i] = ECANCELED;
    }
    if (n > BRIX_SD_BULK_DELETE_WINDOW) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    start  = brix_vfs_now_ns();
    anchor = brix_vfs_ctx_path(ctx);

    if (brix_vfs_require_confined_mutation(ctx,
            BRIX_VFS_MUTATE_REMOVE) != NGX_OK)
    {
        saved = errno;
        brix_vfs_observe_ctx_op(ctx, anchor, BRIX_METRIC_OP_DELETE, NULL, n,
                                  NGX_ERROR, saved, start);
        return NGX_ERROR;
    }
    if (ctx->root_canon == NULL) {
        errno = EINVAL;
        saved = errno;
        brix_vfs_observe_ctx_op(ctx, anchor, BRIX_METRIC_OP_DELETE, NULL, n,
                                  NGX_ERROR, saved, start);
        return NGX_ERROR;
    }
    if (n == 0) {
        brix_vfs_observe_ctx_op(ctx, anchor, BRIX_METRIC_OP_DELETE, NULL, 0,
                                  NGX_OK, 0, start);
        return NGX_OK;
    }

    /* phase-107 C7: lock gate for every key, BEFORE any arm touches storage —
     * the batch must not slip past the gate its single-key twin takes
     * (vfs_unlink.c). The batch form sweeps once with a parent-chain memo (a
     * flat batch costs n + 2 quiet reads, not 3n over a remote leaf). Refusal
     * is atomic: no key has been attempted yet, so the whole batch refuses
     * (errs stays ECANCELED, *done stays 0) rather than leaving a partial
     * delete behind a lock conflict. Same coverage as the single-key gate
     * (exact match + depth-infinity ancestors); strict refuses, advisory books
     * and admits, off reads nothing. */
    if (brix_vfs_require_unlocked_many(ctx, paths, n,
            BRIX_VFS_MUTATE_REMOVE) != NGX_OK)
    {
        saved = errno;
        brix_vfs_observe_ctx_op(ctx, anchor, BRIX_METRIC_OP_DELETE, NULL,
                                  n, NGX_ERROR, saved, start);
        return NGX_ERROR;
    }

    if (brix_vfs_ctx_driver(ctx) != NULL) {
        rc = brix_vfs_delete_many_via_driver(ctx, paths, n, errs, done);
    } else {
        rc = brix_vfs_delete_many_via_namespace(ctx, paths, n, errs, done);
    }
    saved = errno;
    brix_vfs_observe_ctx_op(ctx, anchor, BRIX_METRIC_OP_DELETE, NULL, n,
                              rc, rc == NGX_OK ? 0 : saved, start);
    return rc;
}
