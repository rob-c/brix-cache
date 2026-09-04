/*
 * vfs_rename.c — VFS rename / move.
 *
 * WHAT: Implements brix_vfs_rename(), which moves the resolved ctx (source)
 *       path to a caller-supplied, already-resolved destination
 *       brix_path_result_t.
 *
 * WHY:  kXR_mv and WebDAV MOVE need a single write-gated, confined rename whose
 *       destination is verified to be inside the export root before the syscall,
 *       with one metric/access-log line — not an ad-hoc rename(2) per protocol.
 *
 *       Also owns brix_vfs_exchange() (phase-107 C6): the atomic two-name swap
 *       — same gate, same confinement, same OP_RENAME meter, refused ENOTSUP
 *       where the backend has no primitive (never a two-rename emulation).
 *
 * HOW:  Enforces brix_vfs_require_confined_mutation(MUTATE_RENAME) — EROFS on
 *       a read-only endpoint — then demands a non-NULL root_canon
 *       and a destination that is itself is_confined with a non-empty resolved
 *       path. It delegates the actual move to brix_ns_rename() (namespace
 *       layer), maps the returned status back to errno (sys_errno or EIO), and
 *       observes the operation as BRIX_METRIC_OP_RENAME on every path.
 */
#include "vfs_internal.h"
#include "fs/backend/cache/sd_cache.h"   /* brix_sd_cache_evict: leaf-dispatch bypasses the decorator's own evict */
#include "vfs_backend_registry.h"       /* brix_vfs_backend_durable (C3 barrier gate) */
#include "core/compat/staged_file.h"    /* brix_publish_dirsync (C3 POSIX barrier) */
#include "fs/path/beneath.h"            /* brix_beneath_strip_root (C6 EXDEV gate) */

/* Thread-safe confined rename (no pool alloc, no metric) — relocates the
 * namespace rename into the VFS layer for off-thread / pool-less callers (kXR_mv,
 * WebDAV MOVE collection offload). Maps the namespace status to errno + an
 * optional was_dir flag; see vfs.h. */
ngx_int_t
brix_vfs_rename_path(brix_sd_instance_t *sd, ngx_log_t *log,
    const char *root_canon, const brix_n2n_cfg_t *n2n,
    const char *src, const char *dst,
    unsigned overwrite, int *was_dir_out)
{
    brix_ns_result_t res;

    /* Non-POSIX backend: rename in the driver namespace (export-relative keys).
     * was_dir is derived from a post-rename stat of the destination. */
    if (sd != NULL && sd->driver != brix_sd_default_driver()
        && sd->driver->rename != NULL)
    {
        char      s[PATH_MAX];
        char      d[PATH_MAX];
        ngx_int_t rc;

        if (brix_path_export_to_pfn(root_canon, n2n, src, s, sizeof(s))
                != NGX_OK
            || brix_path_export_to_pfn(root_canon, n2n, dst, d, sizeof(d))
                != NGX_OK)
        {
            return NGX_ERROR;
        }
        rc = sd->driver->rename(sd, s, d, overwrite ? 0 : 1);

        if (was_dir_out != NULL) {
            brix_sd_stat_t st;

            *was_dir_out = (rc == NGX_OK && sd->driver->stat != NULL
                            && sd->driver->stat(sd, d, &st) == NGX_OK)
                               ? st.is_dir : 0;
        }
        return rc;
    }

    res = brix_ns_rename(log, root_canon, src, dst, overwrite ? 1 : 0);
    if (was_dir_out != NULL) {
        *was_dir_out = res.was_dir;
    }
    if (res.status == BRIX_NS_OK) {
        return NGX_OK;
    }
    errno = res.sys_errno != 0 ? res.sys_errno
                               : brix_vfs_ns_status_errno(res.status);
    return NGX_ERROR;
}

/*
 * WHAT: Shared entry gate for the two-name driver mutations (rename/exchange):
 *       capability check, credential materialisation, and derivation of both
 *       export-relative keys.
 * WHY:  Both arms refuse identically (EPERM without DIRS_WRITE, the cred-gate
 *       errno when materialisation fails) and both book the refusal as
 *       OP_RENAME; one body keeps the refusal semantics from drifting apart.
 * HOW:  On refusal, sets errno, observes, returns NGX_ERROR — the caller just
 *       propagates. On NGX_OK the caller owns `store` and must wipe it after
 *       its driver call.
 */
static ngx_int_t
brix_vfs_two_key_gate(brix_vfs_ctx_t *ctx, const brix_path_result_t *second,
    const char *path, uint64_t start, const brix_sd_driver_t *drv,
    brix_sd_ucred_t *store, brix_sd_cred_t *cred, int *use_cred,
    char a_key[PATH_MAX], char b_key[PATH_MAX])
{
    int cred_err = 0;
    int saved_errno;

    ngx_memzero(store, sizeof(*store));
    ngx_memzero(cred, sizeof(*cred));
    if (!(drv->caps & BRIX_SD_CAP_DIRS_WRITE)) {
        errno = EPERM;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                NGX_ERROR, EPERM, start);
        return NGX_ERROR;
    }
    if (brix_vfs_cred_gate_active(ctx)
        && brix_vfs_ns_cred(ctx, store, cred, use_cred, &cred_err) != NGX_OK)
    {
        saved_errno = cred_err ? cred_err : EACCES;
        errno = saved_errno;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }
    if (brix_path_resolved_to_pfn(ctx, path, a_key, PATH_MAX) != NGX_OK
        || brix_path_resolved_to_pfn(ctx,
               (const char *) second->resolved.data, b_key, PATH_MAX) != NGX_OK)
    {
        saved_errno = errno;
        brix_sd_ucred_wipe(store);
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                NGX_ERROR, saved_errno, start);
        errno = saved_errno;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * WHAT: Rename two keys through a non-POSIX storage-driver namespace.
 * WHY:  Credential dispatch and cache eviction are distinct from POSIX rename.
 * HOW:  Gate capability/credentials, call the leaf driver, wipe, evict, observe.
 */
static ngx_int_t
brix_vfs_rename_driver(brix_vfs_ctx_t *ctx, const brix_path_result_t *dst,
    const char *path, uint64_t start, const brix_sd_driver_t *drv)
{
    brix_sd_instance_t *leaf = brix_vfs_ns_leaf(ctx->sd);
    brix_sd_ucred_t store;
    brix_sd_cred_t cred;
    ngx_int_t rc;
    int use_cred = 0;
    int saved_errno;
    char src_key[PATH_MAX];
    char dst_key[PATH_MAX];

    if (brix_vfs_two_key_gate(ctx, dst, path, start, drv, &store, &cred,
                              &use_cred, src_key, dst_key) != NGX_OK)
    {
        return NGX_ERROR;
    }
    rc = drv->rename != NULL
         ? brix_sd_rename_maybe_cred(leaf, src_key, dst_key, 0,
                                    use_cred ? &cred : NULL)
         : (errno = ENOTSUP, NGX_ERROR);
    saved_errno = errno;
    brix_sd_ucred_wipe(&store);

    /* Phase-107 C3: durable-publish barrier on the DESTINATION name. Dispatched
     * on the leaf (a decorator relays; NULL slot = the far end's rename is
     * atomic-and-durable there). A failed barrier FAILS the rename — the name
     * moved and cannot be moved back, but success would claim durability the
     * store does not have. */
    if (rc == NGX_OK && leaf != NULL && leaf->driver->sync_publish != NULL
        && brix_vfs_backend_durable(ctx->root_canon)
        && leaf->driver->sync_publish(leaf, dst_key) != NGX_OK)
    {
        saved_errno = errno ? errno : EIO;
        ngx_log_error(NGX_LOG_CRIT, ctx->log, saved_errno,
                      "brix: rename: durable-publish barrier failed for "
                      "\"%s\"", dst_key);
        errno = saved_errno;
        rc = NGX_ERROR;
    }
    if (rc == NGX_OK) {
        brix_metric_cache_evicted(brix_vfs_metrics_proto(ctx),
            brix_sd_cache_evict(ctx->sd, src_key)
            + brix_sd_cache_evict(ctx->sd, dst_key));
    }
    brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                            rc, saved_errno, start);
    return rc;
}

/*
 * WHAT: Shared public-entry gate for the two-name mutations (rename/exchange):
 *       the write-plane policy gate, then validation of the second endpoint.
 * WHY:  Both verbs are rename-class mutations with an identical refusal shape
 *       (policy errno, EINVAL for an unconfined/absent second name), booked as
 *       OP_RENAME; one body keeps the two entries from drifting apart.
 * HOW:  On refusal, sets errno, observes, returns NGX_ERROR — the caller just
 *       propagates.
 */
static ngx_int_t
brix_vfs_two_name_entry(brix_vfs_ctx_t *ctx, const brix_path_result_t *second,
    const char *path, uint64_t start)
{
    int saved_errno;

    if (brix_vfs_confined_mutation_checked(ctx,
            BRIX_VFS_MUTATE_RENAME) != NGX_OK)
    {
        saved_errno = errno;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    if (ctx->root_canon == NULL || second == NULL || !second->is_confined
        || second->resolved.data == NULL)
    {
        errno = EINVAL;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                  NGX_ERROR, EINVAL, start);
        return NGX_ERROR;
    }
    if (brix_vfs_require_authorized_target(ctx,
            (const char *) second->resolved.data,
            BRIX_VFS_MUTATE_RENAME) != NGX_OK)
    {
        saved_errno = errno;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    /* phase-107 C7: lock gate after the mutation gate (EROFS precedes EBUSY),
     * on BOTH names — a rename removes the source and replaces the second
     * endpoint, so a lock on either refuses. The second name's confinement
     * was validated just above. */
    if (brix_vfs_require_unlocked(ctx, BRIX_VFS_MUTATE_RENAME) != NGX_OK
        || brix_vfs_require_unlocked_at(ctx,
               (const char *) second->resolved.data,
               BRIX_VFS_MUTATE_RENAME) != NGX_OK)
    {
        saved_errno = errno;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* Move the resolved ctx source path to the confined destination `dst`.
 * Write-gated; both endpoints must be confined. Metered as OP_RENAME.
 * `overwrite_dirs` lets the rename replace an existing directory destination
 * (its tree is removed first — WebDAV MOVE Overwrite:T); 0 keeps kXR_mv
 * semantics where an existing dir dest fails with EEXIST. */
ngx_int_t
brix_vfs_rename(brix_vfs_ctx_t *ctx, const brix_path_result_t *dst,
    unsigned overwrite_dirs)
{
    brix_ns_result_t        res;
    const char               *path;
    uint64_t                  start;
    int                       saved_errno;
    const brix_sd_driver_t *drv;

    start = brix_vfs_now_ns();
    path = brix_vfs_ctx_path(ctx);

    if (brix_vfs_two_name_entry(ctx, dst, path, start) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Non-POSIX backend: rename within the driver namespace (both endpoints are
     * keyed export-relative; the move carries content via the catalog).
     * Dispatch on the leaf instance so brix_sd_rename_maybe_cred finds the
     * leaf driver's rename_cred slot (decorators have only plain relays). */
    drv = brix_vfs_ctx_driver(ctx);
    if (drv != NULL)
        return brix_vfs_rename_driver(ctx, dst, path, start, drv);

    res = brix_ns_rename(ctx->log, ctx->root_canon,
                           brix_vfs_ctx_path(ctx),
                           (const char *) dst->resolved.data,
                           overwrite_dirs ? 1 : 0);
    if (res.status == BRIX_NS_OK) {
        /* Phase-107 C3: flush the destination's parent directory entry so the
         * rename itself survives a crash (same barrier the staged commit
         * carries; -1 anchor = dirsync opens its own confined root). Failure
         * FAILS the rename — the name moved, but reporting success without
         * durability is the exact bug the barrier removes. */
        if (brix_vfs_backend_durable(ctx->root_canon)
            && brix_publish_dirsync(ctx->log, -1, ctx->root_canon,
                                    (const char *) dst->resolved.data) != NGX_OK)
        {
            saved_errno = errno ? errno : EIO;
            brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                      NGX_ERROR, saved_errno, start);
            errno = saved_errno;
            return NGX_ERROR;
        }
        brix_vfs_neg_stat_forget(ctx->root_canon,
                                   (const char *) dst->resolved.data);
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                  NGX_OK, 0, start);
        return NGX_OK;
    }

    /* A pre-checked refusal (e.g. destination is an existing directory →
     * BRIX_NS_EXISTS) carries no syscall errno; map the status instead of
     * collapsing it to EIO so mv/MOVE report the true category. */
    errno = res.sys_errno != 0 ? res.sys_errno
                               : brix_vfs_ns_status_errno(res.status);
    saved_errno = errno;
    brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                              NGX_ERROR, saved_errno, start);
    return NGX_ERROR;
}

/*
 * WHAT: Exchange two keys through a non-POSIX storage-driver namespace.
 * WHY:  Same gate/cred/evict shape as rename, but BOTH names change content,
 *       so the C3 barrier and the cache eviction cover both keys.
 * HOW:  Gate capability/credentials, call the leaf driver (ENOTSUP when it has
 *       no primitive — never emulated), wipe, barrier both, evict both, observe.
 */
static ngx_int_t
brix_vfs_exchange_driver(brix_vfs_ctx_t *ctx, const brix_path_result_t *other,
    const char *path, uint64_t start, const brix_sd_driver_t *drv)
{
    brix_sd_instance_t *leaf = brix_vfs_ns_leaf(ctx->sd);
    brix_sd_ucred_t store;
    brix_sd_cred_t cred;
    ngx_int_t rc;
    int use_cred = 0;
    int saved_errno;
    char a_key[PATH_MAX];
    char b_key[PATH_MAX];

    if (brix_vfs_two_key_gate(ctx, other, path, start, drv, &store, &cred,
                              &use_cred, a_key, b_key) != NGX_OK)
    {
        return NGX_ERROR;
    }
    rc = brix_sd_exchange_maybe_cred(leaf, a_key, b_key,
                                     use_cred ? &cred : NULL);
    saved_errno = errno;
    brix_sd_ucred_wipe(&store);

    /* Phase-107 C3: durable-publish barrier on BOTH names — each now maps to
     * the other's content. Dispatched on the leaf (a decorator relays; NULL
     * slot = the far end's swap is atomic-and-durable there). A failed barrier
     * FAILS the exchange — the names swapped and cannot be un-swapped safely,
     * but success would claim durability the store does not have. */
    if (rc == NGX_OK && leaf != NULL && leaf->driver->sync_publish != NULL
        && brix_vfs_backend_durable(ctx->root_canon)
        && (leaf->driver->sync_publish(leaf, a_key) != NGX_OK
            || leaf->driver->sync_publish(leaf, b_key) != NGX_OK))
    {
        saved_errno = errno ? errno : EIO;
        ngx_log_error(NGX_LOG_CRIT, ctx->log, saved_errno,
                      "brix: exchange: durable-publish barrier failed for "
                      "\"%s\" <-> \"%s\"", a_key, b_key);
        errno = saved_errno;
        rc = NGX_ERROR;
    }
    if (rc == NGX_OK) {
        brix_metric_cache_evicted(brix_vfs_metrics_proto(ctx),
            brix_sd_cache_evict(ctx->sd, a_key)
            + brix_sd_cache_evict(ctx->sd, b_key));
    }
    brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                            rc, saved_errno, start);
    return rc;
}

/* Atomically exchange the resolved ctx path with the confined name `other`
 * (phase-107 C6): no instant at which either name is missing. Write-gated as a
 * rename-class mutation; both endpoints must be confined in the SAME export
 * (EXDEV otherwise); metered as OP_RENAME. ENOTSUP where the backend has no
 * primitive — NEVER emulated with two renames (§3.5): a caller that asked for
 * an atomic swap would rather have a refusal than a window in which neither
 * name resolves. */
ngx_int_t
brix_vfs_exchange(brix_vfs_ctx_t *ctx, const brix_path_result_t *other)
{
    brix_ns_result_t        res;
    const char               *path;
    uint64_t                  start;
    int                       saved_errno;
    const brix_sd_driver_t *drv;

    start = brix_vfs_now_ns();
    path = brix_vfs_ctx_path(ctx);

    if (brix_vfs_two_name_entry(ctx, other, path, start) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Both names must live in THIS export: a cross-export swap is EXDEV, not a
     * confinement escape. The driver arm needs the check here — its
     * export-relative keying passes a foreign absolute path through UNCHANGED,
     * which would hand the backend a key outside the export. (The POSIX arm
     * re-derives the same answer inside brix_ns_exchange.) */
    if (brix_beneath_strip_root(ctx->root_canon,
                                (const char *) other->resolved.data) == NULL)
    {
        errno = EXDEV;
        saved_errno = errno;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    drv = brix_vfs_ctx_driver(ctx);
    if (drv != NULL)
        return brix_vfs_exchange_driver(ctx, other, path, start, drv);

    res = brix_ns_exchange(ctx->log, ctx->root_canon, path,
                           (const char *) other->resolved.data);
    if (res.status == BRIX_NS_OK) {
        /* Phase-107 C3: both directory entries changed — flush both parents
         * (same barrier rename carries for its destination). Failure FAILS the
         * exchange: the names swapped, but reporting success without
         * durability is the exact bug the barrier removes. */
        if (brix_vfs_backend_durable(ctx->root_canon)
            && (brix_publish_dirsync(ctx->log, -1, ctx->root_canon,
                                     path) != NGX_OK
                || brix_publish_dirsync(ctx->log, -1, ctx->root_canon,
                                        (const char *)
                                        other->resolved.data) != NGX_OK))
        {
            saved_errno = errno ? errno : EIO;
            brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                      NGX_ERROR, saved_errno, start);
            errno = saved_errno;
            return NGX_ERROR;
        }
        brix_vfs_neg_stat_forget(ctx->root_canon, path);
        brix_vfs_neg_stat_forget(ctx->root_canon,
                                   (const char *) other->resolved.data);
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                                  NGX_OK, 0, start);
        return NGX_OK;
    }

    errno = res.sys_errno != 0 ? res.sys_errno
                               : brix_vfs_ns_status_errno(res.status);
    saved_errno = errno;
    brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_RENAME, NULL, 0,
                              NGX_ERROR, saved_errno, start);
    return NGX_ERROR;
}
