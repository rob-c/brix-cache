/*
 * fuse_ops.c — implementation of the pooled metadata-op runner + op thunks.
 *
 * See fuse_ops.h for the rationale.  The runner is a direct generalisation of
 * the per-driver harnesses: the resilient driver's retry loop with max_retries
 * set to 0 collapses to exactly the simple driver's single checkout/op/checkin,
 * so both drivers share this one function.
 */
#include "fuse_ops.h"

#include <errno.h>

int
xrdc_fuse_errno(const xrdc_status *st)
{
    int e = xrdc_kxr_to_errno(st);
    return e != 0 ? e : -EIO;
}

int
xrdc_fuse_conn_healthy(const xrdc_status *st)
{
    return st->kxr != XRDC_ESOCK && st->kxr != XRDC_EPROTO;
}

int
xrdc_fuse_run(xrdc_pool *pool, int max_retries,
              xrdc_fuse_op_fn op, void *ctx, xrdc_status *st)
{
    unsigned max = max_retries > 0 ? (unsigned) max_retries : 0;
    unsigned attempt;

    for (attempt = 0; attempt <= max; attempt++) {
        /* Exponential backoff + jitter BEFORE each retry (never the first), so a
         * transient fault on a flaky link is ridden out without a reconnect
         * storm and concurrent FUSE threads do not re-hammer in lockstep. */
        if (attempt > 0) {
            xrdc_backoff_sleep_fast(attempt - 1);
        }

        xrdc_conn *c = xrdc_pool_checkout(pool, st);
        if (c == NULL) {
            if (attempt < max && xrdc_status_retryable(st)) {
                continue;
            }
            return xrdc_fuse_errno(st);
        }

        int rc = op(c, ctx, st);
        xrdc_pool_checkin(pool, c, rc == 0 ? 1 : xrdc_fuse_conn_healthy(st));
        if (rc == 0) {
            return 0;
        }
        if (attempt == max || !xrdc_status_retryable(st)) {
            return xrdc_fuse_errno(st);
        }
        /* transient → backoff, then retry on a freshly (re)connected slot */
    }
    return xrdc_fuse_errno(st);
}

/* ---- op thunks ---------------------------------------------------------- */

int
xrdc_fuse_op_stat(xrdc_conn *c, void *ctx, xrdc_status *st)
{
    struct xrdc_fuse_ctx_stat *a = ctx;
    return xrdc_stat(c, a->path, a->si, st);
}

int
xrdc_fuse_op_lstat(xrdc_conn *c, void *ctx, xrdc_status *st)
{
    struct xrdc_fuse_ctx_stat *a = ctx;
    return xrdc_lstat(c, a->path, a->si, st);
}

int
xrdc_fuse_op_dirlist(xrdc_conn *c, void *ctx, xrdc_status *st)
{
    struct xrdc_fuse_ctx_dir *a = ctx;
    return xrdc_dirlist(c, a->path, 1, a->ents, a->n, st);
}

int
xrdc_fuse_op_mkdir(xrdc_conn *c, void *ctx, xrdc_status *st)
{
    struct xrdc_fuse_ctx_mkdir *a = ctx;
    return xrdc_mkdir(c, a->path, a->mode, 0, st);
}

int
xrdc_fuse_op_rm(xrdc_conn *c, void *ctx, xrdc_status *st)
{
    return xrdc_rm(c, (const char *) ctx, st);
}

int
xrdc_fuse_op_rmdir(xrdc_conn *c, void *ctx, xrdc_status *st)
{
    return xrdc_rmdir(c, (const char *) ctx, st);
}

int
xrdc_fuse_op_mv(xrdc_conn *c, void *ctx, xrdc_status *st)
{
    struct xrdc_fuse_ctx_mv *a = ctx;
    return xrdc_mv(c, a->from, a->to, st);
}

int
xrdc_fuse_op_chmod(xrdc_conn *c, void *ctx, xrdc_status *st)
{
    struct xrdc_fuse_ctx_chmod *a = ctx;
    return xrdc_chmod(c, a->path, a->mode, st);
}

int
xrdc_fuse_op_trunc(xrdc_conn *c, void *ctx, xrdc_status *st)
{
    struct xrdc_fuse_ctx_trunc *a = ctx;
    return xrdc_truncate(c, a->path, a->size, st);
}

int
xrdc_fuse_op_setattr(xrdc_conn *c, void *ctx, xrdc_status *st)
{
    struct xrdc_fuse_ctx_setattr *a = ctx;
    return xrdc_setattr(c, a->path, a->set_times, a->times,
                        a->set_owner, a->uid, a->gid, st);
}

int
xrdc_fuse_op_symlink(xrdc_conn *c, void *ctx, xrdc_status *st)
{
    struct xrdc_fuse_ctx_link2 *a = ctx;
    return xrdc_symlink(c, a->a, a->b, st);
}

int
xrdc_fuse_op_link(xrdc_conn *c, void *ctx, xrdc_status *st)
{
    struct xrdc_fuse_ctx_link2 *a = ctx;
    return xrdc_link(c, a->a, a->b, st);
}
