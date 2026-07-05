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
brix_fuse_errno(const brix_status *st)
{
    int e = brix_kxr_to_errno(st);
    return e != 0 ? e : -EIO;
}

int
brix_fuse_conn_healthy(const brix_status *st)
{
    return st->kxr != XRDC_ESOCK && st->kxr != XRDC_EPROTO;
}

/* Retry budget exhausted? Deadline-bounded when `deadline` is set (ride the loss
 * out for the patience window); else the legacy count bound (stop once `attempt`
 * has reached `max`, i.e. max+1 total attempts — max==0 is a single attempt). */
static int
fuse_run_done(uint64_t deadline, unsigned attempt, unsigned max)
{
    if (deadline != 0) {
        return brix_mono_ns() >= deadline;
    }
    return attempt >= max;
}

int
brix_fuse_run(brix_pool *pool, int max_retries, int max_stall_ms,
              int benign_errno, brix_fuse_op_fn op, void *ctx, brix_status *st)
{
    uint64_t deadline = (max_stall_ms > 0)
                        ? brix_mono_ns() + (uint64_t) max_stall_ms * 1000000ULL
                        : 0;
    unsigned max = max_retries > 0 ? (unsigned) max_retries : 0;
    unsigned attempt;

    for (attempt = 0; ; attempt++) {
        /* Exponential backoff + jitter BEFORE each retry (never the first), so a
         * transient fault on a flaky link is ridden out without a reconnect
         * storm and concurrent FUSE threads do not re-hammer in lockstep. */
        if (attempt > 0) {
            brix_backoff_sleep_fast(attempt - 1);
        }

        brix_conn *c = brix_pool_checkout(pool, st);
        if (c == NULL) {
            if (brix_status_retryable(st)
                && !fuse_run_done(deadline, attempt, max)) {
                continue;
            }
            return brix_fuse_errno(st);
        }

        int rc = op(c, ctx, st);
        brix_pool_checkin(pool, c, rc == 0 ? 1 : brix_fuse_conn_healthy(st));
        if (rc == 0) {
            return 0;
        }
        /* Idempotency normalization for a re-issued mutation: once we have
         * retried (attempt > 0), the first attempt may already have applied the
         * change and had its reply lost to the sever. A benign "already in the
         * desired state" code (EEXIST for mkdir/symlink/link, ENOENT for
         * rm/rmdir/mv) then means success, not a spurious error. */
        if (attempt > 0 && benign_errno != 0
            && brix_kxr_to_errno(st) == benign_errno) {
            brix_status_clear(st);
            return 0;
        }
        if (!brix_status_retryable(st)
            || fuse_run_done(deadline, attempt, max)) {
            return brix_fuse_errno(st);
        }
        /* transient → backoff, then retry on a freshly (re)connected slot */
    }
}

/* op thunks */
int
brix_fuse_op_stat(brix_conn *c, void *ctx, brix_status *st)
{
    struct brix_fuse_ctx_stat *a = ctx;
    return brix_stat(c, a->path, a->si, st);
}

int
brix_fuse_op_lstat(brix_conn *c, void *ctx, brix_status *st)
{
    struct brix_fuse_ctx_stat *a = ctx;
    return brix_lstat(c, a->path, a->si, st);
}

int
brix_fuse_op_dirlist(brix_conn *c, void *ctx, brix_status *st)
{
    struct brix_fuse_ctx_dir *a = ctx;
    return brix_dirlist(c, a->path, 1, a->ents, a->n, st);
}

int
brix_fuse_op_mkdir(brix_conn *c, void *ctx, brix_status *st)
{
    struct brix_fuse_ctx_mkdir *a = ctx;
    return brix_mkdir(c, a->path, a->mode, 0, st);
}

int
brix_fuse_op_rm(brix_conn *c, void *ctx, brix_status *st)
{
    return brix_rm(c, (const char *) ctx, st);
}

int
brix_fuse_op_rmdir(brix_conn *c, void *ctx, brix_status *st)
{
    return brix_rmdir(c, (const char *) ctx, st);
}

int
brix_fuse_op_mv(brix_conn *c, void *ctx, brix_status *st)
{
    struct brix_fuse_ctx_mv *a = ctx;
    return brix_mv(c, a->from, a->to, st);
}

int
brix_fuse_op_chmod(brix_conn *c, void *ctx, brix_status *st)
{
    struct brix_fuse_ctx_chmod *a = ctx;
    return brix_chmod(c, a->path, a->mode, st);
}

int
brix_fuse_op_trunc(brix_conn *c, void *ctx, brix_status *st)
{
    struct brix_fuse_ctx_trunc *a = ctx;
    return brix_truncate(c, a->path, a->size, st);
}

int
brix_fuse_op_setattr(brix_conn *c, void *ctx, brix_status *st)
{
    struct brix_fuse_ctx_setattr *a = ctx;
    return brix_setattr(c, a->path, a->set_times, a->times,
                        a->set_owner, a->uid, a->gid, st);
}

int
brix_fuse_op_symlink(brix_conn *c, void *ctx, brix_status *st)
{
    struct brix_fuse_ctx_link2 *a = ctx;
    return brix_symlink(c, a->a, a->b, st);
}

int
brix_fuse_op_link(brix_conn *c, void *ctx, brix_status *st)
{
    struct brix_fuse_ctx_link2 *a = ctx;
    return brix_link(c, a->a, a->b, st);
}
