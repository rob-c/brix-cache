/*
 * vfs_lock_gate.c — the cross-protocol lock gate (phase-107 C7).
 *
 * WHAT: brix_vfs_require_unlocked(): may this mutation proceed against the
 *       ctx's target, or does a live foreign lock cover it (EBUSY)?
 *
 * WHY:  A WebDAV LOCK used to bind only WebDAV verbs; an XRootD or GridFTP
 *       write landed on a locked file unopposed. The gate makes lock coverage
 *       a VFS question, asked once, after the mutation kernel — so EROFS still
 *       precedes every other refusal and a read-only endpoint discloses
 *       nothing about lock state.
 *
 * HOW:  Walk the resolved target up to the export root (the same ancestor walk
 *       and coverage rule as the WebDAV edge's webdav_check_locks), reading
 *       the shared lock record (core/compat/lock_record.h) through the QUIET
 *       xattr path so the per-request OP_XATTR counter deltas the metrics
 *       conformance contract pins stay depth-independent. A record past expiry
 *       is treated as absent and NOT reaped — reaping is itself a mutation,
 *       and a read-only export must never reap. Ownership is the ctx's
 *       lock-token presentation (ctx->lock_token, the raw If/Lock-Token header
 *       value) matched by substring, exactly as the edge matches, so the two
 *       planes agree on who owns a lock. The enforcement mode comes from the
 *       backend registry keyed on root_canon (absence = STRICT, failing toward
 *       enforcement); a call site cannot opt itself out. Descendant scans for
 *       collection DELETE/MOVE/COPY stay at the WebDAV edge — this gate is the
 *       ancestor half every plane shares. Impure by design (reads xattrs),
 *       which is why it is not part of vfs_policy.c's pure kernel.
 */
#include "vfs_internal.h"
#include "vfs_policy.h"
#include "vfs_backend_registry.h"
#include "core/compat/lock_record.h"

#include <limits.h>
#include <string.h>

#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

/* One level of the ancestor walk: the (mutable) ancestor path being examined
 * plus the (immutable) target path the whole walk is checking. Mirrors the
 * WebDAV edge's walk struct so the coverage rule reads identically. */
typedef struct {
    const char *check;
    size_t      check_len;
    const char *path;
    size_t      path_len;
} brix_vfs_lock_walk_t;

/* The absent-class xattr errnos — the WebDAV lock DB's own list
 * (prop_xattr.c): no record is stored here, or the backend cannot store one.
 * EACCES/EPERM stay absent-class so a backend that hides the attribute cannot
 * wedge every mutation. */
static int
brix_vfs_lock_errno_absent(int err)
{
    return err == ENODATA || err == ENOATTR || err == ENOENT
        || err == ENOTSUP || err == EOPNOTSUPP || err == ENOSYS
        || err == EACCES || err == EPERM;
}

/*
 * brix_vfs_lock_probe_level — evaluate the lock (if any) recorded on one
 * ancestor path against the walk's target.
 *
 * WHAT: NGX_OK when nothing here blocks the target (no record, not a valid
 *       record, expired, not covering, or owned by the presented token);
 *       NGX_BUSY when a live foreign lock covers the target; NGX_ERROR with
 *       errno preserved on a hard xattr read fault.
 * WHY:  Isolating the per-level decision keeps the ascent loop in the entry
 *       point a simple path-walk, exactly as the WebDAV edge splits it.
 * HOW:  Quiet getxattr (no OP_XATTR observation) → decode → expiry → the
 *       edge's coverage rule (exact match, or a depth-infinity ancestor on a
 *       path boundary) → substring token match. Absent-class errnos admit
 *       (brix_vfs_lock_errno_absent above).
 */
static ngx_int_t
brix_vfs_lock_probe_level(brix_vfs_ctx_t *ctx, const brix_vfs_lock_walk_t *w)
{
    char                raw[BRIX_LOCK_XATTR_MAXLEN + 1];
    brix_lock_record_t  rec;
    ssize_t             n;
    int                 covers;

    n = brix_vfs_getxattr_quiet_at(ctx, w->check, BRIX_LOCK_XATTR_KEY,
                                   raw, BRIX_LOCK_XATTR_MAXLEN);
    if (n < 0) {
        if (brix_vfs_lock_errno_absent(errno)) {
            return NGX_OK;   /* absent-class: no lock recorded here */
        }
        return NGX_ERROR;    /* hard read fault; errno preserved */
    }

    if (brix_lock_record_decode(raw, (size_t) n, &rec) != NGX_OK) {
        return NGX_OK;       /* not a lock record */
    }

    if (rec.expires <= (int64_t) ngx_time()) {
        /* Expired = absent. Deliberately NOT reaped: reaping is a mutation,
         * this gate also runs for read-only-adjacent surfaces, and the WebDAV
         * edge's own expiry cleanup (which already declines on a read-only
         * export) remains the reaper. */
        return NGX_OK;
    }

    /* Lock covers the target if: exact match, or a depth-infinity ancestor on
     * a path boundary — byte-identical to webdav_check_lock_at. */
    covers = (w->check_len == w->path_len)
             || (rec.depth_infinity
                 && w->check_len < w->path_len
                 && (w->check[w->check_len - 1] == '/'
                     || w->path[w->check_len] == '/'));

    if (covers
        && !(ctx->lock_token != NULL
             && strstr(ctx->lock_token, rec.token) != NULL))
    {
        return NGX_BUSY;
    }

    return NGX_OK;
}

/* Shared refusal tail: book the per-proto refusal metric (in BOTH strict and
 * advisory — the advisory count is what tells an operator the relaxed mode is
 * masking real contention), then refuse (strict: EBUSY) or warn-and-admit
 * (advisory). The warning names the path and operation, NEVER the held token —
 * the token is a bearer secret. */
static ngx_int_t
brix_vfs_lock_refuse(const brix_vfs_ctx_t *ctx, brix_vfs_mutation_op_t op,
    ngx_uint_t mode)
{
    brix_metric_vfs_lock_refused(brix_vfs_metrics_proto(ctx));

    if (mode == BRIX_VFS_LOCK_ADVISORY) {
        if (ctx->log != NULL) {
            ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                          "brix: %s on \"%s\" proceeds under a live foreign "
                          "lock (brix_lock_enforcement advisory)",
                          brix_vfs_mutation_op_name(op),
                          brix_vfs_ctx_path(ctx));
        }
        return NGX_OK;
    }

    errno = EBUSY;
    return NGX_ERROR;
}

/* ---- May this mutation proceed, or is the target under a foreign lock? ----
 *
 * WHAT: NGX_OK when no live foreign lock covers ctx's target (or the export
 *       relaxed enforcement); NGX_ERROR with EINVAL for a missing/unconfined
 *       ctx or an out-of-range op, EBUSY under a live foreign lock in strict
 *       mode, or the read fault's errno when a lock record cannot be read in
 *       strict mode (unlocked cannot be proven — fail closed).
 *
 * WHY:  Position 2 in the mutation-gate order (§3.4): after the policy kernel,
 *       before confinement-derived leaf work — EROFS always precedes EBUSY.
 *
 * HOW:  Validate op → require confinement → registry mode (OFF reads nothing)
 *       → ancestor walk with the per-level probe above. The walk's stop
 *       conditions are the WebDAV edge's own: the export root is the last
 *       level examined.
 */
/*
 * brix_vfs_lock_walk_gate — the ancestor walk itself, shared by the single and
 * batch entry points (op validation, confinement and mode lookup are the
 * caller's).
 *
 * cleared_parent (batch only, else NULL): an ancestor path this SWEEP already
 * walked to the export root and proved lock-free — reaching it ends the walk
 * without re-reading the chain above. The memo is never consulted for the
 * target itself (check_len < path_len), so the exact-node probe always runs.
 *
 * *clean is set to 0 when any level went unproven — an advisory admit past a
 * live foreign lock, or an advisory-swallowed read fault — so the batch caller
 * only memoizes chains that were actually walked clean to the root.
 */
static ngx_int_t
brix_vfs_lock_walk_gate(brix_vfs_ctx_t *ctx, brix_vfs_mutation_op_t op,
    ngx_uint_t mode, const char *cleared_parent, int *clean)
{
    char                  check[PATH_MAX];
    size_t                root_len;
    ngx_int_t             rc;
    brix_vfs_lock_walk_t  w;

    *clean = 1;

    w.path     = brix_vfs_ctx_path(ctx);
    if (w.path == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    w.path_len = strlen(w.path);
    root_len   = strlen(ctx->root_canon);

    ngx_cpystrn((u_char *) check, (u_char *) w.path, sizeof(check));
    w.check = check;

    for ( ;; ) {
        w.check_len = strlen(check);

        if (cleared_parent != NULL && w.check_len < w.path_len
            && strcmp(check, cleared_parent) == 0)
        {
            break;   /* chain above proven lock-free earlier this sweep */
        }

        rc = brix_vfs_lock_probe_level(ctx, &w);
        if (rc == NGX_BUSY) {
            *clean = 0;
            return brix_vfs_lock_refuse(ctx, op, mode);
        }
        if (rc != NGX_OK) {
            if (mode != BRIX_VFS_LOCK_ADVISORY) {
                return NGX_ERROR;   /* strict: unreadable ⇒ fail closed */
            }
            *clean = 0;   /* advisory swallows the fault; level unproven */
        }

        /* Stop at or above export root (the root itself was just checked). */
        if (w.check_len <= root_len) {
            break;
        }

        if (!brix_lock_path_ascend(check, w.check_len)) {
            break;
        }

        if (strlen(check) < root_len) {
            break;
        }
    }

    return NGX_OK;
}

ngx_int_t
brix_vfs_require_unlocked(brix_vfs_ctx_t *ctx, brix_vfs_mutation_op_t op)
{
    ngx_uint_t  mode;
    int         clean;

    if ((ngx_uint_t) op >= BRIX_VFS_MUTATE_OP_COUNT) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (brix_vfs_require_confined(ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    mode = brix_vfs_backend_lock_enforcement(ctx->root_canon);
    if (mode == BRIX_VFS_LOCK_OFF) {
        return NGX_OK;
    }

    return brix_vfs_lock_walk_gate(ctx, op, mode, NULL, &clean);
}

/* Alternate-target form: gate `path` (a validated confined destination in the
 * same export) with ctx's identity, token presentation, and enforcement mode.
 * A stack copy of the ctx with the resolved path swapped keeps the walk, the
 * quiet reads, and the refusal tail in exactly one body above. */
ngx_int_t
brix_vfs_require_unlocked_at(brix_vfs_ctx_t *ctx, const char *path,
    brix_vfs_mutation_op_t op)
{
    brix_vfs_ctx_t  alt;

    if (ctx == NULL || path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return NGX_ERROR;
    }

    alt = *ctx;
    alt.resolved.resolved.data = (u_char *) path;
    alt.resolved.resolved.len  = strlen(path);

    return brix_vfs_require_unlocked(&alt, op);
}

/*
 * Batch form: gate every resolved path of a delete window in ONE sweep.
 *
 * WHY: gating a 1,000-key batch through the per-path entry costs ~3 quiet
 *      xattr reads per key over a remote leaf (exact node, parent, export
 *      root) — ~3,000 upstream round trips for one request, and ONE transient
 *      fault among them fail-closes the whole batch. Batch keys overwhelmingly
 *      share a parent directory, and a parent chain walked clean to the export
 *      root once needs no second read.
 *
 * HOW: per key the exact-node probe ALWAYS runs; the ancestor walk stops on
 *      reaching the previous key's memoized parent (a flat batch costs n + 2
 *      probes instead of 3n). The memo holds only chains proven fully clean —
 *      an advisory admit or swallowed fault leaves it unset, so advisory-mode
 *      contention books its refusal metric per key exactly as the per-path
 *      gate does. Refusal semantics are unchanged and ATOMIC: the first strict
 *      EBUSY or read fault returns before the caller runs any arm.
 */
ngx_int_t
brix_vfs_require_unlocked_many(brix_vfs_ctx_t *ctx, const char *const *paths,
    size_t n, brix_vfs_mutation_op_t op)
{
    char            cleared[PATH_MAX];
    size_t          i, root_len;
    ngx_uint_t      mode;
    int             clean;
    brix_vfs_ctx_t  alt;

    if (paths == NULL || (ngx_uint_t) op >= BRIX_VFS_MUTATE_OP_COUNT) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (brix_vfs_require_confined(ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    mode = brix_vfs_backend_lock_enforcement(ctx->root_canon);
    if (mode == BRIX_VFS_LOCK_OFF) {
        return NGX_OK;
    }

    root_len   = strlen(ctx->root_canon);
    cleared[0] = '\0';
    alt        = *ctx;

    for (i = 0; i < n; i++) {
        if (paths[i] == NULL || paths[i][0] == '\0') {
            errno = EINVAL;
            return NGX_ERROR;
        }

        alt.resolved.resolved.data = (u_char *) paths[i];
        alt.resolved.resolved.len  = strlen(paths[i]);

        if (brix_vfs_lock_walk_gate(&alt, op, mode,
                                    (cleared[0] != '\0') ? cleared : NULL,
                                    &clean) != NGX_OK)
        {
            return NGX_ERROR;   /* EBUSY or the read fault's errno */
        }

        if (clean) {
            ngx_cpystrn((u_char *) cleared, (u_char *) paths[i],
                        sizeof(cleared));
            if (!brix_lock_path_ascend(cleared, strlen(cleared))
                || strlen(cleared) < root_len)
            {
                cleared[0] = '\0';   /* key sits at the root: nothing above */
            }
        }
    }

    return NGX_OK;
}
