/*
 * vfs_recall.c — the nearline lifecycle pair (phase-107 C2): prestage a
 * nearline object into the online buffer, and evict an online copy.
 *
 * WHAT: brix_vfs_recall() initiates (or reports) a recall of the resolved ctx
 *       path from a nearline tier; brix_vfs_evict() drops the online copy the
 *       top of the driver chain holds. Both are typed export mutations
 *       (MUTATE_STAGE / MUTATE_EVICT) and pass the policy kernel FIRST, so a
 *       read-only endpoint answers EROFS before any capability, credential or
 *       registry question is asked (INVARIANT #12).
 *
 * WHY:  Until this file, prestage ran only as the fork/exec prepare_command
 *       while every wire-native recall slot sat implemented and uncalled, and
 *       the kXR_prepare evict arm was a documented no-op. The two verbs also
 *       dispatch in OPPOSITE directions, which is why they share a file but
 *       not a body:
 *
 *       - recall DESCENDS the decorator chain (brix_vfs_decorator_source, the
 *         residency seam's walk): the nearline authority is the buried leaf —
 *         asking a cache decorator to recall is asking the wrong tier.
 *       - evict dispatches on the TOP: "drop the online copy" means the copy
 *         the outermost tier holds (a cache store entry on a cache-fronted
 *         export); descending would evict the origin's copy instead.
 *
 * HOW:  Gate, resolve the per-user credential when the cred gate is active
 *       (zeroed first — an unzeroed cred hands a garbage inactive pointer to
 *       the driver's cred slot), dispatch through the *_maybe_cred forwarders
 *       (which refuse in DENY mode rather than falling back to the service
 *       identity), wipe the credential store, book the C2 counters. The stage
 *       REGISTRY lifecycle (record-before-driver-call, delete-on-failure) is
 *       deliberately NOT here: it belongs to the protocol planes that own the
 *       reqid namespace (prepare.c, the Tape REST plane) — the VFS verb stays
 *       registry-agnostic so a caller with no reqid namespace (the cache
 *       tier's recall-at-fill) pays nothing for one.
 */
#include "vfs_internal.h"

/* brix_vfs_recall — prestage the resolved ctx path from its nearline tier.
 *
 * WHAT: NGX_OK (already online — nothing to stage), NGX_AGAIN (recall queued /
 *       in flight; reqid_out (optional, ≤39 chars + NUL) carries the driver's
 *       parking handle, "" when it has none), or NGX_ERROR with errno set:
 *       EROFS (read-only endpoint, before anything else), ENOTSUP (no
 *       nearline tier in the chain — the caller falls back to
 *       prepare_command), EACCES (cred gate / DENY-mode refusal), or the
 *       driver's own errno (ENOENT for an unknown key, EBUSY, EIO).
 * WHY:  This is the VFS face of the recall slot the cache tier already drives
 *       at fill time; routing kXR_prepare(kXR_stage) here makes prestage one
 *       verb with one gate instead of a subprocess beside an uncalled slot.
 * HOW:  Same decorator walk as brix_vfs_residency — the FIRST tier advertising
 *       CAP_NEARLINE with a recall slot answers. Books brix_vfs_recall_total:
 *       online/queued/error by outcome; ENOTSUP books nothing (a capability
 *       probe, not a recall attempt); the registry-owning caller books
 *       `joined` itself when an existing record absorbs the request. */
ngx_int_t
brix_vfs_recall(brix_vfs_ctx_t *ctx, char reqid_out[40])
{
    brix_sd_instance_t *inst;
    brix_sd_ucred_t     store;
    brix_sd_cred_t      cred;
    ngx_int_t           rc;
    int                 saved_errno;
    int                 use_cred = 0, cred_err = 0;

    if (reqid_out != NULL) {
        reqid_out[0] = '\0';
    }
    if (brix_vfs_require_confined_mutation(ctx, BRIX_VFS_MUTATE_STAGE)
        != NGX_OK)
    {
        return NGX_ERROR;                  /* EROFS/EINVAL; gate booked it */
    }

    for (inst = ctx->sd; inst != NULL;
         inst = brix_vfs_decorator_source(inst))
    {
        if ((brix_sd_caps(inst) & BRIX_SD_CAP_NEARLINE) != 0
            && (inst->driver->recall != NULL
                || inst->driver->recall_cred != NULL))
        {
            break;
        }
    }
    if (inst == NULL) {
        errno = ENOTSUP;                   /* no nearline tier: use the
                                            * prepare_command fallback */
        return NGX_ERROR;
    }

    ngx_memzero(&cred, sizeof(cred));      /* never hand a garbage inactive
                                            * pointer to a cred slot */
    if (brix_vfs_cred_gate_active(ctx)) {
        if (brix_vfs_ns_cred(ctx, &store, &cred, &use_cred, &cred_err)
            != NGX_OK)
        {
            errno = cred_err ? cred_err : EACCES;
            brix_metric_vfs_recall(BRIX_VFS_RECALL_ERROR);
            return NGX_ERROR;
        }
    }

    rc = brix_sd_recall_maybe_cred(inst,
             brix_vfs_export_relative(ctx, brix_vfs_ctx_path(ctx)),
             reqid_out, use_cred ? &cred : NULL);
    saved_errno = errno;
    brix_sd_ucred_wipe(&store);            /* secret consumed; erase (A-4/T4) */

    brix_metric_vfs_recall(rc == NGX_OK    ? BRIX_VFS_RECALL_ONLINE
                           : rc == NGX_AGAIN ? BRIX_VFS_RECALL_QUEUED
                                             : BRIX_VFS_RECALL_ERROR);
    errno = saved_errno;
    return rc;
}

/* brix_vfs_evict — drop the online copy of the resolved ctx path at the TOP of
 * the driver chain.
 *
 * WHAT: NGX_OK with *bytes_out (optional) = bytes actually reclaimed (0 when
 *       the copy was already absent — evict is idempotent — or the driver
 *       cannot know), or NGX_ERROR with errno set: EROFS first, ENOTSUP when
 *       the top driver has no evict slot (its online copy is the ONLY copy, or
 *       it is read-only to us), EACCES, or the driver's errno.
 * WHY:  The kXR_prepare evict arm and the Tape REST release verb need one
 *       gated seam; today the former is a logged no-op and the only real
 *       eviction path (the cache store's) is reachable only as a side effect
 *       of DELETE. OWNERSHIP of a reqid-bound evict (FRM-1) is the protocol
 *       caller's check, exactly like the registry lifecycle on recall.
 * HOW:  Top dispatch via brix_sd_evict_maybe_cred (never the descend walk —
 *       see the file banner), then book the reclaimed bytes under the
 *       dispatching driver's label. */
ngx_int_t
brix_vfs_evict(brix_vfs_ctx_t *ctx, uint64_t *bytes_out)
{
    brix_sd_ucred_t  store;
    brix_sd_cred_t   cred;
    uint64_t         bytes = 0;
    ngx_int_t        rc;
    int              saved_errno;
    int              use_cred = 0, cred_err = 0;

    if (bytes_out != NULL) {
        *bytes_out = 0;
    }
    if (brix_vfs_require_confined_mutation(ctx, BRIX_VFS_MUTATE_EVICT)
        != NGX_OK)
    {
        return NGX_ERROR;                  /* EROFS/EINVAL; gate booked it */
    }
    if (ctx->sd == NULL
        || (ctx->sd->driver->evict == NULL
            && ctx->sd->driver->evict_cred == NULL))
    {
        errno = ENOTSUP;
        return NGX_ERROR;
    }

    ngx_memzero(&cred, sizeof(cred));
    if (brix_vfs_cred_gate_active(ctx)) {
        if (brix_vfs_ns_cred(ctx, &store, &cred, &use_cred, &cred_err)
            != NGX_OK)
        {
            errno = cred_err ? cred_err : EACCES;
            return NGX_ERROR;
        }
    }

    rc = brix_sd_evict_maybe_cred(ctx->sd,
             brix_vfs_export_relative(ctx, brix_vfs_ctx_path(ctx)),
             &bytes, use_cred ? &cred : NULL);
    saved_errno = errno;
    brix_sd_ucred_wipe(&store);

    if (rc == NGX_OK) {
        if (bytes_out != NULL) {
            *bytes_out = bytes;
        }
        brix_metric_vfs_evict(brix_sd_backend_name(ctx->sd), bytes);
    }
    errno = saved_errno;
    return rc;
}

/* brix_vfs_chain_nearline_unstageable — startup advisor probe (phase-107 C2).
 *
 * WHAT: 1 iff `chain` (a composed driver chain head; NULL = default POSIX)
 *       declares CAP_NEARLINE on some tier while NO tier pairs that cap with a
 *       recall slot — i.e. brix_vfs_recall on this export can only ever answer
 *       ENOTSUP, and without a prepare_command the export can never stage.
 * WHY:  That configuration deserves one [warn] at worker startup, not a
 *       kXR_Unsupported at the first client prepare. The walk lives HERE so
 *       the advisor can never disagree with brix_vfs_recall's own tier
 *       selection: both iterate the same chain asking the same two questions.
 * HOW:  Same descent as brix_vfs_recall; no ctx (config-time — there is no
 *       request), no policy gate (a pure capability read mutates nothing). */
int
brix_vfs_chain_nearline_unstageable(brix_sd_instance_t *chain)
{
    brix_sd_instance_t  *inst;
    int                  nearline = 0;

    for (inst = chain; inst != NULL;
         inst = brix_vfs_decorator_source(inst))
    {
        if ((brix_sd_caps(inst) & BRIX_SD_CAP_NEARLINE) != 0) {
            nearline = 1;
            if (inst->driver->recall != NULL
                || inst->driver->recall_cred != NULL)
            {
                return 0;                  /* recall-capable: stageable */
            }
        }
    }
    return nearline;
}
