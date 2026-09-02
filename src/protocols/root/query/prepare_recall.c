/*
 * prepare_recall.c — the W6 (phase-107 C2) per-path arms of kXR_prepare:
 * prestage through brix_vfs_recall() and evict through brix_vfs_evict().
 *
 * WHAT: brix_prepare_recall_one() wraps the VFS recall verb in the stage
 *       REGISTRY lifecycle the VFS deliberately does not own (vfs_recall.c
 *       banner): join an existing record for the same path (one record, one
 *       reqid, however many clients ask), else record BEFORE the driver call,
 *       and delete the record on a synchronous driver failure so a failed
 *       recall never leaves a reqid a client can poll forever.
 *       brix_prepare_evict_one() runs the FRM-1 ownership check (a path bound
 *       to a live stage record may only be evicted by that record's creator)
 *       and then drops the online copy at the top of the driver chain.
 *
 * WHY:  Until W6, prestage ran only as the fork/exec prepare_command while
 *       every wire-native recall slot sat implemented and uncalled, and the
 *       kXR_prepare evict arm was a documented no-op.  prepare_command stays
 *       supported as the FALLBACK for a driver with no recall slot (ENOTSUP),
 *       exactly like the durable FRM engine: both are stagers the registry
 *       record hands the work to.  Only a nearline export with NEITHER fallback
 *       refuses (kXR_Unsupported) — a flat disk export keeps its historical
 *       advisory success, because there staging is a no-op, not a failure.
 *
 * HOW:  Both arms build the same VFS ctx every root:// namespace mutation
 *       builds (op_vfs_ctx: identity + per-user backend credential policy +
 *       phase-70 bearer passthrough), so the recall_cred/evict_cred twins see
 *       the real requester.  The read-only refusal (kXR_fsReadOnly, nothing
 *       recorded) fires in prepare_dispatch_special BEFORE the scan; the
 *       policy kernel inside the VFS verbs is the belt behind that edge gate.
 */
#include "query_internal.h"
#include "prepare_internal.h"
#include "protocols/root/path/op_path.h"   /* brix_root_vfs_bind_session */
#include "fs/xfer/stage_request_registry.h"
#include "core/compat/error_mapping.h"     /* brix_kxr_from_errno */
#include "observability/metrics/unified.h" /* the C2 recall counters */

#include <errno.h>
#include <time.h>

/* Build the stream VFS ctx for one resolved prepare path — the op_vfs_ctx
 * pattern verbatim (op_table.c), so the cred gate and the phase-70 bearer
 * passthrough behave identically to every other root:// namespace mutation.
 * Extern (prepare_internal.h): kXR_QPrep builds the SAME ctx for its per-path
 * brix_vfs_residency probe — residency truth must see the same credential
 * policy the recall saw. */
void
brix_prepare_vfs_ctx(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *resolved,
    brix_vfs_ctx_t *vctx)
{
    brix_vfs_ctx_init(vctx, c->pool, c->log, BRIX_PROTO_ROOT,
        conf->common.root_canon, NULL,
        brix_vfs_policy_from_write_enable(conf->common.allow_write),
        0 /* is_tls */, ctx->identity, resolved);
    brix_vfs_ctx_bind_backend_cred(vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    brix_root_vfs_bind_session(ctx, conf, vctx);
}

/* The first reqid becomes the handle returned to the client (unchanged from
 * the pre-W6 enqueue flow); later paths keep the group handle. */
static void
prepare_adopt_reqid(prepare_scan_t *sc, const char *rq)
{
    if (sc->group_reqid[0] == '\0' && rq != NULL && rq[0] != '\0') {
        ngx_cpystrn((u_char *) sc->group_reqid, (u_char *) rq,
                    BRIX_STAGE_REQID_LEN);
    }
}

/* Record-before-driver-call: create the durable registry record for
 * `out_resolved` (owner = the caller's stable key) so a concurrent second
 * request JOINS instead of duplicating.  Returns 1 with `rq` filled when a
 * record was created, 0 otherwise (creation failure is logged best-effort,
 * matching the pre-W6 enqueue). */
static int
prepare_recall_record(brix_ctx_t *ctx, ngx_connection_t *c,
    prepare_scan_t *sc, brix_stage_registry_t *reg, char *out_resolved,
    char rq[BRIX_STAGE_REQID_LEN])
{
    brix_stage_request_view_t  v;
    char                       owner_key[BRIX_PREPARE_OWNER_KEY_MAX];
    const char                *rdn = brix_prepare_owner_key(ctx, owner_key,
                                                              sizeof(owner_key));

    ngx_memzero(&v, sizeof(v));
    v.lfn          = out_resolved;
    v.requester_dn = (rdn != NULL && rdn[0] != '\0') ? rdn : NULL;
    v.tod_expire   = (int64_t) time(NULL)
                   + (int64_t) (sc->conf->frm.stage_ttl / 1000);

    if (brix_stage_request_add(reg, &v, rq, BRIX_STAGE_REQID_LEN, c->log)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "brix: stage request add failed for \"%s\"",
                      out_resolved);
        rq[0] = '\0';
        return 0;
    }
    prepare_adopt_reqid(sc, rq);
    return 1;
}

/* The ENOTSUP arm: no nearline tier with a recall slot in the chain.  The
 * request still stages when a fallback stager exists — the legacy
 * prepare_command (collect the path for it) or the durable FRM engine (the
 * record just created IS its work queue).  A nearline export with neither can
 * never stage and says so now (kXR_Unsupported) instead of at the first read;
 * a flat export keeps its historical advisory success. */
static ngx_int_t
prepare_recall_enotsup(brix_ctx_t *ctx, ngx_connection_t *c,
    prepare_scan_t *sc, brix_vfs_ctx_t *vctx, char *out_resolved,
    int have_record)
{
    if (sc->collect_stage && sc->cmd_count < sc->stage_max) {
        sc->stage_paths[sc->cmd_count++] = out_resolved;
        return NGX_OK;                 /* prepare_command is the stager */
    }
    if (have_record) {
        return NGX_OK;                 /* the durable FRM engine is the stager */
    }
    if (brix_vfs_nearline_export(vctx)) {
        (void) brix_prepare_send_fail(ctx, c, out_resolved, kXR_Unsupported,
            "nearline export cannot stage: driver has no recall slot and "
            "no prepare command is configured");
        return NGX_DONE;
    }
    return NGX_OK;                     /* flat export: advisory success */
}

ngx_int_t
brix_prepare_recall_one(brix_ctx_t *ctx, ngx_connection_t *c,
    prepare_scan_t *sc, char *out_resolved)
{
    brix_vfs_ctx_t          vctx;
    brix_stage_registry_t *reg = NULL;
    char                    rq[BRIX_STAGE_REQID_LEN];
    char                    drv_rq[40];
    ngx_int_t               rc;
    int                     have_record = 0, e;

    rq[0] = '\0';
    if (sc->do_enqueue) {
        reg = brix_stage_registry_singleton();
    }

    if (reg != NULL
        && brix_stage_request_find_by_path(reg, out_resolved, rq, sizeof(rq),
                                             c->log) == NGX_OK)
    {
        brix_stage_request_t  old;

        /* JOIN (kXR_prepare idempotency): a live record for the same path
         * absorbs the request — same reqid, one record, status unchanged.
         * The joined outcome is booked HERE, not by the VFS (vfs_recall.c).
         * A retired record (FAILED/CANCELLED — find_by_path matches any
         * non-free slot) never absorbs: the fresh request must retry, so it
         * falls through to record-and-recall and becomes the newest record. */
        if (brix_stage_request_get(reg, rq, &old, c->log) == NGX_OK
            && old.status != BRIX_STAGE_REQ_FAILED
            && old.status != BRIX_STAGE_REQ_CANCELLED)
        {
            brix_metric_vfs_recall(BRIX_VFS_RECALL_JOINED);
            prepare_adopt_reqid(sc, rq);
            return NGX_OK;
        }
        rq[0] = '\0';
    }
    if (reg != NULL) {
        have_record = prepare_recall_record(ctx, c, sc, reg, out_resolved, rq);
    }

    brix_prepare_vfs_ctx(ctx, c, sc->conf, out_resolved, &vctx);
    rc = brix_vfs_recall(&vctx, drv_rq);

    if (rc == NGX_OK) {                /* already online — nothing to stage */
        if (have_record) {
            (void) brix_stage_request_set_status(reg, rq,
                                                   BRIX_STAGE_REQ_DONE, c->log);
        }
        return NGX_OK;
    }
    if (rc == NGX_AGAIN) {             /* queued at the driver */
        if (!have_record) {
            prepare_adopt_reqid(sc, drv_rq);   /* registry-less: the driver's
                                                * own parking handle, if any */
        }
        return NGX_OK;
    }

    e = errno;
    if (e == ENOTSUP) {
        return prepare_recall_enotsup(ctx, c, sc, &vctx, out_resolved,
                                        have_record);
    }
    /* Synchronous driver failure: delete the record so no orphan reqid is
     * pollable (kXR_QPrep on it answers unknown, never "queued forever"). */
    if (have_record) {
        (void) brix_stage_request_delete(reg, rq, c->log);
    }
    ngx_log_error(NGX_LOG_ERR, c->log, e,
                  "brix: prestage recall failed for \"%s\"", out_resolved);
    return NGX_OK;                     /* best-effort per path, like the
                                        * pre-W6 staging-command launch */
}

ngx_int_t
brix_prepare_evict_one(brix_ctx_t *ctx, ngx_connection_t *c,
    prepare_scan_t *sc, char *out_resolved)
{
    brix_vfs_ctx_t          vctx;
    brix_stage_registry_t *reg = NULL;
    uint64_t                bytes = 0;
    char                    rq[BRIX_STAGE_REQID_LEN];
    char                    owner_key[BRIX_PREPARE_OWNER_KEY_MAX];
    int                     have_record = 0;

    if (sc->conf->frm.enable) {
        reg = brix_stage_registry_singleton();
    }

    /* FRM-1 ownership: an evict of a path bound to a live stage record is an
     * act on that record — only its creator may drop the copy it recalled.
     * Runs AFTER the read-only edge gate (a read-only export answered EROFS
     * before disclosing whose record exists) and BEFORE the driver. */
    if (reg != NULL
        && brix_stage_request_find_by_path(reg, out_resolved, rq, sizeof(rq),
                                             c->log) == NGX_OK)
    {
        have_record = 1;
        if (brix_stage_request_owner_check(reg, rq,
                brix_prepare_owner_key(ctx, owner_key, sizeof(owner_key)),
                c->log) != NGX_OK)
        {
            brix_log_access(ctx, c, "PREPARE", out_resolved, "evict-denied",
                              0, kXR_NotAuthorized, NULL, 0);
            (void) brix_prepare_send_fail(ctx, c, out_resolved,
                kXR_NotAuthorized, "not the owner of this staged path");
            return NGX_DONE;
        }
    }

    brix_prepare_vfs_ctx(ctx, c, sc->conf, out_resolved, &vctx);
    if (brix_vfs_evict(&vctx, &bytes) != NGX_OK) {
        int e = errno;

        if (e == ENOTSUP) {
            return NGX_OK;             /* no evictable tier: the online copy is
                                        * the only copy — advisory ok, exactly
                                        * the pre-W6 noop (stock parity) */
        }
        (void) brix_prepare_send_fail(ctx, c, out_resolved,
            brix_kxr_from_errno(e), "evict failed");
        return NGX_DONE;
    }

    if (have_record) {
        /* The online copy is gone: retire the record so kXR_QPrep answers from
         * residency truth, not a stale DONE. */
        (void) brix_stage_request_delete(reg, rq, c->log);
    }
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "brix: prepare evict \"%s\": %uL bytes released",
                  out_resolved, bytes);
    return NGX_OK;
}
