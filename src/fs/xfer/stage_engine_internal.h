#ifndef BRIX_FS_XFER_STAGE_ENGINE_INTERNAL_H
#define BRIX_FS_XFER_STAGE_ENGINE_INTERNAL_H

/*
 * stage_engine_internal.h — private seam shared across the three halves of the
 * async-staging engine after the phase-79 file-size split.
 *
 * WHAT: Declares the module-private durable-request vocabulary (the in-memory
 *       pending item, the per-worker journal directory) and the cross-file entry
 *       points — reqid minting, journal write/remove, and the generic inline
 *       mover — that the journal, scheduler, and reconcile halves call across the
 *       file boundary.
 *
 * WHY:  stage_engine.c was one 1145-line file owning three concerns: the byte
 *       mover + kind vocabulary, the durable journal + dead-letter substrate, and
 *       the front doors + scheduler + restart reconcile. Splitting the journal
 *       and scheduler/reconcile concerns into sibling files keeps each translation
 *       unit under the 500-line cap and focused; the symbols they share are reached
 *       ONLY through this header. The stage/recall state machine, the WAL-style
 *       journal ordering, and the FIFO drain order are unchanged — the split is a
 *       re-home, not a behavior change.
 *
 * HOW:  stage_engine.c defines the generic mover (stage_engine_run);
 *       stage_engine_journal.c defines the journal globals + helpers
 *       (stage_journal_dir, stage_reqid_mint, stage_journal_write,
 *       stage_journal_remove); stage_engine_scheduler.c and
 *       stage_engine_reconcile.c consume them. None of these symbols is exported
 *       beyond the stage-engine module — the public contract stays in
 *       stage_engine.h.
 *
 * Requires: stage_engine.h (public types) and xfer.h (brix_xfer_result_t) before
 *           inclusion.
 */

#include "stage_engine.h"   /* brix_stage_kind_t, brix_sd_instance_t, brix_stage_cred_t */
#include "xfer.h"           /* brix_xfer_result_t (stage_engine_run return type)        */

/*
 * One deferred (async) submit, held on the per-worker in-memory FIFO until the
 * scheduler drains it. The src/dst instances are the memoised per-worker tier
 * instances (they outlive the request), so holding the raw pointers is safe.
 * Shared because stage_journal_write() (journal half) marshals it while
 * brix_stage_submit() / the scheduler (scheduler half) build and drain it.
 */
typedef struct stage_pending_s {
    char                     reqid[40];
    brix_stage_kind_t        kind;
    brix_sd_instance_t      *src;
    char                     src_key[1024];
    brix_sd_instance_t      *dst;
    char                     dst_key[1024];
    char                     export_root[1024]; /* anchor for restart reconcile     */
    brix_stage_cred_t        cred;              /* owner identity for async flush   */
    struct stage_pending_s  *next;
} stage_pending_t;

/*
 * Journal seam — defined in stage_engine_journal.c, consumed by the scheduler and
 * reconcile halves. `stage_journal_dir` is the per-worker durable-journal path
 * ("" = in-memory only); the scheduler and reconcile read it to decide whether a
 * record is persisted. The three functions mint a reqid, persist a QUEUED record,
 * and remove a completed one.
 */
extern char stage_journal_dir[1024];

void stage_reqid_mint(char out[40]);
void stage_journal_write(const stage_pending_t *p);
void stage_journal_remove(const char *reqid);

/*
 * Durable-flush FAILURE persistence (write-back / tape write-out).
 *
 * A transient (non-denied) async FLUSH failure — the tape/remote origin was
 * unreachable — must leave a recoverable FAILED record in the journal rather
 * than being silently lost or left masquerading as QUEUED. Both helpers set
 * state=BRIX_SREQ_FAILED, stamp last_errno + finished_at, and re-persist the
 * record to its active journal slot (never dead-letter — a transient failure is
 * retried by the scheduler tick or the restart reconcile).
 *
 * stage_journal_mark_failed reads the on-disk record by reqid (the scheduler
 * completion path has only the reqid); stage_journal_bump_failed operates on a
 * record the caller already holds (the reconcile path) and ALSO increments
 * attempts, so a restart replay that re-drives a still-dead origin records the
 * re-drive by a higher attempt count.
 */
void stage_journal_mark_failed(const char *journal_dir, const char *reqid,
    int last_errno);
void stage_journal_bump_failed(const char *journal_dir, brix_sreq_t *rec,
    int last_errno);

/*
 * The generic inline mover — defined in stage_engine.c, called by the scheduler
 * (inline + thread paths) and the front doors. Moves the whole object `src_key`
 * on `src` to `dst_key` on `dst`, applying optional per-user credential
 * re-resolution, and books one unified audit line on the terminal state.
 */
brix_xfer_result_t stage_engine_run(brix_stage_kind_t kind,
    brix_sd_instance_t *src, const char *src_key,
    brix_sd_instance_t *dst, const char *dst_key,
    const brix_stage_cred_t *cred);

#endif /* BRIX_FS_XFER_STAGE_ENGINE_INTERNAL_H */
