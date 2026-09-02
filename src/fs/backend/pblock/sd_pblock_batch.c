/*
 * sd_pblock_batch.c - bulk namespace delete for the packed-block store
 * (phase-107 C4).
 *
 * WHAT: sd_pblock_unlink_many and the gated core its _cred twin shares. The
 *       whole window runs inside ONE SQLite transaction: N unlinks cost one
 *       journal commit (one fsync in WAL) instead of N autocommits.
 * WHY:  This driver has no wire batch to exploit - the win is transactional.
 *       The per-key semantics are IDENTICAL to sd_pblock_unlink called in a
 *       loop (lease gate F15, trash push F11, refcount release F10, audit F17
 *       all run per key); only the commit boundary moves.
 * HOW:  BEGIN IMMEDIATE -> per-key [gate ->] sd_pblock_unlink -> COMMIT. A
 *       per-key failure is RECORDED (errs[i]) and the batch continues - a
 *       failed statement does not poison the transaction. Only a failed
 *       BEGIN/COMMIT fails the batch itself (done = 0: the rollback un-did
 *       every key, so none may be reported deleted). No slot in the unlink
 *       call graph opens its own transaction (rename and the snapshot ctl
 *       mutators do, but directories never enter a batch - contract in
 *       sd_batch_types.h), so the wrap cannot nest.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "sd_pblock_catalog.h"
#include "pblock_store.h"
#include "sd_pblock_internal.h"
#include "sd_pblock_catalog_internal.h"   /* cat_exec (transaction control) */

#include <errno.h>

/*
 * The shared core. `gate` is the _cred twin's per-key POSIX authority check
 * (W+X on the parent + sticky rule, sd_pblock_cred.c); NULL for the plain
 * slot and for a service identity. A key the gate refuses records the gate's
 * errno and is NEVER attempted - the authority verdict must precede the
 * mutation, per key, exactly as the single-key slot orders it.
 */
ngx_int_t
sd_pblock_unlink_many_core(brix_sd_instance_t *inst, brix_sd_unlink_batch_t *b,
    sd_pblock_key_gate_fn gate, void *gctx)
{
    pblock_state_t *st = inst->state;
    size_t          i;

    if (b->n > BRIX_SD_BULK_DELETE_WINDOW) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (b->n == 0) {
        b->done = 0;
        return NGX_OK;
    }
    if (cat_exec(st->cat, "BEGIN IMMEDIATE;") != 0) {
        errno = EIO;
        return NGX_ERROR;
    }
    for (i = 0; i < b->n; i++) {
        errno = 0;
        if (gate != NULL && gate(gctx, b->paths[i]) != NGX_OK) {
            b->errs[i] = (errno != 0) ? errno : EACCES;
            continue;
        }
        if (sd_pblock_unlink(inst, b->paths[i], 0) == NGX_OK) {
            b->errs[i] = 0;
        } else {
            b->errs[i] = (errno != 0) ? errno : EIO;
        }
    }
    b->done = b->n;
    if (cat_exec(st->cat, "COMMIT;") != 0) {
        /* The rollback un-does every key above: report NONE attempted, or a
         * caller would answer <Deleted> for rows that still exist. */
        (void) cat_exec(st->cat, "ROLLBACK;");
        b->done = 0;
        errno = EIO;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* The plain slot: no per-key gate (service identity, like sd_pblock_unlink).
 * No BRIX_SD_CAP_BULK_DELETE on this driver - the slot exists for the
 * transaction, and the VFS windows an unadvertised slot at 1... which still
 * buys the single-key case nothing and the rmtree/DeleteObjects callers use
 * the window the cap advertises. The cap decision lives with the descriptor
 * (sd_pblock.c). */
ngx_int_t
sd_pblock_unlink_many(brix_sd_instance_t *inst, brix_sd_unlink_batch_t *b)
{
    return sd_pblock_unlink_many_core(inst, b, NULL, NULL);
}

#endif /* BRIX_HAVE_SQLITE */
