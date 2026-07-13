#ifndef BRIX_SD_STAGE_H
#define BRIX_SD_STAGE_H

/*
 * sd_stage.h - the generic write-stage decorator (phase-64 section 12.2; was the
 * phase-63 C-2/C-6 write-back stager).
 *
 * WHAT: An SD-driver instance that WRAPS a source backend (`source`) and an
 *       explicit STAGE STORE instance (`store`, any driver), interposing only the
 *       staged-write path: a staged upload lands on the stage store and is FLUSHED
 *       to the backend on commit through the one staging engine. Every read /
 *       namespace / xattr op delegates straight to `source` (open returns the
 *       source's own object, so reads bypass the decorator).
 *
 * WHY:  Phase-63 hard-coded the stage area as a local POSIX directory under the
 *       export root and promoted with a bespoke temp-file loop. Phase-64 makes the
 *       stage area a first-class TIER (`store`, which may be local or a remote
 *       stage server) and routes the flush through brix_stage_submit / _run_inline
 *       - the ONE async-staging engine every write-back/upload/migrate path shares
 *       (P5, G9). A posix stage store is byte-equivalent to phase-63.
 *
 * HOW:  staged_open -> store->driver->staged_open; staged_write ->
 *       store->driver->staged_write; staged_commit publishes the object on the
 *       stage store then brix_stage_run_inline(FLUSH, store, key, source, key)
 *       moves it to the backend (sync) - the durable async-defer arrives with the
 *       SP4 queue; staged_abort drops the stage temp. See docs/refactor/phase-64-
 *       fully-tiered-composable-storage.md (section 11, 12.2, Appendix J4).
 */

#include <ngx_core.h>

#include "fs/backend/sd.h"
#include "fs/tier/tier.h"         /* brix_stage_policy_t */
#include "fs/xfer/stage_engine.h" /* brix_stage_cred_t (reflush cred param)   */

/* Wrap `source` in a write-stage decorator buffering staged writes on the `store`
 * instance, with `policy` (flush sync/async; copied; NULL = a default sync flush).
 * Returns a malloc-owned instance (worker-safe, no nginx pool), or NULL (errno
 * set). `source` and `store` are BORROWED - not freed by brix_sd_stage_destroy
 * (the registry owns them). NULL source/store -> NULL. */
brix_sd_instance_t *brix_sd_stage_create(brix_sd_instance_t *source,
    brix_sd_instance_t *store, const brix_stage_policy_t *policy,
    const char *root_canon, ngx_log_t *log);

/* Free a decorator built by brix_sd_stage_create (NOT the wrapped source/store). */
void brix_sd_stage_destroy(brix_sd_instance_t *inst);

/* 1 iff `inst` is a stage decorator built by brix_sd_stage_create. */
int brix_sd_stage_instance_is(const brix_sd_instance_t *inst);

/* The stage SOURCE instance (reads forward to it), or NULL if not a stage
 * decorator. Used by the serve-locality predicate. */
brix_sd_instance_t *brix_sd_stage_source_instance(
    const brix_sd_instance_t *inst);

/* The stage STORE instance (the staged-object buffer), or NULL if not a stage. */
brix_sd_instance_t *brix_sd_stage_store_instance(
    const brix_sd_instance_t *inst);

/* SP4 restart-reconcile: re-flush durable staged object `key` (stage store ->
 * backend) and drop the stage copy.  `cred` carries the owner identity so a
 * restart-reconcile can authenticate as the original user; NULL uses the service
 * credential.  NGX_OK / NGX_DECLINED / NGX_ERROR. */
ngx_int_t brix_sd_stage_reflush(brix_sd_instance_t *inst, const char *key,
    const brix_stage_cred_t *cred);

#endif /* BRIX_SD_STAGE_H */
