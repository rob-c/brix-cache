#ifndef BRIX_SSI_CTA_EXEC_H
#define BRIX_SSI_CTA_EXEC_H

/*
 * cta_exec.h — CTA request executor (pluggable vtable).
 *
 * WHAT: drives a queued request through its lifecycle, emitting progress alerts.
 * WHY:  separates the "what work happens" (archive/retrieve/cancel) from the SSI
 *       glue, so the test build simulates tape transitions while a production
 *       build hooks the real nearline/tape engine.
 * HOW:  a vtable per backend; the SSI service supplies a progress callback that
 *       forwards each alert to the client. Pure C, standalone-testable.
 */

#include "cta_queue.h"

/*
 * Progress sink: the executor calls alert(ctx, msg) at each lifecycle step, in
 * the queue `q`, transitioning through `transition`.
 *
 * The queue rides HERE, and not on cta_req_t, because the queue lives in shared
 * memory (cta_shm.c): an entry may hold no pointer into one process's address
 * space. It rides here, and not as a fourth executor parameter, because every
 * executor already receives the sink. `q` is first so that the old two-field
 * positional initialisers fail to compile rather than silently leaving it NULL.
 *
 * `transition` is the seam that keeps the zone lock OFF the executor run: the
 * nginx build supplies brix_cta_shm_transition, which takes the lock for one
 * transition and drops it, so a production executor blocking on tape does not
 * hold the whole worker set out of the queue. NULL means "call the queue
 * directly", which is what the standalone unit suites want.
 */
typedef struct {
    brix_cta_queue_t *q;
    int (*transition)(brix_cta_queue_t *q, cta_req_t *e, cta_state_t to);
    void (*alert)(void *ctx, const char *msg);
    void  *ctx;
} cta_progress_t;

/* Every entry takes the same (entry, progress) pair — cancel included, so that
 * it too reaches the queue it must transition. */
typedef struct {
    int (*archive)(cta_req_t *e, cta_progress_t *p);   /* 0 ok, -1 failed */
    int (*retrieve)(cta_req_t *e, cta_progress_t *p);
    int (*cancel)(cta_req_t *e, cta_progress_t *p);
} cta_exec_vtbl_t;

/* The simulated executor: deterministic state transitions + progress alerts, no
 * real storage. Used in tests and where no nearline backend is configured. */
const cta_exec_vtbl_t *cta_exec_test_vtbl(void);

/* The production executor: archive/retrieve hook the real tier/frm engine. In a
 * build without a nearline backend these fail with a clear error (the documented
 * seam — see cta_exec.c). */
const cta_exec_vtbl_t *cta_exec_prod_vtbl(void);

/* Dispatch a request to the vtable by its op (archive/retrieve/cancel). Returns
 * the executor result, or -1 for an op the executor does not handle (e.g. query). */
int cta_exec_run(const cta_exec_vtbl_t *vt, cta_req_t *e, cta_progress_t *p);

#endif /* BRIX_SSI_CTA_EXEC_H */
