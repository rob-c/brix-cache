/*
 * cta_exec.c — CTA request executor. See cta_exec.h.
 *
 * The test executor walks the lifecycle deterministically and emits a progress
 * alert at each step, so the whole SSI archive/retrieve flow (waitresp → alerts →
 * response) is exercised without a tape system. The production executor is the
 * documented seam where archive/retrieve hook the real tier/frm engine.
 */

#include "cta_exec.h"
#include <stddef.h>

static void
emit(cta_progress_t *p, const char *msg)
{
    if (p != NULL && p->alert != NULL) {
        p->alert(p->ctx, msg);
    }
}

/* Advance through QUEUED → ACTIVE → COMPLETE, alerting at each step. */
static int
sim_lifecycle(cta_req_t *e, cta_progress_t *p, const char *queued_msg,
              const char *active_msg)
{
    if (cta_queue_transition(e, CTA_ST_QUEUED) != 0) {
        return -1;
    }
    emit(p, queued_msg);
    if (cta_queue_transition(e, CTA_ST_ACTIVE) != 0) {
        return -1;
    }
    emit(p, active_msg);
    if (cta_queue_transition(e, CTA_ST_COMPLETE) != 0) {
        return -1;
    }
    return 0;
}

static int
test_archive(cta_req_t *e, cta_progress_t *p)
{
    return sim_lifecycle(e, p, "queued for archival", "writing to tape");
}

static int
test_retrieve(cta_req_t *e, cta_progress_t *p)
{
    return sim_lifecycle(e, p, "queued for retrieval", "recalling from tape");
}

static int
test_cancel(cta_req_t *e)
{
    return cta_queue_transition(e, CTA_ST_CANCELED);
}

static const cta_exec_vtbl_t test_vtbl = {
    test_archive, test_retrieve, test_cancel
};

const cta_exec_vtbl_t *
cta_exec_test_vtbl(void)
{
    return &test_vtbl;
}

/*
 * Production executor seam. In a build without a configured nearline/tape backend
 * archive and retrieve cannot do real work, so they fail cleanly. The real wiring
 * (retrieve → fs/tier + fs/xfer/stage_engine + frm to recall an object online;
 * archive → tape-write hook) lands here when a NEARLINE backend exists; it must
 * drive the same cta_queue transitions + progress alerts as the test executor.
 */
static int
prod_archive(cta_req_t *e, cta_progress_t *p)
{
    (void) e;
    emit(p, "no nearline backend configured");
    return -1;
}

static int
prod_retrieve(cta_req_t *e, cta_progress_t *p)
{
    (void) e;
    emit(p, "no nearline backend configured");
    return -1;
}

static const cta_exec_vtbl_t prod_vtbl = {
    prod_archive, prod_retrieve, test_cancel   /* cancel is backend-agnostic */
};

const cta_exec_vtbl_t *
cta_exec_prod_vtbl(void)
{
    return &prod_vtbl;
}

int
cta_exec_run(const cta_exec_vtbl_t *vt, cta_req_t *e, cta_progress_t *p)
{
    switch (e->req.op) {
    case CTA_OP_ARCHIVE:
        return vt->archive(e, p);
    case CTA_OP_RETRIEVE:
        return vt->retrieve(e, p);
    case CTA_OP_CANCEL:
        return vt->cancel(e);
    case CTA_OP_QUERY:
    case CTA_OP_UNKNOWN:
    default:
        return -1;   /* not an executor op (query is handled by the service) */
    }
}
