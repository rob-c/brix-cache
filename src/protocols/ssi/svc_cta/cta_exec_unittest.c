/*
 * cta_exec_unittest.c — standalone unit test for the CTA executor vtable.
 *
 *   gcc -Wall -Wextra -Werror -I src -I src/protocols/ssi/svc_cta \
 *       -o /tmp/cta_exec_ut \
 *       src/protocols/ssi/svc_cta/cta_exec_unittest.c \
 *       src/protocols/ssi/svc_cta/cta_exec.c \
 *       src/protocols/ssi/svc_cta/cta_queue.c && /tmp/cta_exec_ut
 */
#include "cta_exec.h"
#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

/* recording progress sink */
static char  g_alerts[8][64];
static int   g_nalerts;
static void  rec_alert(void *ctx, const char *msg)
{
    (void) ctx;
    if (g_nalerts < 8) {
        size_t n = strlen(msg);
        if (n >= sizeof(g_alerts[0])) n = sizeof(g_alerts[0]) - 1;
        memcpy(g_alerts[g_nalerts], msg, n);
        g_alerts[g_nalerts][n] = '\0';
        g_nalerts++;
    }
}

static cta_req_t *submit(brix_cta_queue_t *q, cta_op_t op)
{
    cta_request_t r;
    memset(&r, 0, sizeof(r));
    r.op = op;
    return cta_queue_submit(q, &r, "u");
}

/*
 * Run one op through a vtable on a throwaway queue, hand back the entry's
 * final state, and leave the executor's return in *rc. The five cases below
 * differ only in vtable, op, and expected outcome — the setup was identical
 * in all of them.
 */
static cta_state_t
run_one(const cta_exec_vtbl_t *vt, cta_op_t op, int *rc)
{
    brix_cta_queue_t *q = cta_queue_create();
    cta_req_t        *e = submit(q, op);
    cta_progress_t    prog = { q, NULL, rec_alert, NULL };
    cta_state_t       st;

    g_nalerts = 0;
    *rc = cta_exec_run(vt, e, &prog);
    st = e->state;
    cta_queue_destroy(q);
    return st;
}

static void test_archive_completes_with_alerts(void)
{
    int rc;
    CHECK(run_one(cta_exec_test_vtbl(), CTA_OP_ARCHIVE, &rc) == CTA_ST_COMPLETE);
    CHECK(rc == 0);
    CHECK(g_nalerts >= 2);   /* at least "queued" + "active" progress */
}

static void test_retrieve_completes(void)
{
    int rc;
    CHECK(run_one(cta_exec_test_vtbl(), CTA_OP_RETRIEVE, &rc) == CTA_ST_COMPLETE);
    CHECK(rc == 0);
}

static void test_cancel_transitions(void)
{
    int rc;
    CHECK(run_one(cta_exec_test_vtbl(), CTA_OP_CANCEL, &rc) == CTA_ST_CANCELED);
    CHECK(rc == 0);
}

static void test_query_not_an_exec_op(void)
{
    int rc;
    (void) run_one(cta_exec_test_vtbl(), CTA_OP_QUERY, &rc);
    CHECK(rc == -1);
}

static void test_prod_archive_fails_without_backend(void)
{
    int rc;
    /* no nearline backend in this build → prod executor reports failure */
    (void) run_one(cta_exec_prod_vtbl(), CTA_OP_ARCHIVE, &rc);
    CHECK(rc == -1);
}


/* ---- the transition seam ------------------------------------------------
 *
 * The executor moves entries through cta_progress_t::transition so that the
 * nginx build can take the shared-zone lock once per transition instead of
 * holding it for the length of an archive or retrieve. These pin both halves
 * of that seam: the hook is used when supplied, and the queue is called
 * directly when it is not.
 */

static int g_hook_calls;
static int
counting_transition(brix_cta_queue_t *q, cta_req_t *e, cta_state_t to)
{
    g_hook_calls++;
    return cta_queue_transition(q, e, to);
}

static void test_the_executor_transitions_through_the_hook(void)
{
    brix_cta_queue_t *q = cta_queue_create();
    cta_req_t *e = submit(q, CTA_OP_ARCHIVE);
    cta_progress_t prog = { q, counting_transition, rec_alert, NULL };
    g_hook_calls = 0;
    CHECK(cta_exec_run(cta_exec_test_vtbl(), e, &prog) == 0);
    CHECK(e->state == CTA_ST_COMPLETE);
    CHECK(g_hook_calls == 3);   /* QUEUED, ACTIVE, COMPLETE */
    cta_queue_destroy(q);
}

static void test_a_null_hook_falls_back_to_the_queue(void)
{
    brix_cta_queue_t *q = cta_queue_create();
    cta_req_t *e = submit(q, CTA_OP_ARCHIVE);
    cta_progress_t prog = { q, NULL, rec_alert, NULL };
    g_hook_calls = 0;
    CHECK(cta_exec_run(cta_exec_test_vtbl(), e, &prog) == 0);
    CHECK(e->state == CTA_ST_COMPLETE);
    CHECK(g_hook_calls == 0);
    cta_queue_destroy(q);
}

/* Security-negative: an executor handed no queue must refuse, not transition
 * an entry it cannot journal. This is the shape a caller hits when the SHM
 * zone is absent — the case that must NOT silently fall back to a private
 * queue and fabricate a durability guarantee. */
static void test_no_queue_refuses_every_op(void)
{
    brix_cta_queue_t *q = cta_queue_create();
    cta_req_t *arch = submit(q, CTA_OP_ARCHIVE);
    cta_req_t *retr = submit(q, CTA_OP_RETRIEVE);
    cta_req_t *canc = submit(q, CTA_OP_CANCEL);
    cta_progress_t none = { NULL, NULL, rec_alert, NULL };

    CHECK(cta_exec_run(cta_exec_test_vtbl(), arch, &none) == -1);
    CHECK(arch->state == CTA_ST_SUBMITTED);
    CHECK(cta_exec_run(cta_exec_test_vtbl(), retr, &none) == -1);
    CHECK(retr->state == CTA_ST_SUBMITTED);
    CHECK(cta_exec_run(cta_exec_test_vtbl(), canc, &none) == -1);
    CHECK(canc->state == CTA_ST_SUBMITTED);

    /* and with no sink at all */
    CHECK(cta_exec_run(cta_exec_test_vtbl(), arch, NULL) == -1);
    CHECK(arch->state == CTA_ST_SUBMITTED);
    cta_queue_destroy(q);
}

int main(void)
{
    test_archive_completes_with_alerts();
    test_retrieve_completes();
    test_cancel_transitions();
    test_query_not_an_exec_op();
    test_prod_archive_fails_without_backend();
    test_the_executor_transitions_through_the_hook();
    test_a_null_hook_falls_back_to_the_queue();
    test_no_queue_refuses_every_op();
    printf(g_fail ? "FAILED (%d)\n" : "OK\n", g_fail);
    return g_fail ? 1 : 0;
}
