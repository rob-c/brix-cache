/*
 * cta_exec_unittest.c — standalone unit test for the CTA executor vtable.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/cta_exec_ut \
 *       src/ssi/svc_cta/cta_exec_unittest.c src/ssi/svc_cta/cta_exec.c \
 *       src/ssi/svc_cta/cta_queue.c && /tmp/cta_exec_ut
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

static cta_req_t *submit(xrootd_cta_queue_t *q, cta_op_t op)
{
    cta_request_t r;
    memset(&r, 0, sizeof(r));
    r.op = op;
    return cta_queue_submit(q, &r, "u");
}

static void test_archive_completes_with_alerts(void)
{
    xrootd_cta_queue_t *q = cta_queue_create();
    cta_req_t *e = submit(q, CTA_OP_ARCHIVE);
    cta_progress_t prog = { rec_alert, NULL };
    g_nalerts = 0;
    CHECK(cta_exec_run(cta_exec_test_vtbl(), e, &prog) == 0);
    CHECK(e->state == CTA_ST_COMPLETE);
    CHECK(g_nalerts >= 2);   /* at least "queued" + "active" progress */
    cta_queue_destroy(q);
}

static void test_retrieve_completes(void)
{
    xrootd_cta_queue_t *q = cta_queue_create();
    cta_req_t *e = submit(q, CTA_OP_RETRIEVE);
    cta_progress_t prog = { rec_alert, NULL };
    g_nalerts = 0;
    CHECK(cta_exec_run(cta_exec_test_vtbl(), e, &prog) == 0);
    CHECK(e->state == CTA_ST_COMPLETE);
    cta_queue_destroy(q);
}

static void test_cancel_transitions(void)
{
    xrootd_cta_queue_t *q = cta_queue_create();
    cta_req_t *e = submit(q, CTA_OP_CANCEL);
    cta_progress_t prog = { rec_alert, NULL };
    CHECK(cta_exec_run(cta_exec_test_vtbl(), e, &prog) == 0);
    CHECK(e->state == CTA_ST_CANCELED);
    cta_queue_destroy(q);
}

static void test_query_not_an_exec_op(void)
{
    xrootd_cta_queue_t *q = cta_queue_create();
    cta_req_t *e = submit(q, CTA_OP_QUERY);
    cta_progress_t prog = { rec_alert, NULL };
    CHECK(cta_exec_run(cta_exec_test_vtbl(), e, &prog) == -1);
    cta_queue_destroy(q);
}

static void test_prod_archive_fails_without_backend(void)
{
    xrootd_cta_queue_t *q = cta_queue_create();
    cta_req_t *e = submit(q, CTA_OP_ARCHIVE);
    cta_progress_t prog = { rec_alert, NULL };
    /* no nearline backend in this build → prod executor reports failure */
    CHECK(cta_exec_run(cta_exec_prod_vtbl(), e, &prog) == -1);
    cta_queue_destroy(q);
}

int main(void)
{
    test_archive_completes_with_alerts();
    test_retrieve_completes();
    test_cancel_transitions();
    test_query_not_an_exec_op();
    test_prod_archive_fails_without_backend();
    printf(g_fail ? "FAILED (%d)\n" : "OK\n", g_fail);
    return g_fail ? 1 : 0;
}
