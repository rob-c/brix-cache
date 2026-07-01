/*
 * cta_queue_unittest.c — standalone unit test for the CTA request queue.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/cta_queue_ut \
 *       src/ssi/svc_cta/cta_queue_unittest.c src/ssi/svc_cta/cta_queue.c \
 *       && /tmp/cta_queue_ut
 */
#include "cta_queue.h"
#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

static cta_request_t mk(cta_op_t op)
{
    cta_request_t r;
    memset(&r, 0, sizeof(r));
    r.op = op;
    return r;
}

static void test_submit_and_find(void)
{
    xrootd_cta_queue_t *q = cta_queue_create();
    cta_request_t r = mk(CTA_OP_ARCHIVE);
    cta_req_t *e = cta_queue_submit(q, &r, "alice");
    CHECK(e != NULL);
    CHECK(e->state == CTA_ST_SUBMITTED);
    CHECK(strcmp(e->owner, "alice") == 0);
    CHECK(cta_queue_find(q, e->id) == e);
    CHECK(cta_queue_find(q, 999999) == NULL);
    cta_queue_destroy(q);
}

static void test_legal_and_illegal_transitions(void)
{
    xrootd_cta_queue_t *q = cta_queue_create();
    cta_request_t r = mk(CTA_OP_ARCHIVE);
    cta_req_t *e = cta_queue_submit(q, &r, "u");
    CHECK(cta_queue_transition(e, CTA_ST_QUEUED) == 0);
    CHECK(cta_queue_transition(e, CTA_ST_ACTIVE) == 0);
    CHECK(cta_queue_transition(e, CTA_ST_COMPLETE) == 0);
    /* COMPLETE is terminal → no further transitions */
    CHECK(cta_queue_transition(e, CTA_ST_ACTIVE) == -1);
    CHECK(e->state == CTA_ST_COMPLETE);
    cta_queue_destroy(q);
}

static void test_cancel_owner_admin_gate(void)
{
    xrootd_cta_queue_t *q = cta_queue_create();
    cta_request_t r = mk(CTA_OP_RETRIEVE);
    cta_req_t *e = cta_queue_submit(q, &r, "alice");

    /* a different non-admin requester is denied */
    CHECK(cta_queue_cancel(q, e->id, "bob", 0) == CTA_QUEUE_EACCES);
    CHECK(e->state != CTA_ST_CANCELED);
    /* an admin may cancel anyone's request */
    CHECK(cta_queue_cancel(q, e->id, "bob", 1) == 0);
    CHECK(e->state == CTA_ST_CANCELED);

    /* unknown id */
    CHECK(cta_queue_cancel(q, 424242, "alice", 0) == CTA_QUEUE_ENOENT);
    cta_queue_destroy(q);
}

static void test_owner_can_cancel(void)
{
    xrootd_cta_queue_t *q = cta_queue_create();
    cta_request_t r = mk(CTA_OP_ARCHIVE);
    cta_req_t *e = cta_queue_submit(q, &r, "carol");
    CHECK(cta_queue_cancel(q, e->id, "carol", 0) == 0);
    CHECK(e->state == CTA_ST_CANCELED);
    cta_queue_destroy(q);
}

static void test_active_count(void)
{
    xrootd_cta_queue_t *q = cta_queue_create();
    cta_request_t r = mk(CTA_OP_ARCHIVE);
    cta_req_t *a = cta_queue_submit(q, &r, "u");
    cta_req_t *b = cta_queue_submit(q, &r, "u");
    CHECK(cta_queue_active_count(q) == 2);
    cta_queue_transition(a, CTA_ST_QUEUED);
    cta_queue_transition(a, CTA_ST_ACTIVE);
    cta_queue_transition(a, CTA_ST_COMPLETE);   /* terminal → no longer active */
    CHECK(cta_queue_active_count(q) == 1);
    (void) b;
    cta_queue_destroy(q);
}

static void test_journal_round_trip(void)
{
    const char *path = "/tmp/cta_queue_ut.journal";
    uint64_t a_id, b_id;
    remove(path);

    /* first run: submit two requests, advance one to COMPLETE */
    {
        xrootd_cta_queue_t *q = cta_queue_create();
        cta_request_t r = mk(CTA_OP_ARCHIVE);
        cta_req_t *a, *b;
        CHECK(cta_queue_open_journal(q, path) == 0);
        a = cta_queue_submit(q, &r, "alice");
        b = cta_queue_submit(q, &r, "bob");
        a_id = a->id; b_id = b->id;
        cta_queue_transition(a, CTA_ST_QUEUED);
        cta_queue_transition(a, CTA_ST_ACTIVE);
        cta_queue_transition(a, CTA_ST_COMPLETE);
        cta_queue_destroy(q);
    }
    /* second run: replay restores both entries with their latest state */
    {
        xrootd_cta_queue_t *q = cta_queue_create();
        cta_req_t *a, *b;
        CHECK(cta_queue_open_journal(q, path) == 0);
        a = cta_queue_find(q, a_id);
        b = cta_queue_find(q, b_id);
        CHECK(a != NULL && a->state == CTA_ST_COMPLETE);
        CHECK(b != NULL && b->state == CTA_ST_SUBMITTED);
        CHECK(strcmp(a->owner, "alice") == 0);
        /* next_id advanced past the replayed ids */
        CHECK(cta_queue_submit(q, &(cta_request_t){0}, "x")->id > b_id);
        cta_queue_destroy(q);
    }
    remove(path);
}

int main(void)
{
    test_submit_and_find();
    test_legal_and_illegal_transitions();
    test_cancel_owner_admin_gate();
    test_owner_can_cancel();
    test_active_count();
    test_journal_round_trip();
    printf(g_fail ? "FAILED (%d)\n" : "OK\n", g_fail);
    return g_fail ? 1 : 0;
}
