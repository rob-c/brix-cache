/*
 * cta_queue_unittest.c — standalone unit test for the CTA request queue.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/cta_queue_ut \
 *       src/protocols/ssi/svc_cta/cta_queue_unittest.c \
 *       src/protocols/ssi/svc_cta/cta_queue.c \
 *       && /tmp/cta_queue_ut
 */
#include "cta_queue.h"
#include <stdio.h>
#include <stdlib.h>
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

/* Create a fresh queue in *qp and submit one `op` request owned by `owner`. */
static cta_req_t *
submit_one(brix_cta_queue_t **qp, cta_op_t op, const char *owner)
{
    cta_request_t r = mk(op);

    *qp = cta_queue_create();
    return cta_queue_submit(*qp, &r, owner);
}

static void test_submit_and_find(void)
{
    brix_cta_queue_t *q;
    cta_req_t *e = submit_one(&q, CTA_OP_ARCHIVE, "alice");
    CHECK(e != NULL);
    CHECK(e->state == CTA_ST_SUBMITTED);
    CHECK(strcmp(e->owner, "alice") == 0);
    CHECK(cta_queue_find(q, e->id) == e);
    CHECK(cta_queue_find(q, 999999) == NULL);
    cta_queue_destroy(q);
}

static void test_legal_and_illegal_transitions(void)
{
    brix_cta_queue_t *q;
    cta_req_t *e = submit_one(&q, CTA_OP_ARCHIVE, "u");
    CHECK(cta_queue_transition(q, e, CTA_ST_QUEUED) == 0);
    CHECK(cta_queue_transition(q, e, CTA_ST_ACTIVE) == 0);
    CHECK(cta_queue_transition(q, e, CTA_ST_COMPLETE) == 0);
    /* COMPLETE is terminal → no further transitions */
    CHECK(cta_queue_transition(q, e, CTA_ST_ACTIVE) == -1);
    CHECK(e->state == CTA_ST_COMPLETE);
    cta_queue_destroy(q);
}

static void test_cancel_owner_admin_gate(void)
{
    brix_cta_queue_t *q;
    cta_req_t *e = submit_one(&q, CTA_OP_RETRIEVE, "alice");

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
    brix_cta_queue_t *q;
    cta_req_t *e = submit_one(&q, CTA_OP_ARCHIVE, "carol");
    CHECK(cta_queue_cancel(q, e->id, "carol", 0) == 0);
    CHECK(e->state == CTA_ST_CANCELED);
    cta_queue_destroy(q);
}

static void test_active_count(void)
{
    brix_cta_queue_t *q;
    cta_req_t *a = submit_one(&q, CTA_OP_ARCHIVE, "u");
    cta_request_t r = mk(CTA_OP_ARCHIVE);
    cta_req_t *b = cta_queue_submit(q, &r, "u");
    CHECK(cta_queue_active_count(q) == 2);
    cta_queue_transition(q, a, CTA_ST_QUEUED);
    cta_queue_transition(q, a, CTA_ST_ACTIVE);
    cta_queue_transition(q, a, CTA_ST_COMPLETE);   /* terminal → no longer active */
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
        brix_cta_queue_t *q = cta_queue_create();
        cta_request_t r = mk(CTA_OP_ARCHIVE);
        cta_req_t *a, *b;
        CHECK(cta_queue_open_journal(q, path) == 0);
        a = cta_queue_submit(q, &r, "alice");
        b = cta_queue_submit(q, &r, "bob");
        a_id = a->id; b_id = b->id;
        cta_queue_transition(q, a, CTA_ST_QUEUED);
        cta_queue_transition(q, a, CTA_ST_ACTIVE);
        cta_queue_transition(q, a, CTA_ST_COMPLETE);
        cta_queue_destroy(q);
    }
    /* second run: replay restores both entries with their latest state */
    {
        brix_cta_queue_t *q = cta_queue_create();
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

/* A journal path in a scratch directory the caller owns. */
static const char *
journal_path(const char *leaf)
{
    static char buf[256];
    const char *dir = getenv("TMPDIR");

    snprintf(buf, sizeof(buf), "%s/%s", (dir && *dir) ? dir : "/tmp", leaf);
    return buf;
}

/*
 * The two halves of a journal round trip, factored out: every journal test
 * writes one request into a fresh journal and then reopens it in a second
 * queue. Kept as two helpers rather than one, because the replay half needs
 * further assertions on the live queue (a forged id that must be absent, an
 * ACL check on the entry that came back) before it is destroyed.
 */

/* Submit `req_path` as `owner` into a fresh journal at `path`; return its id. */
static uint64_t
journal_submit_one(const char *path, const char *req_path, const char *owner)
{
    brix_cta_queue_t *q = cta_queue_create();
    cta_request_t     r = mk(CTA_OP_ARCHIVE);
    cta_req_t        *e;
    uint64_t          id = 0;

    CHECK(cta_queue_open_journal(q, path) == 0);
    snprintf(r.path, sizeof(r.path), "%s", req_path);
    e = cta_queue_submit(q, &r, owner);
    CHECK(e != NULL);
    if (e != NULL) {
        id = e->id;
    }
    cta_queue_destroy(q);
    return id;
}

/* Replay `path` into a fresh queue; the caller destroys it. */
static brix_cta_queue_t *
journal_replay(const char *path)
{
    brix_cta_queue_t *q = cta_queue_create();

    CHECK(cta_queue_open_journal(q, path) == 0);
    return q;
}

/* Assert entry `id` replayed with exactly `req_path` and `owner`; return it. */
static cta_req_t *
journal_expect_entry(brix_cta_queue_t *q, uint64_t id, const char *req_path,
                     const char *owner)
{
    cta_req_t *e = cta_queue_find(q, id);

    CHECK(e != NULL);
    if (e != NULL) {
        CHECK(strcmp(e->req.path, req_path) == 0);
        CHECK(strcmp(e->owner, owner) == 0);
    }
    return e;
}

/*
 * The journal's text fields survive a round trip BYTE-EXACT, including the two
 * bytes its own record grammar reserves.
 *
 * A path is `Notification.file.lpath` and nothing filters it; a tab or newline
 * in one is unusual but perfectly legal, and replay must give back what was
 * submitted rather than a truncated or re-split version of it.
 */
static void test_journal_escapes_round_trip(void)
{
    const char *path = journal_path("cta_ut_escape.jrnl");
    /* every reserved byte, the escape byte itself, and a trailing lone
     * backslash — the shape most likely to run an unescaper off the end. */
    const char *nasty = "/tape/a\tb\nc\rd\\e\\";
    uint64_t    id;

    remove(path);
    id = journal_submit_one(path, nasty, "alice");
    {
        brix_cta_queue_t *q = journal_replay(path);

        journal_expect_entry(q, id, nasty, "alice");
        cta_queue_destroy(q);
    }
    remove(path);
}

/*
 * SECURITY NEGATIVE: a submitted path cannot forge a journal record.
 *
 * The request path is up to 1023 wire-chosen bytes. Written raw into a
 * tab-delimited, newline-terminated grammar, a path containing a newline
 * appends a SECOND record of the submitter's choosing — id, state and, worst,
 * `owner`, which is the principal cta_queue_cancel() checks. The forgery is
 * inert until the next replay, so the request that plants it looks unremarkable
 * at the time. Assert the whole payload comes back as ONE path on ONE entry and
 * that the id it names never appears.
 */
static void test_journal_path_cannot_forge_a_record(void)
{
    const char *path = journal_path("cta_ut_forge.jrnl");
    const char *forge = "/tape/ok\n4242\t0\t0\troot\t/tape/owned-by-root";
    uint64_t    id;

    remove(path);
    id = journal_submit_one(path, forge, "mallory");
    CHECK(id != 4242);              /* or the test proves nothing */
    {
        brix_cta_queue_t *q = journal_replay(path);
        cta_req_t        *e;

        /* the forged id was never a record */
        CHECK(cta_queue_find(q, 4242) == NULL);
        /* the payload is a path, whole, and still mallory's */
        e = journal_expect_entry(q, id, forge, "mallory");
        if (e != NULL) {
            /* and mallory did not become root by writing the word down */
            CHECK(cta_queue_cancel(q, e->id, "root", 0) == CTA_QUEUE_EACCES);
        }
        cta_queue_destroy(q);
    }
    remove(path);
}

/*
 * ERROR PATH: an over-long line is discarded WHOLE.
 *
 * No record this code writes can exceed the line buffer, so such a line is
 * corruption or a hand edit. fgets hands back its head and then its tail; if
 * the tail were parsed as a record of its own, a long field would let its
 * author resynchronise the parser onto bytes they chose — the forgery above
 * by a different door. Both halves must be dropped, and replay must keep going.
 */
/* One over-long line: `pad` filler bytes, then a complete forged record as its
 * tail. Written twice with different pads so that one of them lands the forged
 * record exactly on fgets' read boundary whatever the (private) line cap is —
 * that alignment IS the attack, so a layout that always splits mid-filler would
 * make the assertion below vacuous. 4081 is the exact hit for a 4096 cap. */
static void
write_overlong(FILE *f, int pad)
{
    int i;

    fprintf(f, "9\t0\t0\tmallory\t");            /* 14 bytes */
    for (i = 0; i < pad; i++) {
        fputc('A', f);
    }
    fprintf(f, "7777\t0\t0\troot\t/tape/owned-by-root\n");
    fflush(f);
}

/*
 * ERROR PATH: an over-long line is discarded WHOLE.
 *
 * No record this code writes can exceed the line buffer, so such a line is
 * corruption or a hand edit. fgets hands back its head and then its tail; if
 * the tail were parsed as a record of its own, a long field would let its
 * author resynchronise the parser onto bytes they chose — the forgery above
 * by a different door. Both halves must be dropped, and replay must keep going.
 */
static void test_journal_overlong_line_is_dropped_whole(void)
{
    const char *path = journal_path("cta_ut_overlong.jrnl");
    FILE       *f;

    remove(path);
    f = fopen(path, "w");
    CHECK(f != NULL);
    if (f == NULL) {
        return;
    }
    write_overlong(f, 4081);   /* forged tail exactly on the 4096 boundary */
    write_overlong(f, 5000);   /* and one that splits mid-filler */
    /* a legitimate record after both: replay must recover, not stop */
    fprintf(f, "11\t0\t0\talice\t/tape/real\n");
    fclose(f);

    {
        brix_cta_queue_t *q = cta_queue_create();
        cta_req_t *e;

        CHECK(cta_queue_open_journal(q, path) == 0);
        CHECK(cta_queue_find(q, 9) == NULL);      /* the head is not a record */
        CHECK(cta_queue_find(q, 7777) == NULL);   /* nor is the tail */
        e = cta_queue_find(q, 11);
        CHECK(e != NULL);                          /* and replay carried on */
        if (e != NULL) {
            CHECK(strcmp(e->owner, "alice") == 0);
        }
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
    test_journal_escapes_round_trip();
    test_journal_path_cannot_forge_a_record();
    test_journal_overlong_line_is_dropped_whole();
    printf(g_fail ? "FAILED (%d)\n" : "OK\n", g_fail);
    return g_fail ? 1 : 0;
}
