/* cpool_unittest.c — brix_cpool engine, no network. Compiled by
 * tests/cmdscripts/cpool_unit.py with cpool.c + status.c + pthread,
 * -Wall -Wextra -Werror. */
#include "brix.h"
#include "net/cpool.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

typedef struct { int id; } fake_conn;

typedef struct {
    atomic_int connects;
    atomic_int closes;
    int        fail_slot0;   /* make the very first connect fail */
    atomic_int seen;         /* how many connects have happened, for fail_slot0 */
} fake_ctx;

static int
fake_connect(void *conn, void *ctx, brix_status *st)
{
    fake_ctx  *c = ctx;
    fake_conn *fc = conn;
    if (c->fail_slot0 && atomic_fetch_add(&c->seen, 1) == 0) {
        brix_status_set(st, XRDC_ESOCK, 0, "fake: refused");
        return -1;
    }
    fc->id = atomic_fetch_add(&c->connects, 1) + 1;
    return 0;
}
static void fake_close(void *conn) { (void) conn; }
/* separate close-counting vtable for the destroy test */
static fake_ctx *g_close_ctx;
static void fake_close_counting(void *conn) { (void) conn; atomic_fetch_add(&g_close_ctx->closes, 1); }

static const brix_cpool_vtbl VT = { sizeof(fake_conn), fake_connect, fake_close };

static void
test_reuse(void)
{
    fake_ctx     ctx = {0};
    brix_status  st; brix_status_clear(&st);
    brix_cpool  *p = brix_cpool_create(&VT, &ctx, 4, &st);
    int          i;
    assert(p != NULL);
    assert(atomic_load(&ctx.connects) == 1);          /* eager slot-0 only */
    for (i = 0; i < 20; i++) {
        void *c = brix_cpool_checkout(p, &st);
        assert(c != NULL);
        brix_cpool_checkin(p, c, 1);                  /* healthy → reuse */
    }
    /* single-threaded serial reuse never opens a 2nd slot */
    assert(atomic_load(&ctx.connects) == 1);
    brix_cpool_destroy(p);
    printf("ok test_reuse\n");
}

static void
test_health_drop_reconnects(void)
{
    fake_ctx     ctx = {0};
    brix_status  st; brix_status_clear(&st);
    brix_cpool  *p = brix_cpool_create(&VT, &ctx, 1, &st);
    void        *c;
    assert(p != NULL && atomic_load(&ctx.connects) == 1);
    c = brix_cpool_checkout(p, &st); assert(c != NULL);
    brix_cpool_checkin(p, c, 0);                       /* unhealthy → drop */
    c = brix_cpool_checkout(p, &st); assert(c != NULL);
    assert(atomic_load(&ctx.connects) == 2);           /* reconnected */
    brix_cpool_checkin(p, c, 1);
    brix_cpool_destroy(p);
    printf("ok test_health_drop_reconnects\n");
}

static void
test_create_fails_on_bad_endpoint(void)
{
    fake_ctx     ctx = {0}; ctx.fail_slot0 = 1;
    brix_status  st; brix_status_clear(&st);
    brix_cpool  *p = brix_cpool_create(&VT, &ctx, 4, &st);
    assert(p == NULL);                                 /* eager slot-0 failed */
    assert(st.kxr == XRDC_ESOCK);
    printf("ok test_create_fails_on_bad_endpoint\n");
}

/* N+1 threads contend for N slots: assert no conn pointer is ever held by two
 * threads at once (unique-issue), and the (N+1)th blocks then proceeds. */
#define NSLOT 3
#define NTHR  (NSLOT + 1)
static brix_cpool  *g_p;
static atomic_int    g_inflight[64];   /* per-slot-id in-use flag */
static void *
worker(void *arg)
{
    int          rounds = *(int *) arg, r;
    brix_status  st; brix_status_clear(&st);
    for (r = 0; r < rounds; r++) {
        fake_conn *c = brix_cpool_checkout(g_p, &st);
        assert(c != NULL);
        int prev = atomic_fetch_add(&g_inflight[c->id], 1);
        assert(prev == 0);                             /* NOT double-issued */
        atomic_fetch_sub(&g_inflight[c->id], 1);
        brix_cpool_checkin(g_p, c, 1);
    }
    return NULL;
}
static void
test_contention_unique_issue(void)
{
    fake_ctx     ctx = {0};
    brix_status  st; brix_status_clear(&st);
    pthread_t    th[NTHR];
    int          rounds = 500, i;
    memset(g_inflight, 0, sizeof(g_inflight));
    g_p = brix_cpool_create(&VT, &ctx, NSLOT, &st);
    assert(g_p != NULL);
    for (i = 0; i < NTHR; i++) pthread_create(&th[i], NULL, worker, &rounds);
    for (i = 0; i < NTHR; i++) pthread_join(th[i], NULL);
    assert(atomic_load(&ctx.connects) <= NSLOT);       /* never more than N */
    brix_cpool_destroy(g_p);
    printf("ok test_contention_unique_issue\n");
}

static void
test_destroy_closes_connected(void)
{
    fake_ctx           ctx = {0};
    brix_cpool_vtbl    vt = { sizeof(fake_conn), fake_connect, fake_close_counting };
    brix_status        st; brix_status_clear(&st);
    brix_cpool        *p;
    void              *a, *b;
    g_close_ctx = &ctx;
    p = brix_cpool_create(&vt, &ctx, 4, &st); assert(p != NULL);   /* 1 connect */
    a = brix_cpool_checkout(p, &st);                                /* slot reuse */
    brix_cpool_checkin(p, a, 1);
    b = brix_cpool_checkout(p, &st);
    brix_cpool_checkin(p, b, 1);
    brix_cpool_destroy(p);
    assert(atomic_load(&ctx.closes) == atomic_load(&ctx.connects)); /* balanced */
    printf("ok test_destroy_closes_connected\n");
}

int
main(void)
{
    test_reuse();
    test_health_drop_reconnects();
    test_create_fails_on_bad_endpoint();
    test_contention_unique_issue();
    test_destroy_closes_connected();
    printf("ALL PASS\n");
    return 0;
}
