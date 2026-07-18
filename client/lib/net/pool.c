/*
 * pool.c — brix_conn adapter over the generic brix_cpool engine.
 *
 * WHAT: brix_pool_create/checkout/checkin/destroy — the same public API as
 *       before (a pool of N brix_conn to one endpoint), now implemented as a
 *       thin vtable adapter over lib/net/cpool.c so the binary root:// path and
 *       the HTTP keep-alive metadata path share ONE pool implementation.
 * WHY:  the pool's slot/mutex/condvar/health-drop bookkeeping is transport-
 *       agnostic; only the connect/close and the connection type differ. Keeping
 *       brix_pool behavior-identical means the core root:// path is unchanged.
 * HOW:  a pool_ctx {url, opts} is the connect template stored INSIDE the heap
 *       brix_pool (so the &p->ctx handed to brix_cpool is stable for the pool's
 *       lifetime); the vtable wraps brix_connect/brix_close. No goto.
 *
 * Clean-room: composes the public libbrix connection API only.
 */
#include "brix.h"
#include "net/cpool.h"

#include <stdlib.h>

typedef struct { brix_url url; brix_opts opts; } pool_ctx;   /* connect template */

static int
pool_conn_connect(void *conn, void *ctx, brix_status *st)
{
    pool_ctx *c = ctx;
    return brix_connect((brix_conn *) conn, &c->url, &c->opts, st);
}

static void
pool_conn_close(void *conn)
{
    brix_close((brix_conn *) conn);
}

static const brix_cpool_vtbl POOL_VT = {
    sizeof(brix_conn), pool_conn_connect, pool_conn_close,
};

struct brix_pool { brix_cpool *cp; pool_ctx ctx; };   /* ctx outlives cp */

brix_pool *
brix_pool_create(const brix_url *u, const brix_opts *o, int n, brix_status *st)
{
    brix_pool *p;

    if (u == NULL || n < 1) {
        brix_status_set(st, XRDC_EUSAGE, 0, "pool: bad arguments");
        return NULL;
    }
    p = calloc(1, sizeof(*p));
    if (p == NULL) {
        brix_status_set(st, XRDC_ESOCK, 0, "pool: out of memory");
        return NULL;
    }
    p->ctx.url = *u;
    if (o != NULL) {
        p->ctx.opts = *o;
    }
    p->cp = brix_cpool_create(&POOL_VT, &p->ctx, n, st);   /* &p->ctx: stable */
    if (p->cp == NULL) {
        free(p);
        return NULL;
    }
    return p;
}

brix_conn *
brix_pool_checkout(brix_pool *p, brix_status *st)
{
    if (p == NULL) {
        brix_status_set(st, XRDC_EUSAGE, 0, "pool: null");
        return NULL;
    }
    return (brix_conn *) brix_cpool_checkout(p->cp, st);
}

void
brix_pool_checkin(brix_pool *p, brix_conn *c, int healthy)
{
    if (p != NULL) {
        brix_cpool_checkin(p->cp, c, healthy);
    }
}

void
brix_pool_destroy(brix_pool *p)
{
    if (p == NULL) {
        return;
    }
    brix_cpool_destroy(p->cp);
    free(p);
}
