/*
 * cpool.c — a small thread-safe pool of opaque connections (generic engine).
 *
 * WHAT: brix_cpool_create/checkout/checkin/destroy over a caller-defined
 *       connection type (vtable {conn_size, connect, close}). Extracted from
 *       lib/net/pool.c so the binary root:// path (brix_pool adapter) and the
 *       HTTP keep-alive metadata path (brix_webmeta) share ONE pool.
 * WHY:  a connection is one-op-in-flight and NOT thread-safe; a multi-threaded
 *       consumer needs N independent connections. The pool is the concurrency
 *       primitive; the transport is a vtable parameter.
 * HOW:  one mutex guards slot bookkeeping only (never held across connect/op);
 *       a condvar wakes a waiter on checkin; the vtable connects/closes the
 *       opaque per-slot memory. No goto. Clean-room (libc + pthread only).
 */
#include "brix.h"
#include "net/cpool.h"

#include <pthread.h>
#include <stdlib.h>

typedef struct {
    void *conn;        /* calloc(1, vt->conn_size) — opaque to the pool */
    int   connected;   /* 1 once a successful connect/reconnect has run */
    int   in_use;      /* checked out by a thread */
} cpool_slot;

struct brix_cpool {
    brix_cpool_vtbl vt;
    void           *ctx;    /* connect template; NOT owned, must outlive pool */
    int             n;
    cpool_slot     *slots;
    pthread_mutex_t lock;
    pthread_cond_t  avail;
};

/* Bring a reserved (in_use) slot to a connected state; lock NOT held. */
static int
cpool_slot_connect(brix_cpool *p, cpool_slot *s, brix_status *st)
{
    if (s->connected) {
        return 0;
    }
    if (p->vt.connect(s->conn, p->ctx, st) != 0) {
        return -1;
    }
    s->connected = 1;
    return 0;
}

brix_cpool *
brix_cpool_create(const brix_cpool_vtbl *vt, void *ctx, int n, brix_status *st)
{
    brix_cpool *p;
    int         i;

    if (vt == NULL || vt->connect == NULL || vt->close == NULL
        || vt->conn_size == 0 || n < 1) {
        brix_status_set(st, XRDC_EUSAGE, 0, "cpool: bad arguments");
        return NULL;
    }
    if (n > 256) {
        n = 256;   /* sanity cap */
    }
    p = calloc(1, sizeof(*p));
    if (p == NULL) {
        brix_status_set(st, XRDC_ESOCK, 0, "cpool: out of memory");
        return NULL;
    }
    p->slots = calloc((size_t) n, sizeof(*p->slots));
    if (p->slots == NULL) {
        free(p);
        brix_status_set(st, XRDC_ESOCK, 0, "cpool: out of memory");
        return NULL;
    }
    for (i = 0; i < n; i++) {
        p->slots[i].conn = calloc(1, vt->conn_size);
        if (p->slots[i].conn == NULL) {
            while (--i >= 0) {
                free(p->slots[i].conn);
            }
            free(p->slots);
            free(p);
            brix_status_set(st, XRDC_ESOCK, 0, "cpool: out of memory");
            return NULL;
        }
    }
    p->vt  = *vt;
    p->ctx = ctx;
    p->n   = n;
    pthread_mutex_init(&p->lock, NULL);
    pthread_cond_init(&p->avail, NULL);

    /* Connect slot 0 eagerly so a bad endpoint / auth fails up front; the
     * remaining slots connect lazily on first use. */
    p->slots[0].in_use = 1;
    if (cpool_slot_connect(p, &p->slots[0], st) != 0) {
        p->slots[0].in_use = 0;
        brix_cpool_destroy(p);
        return NULL;
    }
    p->slots[0].in_use = 0;
    return p;
}

void *
brix_cpool_checkout(brix_cpool *p, brix_status *st)
{
    cpool_slot *s = NULL;
    int         i;

    if (p == NULL) {
        brix_status_set(st, XRDC_EUSAGE, 0, "cpool: null");
        return NULL;
    }
    pthread_mutex_lock(&p->lock);
    for (;;) {
        for (i = 0; i < p->n; i++) {
            if (!p->slots[i].in_use) {
                s = &p->slots[i];
                s->in_use = 1;
                break;
            }
        }
        if (s != NULL) {
            break;
        }
        pthread_cond_wait(&p->avail, &p->lock);   /* all busy: wait for checkin */
    }
    pthread_mutex_unlock(&p->lock);

    /* Connect/reconnect outside the lock (the slot is reserved). */
    if (cpool_slot_connect(p, s, st) != 0) {
        pthread_mutex_lock(&p->lock);
        s->in_use = 0;
        pthread_cond_signal(&p->avail);
        pthread_mutex_unlock(&p->lock);
        return NULL;
    }
    return s->conn;
}

void
brix_cpool_checkin(brix_cpool *p, void *conn, int healthy)
{
    int i;

    if (p == NULL || conn == NULL) {
        return;
    }
    /* A connection-level failure (healthy==0) means this conn's socket/session
     * is suspect — close it and clear `connected` so the next checkout
     * reconnects on a clean session rather than handing back a dead socket. */
    if (!healthy) {
        for (i = 0; i < p->n; i++) {
            if (p->slots[i].conn == conn) {
                if (p->slots[i].connected) {
                    p->vt.close(p->slots[i].conn);
                    p->slots[i].connected = 0;
                }
                break;
            }
        }
    }
    pthread_mutex_lock(&p->lock);
    for (i = 0; i < p->n; i++) {
        if (p->slots[i].conn == conn) {
            p->slots[i].in_use = 0;
            break;
        }
    }
    pthread_cond_signal(&p->avail);
    pthread_mutex_unlock(&p->lock);
}

void
brix_cpool_destroy(brix_cpool *p)
{
    int i;

    if (p == NULL) {
        return;
    }
    for (i = 0; i < p->n; i++) {
        if (p->slots[i].connected) {
            p->vt.close(p->slots[i].conn);
        }
        free(p->slots[i].conn);
    }
    pthread_mutex_destroy(&p->lock);
    pthread_cond_destroy(&p->avail);
    free(p->slots);
    free(p);
}
