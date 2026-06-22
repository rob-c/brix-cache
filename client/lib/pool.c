/*
 * pool.c — a small thread-safe pool of xrdc_conn for concurrent callers.
 *
 * WHAT: xrdc_pool_create/checkout/checkin/destroy. A fixed array of N xrdc_conn,
 *       each lazily connected to the same endpoint; checkout hands a free,
 *       connected conn to one thread (blocking until one is free), checkin
 *       returns it (and, when the caller reports the op hit a connection-level
 *       error, drops the conn so the next checkout transparently reconnects).
 * WHY:  An xrdc_conn is one-request-in-flight and NOT thread-safe, so a
 *       multi-threaded consumer (the FUSE driver) needs several independent
 *       connections rather than one mutex-serialised global. The pool is the
 *       concurrency primitive that lets xrootdfs drop its forced single-thread.
 * HOW:  One mutex guards slot bookkeeping only (held briefly — never during the
 *       slow connect/op), a condvar wakes a waiter on checkin. Each slot owns its
 *       xrdc_conn; reconnect reuses xrdc_connect with the stored url+opts so a
 *       redirected/dropped conn returns to a clean session. No goto.
 *
 * Clean-room: composes the public libxrdc connection API only.
 */
#include "xrdc.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    xrdc_conn conn;
    int       connected;   /* 1 once a successful connect/reconnect has run */
    int       in_use;      /* checked out by a thread */
} xrdc_pool_slot;

struct xrdc_pool {
    xrdc_url        url;
    xrdc_opts       opts;
    int             n;
    xrdc_pool_slot *slots;
    pthread_mutex_t lock;
    pthread_cond_t  avail;
};

/* Bring a reserved (in_use) slot to a connected state; lock NOT held (connect is
 * slow and the slot is already reserved, so no other thread can touch it). */
static int
pool_slot_connect(xrdc_pool *p, xrdc_pool_slot *s, xrdc_status *st)
{
    if (s->connected) {
        return 0;
    }
    if (xrdc_connect(&s->conn, &p->url, &p->opts, st) != 0) {
        return -1;
    }
    s->connected = 1;
    return 0;
}

xrdc_pool *
xrdc_pool_create(const xrdc_url *u, const xrdc_opts *o, int n, xrdc_status *st)
{
    xrdc_pool *p;

    if (u == NULL || n < 1) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "pool: bad arguments");
        return NULL;
    }
    if (n > 256) {
        n = 256;   /* sanity cap */
    }

    p = calloc(1, sizeof(*p));
    if (p == NULL) {
        xrdc_status_set(st, XRDC_ESOCK, 0, "pool: out of memory");
        return NULL;
    }
    p->slots = calloc((size_t) n, sizeof(*p->slots));
    if (p->slots == NULL) {
        free(p);
        xrdc_status_set(st, XRDC_ESOCK, 0, "pool: out of memory");
        return NULL;
    }
    p->url = *u;
    if (o != NULL) {
        p->opts = *o;
    }
    p->n = n;
    pthread_mutex_init(&p->lock, NULL);
    pthread_cond_init(&p->avail, NULL);

    /* Connect slot 0 eagerly so a bad endpoint / auth fails the mount up front;
     * the remaining slots connect lazily on first use. */
    p->slots[0].in_use = 1;
    if (pool_slot_connect(p, &p->slots[0], st) != 0) {
        p->slots[0].in_use = 0;
        xrdc_pool_destroy(p);
        return NULL;
    }
    p->slots[0].in_use = 0;
    return p;
}

xrdc_conn *
xrdc_pool_checkout(xrdc_pool *p, xrdc_status *st)
{
    xrdc_pool_slot *s = NULL;
    int             i;

    if (p == NULL) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "pool: null");
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
        pthread_cond_wait(&p->avail, &p->lock);   /* all busy: wait for a checkin */
    }
    pthread_mutex_unlock(&p->lock);

    /* Connect/reconnect outside the lock (the slot is reserved). */
    if (pool_slot_connect(p, s, st) != 0) {
        pthread_mutex_lock(&p->lock);
        s->in_use = 0;
        pthread_cond_signal(&p->avail);
        pthread_mutex_unlock(&p->lock);
        return NULL;
    }
    return &s->conn;
}

void
xrdc_pool_checkin(xrdc_pool *p, xrdc_conn *c, int healthy)
{
    int i;

    if (p == NULL || c == NULL) {
        return;
    }

    /* A connection-level failure (healthy==0) means this conn's socket/session is
     * suspect — close it and clear `connected` so the next checkout reconnects on
     * a clean session rather than handing back a dead socket. */
    if (!healthy) {
        for (i = 0; i < p->n; i++) {
            if (&p->slots[i].conn == c) {
                if (p->slots[i].connected) {
                    xrdc_close(&p->slots[i].conn);
                    p->slots[i].connected = 0;
                }
                break;
            }
        }
    }

    pthread_mutex_lock(&p->lock);
    for (i = 0; i < p->n; i++) {
        if (&p->slots[i].conn == c) {
            p->slots[i].in_use = 0;
            break;
        }
    }
    pthread_cond_signal(&p->avail);
    pthread_mutex_unlock(&p->lock);
}

void
xrdc_pool_destroy(xrdc_pool *p)
{
    int i;

    if (p == NULL) {
        return;
    }
    for (i = 0; i < p->n; i++) {
        if (p->slots[i].connected) {
            xrdc_close(&p->slots[i].conn);
        }
    }
    pthread_mutex_destroy(&p->lock);
    pthread_cond_destroy(&p->avail);
    free(p->slots);
    free(p);
}
