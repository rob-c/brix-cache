/*
 * cpool.h — a thread-safe pool of opaque connections (generic engine).
 *
 * WHAT: brix_cpool_create/checkout/checkin/destroy over a caller-defined
 *       connection type (vtable {conn_size, connect, close}). Generalises
 *       lib/net/pool.c (now a thin brix_conn adapter over this) so the binary
 *       root:// path and the HTTP keep-alive metadata path share ONE
 *       slot/mutex/condvar/health-drop implementation.
 * WHY:  a connection is one-op-in-flight and NOT thread-safe; a multi-threaded
 *       consumer (the FUSE driver) needs N independent connections. The pool is
 *       the concurrency primitive; the transport is a vtable parameter.
 * HOW:  one mutex guards slot bookkeeping only (never held across connect/op);
 *       a condvar wakes a waiter on checkin; the vtable connects/closes the
 *       opaque per-slot memory. No goto. Clean-room (libc + pthread only).
 */
#ifndef BRIX_CPOOL_H
#define BRIX_CPOOL_H

#include "brix.h"
#include <stddef.h>

typedef struct {
    size_t conn_size;                                        /* slot memory bytes */
    int  (*connect)(void *conn, void *ctx, brix_status *st); /* bring a slot up   */
    void (*close)(void *conn);                               /* tear a slot down  */
} brix_cpool_vtbl;

typedef struct brix_cpool brix_cpool;

/* Create a pool of `n` slots. `ctx` is passed verbatim to every connect() (the
 * shared endpoint/opts template; the pool does NOT copy or own it — it must
 * outlive the pool). Slot 0 connects eagerly so a bad endpoint/auth fails up
 * front. NULL + st on failure. n clamped to [1,256]. */
brix_cpool *brix_cpool_create(const brix_cpool_vtbl *vt, void *ctx, int n,
                              brix_status *st);

/* Borrow a connected slot's conn memory, blocking until one is free; reconnects
 * a dropped slot transparently. NULL + st only if (re)connect fails. */
void *brix_cpool_checkout(brix_cpool *p, brix_status *st);

/* Return a checked-out conn. healthy==0 drops it (close + mark unconnected) so
 * the next checkout reconnects on a clean session. `conn` must be a pointer a
 * prior checkout returned. */
void  brix_cpool_checkin(brix_cpool *p, void *conn, int healthy);

void  brix_cpool_destroy(brix_cpool *p);   /* closes all connected slots */

#endif /* BRIX_CPOOL_H */
