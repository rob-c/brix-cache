/*
 * scan_emit.h — ordered-emit reorder buffer for the storage-scan engine.
 *
 * WHAT: a small, pure, allocation-free reorder window. Worker threads finish
 *       per-object actions out of order but each carries a monotonic sequence
 *       number (assigned by the single producer walk); this buffer releases
 *       records to the emit callback strictly in sequence order.
 * WHY:  emitting in walk order is what makes the `after=<cursor>` resume
 *       contract sound — a cursor P means "every path ≤ P in walk order is
 *       done." Isolating the reorder logic keeps it unit-testable (no threads,
 *       no nginx) — the engine wraps it under its emit mutex.
 * HOW:  caller-owned storage (slots[window]/used[window]); submit(seq,payload)
 *       buffers then drains every now-contiguous record via the callback.
 */
#ifndef BRIX_SCAN_EMIT_H
#define BRIX_SCAN_EMIT_H

#include <stdint.h>

typedef void (*brix_scan_emit_cb)(void *ctx, uint64_t seq, void *payload);

typedef struct {
    uint64_t        next;     /* next sequence number to release                 */
    unsigned        window;   /* reorder window size (== #slots)                 */
    void          **slots;    /* [window] buffered payloads (NULL = empty)       */
    unsigned char  *used;     /* [window] occupancy flags                        */
} brix_scan_emitq_t;

/* Bind caller-owned storage. slots/used must each hold `window` entries. */
void brix_scan_emitq_init(brix_scan_emitq_t *q, void **slots,
                            unsigned char *used, unsigned window);

/* Buffer record `seq` (payload is opaque, caller-owned) then release every
 * contiguous record from `next` via cb (in order). Returns the number released,
 * or -1 if seq is a duplicate/already-emitted (< next) or beyond the window
 * (≥ next + window) — i.e. the reorder window would overflow. */
int brix_scan_emitq_submit(brix_scan_emitq_t *q, uint64_t seq, void *payload,
                             brix_scan_emit_cb cb, void *ctx);

#endif /* BRIX_SCAN_EMIT_H */
