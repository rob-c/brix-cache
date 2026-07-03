/*
 * scan_emit.c — ordered-emit reorder buffer (see scan_emit.h).
 *
 * Pure, allocation-free, no threads of its own. The engine calls submit() under
 * its emit mutex so concurrent worker completions serialize through here and
 * leave in walk order. Unit-tested by scan_unittest.c.
 */
#include "scan_emit.h"

#include <stddef.h>

void
brix_scan_emitq_init(brix_scan_emitq_t *q, void **slots, unsigned char *used,
                       unsigned window)
{
    unsigned i;

    q->next = 0;
    q->window = window;
    q->slots = slots;
    q->used = used;
    for (i = 0; i < window; i++) {
        q->slots[i] = NULL;
        q->used[i] = 0;
    }
}

int
brix_scan_emitq_submit(brix_scan_emitq_t *q, uint64_t seq, void *payload,
                         brix_scan_emit_cb cb, void *ctx)
{
    unsigned idx;
    int      released = 0;

    /* already emitted, or beyond the reorder window ⇒ caller error */
    if (seq < q->next || seq >= q->next + q->window) {
        return -1;
    }
    idx = (unsigned) (seq % q->window);
    if (q->used[idx]) {
        return -1;   /* duplicate seq in-flight */
    }
    q->slots[idx] = payload;
    q->used[idx] = 1;

    /* drain every now-contiguous record in order */
    while (q->used[q->next % q->window]) {
        unsigned i = (unsigned) (q->next % q->window);
        void    *p = q->slots[i];

        q->used[i] = 0;
        q->slots[i] = NULL;
        cb(ctx, q->next, p);
        q->next++;
        released++;
    }
    return released;
}
