/*
 * tap_emit.c — sink registry + fan-out for the tap core.
 *
 * A bounded fixed array of sinks (no allocation). register_sink appends until
 * full (silently ignores overflow — a misconfiguration, not a runtime error);
 * emit calls every registered sink with the decoded frame + raw payload slice.
 */

#include "tap.h"

void
brix_tap_register_sink(brix_tap_ctx_t *t, brix_tap_sink_fn fn, void *ctx)
{
    if (t == NULL || fn == NULL || t->n >= BRIX_TAP_MAX_SINKS) {
        return;
    }
    t->sinks[t->n].fn  = fn;
    t->sinks[t->n].ctx = ctx;
    t->n++;
}

void
brix_tap_emit(brix_tap_ctx_t *t, const brix_tap_frame_t *f,
    brix_tap_dir_t dir, const uint8_t *payload, size_t payload_len)
{
    int i;

    if (t == NULL || f == NULL) {
        return;
    }
    for (i = 0; i < t->n; i++) {
        t->sinks[i].fn(t->sinks[i].ctx, f, dir, payload, payload_len);
    }
}
