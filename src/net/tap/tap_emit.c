/*
 * tap_emit.c — sink registry + fan-out for the tap core.
 *
 * A bounded fixed array of sinks (no allocation). register_sink appends until
 * full (silently ignores overflow — a misconfiguration, not a runtime error);
 * emit calls every registered sink with the decoded frame + raw payload slice.
 */

#include "tap.h"

void
xrootd_tap_register_sink(xrootd_tap_ctx_t *t, xrootd_tap_sink_fn fn, void *ctx)
{
    if (t == NULL || fn == NULL || t->n >= XROOTD_TAP_MAX_SINKS) {
        return;
    }
    t->sinks[t->n].fn  = fn;
    t->sinks[t->n].ctx = ctx;
    t->n++;
}

void
xrootd_tap_emit(xrootd_tap_ctx_t *t, const xrootd_tap_frame_t *f,
    xrootd_tap_dir_t dir, const uint8_t *payload, size_t payload_len)
{
    int i;

    if (t == NULL || f == NULL) {
        return;
    }
    for (i = 0; i < t->n; i++) {
        t->sinks[i].fn(t->sinks[i].ctx, f, dir, payload, payload_len);
    }
}
