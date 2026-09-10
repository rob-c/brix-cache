/* File: stream_plan.c — pure arithmetic behind the multi-stream TPC pull
 * WHAT: the stream-count clamp, the per-round advance/EOF/hole verdict and the
 *       kXR_read read_args packer used by source_stream_multi.c. No nginx headers,
 *       no sockets — see stream_plan.h for the contract and the WHY.
 * HOW:  strtol with full-consumption check for the hint; a single left-to-right
 *       scan for the round verdict (first short slot ends the proven prefix, any
 *       later data is a hole); memset + one byte for the read_args. */
#include "stream_plan.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* WHAT: parse the client's tpc.str hint; anything not a clean positive decimal
 * integer means "no hint" (1). */
static int
tpc_stream_plan_parse_hint(const char *hint)
{
    char *end = NULL;
    long  v;

    if (hint == NULL || *hint == '\0') {
        return 1;
    }
    errno = 0;
    v = strtol(hint, &end, 10);
    if (errno != 0 || end == hint || *end != '\0' || v <= 0) {
        return 1;
    }
    return (v > TPC_STREAMS_MAX) ? TPC_STREAMS_MAX : (int) v;
}

int
tpc_stream_plan_clamp(const char *hint, int cap)
{
    int want = tpc_stream_plan_parse_hint(hint);

    if (cap < 1) {
        cap = 1;
    }
    if (cap > TPC_STREAMS_MAX) {
        cap = TPC_STREAMS_MAX;
    }
    return (want > cap) ? cap : want;
}

int
tpc_stream_plan_round(const size_t *got, int nslots, size_t window,
                      size_t *advance, int *eof)
{
    int    slot;
    int    short_seen = 0;
    size_t total      = 0;

    if (got == NULL || nslots <= 0 || advance == NULL || eof == NULL) {
        return -1;
    }

    for (slot = 0; slot < nslots; slot++) {
        if (short_seen) {
            if (got[slot] != 0) {
                return -1;                  /* data after a short window: a hole */
            }
            continue;
        }
        if (got[slot] > window) {
            return -1;                      /* the source over-delivered a window */
        }
        total += got[slot];
        if (got[slot] < window) {
            short_seen = 1;
        }
    }

    *advance = total;
    *eof     = (got[0] == 0) ? 1 : 0;
    return 0;
}

void
tpc_stream_plan_read_args(unsigned char out[TPC_READ_ARGS_LEN],
                          unsigned char pathid)
{
    memset(out, 0, TPC_READ_ARGS_LEN);
    out[0] = pathid;
}
