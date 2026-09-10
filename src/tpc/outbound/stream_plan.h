/*
 * stream_plan.h — pure planning helpers for the multi-stream native TPC pull.
 *
 * WHAT: the three decisions the parallel-stream read loop (source_stream_multi.c)
 *       makes per round, kept free of nginx and sockets so they are unit-tested
 *       directly (stream_plan_unittest.c) instead of only through a live pull:
 *         - tpc_stream_plan_clamp:     how many streams a transfer may use, from
 *                                      the client's tpc.str hint and the server cap
 *         - tpc_stream_plan_round:     how far a round of N windowed reads advanced
 *                                      the file, and whether it reached EOF
 *         - tpc_stream_plan_read_args: the 8-byte kXR_read read_args payload that
 *                                      steers a reply out of a bound sub-stream
 * WHY:  a windowed pull that mis-accounts a short window silently commits a file
 *       with a hole in it; a clamp that trusts the client hint lets one transfer
 *       open an unbounded fan of sockets to a source. Both are pure arithmetic and
 *       belong under a deterministic test, not behind a rendezvous.
 * HOW:  header-only prototypes; the implementation (stream_plan.c) uses only the
 *       C library. Wire facts: XRootD read_args = { pathid[1], reserved[7] }
 *       (XProtocol.hh), pathid 0 = the requesting (primary) stream.
 */
#ifndef BRIX_TPC_OUTBOUND_STREAM_PLAN_H
#define BRIX_TPC_OUTBOUND_STREAM_PLAN_H

#include <stddef.h>

/* Absolute ceiling on parallel source streams for one native TPC pull: the
 * primary plus up to 14 bound sub-streams. Matches the largest value the
 * brix_tpc_streams directive accepts (its range check names this number). */
#define TPC_STREAMS_MAX       15
#define TPC_SUBSTREAMS_MAX    (TPC_STREAMS_MAX - 1)

/* Length of the kXR_read read_args payload (pathid + 7 reserved bytes). */
#define TPC_READ_ARGS_LEN     8

/*
 * Resolve the stream count for a transfer. `hint` is the client's tpc.str value
 * (NULL/empty/non-numeric/<=0 → 1: a single stream, the pre-F7 behaviour); `cap`
 * is the server's brix_tpc_streams (<1 → 1). Returns a value in [1, min(cap,
 * TPC_STREAMS_MAX)] — the client can lower the server's ceiling, never raise it.
 */
int tpc_stream_plan_clamp(const char *hint, int cap);

/*
 * Judge one round of `nslots` windowed reads of `window` bytes each, issued at
 * consecutive offsets (slot i covers [base + i*window, base + (i+1)*window)).
 * got[i] = bytes the source delivered for slot i. On success sets *advance to
 * the contiguous byte count the round proved (the sum up to and including the
 * first short slot) and *eof to 1 when slot 0 delivered nothing (the source is
 * exhausted; nothing after it can hold data). Returns 0, or -1 when a slot AFTER
 * a short one still delivered bytes — a hole that must fail the pull rather than
 * be committed. `got` may not be NULL; nslots <= 0 is an error.
 */
int tpc_stream_plan_round(const size_t *got, int nslots, size_t window,
                          size_t *advance, int *eof);

/*
 * Fill the kXR_read read_args payload that asks the source to answer on the
 * sub-stream bound as `pathid` (0 = answer on the requesting stream).
 */
void tpc_stream_plan_read_args(unsigned char out[TPC_READ_ARGS_LEN],
                               unsigned char pathid);

#endif /* BRIX_TPC_OUTBOUND_STREAM_PLAN_H */
