#ifndef BRIX_TPC_OUTBOUND_SOURCE_INTERNAL_H
#define BRIX_TPC_OUTBOUND_SOURCE_INTERNAL_H

/*
 * source_internal.h — cross-file seam for the TPC remote-source pull, split
 * (phase-79 file-size burndown) from a single oversized source.c into three
 * cohesive units with zero behaviour change:
 *
 *   source.c         — the public driver tpc_pull_from_source() (open→stream→close)
 *   source_open.c    — Phase 1: build/send kXR_open, resolve the async reply,
 *                      extract the origin fhandle (tpc_open_source)
 *   source_stream.c  — Phase 2/3: kXR_read stream loop + fsync, and the
 *                      best-effort remote close (tpc_stream_to_dst,
 *                      tpc_close_source)
 *
 * Only the three phase entry points cross a file boundary; every framing/parse
 * helper stays file-static in its own unit. Declared here so the driver and the
 * two phase units share one contract.
 */

#include "tpc/engine/tpc_internal.h"   /* brix_tpc_pull_t, XRD_FHANDLE_LEN */

/*
 * tpc_open_source — Phase 1: build and send the kXR_open for the remote source,
 * resolve the (possibly asynchronous) reply, and extract the origin fhandle.
 * Returns 0 with `fhandle` filled, or -1 with t->err_msg / t->xrd_error set. On
 * failure the caller has no origin handle to close. Defined in source_open.c.
 */
int tpc_open_source(brix_tpc_pull_t *t, int fd,
                    u_char fhandle[XRD_FHANDLE_LEN]);

/*
 * tpc_stream_to_dst — Phase 2/3: stream the whole source into t->dst_fd one
 * kXR_read window at a time, then fsync for durability. Returns 0 (with
 * t->result=NGX_OK, t->xrd_error=0) once fully written and synced, or -1 with
 * t->err_msg / t->xrd_error set. Defined in source_stream.c.
 */
int tpc_stream_to_dst(brix_tpc_pull_t *t, int fd, const u_char *fhandle);

/*
 * tpc_close_source — best-effort kXR_close of the origin fhandle, called on both
 * success and failure so the remote handle is never leaked; the result is
 * discarded but the reply is drained and freed. Defined in source_stream.c.
 */
void tpc_close_source(brix_tpc_pull_t *t, int fd, const u_char *fhandle);

#endif /* BRIX_TPC_OUTBOUND_SOURCE_INTERNAL_H */
