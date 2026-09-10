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
#include <time.h>

/*
 * tpc_open_spec_t — the three things that differ between one outbound kXR_open
 * and another: the remote path, the opaque suffix to append to it (may be empty,
 * opqlen 0), and the kXR_open_* option bits. Everything else about an outbound
 * open — async wait/waitresp resolution, redirect capture, fhandle extraction —
 * is direction-independent and lives in tpc_open_remote.
 *
 * F16: the push's leg-3 open uses kXR_open_updt ONLY — never kXR_new/kXR_delete.
 * The destination file was already created by the CLIENT's leg-1 write-open,
 * which is what registered the rendezvous key; an update-only open therefore
 * cannot bring a new file into existence, so a push can only ever write where a
 * client explicitly asked for one. Widening these bits would break that.
 */
typedef struct {
    const char *path;       /* remote path to open (NUL-terminated) */
    const char *opaque;     /* "?a=b&c=d" suffix, or NULL/"" for none */
    size_t      opqlen;     /* bytes of `opaque` to send, 0 for none */
    uint16_t    options;    /* kXR_open_* bits, host byte order */
} tpc_open_spec_t;

/*
 * tpc_open_remote — send one kXR_open described by `spec` on the bootstrapped
 * socket `fd`, resolve the (possibly asynchronous) reply, and extract the remote
 * fhandle. Returns 0 with `fhandle` filled, or -1 with t->err_msg /
 * t->xrd_error set. Defined in source_open.c; used by both directions.
 */
int tpc_open_remote(brix_tpc_pull_t *t, int fd, const tpc_open_spec_t *spec,
                    u_char fhandle[XRD_FHANDLE_LEN]);

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
 * tpc_stream_to_dst_multi — F7: the same contract as tpc_stream_to_dst with
 * one kXR_read window in flight per bound sub-stream plus the primary
 * (t->nsub > 0). Defined in source_stream_multi.c.
 */
int tpc_stream_to_dst_multi(brix_tpc_pull_t *t, int fd, const u_char *fhandle);

/*
 * Pieces of the single-stream loop shared with the multi-stream loop (F7) so
 * the two cannot drift: frame classification, the positional write of one
 * frame (advancing *got and t->bytes_written), the brix_tpc_max_transfer_secs
 * deadline, and the completion gate + fsync that sets t->result. All defined
 * in source_stream.c; each returns 0 or -1 with t->err_msg / t->xrd_error set.
 */
int tpc_stream_classify_frame(brix_tpc_pull_t *t, uint16_t status,
                              const u_char *body, uint32_t dlen,
                              uint64_t offset);
int tpc_stream_write_frame(brix_tpc_pull_t *t, uint64_t offset, size_t *got,
                           u_char *body, uint32_t dlen);
int tpc_stream_check_deadline(brix_tpc_pull_t *t, time_t pull_start,
                              uint64_t offset);
int tpc_stream_finish(brix_tpc_pull_t *t);

/*
 * tpc_close_source — best-effort kXR_close of the origin fhandle, called on both
 * success and failure so the remote handle is never leaked; the result is
 * discarded but the reply is drained and freed. Defined in source_stream.c.
 */
void tpc_close_source(brix_tpc_pull_t *t, int fd, const u_char *fhandle);

/*
 * tpc_stat_source — kXR_stat the remote source by path to capture its
 * authoritative size (t->src_size / t->src_size_known), the pull's real
 * completion signal. Returns 0 if the stat round-tripped (a source that errors
 * or omits a parseable size just leaves src_size_known=0 for the caller's policy
 * to weigh), -1 only on a socket/framing failure that must abort the pull.
 * Defined in source_stream.c.
 */
int tpc_stat_source(brix_tpc_pull_t *t, int fd);

/*
 * tpc_verify_source_checksum — opt-in post-copy integrity: kXR_query(kXR_Qcksum)
 * the source for its content checksum, recompute the same algorithm over the
 * written destination file, and fail closed on any mismatch (or when the source
 * cannot supply a checksum). Returns 0 on a verified match, -1 with t->err_msg /
 * t->xrd_error set otherwise. Defined in source_stream.c.
 */
int tpc_verify_source_checksum(brix_tpc_pull_t *t, int fd);

#endif /* BRIX_TPC_OUTBOUND_SOURCE_INTERNAL_H */
