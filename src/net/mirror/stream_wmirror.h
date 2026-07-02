#ifndef XROOTD_STREAM_WMIRROR_H
#define XROOTD_STREAM_WMIRROR_H

/*
 * stream_wmirror.h — Phase 24 W3: XRootD stream DATA-write mirroring.
 *
 * WHAT: Mirrors a client's open(write) -> write/pgwrite -> close sequence to an
 * ISOLATED shadow XRootD server so a new storage backend's write path can be
 * validated against real production writes.  Unlike the stateless read/metadata
 * mirror (stream_mirror.c), data writes are stateful: the client's file handle is
 * meaningless on the shadow and the payload spans many frames.
 *
 * HOW (low-risk design): per write-open, the bytes are accumulated into a bounded
 * per-file buffer attached to the client connection context.  On kXR_close the
 * buffered file is handed to a DETACHED replay (its own cycle-pool context, the
 * same fire-and-forget lifetime as the read mirror) that bootstraps a fresh shadow
 * session and performs open(create) -> write -> close.  This avoids a persistent
 * client-lifetime shadow connection (and the use-after-free hazards that come with
 * it).  A write that exceeds the per-file or per-connection byte cap, or is sparse
 * / non-sequential, aborts that file's mirror (counted) and never blocks the
 * client — write mirroring is best-effort validation.
 *
 * GATING: no-op unless xrootd_mirror_writes is on, OP_WRITE is selected in
 * xrootd_mirror_opcodes, and a stream mirror target is configured.  The target
 * MUST be an isolated namespace; replaying writes onto the primary's store would
 * corrupt it.
 *
 * Requires: types/context.h (xrootd_ctx_t), protocol headers, nginx headers.
 */

#include "core/ngx_xrootd_module.h"   /* umbrella: nginx + protocol + ctx/conf types */

/*
 * Begin accumulating a write-open for the data-write mirror.  Called from the
 * kXR_open success path (open_resolved_file.c), where the just-allocated client
 * handle index, the resolved request path, and the write flag are all known.
 * No-op unless this is a write open and data-write mirroring is enabled.
 */
void xrootd_stream_wmirror_on_open(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int client_idx, int is_write);

/*
 * Observe a just-dispatched kXR_write / kXR_pgwrite / kXR_close for the
 * data-write mirror.  Called from dispatch.c after the primary handled the op
 * (the client handle index is in ctx->hdr_buf[4]).  primary_rc is the primary's
 * dispatch result — a failed primary op is not mirrored.  On close, if a complete
 * sequential write was accumulated, a detached shadow replay is launched.  No-op
 * when data-write mirroring is not configured/enabled.
 */
void xrootd_stream_wmirror_observe(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, ngx_int_t primary_rc);

/*
 * Free any per-connection write-mirror accumulation state.  Called from the
 * connection teardown path (disconnect) so malloc'd per-file buffers are released.
 * Safe to call when no wmirror state was ever allocated.
 */
void xrootd_stream_wmirror_cleanup(xrootd_ctx_t *ctx);

#endif /* XROOTD_STREAM_WMIRROR_H */
