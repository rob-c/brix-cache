#ifndef BRIX_READ_INTERNAL_H
#define BRIX_READ_INTERNAL_H

/*
 * read_internal.h — cross-file glue for the kXR_read serve paths.
 *
 * WHAT: the shared decoded-request struct plus the handful of serve helpers the
 * kXR_read dispatcher (read.c) reaches into read_sendfile.c / read_buffered.c to
 * call.  Everything declared here is DEFINED in one of those translation units
 * and REFERENCED from another; helpers used within a single file stay static
 * there and never appear in this header.
 * WHY: read.c was split for file-size — this header keeps the split link-clean
 * without changing any behavior.
 */

#include "read.h"
#include "core/ngx_brix_module.h"                      /* ngx_stream_brix_module */
#include "protocols/root/session/offload_registry.h"   /* brix_offload_lookup */

/*
 * brix_read_io_t — decoded per-request read parameters, threaded through the
 * serve helpers below.
 *
 * WHAT: the validated (idx, fd, offset, rlen) tuple of one kXR_read plus the
 * per-in-flight memory buffer once the buffered path acquires it.
 * WHY: the read handler dispatches across several serve strategies (sendfile,
 * windowed, warm-probe, AIO, sync); passing one struct keeps every helper at a
 * small explicit signature instead of re-plumbing five scalars each time.
 * HOW: filled by read_validate_req(); databuf stays NULL until the buffered
 * path allocates it.  File-local only — never crosses the event loop (the
 * windowed/AIO state machines snapshot what they need into ctx as before).
 */
typedef struct {
    int       idx;      /* file-table slot */
    ngx_fd_t  fd;       /* backing fd for the slot */
    int64_t   offset;   /* requested file offset */
    size_t    rlen;     /* requested length, clamped to BRIX_READ_REQUEST_MAX */
    u_char   *databuf;  /* per-in-flight buffer (memory path only) */
    unsigned  pathid;   /* §1.1 read_args response-offload channel (0 = primary/
                           control stream); validated as a live bound path */
} brix_read_io_t;

/* Defined in read_sendfile.c */
ngx_fd_t read_sendfile_serve_fd(brix_ctx_t *ctx, ngx_connection_t *c,
    const brix_read_io_t *io);
ngx_int_t brix_read_serve_sendfile(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, const brix_read_io_t *io,
    ngx_fd_t sfd);

/* Defined in read_buffered.c */
size_t read_clamped_total(brix_ctx_t *ctx, const brix_read_io_t *io);
ngx_int_t read_serve_windowed(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, const brix_read_io_t *io,
    size_t total);
ngx_int_t read_serve_buffered(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, brix_read_io_t *io);

/* Resolve a data-path `pathid` to a live secondary connection with a free ring
 * slot, for offloading a single-frame read/readv/pgread reply. Returns the
 * secondary ctx (with *sec_c_out set) when the reply may pipeline behind its
 * existing responses, or NULL to fall back to the primary. A free slot needs
 * every pending response counted — queued (out.count) + write-ack (wr_inflight)
 * + read AIO (rd.aio_inflight) strictly below pipeline_depth — so the queued
 * frame can never overrun the ring. resp_async streams stay on the control path. */
static inline brix_ctx_t *
brix_read_offload_secondary(brix_ctx_t *ctx, ngx_connection_t *c,
    uint32_t pathid, ngx_connection_t **sec_c_out)
{
    const u_char     *sessid;
    ngx_connection_t *sec_c;
    brix_ctx_t       *sec_ctx;

    if (pathid == 0) {
        return NULL;   /* primary/control stream — no lookup needed */
    }
    /* The pathid was validated against this session key at request decode. */
    sessid = ctx->is_bound ? ctx->bound_sessid : ctx->login.sessid;
    sec_c  = brix_offload_lookup(sessid, pathid);
    if (sec_c == NULL || sec_c == c) {
        return NULL;   /* bound elsewhere (or self) — use the control stream */
    }
    sec_ctx = ngx_stream_get_module_ctx((ngx_stream_session_t *) sec_c->data,
                                        ngx_stream_brix_module);
    if (sec_ctx == NULL || sec_ctx->destroyed
        || sec_c->fd == (ngx_socket_t) -1 || sec_ctx->out.resp_async
        || sec_ctx->out.count + sec_ctx->out.wr_inflight
           + sec_ctx->rd.aio_inflight >= sec_ctx->out.pipeline_depth)
    {
        return NULL;
    }
    *sec_c_out = sec_c;
    return sec_ctx;
}

#endif // BRIX_READ_INTERNAL_H
