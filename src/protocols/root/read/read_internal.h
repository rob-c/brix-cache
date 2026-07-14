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
} brix_read_io_t;

/* Defined in read_sendfile.c */
ngx_flag_t read_sendfile_eligible(brix_ctx_t *ctx, ngx_connection_t *c,
    int idx);
ngx_int_t brix_read_serve_sendfile(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, const brix_read_io_t *io);

/* Defined in read_buffered.c */
size_t read_clamped_total(brix_ctx_t *ctx, const brix_read_io_t *io);
ngx_int_t read_serve_windowed(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, const brix_read_io_t *io,
    size_t total);
ngx_int_t read_serve_buffered(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, brix_read_io_t *io);

#endif // BRIX_READ_INTERNAL_H
