/*
 * pgread_internal.h — seam between pgread.c (offload/response orchestration)
 * and pgread_request.c (request decode + warm inline path): the per-request
 * run struct, the page-geometry constants, and the three front-half steps
 * the handler calls in order.
 */
#ifndef BRIX_READ_PGREAD_INTERNAL_H
#define BRIX_READ_PGREAD_INTERNAL_H

#include "read.h"
#include "core/compat/pgio.h"     /* kXR_pgPageSZ / kXR_pgUnitSZ page geometry */

/* CRC32c word size per page unit ([CRC32c(4)][data]); == kXR_pgUnitSZ - page. */
#define BRIX_PG_CKSZ        ((size_t) (kXR_pgUnitSZ - kXR_pgPageSZ))

/*
 * Warm-probe ceiling: a request at most this large is read+CRCed inline on
 * the event loop when page-cache resident (the thread-pool handoff, not the
 * copy, dominates at this size).  Anything larger always posts to the pool:
 * with pgreads pipelined, a pool thread reads+CRCs request N+1 into its own
 * rd_pool slot WHILE the event loop writev-s response N — overlapping the two
 * kernel copies that an inline serve would serialize.  One streaming window
 * keeps the inline cost well under a millisecond.
 */
#define BRIX_PGREAD_WARM_INLINE_MAX  ((size_t) BRIX_READ_WINDOW)

/*
 * brix_pgread_run_t - per-request state threaded through the pgread steps.
 *
 * WHAT: The decoded request (handle index, fd, offset, capped length), the
 *       per-request wire buffer, and the produced output {out_buf, out_size,
 *       flat_buf} — filled by exactly one producer path (warm hit, AIO
 *       offload, or sync fallback).
 *
 * WHY: Makes the phase-72.A invariant structural: out_buf/flat_buf/out_size
 *      start NULL/0 (the handler zeroes the struct) and every producer sets
 *      all three through this one struct, so the pre-framing out_buf==NULL
 *      guard catches any path that failed to produce output.
 */
typedef struct {
    int       idx;        /* file-handle table index                        */
    int       fd;         /* resolved file descriptor                       */
    int64_t   offset;     /* requested file offset                          */
    size_t    rlen;       /* capped request length; sync path: bytes read   */
    unsigned  pathid;     /* §1.2 request args: response path (0 = primary) */
    unsigned  reqflags;   /* §1.2 request args: kXR_pgRetry or 0            */
    u_char   *scratch;    /* gapped wire buffer (this request's rd_pool slot;
                             the offload path substitutes the secondary's
                             frame buffer instead)                          */
    u_char   *out_buf;    /* encoded output start (NULL until produced)     */
    u_char   *flat_buf;   /* buffer to release after send (NULL until set)  */
    size_t    out_size;   /* encoded output bytes (0 until produced)        */
} brix_pgread_run_t;

/* Decode + early checks; 0 = fully handled, *rc set (see docblock). */
ngx_int_t brix_pgread_parse_validate(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_pgread_run_t *run, ngx_int_t *rc);
/* Worst-case gapped wire-buffer size for run->rlen. */
size_t brix_pgread_scratch_size(const brix_pgread_run_t *run);
/* Inline warm-cache fast path; non-zero = run->out_buf/out_size produced. */
ngx_flag_t brix_pgread_try_warm(brix_ctx_t *ctx,
    ngx_stream_brix_srv_conf_t *rconf, brix_pgread_run_t *run);
/* Windowed primary-path streaming for a request larger than one window:
 * arms the rd.win_* state machine with win_pgread set and kicks the shared
 * window pump (pgread_window.c). */
ngx_int_t brix_pgread_serve_windowed(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, const brix_pgread_run_t *run);

#endif /* BRIX_READ_PGREAD_INTERNAL_H */
