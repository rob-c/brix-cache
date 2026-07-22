#include "read.h"
#include "fs/backend/sd.h"      /* phase-55: route preadv through the SD seam */
#include "fs/vfs/vfs_io_core.h" /* brix_vfs_effective_obj + brix_readv_seg_desc_t */
#include "core/aio/aio.h"       /* brix_readv_read_segments prototype + seg desc */
#include "core/compat/safe_size.h"   /* Phase 27 W1: overflow-checked size math */

#include "core/ngx_brix_module.h"
#include "core/compat/range_vector.h"

#include <stdlib.h>
#include <sys/uio.h>

#define BRIX_READV_PREADV_MAXIOV  64

/* ---- Validate segments and populate the coalescer range array ----
 *
 * WHAT: Validates every segment's offset (non-negative, no read_length
 *   overflow) and fills the caller-owned `ranges` array with the
 *   brix_byte_range_t view the shared coalescer consumes.  Returns NGX_OK, or
 *   NGX_ERROR with `error_message` set on the first offending segment.
 *
 * WHY: The per-segment offset/overflow checks and range construction are a
 *   single pure pass with no I/O; isolating them keeps brix_readv_read_segments
 *   below the complexity gate and makes the validation independently reviewable.
 *
 * HOW:
 *   1. For each segment reject a negative offset (degenerate wire input).
 *   2. Reject a read_length that would overflow off_t when added to offset.
 *   3. Record fd/start/end for the coalescer; a zero-length segment gets a
 *      degenerate end (start-1) so it never coalesces.
 */
static ngx_int_t
brix_readv_build_ranges(const brix_readv_seg_desc_t *segments,
    size_t segment_count, brix_byte_range_t *ranges, char *error_message,
    size_t error_message_len)
{
    size_t i;

    for (i = 0; i < segment_count; i++) {
        if (segments[i].offset < 0) {
            snprintf(error_message, error_message_len,
                     "negative readv offset at seg %zu", i);
            return NGX_ERROR;
        }
        if (segments[i].read_length > 0
            && (off_t) segments[i].read_length
               > NGX_MAX_OFF_T_VALUE - segments[i].offset)
        {
            snprintf(error_message, error_message_len,
                     "readv offset overflow at seg %zu", i);
            return NGX_ERROR;
        }
        ranges[i].fd     = segments[i].fd;
        ranges[i].start  = segments[i].offset;
        ranges[i].end    = (segments[i].read_length > 0)
                           ? segments[i].offset
                             + (off_t) segments[i].read_length - 1
                           : segments[i].offset - 1; /* degenerate, no coalescing */
        ranges[i].handle = 0;
    }

    return NGX_OK;
}

/* ---- Immutable per-request context for the segment-run reader ----
 *
 * WHAT: Bundles the request-wide inputs the run reader needs on every call —
 *   the segment array, its count, the coalescer range view, and the error
 *   buffer — so only the varying cursor/out-params are passed per run.
 *
 * WHY: Keeps brix_readv_read_one_run within the parameter gate and makes the
 *   fixed-vs-varying split explicit (nothing in here changes across runs).
 *
 * HOW: brix_readv_read_segments fills it once and passes &rctx into each run.
 */
typedef struct {
    brix_readv_seg_desc_t *segments;
    size_t                   segment_count;
    const brix_byte_range_t *ranges;
    char                    *error_message;
    size_t                   error_message_len;
} brix_readv_run_ctx_t;

/* ---- Read one coalesced run of contiguous same-fd segments ----
 *
 * WHAT: Determines the contiguous run starting at `segment_index`, issues one
 *   preadv() through the Storage Driver seam to fill each segment's buffer, and
 *   reports the run's byte total via *run_bytes_out and its length via
 *   *run_count_out.  Returns NGX_OK, or NGX_ERROR with rctx->error_message set
 *   on an I/O error or a short (past-EOF) read.
 *
 * WHY: The coalesce-decision + iovec-assembly + single vectored read is the
 *   body of the segment loop; extracting it keeps the loop flat and lifts the
 *   EINTR / short-read policy into one named, testable step.
 *
 * HOW:
 *   1. Write the actual read length back into the run's leading wire header.
 *   2. Ask the shared coalescer how many segments form the next contiguous run.
 *   3. Assemble the preadv iovec from the original descriptors, summing bytes.
 *   4. Resolve the effective SD object (bound driver or POSIX fd wrap) and
 *      issue preadv, retrying on EINTR.
 *   5. Map a negative result to an I/O error and a short read to a past-EOF
 *      error; otherwise publish the run count and byte total.
 */
static ngx_int_t
brix_readv_read_one_run(const brix_readv_run_ctx_t *rctx,
    size_t segment_index, ngx_uint_t *run_count_out, size_t *run_bytes_out)
{
    struct iovec             iov[BRIX_READV_PREADV_MAXIOV];
    brix_readv_seg_desc_t *segments = rctx->segments;
    brix_readv_seg_desc_t *first_segment = &segments[segment_index];
    ngx_uint_t               run_count;
    size_t                   run_bytes;
    ngx_uint_t               k;
    ssize_t                  bytes_read;
    uint32_t                 rlen_be;

    /* Write actual read length back to the wire header. */
    rlen_be = htonl(first_segment->read_length);
    ngx_memcpy(first_segment->header_read_length_ptr, &rlen_be, 4);

    /*
     * Delegate the contiguous-run decision to the shared coalescer.
     * The coalescer checks fd equality and byte adjacency using the
     * ranges array built above.
     */
    run_count = brix_range_vector_next_coalesced_run(
        rctx->ranges, (ngx_uint_t) rctx->segment_count,
        (ngx_uint_t) segment_index,
        (ngx_uint_t) BRIX_READV_PREADV_MAXIOV);

    /* Assemble the preadv iovec from the original segment descriptors. */
    run_bytes = 0;
    for (k = 0; k < run_count; k++) {
        iov[k].iov_base = segments[segment_index + k].payload_ptr;
        iov[k].iov_len  = (size_t) segments[segment_index + k].read_length;
        run_bytes      += (size_t) segments[segment_index + k].read_length;
    }

    {
        brix_sd_obj_t  scratch;
        brix_sd_obj_t *obj;

        /* Route the coalesced vectored read through the Storage Driver seam:
         * the handle's bound driver object when set (block-striped/object
         * backend), else a POSIX fd wrap (unchanged). The EINTR /
         * coalescing policy stays here. */
        obj = brix_vfs_effective_obj(&first_segment->obj,
                                       first_segment->fd, &scratch);
        do {
            /* Compat seam: falls back to per-iovec pread when the driver has
             * no native preadv slot (remote/object backends). */
            bytes_read = brix_sd_obj_preadv(
                obj, iov, (int) run_count, first_segment->offset);
        } while (bytes_read < 0 && errno == EINTR);
    }

    if (bytes_read < 0) {
        snprintf(rctx->error_message, rctx->error_message_len,
                 "readv I/O error at seg %zu: %s",
                 segment_index, strerror(errno));
        return NGX_ERROR;
    }

    if ((size_t) bytes_read != run_bytes) {
        snprintf(rctx->error_message, rctx->error_message_len,
                 "readv past EOF at seg %zu", segment_index);
        return NGX_ERROR;
    }

    *run_count_out = run_count;
    *run_bytes_out = run_bytes;
    return NGX_OK;
}

/* Perform the readv I/O: coalesce contiguous same-fd segments into grouped
 * preadv calls (preserving on-wire order) and fill each segment's buffer.
 * Returns NGX_OK, or NGX_ERROR with the kXR error set. */
ngx_int_t
brix_readv_read_segments(brix_readv_seg_desc_t *segments,
    size_t segment_count, size_t *bytes_read_total, char *error_message,
    size_t error_message_len)
{
    brix_byte_range_t *ranges;
    size_t               segment_index;

    if (bytes_read_total == NULL) {
        return NGX_ERROR;
    }

    *bytes_read_total = 0;

    /* Phase 27 W1/F1: defense-in-depth — bound the segment count and use an
     * overflow-checked multiply for the array size (segment_count is derived
     * from the wire dlen and capped at recv time, but this guards a bypass). */
    {
        size_t ranges_sz;
        if (segment_count == 0 || segment_count > BRIX_READV_MAXSEGS
            || brix_size_mul(segment_count, sizeof(*ranges), &ranges_sz)
               != NGX_OK)
        {
            snprintf(error_message, error_message_len,
                     "readv: segment count out of range");
            return NGX_ERROR;
        }
        ranges = malloc(ranges_sz);
    }
    if (ranges == NULL) {
        snprintf(error_message, error_message_len, "readv: out of memory");
        return NGX_ERROR;
    }

    /*
     * Validate all segments upfront and build the brix_byte_range_t array
     * used by the shared coalescer.  Overflow and negative-offset errors are
     * caught here before any I/O.
     */
    if (brix_readv_build_ranges(segments, segment_count, ranges,
                                  error_message, error_message_len) != NGX_OK)
    {
        free(ranges);
        return NGX_ERROR;
    }

    {
    brix_readv_run_ctx_t rctx;

    rctx.segments          = segments;
    rctx.segment_count     = segment_count;
    rctx.ranges            = ranges;
    rctx.error_message     = error_message;
    rctx.error_message_len = error_message_len;

    for (segment_index = 0; segment_index < segment_count; ) {
        ngx_uint_t run_count;
        size_t     run_bytes;

        /* A zero-length segment still needs its wire header rewritten (to 0)
         * but performs no I/O and never coalesces; advance past it. */
        if (segments[segment_index].read_length == 0) {
            uint32_t rlen_be = htonl(segments[segment_index].read_length);
            ngx_memcpy(segments[segment_index].header_read_length_ptr,
                       &rlen_be, 4);
            segment_index++;
            continue;
        }

        if (brix_readv_read_one_run(&rctx, segment_index,
                                      &run_count, &run_bytes) != NGX_OK)
        {
            free(ranges);
            return NGX_ERROR;
        }

        *bytes_read_total += run_bytes;
        segment_index     += run_count;
    }
    }

    free(ranges);
    return NGX_OK;
}
